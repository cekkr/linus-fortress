import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from fastapi import HTTPException
from fastapi.testclient import TestClient

from test_permissions_matrix import load_server_module

from fortress import containers as container_ops
from fortress.api import containers as container_api


class ContainerRouteTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        temp_dir = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.audit_db = temp_dir / "audit.db"
        stack.enter_context(mock.patch.dict(os.environ, {
            "FORTRESS_LOG_PATH": str(temp_dir / "fortress.log"),
            "FORTRESS_COMMAND_LOG_DB": str(self.audit_db),
        }))
        previous_audit = container_ops._AUDIT_CALLBACK
        self.addCleanup(container_ops.configure_audit, previous_audit)
        server, module_name = load_server_module(str(temp_dir))
        self.addCleanup(sys.modules.pop, module_name, None)
        server.API_USERS_DB = str(temp_dir / "api_users.json")
        server.save_api_users({
            "token-operator": {"permissions": ["manage_containers"], "allowed_containers": ["web"]},
            "token-links": {"permissions": ["connectivity"], "allowed_containers": ["web", "db"]},
            "token-links-scoped": {"permissions": ["connectivity"], "allowed_containers": ["web"]},
        })
        self.client = stack.enter_context(TestClient(server.app))
        self.run_command = stack.enter_context(mock.patch.object(container_ops, "run_command", return_value=""))

    def request(self, method, path, token="token-operator", **kwargs):
        return self.client.request(method, path, headers={"X-User-Token": token}, **kwargs)

    def audit_rows(self, action):
        with sqlite3.connect(self.audit_db) as db:
            return db.execute("SELECT status, details FROM command_log WHERE action = ? ORDER BY id", (action,)).fetchall()

    def test_lifecycle_requires_permission_and_scope_and_audits_failures(self):
        for token, name in [("token-links", "web"), ("token-operator", "db")]:
            response = self.request("POST", "/containers/start", token, json={"container_name": name})
            self.assertEqual(response.status_code, 403)
        self.run_command.assert_not_called()

        for action, extra_args in [("start", []), ("stop", ["--force"]), ("restart", ["--force"])]:
            with self.subTest(action=action):
                response = self.request("POST", f"/containers/{action}", json={"container_name": "web", "force": True})
                self.assertEqual(response.status_code, 200, response.text)
                self.run_command.assert_called_with(["lxc", action, "web", *extra_args])
        self.assertEqual(self.run_command.call_count, 3)

        self.run_command.side_effect = HTTPException(500, "LXD unavailable")
        response = self.request("POST", "/containers/restart", json={"container_name": "web"})
        self.assertEqual(response.status_code, 500)
        self.assertEqual([status for status, _ in self.audit_rows("containers_restart")], ["success", "error"])

    def test_snapshot_and_log_routes_preserve_response_shape(self):
        snapshot = {"container_name": "web", "snapshot_name": "checkpoint", "stateful": True}
        self.assertEqual(self.request("GET", "/containers/db/snapshots").status_code, 403)
        self.assertEqual(self.request("POST", "/containers/snapshot", json=snapshot).status_code, 200)
        self.run_command.assert_called_with(["lxc", "snapshot", "web", "checkpoint", "--stateful"])

        self.run_command.return_value = '[{"name": "checkpoint", "stateful": true}]'
        self.assertEqual(self.request("GET", "/containers/web/snapshots").json(), {"snapshots": ["checkpoint"]})
        self.run_command.assert_called_with(["lxc", "query", "/1.0/instances/web/snapshots?recursion=1"])
        self.run_command.return_value = "[]"
        self.assertEqual(self.request("GET", "/containers/web/snapshots").json(), {"snapshots": []})
        self.run_command.return_value = "{}"
        self.assertEqual(self.request("GET", "/containers/web/snapshots").status_code, 500)

        self.assertEqual(self.request("POST", "/containers/snapshots/restore", json=snapshot).status_code, 200)
        self.run_command.assert_called_with(["lxc", "restore", "web", "checkpoint", "--stateful"])
        self.assertEqual(self.request("DELETE", "/containers/web/snapshots/checkpoint").status_code, 200)
        self.run_command.assert_called_with(["lxc", "delete", "web/checkpoint"])
        self.run_command.return_value = "container logs"
        self.assertEqual(self.request("GET", "/containers/web/logs").json(), {"logs": "container logs"})
        self.run_command.assert_called_with(["lxc", "info", "web", "--show-log"])

    def test_exec_passes_options_and_omits_environment_and_stderr_from_audit(self):
        payload = {
            "container_name": "web",
            "command": ["echo", "hello world"],
            "user": "1000",
            "workdir": "/srv/www",
            "environment": {"APP_TOKEN": "placeholder-secret"},
        }
        self.assertEqual(self.request("POST", "/containers/exec", "token-links", json=payload).status_code, 403)
        self.run_command.assert_not_called()
        self.run_command.return_value = "hello world"
        self.assertEqual(self.request("POST", "/containers/exec", json=payload).json(), {"output": "hello world"})
        self.run_command.assert_called_once_with([
            "lxc", "exec", "web", "--env", "APP_TOKEN=placeholder-secret", "--cwd", "/srv/www",
            "--user", "1000", "--", "echo", "hello world",
        ])
        self.run_command.side_effect = HTTPException(500, "command failed: placeholder-secret")
        self.assertEqual(self.request("POST", "/containers/exec", json=payload).status_code, 500)
        rows = self.audit_rows("containers_exec")
        self.assertEqual([status for status, _ in rows], ["success", "error"])
        self.assertNotIn("placeholder-secret", str(rows + self.audit_rows("exec:echo")))

    def test_connectivity_checks_both_ends_before_applying_proxy(self):
        payload = {"source_container": "web", "target_container": "db", "listen_port": 15432, "target_port": 5432}
        self.assertEqual(self.request("POST", "/containers/connect/tcp", "token-links-scoped", json=payload).status_code, 403)
        self.assertEqual(self.request("POST", "/containers/connect/tcp", "token-operator", json=payload).status_code, 403)
        self.run_command.assert_not_called()
        self.run_command.side_effect = ['[{"state":{"network":{"eth0":{"addresses":[{"address":"192.0.2.15"}]}}}}]', ""]
        response = self.request("POST", "/containers/connect/tcp", "token-links", json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["device_name"], "link-db-15432")
        self.run_command.assert_called_with([
            "lxc", "config", "device", "add", "web", "link-db-15432", "proxy", "listen=tcp:0.0.0.0:15432",
            "connect=tcp:192.0.2.15:5432",
        ])

    def test_exposure_rolls_back_devices_and_applied_firewall_rules(self):
        def apply_rule(port, protocol, source, allow):
            if allow and source == "192.0.2.0/24":
                raise HTTPException(500, "firewall unavailable")

        with mock.patch.object(container_api, "apply_firewall_rule", side_effect=apply_rule) as firewall:
            response = self.request("POST", "/containers/expose", "token-links", json={
                "container_name": "web",
                "exposures": [{
                    "host_ports": [8080], "target_address": "192.0.2.15", "open_firewall": True,
                    "allow_sources": ["198.51.100.0/24", "192.0.2.0/24"],
                }],
            })
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.run_command.call_count, 2)
        self.run_command.assert_called_with(["lxc", "config", "device", "remove", "web", "expose-tcp-8080"])
        self.assertEqual(firewall.call_args_list, [
            mock.call(8080, "tcp", "198.51.100.0/24", allow=True),
            mock.call(8080, "tcp", "192.0.2.0/24", allow=True),
            mock.call(8080, "tcp", "198.51.100.0/24", allow=False),
        ])
        self.assertEqual(self.audit_rows("containers_expose")[0][0], "error")
