import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.recipes import build_recipe_export_bundle


SERVER_PATH = Path(__file__).resolve().parents[1] / "py" / "server.py"


def load_server_module(temp_dir: str):
    module_name = f"fortress_server_test_{os.getpid()}_{Path(temp_dir).name}"
    spec = importlib.util.spec_from_file_location(module_name, str(SERVER_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class PermissionMatrixIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self._original_env = {
            "FORTRESS_LOG_PATH": os.environ.get("FORTRESS_LOG_PATH"),
            "FORTRESS_COMMAND_LOG_DB": os.environ.get("FORTRESS_COMMAND_LOG_DB"),
            "FORTRESS_RECIPE_BUNDLE_SIGNING_KEY": os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEY"),
            "FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS": os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS"),
            "FORTRESS_RECIPE_BUNDLE_SIGNING_KEY_IDS": os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEY_IDS"),
            "FORTRESS_API_KEY": os.environ.get("FORTRESS_API_KEY"),
        }
        os.environ["FORTRESS_LOG_PATH"] = os.path.join(self.tmpdir.name, "fortress.log")
        os.environ["FORTRESS_COMMAND_LOG_DB"] = os.path.join(self.tmpdir.name, "command_log.db")
        os.environ["FORTRESS_RECIPE_BUNDLE_SIGNING_KEY"] = "integration-signing-key"
        os.environ["FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS"] = "integration-previous-signing-key"
        os.environ.pop("FORTRESS_RECIPE_BUNDLE_SIGNING_KEY_IDS", None)
        os.environ["FORTRESS_API_KEY"] = "integration-master-key"
        self.module, self.module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(self._cleanup_module)
        self.addCleanup(self._restore_env)

        self.module.API_USERS_DB = os.path.join(self.tmpdir.name, "api_users.json")
        self.module.RECIPES_DB = os.path.join(self.tmpdir.name, "recipes.json")
        self.module.ROUTING_DB = os.path.join(self.tmpdir.name, "routes.json")
        self.module.SITES_DB = os.path.join(self.tmpdir.name, "sites.json")
        self.module.SITE_BACKUP_DIR = os.path.join(self.tmpdir.name, "site_backups")
        self.module.RECIPE_HEALTH_HISTORY_DB = os.path.join(self.tmpdir.name, "recipe_health_history.json")
        self.module.FIREWALL_ROLLBACK_DIR = os.path.join(self.tmpdir.name, "firewall_rollbacks")
        self.module.FIREWALL_DDOS_POLICY_PATH = os.path.join(self.tmpdir.name, "ddos_policy.json")

        os.makedirs(self.module.SITE_BACKUP_DIR, exist_ok=True)
        os.makedirs(self.module.FIREWALL_ROLLBACK_DIR, exist_ok=True)

        self._write_json(
            self.module.RECIPES_DB,
            {
                "base": {
                    "name": "base",
                    "dependencies": [],
                    "packages": ["curl"],
                    "commands": [],
                    "parameters": {},
                    "required_parameters": [],
                }
            },
        )
        self._write_json(self.module.API_USERS_DB, {})
        self._write_json(self.module.ROUTING_DB, {})
        self._write_json(self.module.SITES_DB, {})
        self._write_json(self.module.RECIPE_HEALTH_HISTORY_DB, {"entries": []})
        self._write_json(self.module.FIREWALL_DDOS_POLICY_PATH, {"enabled": False})

    def _cleanup_module(self) -> None:
        sys.modules.pop(self.module_name, None)

    def _restore_env(self) -> None:
        for key, value in self._original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_json(self, path: str, payload: dict) -> None:
        with open(path, "w") as fh:
            json.dump(payload, fh)

    def _write_users(self, users: dict) -> None:
        self._write_json(self.module.API_USERS_DB, users)

    def _expect_denied(self, fn) -> None:
        with self.assertRaises(HTTPException) as exc:
            fn()
        self.assertEqual(exc.exception.status_code, 403)

    def test_scheduled_tls_renewal_report_is_host_only(self) -> None:
        from fastapi.testclient import TestClient

        self._write_users({
            "host-view": {"username": "operator", "permissions": ["read_status"], "allowed_containers": []},
            "scoped-view": {"username": "viewer", "permissions": ["read_status"], "allowed_containers": ["alpha"]},
            "no-view": {"username": "other", "permissions": ["manage_routing"]},
        })
        logger = self.module.command_logger
        url = "/monitoring/resources"
        with TestClient(self.module.app) as client, \
                mock.patch.object(self.module, "gather_resource_snapshot", return_value={}), \
                mock.patch.object(self.module, "record_resource_snapshot", side_effect=lambda snapshot, *a, **k: snapshot.copy()):
            host = {"X-User-Token": "host-view"}
            self.assertEqual(client.get(url, headers=host).json()["scheduled_tls_renewal"], {"status": "never_run"})
            logger.log("systemd", "service", "internal", "tls_renew_scheduled", status="error",
                       request_id="schedule-run", details={"failed_steps": ["certbot", "private info"], "output": "private info"})
            logger.log("operator", "tls_renew", "api", "tls_renew", status="success")
            response = client.get(url, headers=host)
            self.assertEqual(response.status_code, 200)
            result = response.json()["scheduled_tls_renewal"]
            self.assertTrue(result.pop("timestamp").endswith("Z"))
            self.assertEqual(result, {"status": "error", "run_id": "schedule-run", "failed_steps": ["certbot"]})
            self.assertNotIn("private info", response.text)
            self.assertNotIn("scheduled_tls_renewal", client.get(url, headers={"X-User-Token": "scoped-view"}).json())
            self.assertEqual(client.get(url, headers={"X-User-Token": "no-view"}).status_code, 403)

    def test_monitoring_scope_filters_current_history_and_signals(self) -> None:
        from fastapi.testclient import TestClient

        self._write_users({
            "monitor-alpha": {"username": "viewer", "permissions": ["read_status"], "allowed_containers": ["alpha"]},
            "monitor-host": {"username": "operator", "permissions": ["read_status"], "allowed_containers": []},
        })
        containers = [{"name": "alpha"}, {"name": "private-beta"}]
        signals = {"host": [], "containers": {"alpha": [{"message": "alpha"}], "private-beta": [{"message": "private-beta"}]}}
        sample = {"containers": containers, "alerts": signals}
        recorded = {**sample, "anomalies": signals}
        with TestClient(self.module.app) as client, \
                mock.patch.object(self.module, "gather_resource_snapshot", return_value=sample), \
                mock.patch.object(self.module, "record_resource_snapshot", return_value=recorded) as record, \
                mock.patch.object(self.module, "load_json", return_value=[sample]):
            url = "/monitoring/resources?include_history=true"
            response = client.get(url, headers={"X-User-Token": "monitor-alpha"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn("private-beta", response.text)
            self.assertEqual(response.json()["containers"], [{"name": "alpha"}])
            self.assertEqual(list(response.json()["anomalies"]["containers"]), ["alpha"])
            self.assertEqual(response.json()["history_samples"][0]["containers"], [{"name": "alpha"}])
            self.assertIs(record.call_args.args[0], sample)
            self.assertEqual(sample["containers"], containers)
            host = client.get(url, headers={"X-User-Token": "monitor-host"})
            self.assertEqual(host.json()["containers"], containers)

    def test_monitoring_recipe_alerts_require_opt_in_and_recipe_permission(self) -> None:
        from fastapi.testclient import TestClient

        self._write_users({
            "reader": {"username": "reader", "permissions": ["read_status"]},
            "operator": {"username": "operator", "permissions": ["read_status", "recipes_apply"], "allowed_containers": ["alpha"]},
        })
        self._write_json(self.module.RECIPE_HEALTH_HISTORY_DB, {"entries": [
            {"container_name": name, "requested_recipe": "lamp", "timestamp": f"2026-11-27T00:00:0{second}Z",
             "summary": {"passed": 0, "failed": 1}}
            for name in ("alpha", "private-beta") for second in (0, 1)
        ]})
        with TestClient(self.module.app) as client, \
                mock.patch.object(self.module, "gather_resource_snapshot", side_effect=lambda *args: {}), \
                mock.patch.object(self.module, "record_resource_snapshot", side_effect=lambda snapshot, *a, **k: snapshot):
            url = "/monitoring/resources"
            operator = {"X-User-Token": "operator"}
            with mock.patch.object(self.module, "RECIPE_HEALTH_ALERT_FAILURE_STREAK", 0):
                self.assertNotIn("recipe_health_alerts", client.get(url, headers=operator).json())
            with mock.patch.object(self.module, "RECIPE_HEALTH_ALERT_FAILURE_STREAK", 2):
                self.assertNotIn("recipe_health_alerts", client.get(url, headers={"X-User-Token": "reader"}).json())
                response = client.get(url, headers=operator)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("private-beta", response.text)
        self.assertEqual(response.json()["recipe_health_alerts"], [{
            "container_name": "alpha", "recipe_name": "lamp", "failed_runs": 2, "last_failed_at": "2026-11-27T00:00:01Z",
        }])

    def test_recipe_bundle_reports_only_the_locally_verified_key_id(self) -> None:
        from fastapi.testclient import TestClient

        self._write_users({"bundle-manager": {"username": "operator", "permissions": ["recipes_manage"]}})
        key_ids = {"integration-signing-key": "new-key", "integration-previous-signing-key": "old-key"}
        old_bundle = build_recipe_export_bundle({}, signing_key="integration-previous-signing-key", signing_key_id="foreign-label")
        headers = {"X-User-Token": "bundle-manager"}
        with TestClient(self.module.app) as client, mock.patch.object(self.module, "RECIPE_BUNDLE_SIGNING_KEY_IDS", key_ids):
            exported = client.post("/recipes/export", headers=headers, json={})
            self.assertEqual(exported.status_code, 200, exported.text)
            self.assertEqual(exported.json()["bundle"]["key_id"], "new-key")
            imported = client.post("/recipes/import", headers=headers, json={"bundle": old_bundle})
            self.assertEqual(imported.status_code, 200, imported.text)
            self.assertEqual(imported.json()["verification"]["verified_with_key_id"], "old-key")
            self.assertFalse(imported.json()["verification"]["verified_with_primary"])
            self.assertNotIn("foreign-label", imported.text)

    def test_site_tls_history_records_only_named_attempts_and_respects_scope(self) -> None:
        from fastapi.testclient import TestClient

        self._write_users({
            "renew": {"username": "operator", "permissions": ["manage_routing"], "allowed_containers": ["alpha"]},
            "view": {"username": "viewer", "permissions": ["sites_read"], "allowed_containers": ["alpha"]},
            "other": {"username": "other", "permissions": ["sites_read"], "allowed_containers": ["beta"]},
        })
        self._write_json(self.module.SITES_DB, {
            "app": {
                "name": "app", "primary_domain": "app.example.com", "container_name": "alpha",
                "domains": ["www.app.example.com"], "tls": {"mode": "letsencrypt", "cert_name": "app-production"},
            },
            "other": {
                "name": "other", "primary_domain": "other.example.com", "container_name": "beta",
                "tls": {"mode": "letsencrypt"},
            },
        })
        self._write_json(self.module.ROUTING_DB, {
            "shared.example.com": {
                "container_name": "beta", "tls": {"mode": "letsencrypt", "cert_name": "app-production"},
            },
        })
        renewer = {"X-User-Token": "renew"}
        viewer = {"X-User-Token": "view"}
        master = {"X-API-Key": "integration-master-key"}
        failure = HTTPException(500, detail="certbot stderr with private placeholder")
        with TestClient(self.module.app) as client, mock.patch.object(self.module, "renew_letsencrypt") as renew:
            url = "/sites/app/tls/status"
            self.assertEqual(client.get(url, headers=viewer).json()["tls_status"]["renewal_history"], [])
            self.assertEqual(client.get(url, headers={"X-User-Token": "other"}).status_code, 403)
            self.assertEqual(client.get(url, headers=renewer).status_code, 403)
            for payload in ({}, {"cert_name": "app-production"}, {"domain": "other.example.com"},
                            {"domain": "www.app.example.com"}):
                with self.subTest(payload=payload):
                    self.assertEqual(client.post("/tls/renew", headers=renewer, json=payload).status_code, 403)
            renew.assert_not_called()

            self._write_json(self.module.ROUTING_DB, {})
            renew.return_value = "Certbot completed"
            success = client.post("/tls/renew", headers=renewer, json={"domain": "www.app.example.com"})
            self.assertEqual(success.status_code, 200)
            renew.assert_called_once_with("app-production", dry_run=False)
            self.assertEqual(client.post("/tls/renew", headers=master, json={}).status_code, 200)
            self.assertEqual(client.post("/tls/renew", headers=master, json={"cert_name": "other.example.com"}).status_code, 200)
            renew.side_effect = failure
            error = client.post("/tls/renew", headers=master, json={"cert_name": "app-production", "dry_run": True})
            self.assertEqual(error.status_code, 500)

            state = client.get(url, headers=viewer)
            self.assertEqual(state.status_code, 200)
            self.assertNotIn("private placeholder", state.text)
            history = state.json()["tls_status"]["renewal_history"]
            self.assertEqual(
                [(entry["status"], entry["dry_run"], entry["request_id"]) for entry in history],
                [("error", True, error.headers["X-Fortress-Request-ID"]),
                 ("success", False, success.headers["X-Fortress-Request-ID"])],
            )
            for entry in history:
                self.assertEqual(set(entry), {"timestamp", "status", "dry_run", "request_id"})
                self.assertRegex(entry["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            site = client.get("/sites/app", headers=viewer).json()["site"]
            self.assertEqual(site["tls_status"]["renewal_history"], history)

    def test_permission_matrix_recipes_endpoints(self) -> None:
        self._write_users(
            {
                "token-manage": {"username": "manage", "permissions": ["recipes_manage"], "allowed_containers": None},
                "token-apply": {"username": "apply", "permissions": ["recipes_apply"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        signed_bundle = build_recipe_export_bundle({}, signing_key="integration-previous-signing-key")
        matrix = [
            (
                lambda token: self.module.list_recipes(x_api_key=None, x_user_token=token),
                "token-manage",
                "token-none",
            ),
            (
                lambda token: self.module.export_recipes(
                    self.module.RecipeExportRequest(),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-manage",
                "token-apply",
            ),
            (
                lambda token: self.module.import_recipes(
                    self.module.RecipeImportRequest(bundle=signed_bundle),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-manage",
                "token-apply",
            ),
            (
                lambda token: self.module.apply_recipe(
                    self.module.RecipeApplyRequest(recipe_name="base", dry_run=True),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-apply",
                "token-manage",
            ),
            (
                lambda token: self.module.recipe_health_history(
                    container_name=None,
                    recipe_name=None,
                    limit=30,
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-apply",
                "token-manage",
            ),
        ]

        for call, allowed_token, denied_token in matrix:
            result = call(allowed_token)
            self.assertIsInstance(result, dict)
            self._expect_denied(lambda: call(denied_token))

    def test_permission_matrix_container_scope_for_recipe_apply(self) -> None:
        self._write_users(
            {
                "token-scoped": {
                    "username": "scoped",
                    "permissions": ["recipes_apply"],
                    "allowed_containers": ["alpha"],
                }
            }
        )

        allowed = self.module.apply_recipe(
            self.module.RecipeApplyRequest(recipe_name="base", container_name="alpha", dry_run=True),
            x_api_key=None,
            x_user_token="token-scoped",
        )
        self.assertIsInstance(allowed, dict)
        self._expect_denied(
            lambda: self.module.apply_recipe(
                self.module.RecipeApplyRequest(recipe_name="base", container_name="beta", dry_run=True),
                x_api_key=None,
                x_user_token="token-scoped",
            )
        )
        history_allowed = self.module.recipe_health_history(
            container_name="alpha",
            recipe_name=None,
            limit=20,
            x_api_key=None,
            x_user_token="token-scoped",
        )
        self.assertIsInstance(history_allowed, dict)
        self._expect_denied(
            lambda: self.module.recipe_health_history(
                container_name="beta",
                recipe_name=None,
                limit=20,
                x_api_key=None,
                x_user_token="token-scoped",
            )
        )

    def test_permission_matrix_system_upgrade_permissions(self) -> None:
        self._write_users(
            {
                "token-migration": {"username": "migrate", "permissions": ["migration_admin"], "allowed_containers": None},
                "token-full": {
                    "username": "full",
                    "permissions": ["migration_admin", "package_manage"],
                    "allowed_containers": None,
                },
            }
        )

        preflight = self.module.SystemUpgradeRequest(dry_run=True, update_packages=False, apply_migrations=False)
        packages_only = self.module.SystemUpgradeRequest(dry_run=True, update_packages=True, apply_migrations=False)

        migration_ok = self.module.system_upgrade(preflight, x_api_key=None, x_user_token="token-migration")
        self.assertIsInstance(migration_ok, dict)
        self._expect_denied(lambda: self.module.system_upgrade(packages_only, x_api_key=None, x_user_token="token-migration"))
        with mock.patch.object(self.module, "detect_package_manager", return_value="apt"):
            full_ok = self.module.system_upgrade(packages_only, x_api_key=None, x_user_token="token-full")
        self.assertIsInstance(full_ok, dict)
        self.assertIn("packages", full_ok)

    def test_permission_matrix_system_update_reload_permissions(self) -> None:
        self._write_users(
            {
                "token-migration": {"username": "migrate", "permissions": ["migration_admin"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        request = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="auto")
        background_tasks = self.module.BackgroundTasks()
        with mock.patch.object(
            self.module,
            "_run_system_update_reload",
            return_value={"updated": False, "reload": {"scheduled": False}},
        ):
            allowed = self.module.system_update_reload(
                request,
                background_tasks,
                x_api_key=None,
                x_user_token="token-migration",
            )
            self.assertIsInstance(allowed, dict)
            self._expect_denied(
                lambda: self.module.system_update_reload(
                    request,
                    background_tasks,
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_system_update_reload_skips_restart_when_no_new_commit(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="auto", auto_stash=False)
        background_tasks = self.module.BackgroundTasks()
        pull_result = mock.Mock(stdout="Already up to date.\n", stderr="")
        with (
            mock.patch.object(self.module, "_git_has_uncommitted_changes", return_value=False),
            mock.patch.object(self.module, "_git_head_commit", side_effect=["abc123", "abc123"]),
            mock.patch.object(self.module, "_run_local_checked", return_value=pull_result),
        ):
            response = self.module._run_system_update_reload(payload, background_tasks)
        self.assertFalse(response["updated"])
        self.assertEqual(response["migrations"].get("reason"), "no_updates")
        self.assertFalse(response["reload"].get("scheduled"))
        self.assertEqual(len(background_tasks.tasks), 0)

    def test_system_update_reload_applies_migrations_and_schedules_restart(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="screen", auto_stash=False)
        background_tasks = self.module.BackgroundTasks()
        pull_result = mock.Mock(stdout="Updating abc..def\n", stderr="")
        migration_result = {"message": "Migration apply complete", "patch_id": "patch-1", "applied": ["recipes"], "backups": []}
        with (
            mock.patch.object(self.module, "_git_has_uncommitted_changes", return_value=False),
            mock.patch.object(self.module, "_git_head_commit", side_effect=["abc123", "def456"]),
            mock.patch.object(self.module, "_run_local_checked", return_value=pull_result),
            mock.patch.object(self.module, "MIGRATION_ENGINE") as migration_engine,
            mock.patch.object(self.module.os.path, "isfile", return_value=True),
        ):
            migration_engine.status.return_value = {"pending": True}
            migration_engine.apply.return_value = migration_result
            response = self.module._run_system_update_reload(payload, background_tasks)
        self.assertTrue(response["updated"])
        self.assertEqual(response["migrations"], migration_result)
        self.assertTrue(response["reload"].get("scheduled"))
        self.assertEqual(response["reload"].get("mode"), "screen")
        self.assertEqual(len(background_tasks.tasks), 1)

    def test_system_update_reload_rejects_dirty_tree_when_auto_stash_disabled(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="auto", auto_stash=False)
        background_tasks = self.module.BackgroundTasks()
        with mock.patch.object(self.module, "_git_has_uncommitted_changes", return_value=True):
            with self.assertRaises(HTTPException) as exc:
                self.module._run_system_update_reload(payload, background_tasks)
        self.assertEqual(exc.exception.status_code, 409)
        self.assertIn("Working tree has uncommitted changes", str(exc.exception.detail))

    def test_system_update_reload_auto_stashes_and_restores_local_changes(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=False, restart_mode="auto", auto_stash=True)
        background_tasks = self.module.BackgroundTasks()
        stash_push = mock.Mock(stdout="Saved working directory and index state", stderr="", returncode=0)
        pull_result = mock.Mock(stdout="Already up to date.\n", stderr="", returncode=0)
        stash_pop = mock.Mock(stdout="Dropped refs/stash@{0}", stderr="", returncode=0)
        with (
            mock.patch.object(self.module, "_git_has_local_changes", return_value=True),
            mock.patch.object(self.module, "_git_head_commit", side_effect=["abc123", "abc123"]),
            mock.patch.object(self.module, "_run_local_checked", side_effect=[stash_push, pull_result, stash_pop]),
        ):
            response = self.module._run_system_update_reload(payload, background_tasks)
        self.assertFalse(response["updated"])
        self.assertTrue(response["stash"].get("auto_stash"))
        self.assertTrue(response["stash"].get("used"))
        self.assertTrue(response["stash"].get("restored"))
        self.assertFalse(response["stash"].get("restore_conflict"))
        self.assertEqual(len(background_tasks.tasks), 0)

    def test_permission_matrix_routing_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-routing": {"username": "routing", "permissions": ["manage_routing"], "allowed_containers": None},
                "token-routing-scoped": {
                    "username": "routing-scoped",
                    "permissions": ["manage_routing"],
                    "allowed_containers": ["alpha"],
                },
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        route = self.module.DomainRoute(domain="app.example.com", container_name="alpha", container_port=8080)

        with (
            mock.patch.object(self.module, "get_container_ip", return_value="10.8.0.20"),
            mock.patch.object(self.module, "_read_nginx_config", return_value=None),
            mock.patch.object(self.module, "_apply_nginx_config"),
            mock.patch.object(self.module, "write_nginx_config"),
            mock.patch.object(self.module, "ensure_nginx_site"),
            mock.patch.object(self.module, "test_nginx_config"),
            mock.patch.object(self.module, "reload_nginx"),
            mock.patch.object(self.module, "remove_nginx_site"),
        ):
            created = self.module.add_domain_routing(route, x_api_key=None, x_user_token="token-routing")
            self.assertIsInstance(created, dict)

            listed = self.module.list_domain_routing(x_api_key=None, x_user_token="token-routing-scoped")
            self.assertEqual(len(listed.get("routes", [])), 1)
            self.assertEqual(listed["routes"][0]["domain"], "app.example.com")

            refreshed = self.module.refresh_domain_routing(
                domain="app.example.com",
                x_api_key=None,
                x_user_token="token-routing-scoped",
            )
            self.assertEqual(refreshed.get("refreshed"), ["app.example.com"])

            removed = self.module.remove_domain_routing("app.example.com", x_api_key=None, x_user_token="token-routing")
            self.assertIsInstance(removed, dict)

            self._expect_denied(
                lambda: self.module.add_domain_routing(
                    self.module.DomainRoute(domain="blocked.example.com", container_name="beta", container_port=80),
                    x_api_key=None,
                    x_user_token="token-routing-scoped",
                )
            )
            self._expect_denied(
                lambda: self.module.add_domain_routing(
                    self.module.DomainRoute(domain="deny.example.com", container_name="alpha", container_port=80),
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_permission_matrix_firewall_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-firewall": {"username": "fw", "permissions": ["firewall_admin"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )
        current_rules = [
            {"port": 22, "protocol": "tcp", "source": None, "action": "allow", "direction": "in"},
            {"port": 443, "protocol": "tcp", "source": None, "action": "allow", "direction": "in"},
        ]
        apply_result = {"applied": 2, "skipped": 0, "rollback_id": "fw-test-1"}

        with (
            mock.patch.object(self.module, "apply_firewall_rule"),
            mock.patch.object(self.module, "get_firewall_status", return_value={"backend": "ufw", "active": True}),
            mock.patch.object(self.module, "list_firewall_rules", return_value=current_rules),
            mock.patch.object(self.module, "apply_firewall_rules", return_value=apply_result),
            mock.patch.object(self.module, "rollback_firewall_rules"),
            mock.patch.object(self.module, "get_ddos_policy", return_value={"enabled": False}),
            mock.patch.object(self.module, "remove_ddos_policy"),
            mock.patch.object(self.module, "apply_ddos_policy", return_value=(["rate_limit enabled"], [])),
            mock.patch.object(self.module, "update_ddos_policy"),
        ):
            status = self.module.firewall_status(x_api_key=None, x_user_token="token-firewall")
            self.assertEqual(status.get("backend"), "ufw")
            self.assertEqual(status["connlimit"]["status"], "disabled")
            with mock.patch.object(self.module, "get_ddos_policy", return_value={"ports": "invalid"}):
                status = self.module.firewall_status(x_api_key=None, x_user_token="token-firewall")
            self.assertEqual(status["connlimit"]["status"], "policy_unreadable")

            opened = self.module.open_firewall(
                self.module.FirewallRule(port=443, protocol="tcp"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            closed = self.module.close_firewall(
                self.module.FirewallRule(port=443, protocol="tcp"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertIsInstance(opened, dict)
            self.assertIsInstance(closed, dict)

            listed = self.module.firewall_rules(x_api_key=None, x_user_token="token-firewall")
            self.assertEqual(len(listed.get("rules", [])), 2)

            applied = self.module.firewall_rules_apply(
                self.module.FirewallRulesApplyRequest(
                    rules=[self.module.FirewallRuleEntry(port=80, protocol="tcp", action="allow", direction="in")]
                ),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertEqual(applied.get("rollback_id"), "fw-test-1")

            diff = self.module.firewall_rules_diff(
                self.module.FirewallRulesDiffRequest(baseline=[current_rules[0]]),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertEqual(len(diff.get("added", [])), 1)

            rollback = self.module.firewall_rollback(
                self.module.FirewallRollbackRequest(rollback_id="fw-test-1"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertIsInstance(rollback, dict)

            ddos_status = self.module.firewall_ddos_status(x_api_key=None, x_user_token="token-firewall")
            self.assertIn("policy", ddos_status)
            ddos_update = self.module.firewall_ddos_update(
                self.module.DdosPolicyRequest(enabled=True, rate_limit_per_sec=120, dry_run=False),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertTrue(ddos_update.get("policy", {}).get("enabled"))

            self._expect_denied(
                lambda: self.module.firewall_status(x_api_key=None, x_user_token="token-none")
            )
            self._expect_denied(
                lambda: self.module.open_firewall(
                    self.module.FirewallRule(port=53, protocol="udp"),
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_permission_matrix_sites_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-sites-manage": {
                    "username": "sites-manage",
                    "permissions": ["sites_manage", "sites_read"],
                    "allowed_containers": ["alpha"],
                },
                "token-sites-read": {
                    "username": "sites-read",
                    "permissions": ["sites_read"],
                    "allowed_containers": ["alpha"],
                },
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        with (
            mock.patch.object(self.module, "_resolve_runtime_identity", return_value=("www-data", "www-data")),
            mock.patch.object(self.module, "_ensure_docroot"),
            mock.patch.object(self.module, "_apply_php_ini_overrides", return_value={"applied": False, "removed": False}),
            mock.patch.object(
                self.module,
                "_apply_php_fpm_pool_tuning",
                return_value={"pool": "www", "applied": True, "removed": False, "directives": ["pm", "pm.max_children"]},
            ),
            mock.patch.object(
                self.module,
                "_restart_site_services",
                return_value={"restarted": ["php-fpm"], "failed": []},
            ),
            mock.patch.object(self.module, "_apply_site_routing"),
            mock.patch.object(self.module, "_remove_nginx_route"),
            mock.patch.object(self.module, "load_routes", return_value={}),
            mock.patch.object(self.module, "save_routes"),
        ):
            created = self.module.create_site(
                self.module.SiteCreateRequest(
                    name="app",
                    primary_domain="app.example.com",
                    container_name="alpha",
                    docroot="/var/www/app",
                ),
                x_api_key=None,
                x_user_token="token-sites-manage",
            )
            self.assertEqual(created.get("site", {}).get("name"), "app")

            listed = self.module.list_sites(x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(len(listed.get("sites", [])), 1)

            fetched = self.module.get_site("app", x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(fetched.get("site", {}).get("container_name"), "alpha")
            tls_status = self.module.site_tls_status("app", x_api_key=None, x_user_token="token-sites-read")
            self.assertIn("tls_status", tls_status)

            backup_id = "app-test-backup"
            self._write_json(
                os.path.join(self.module.SITE_BACKUP_DIR, f"{backup_id}.json"),
                {
                    "backup_id": backup_id,
                    "site_id": "app",
                    "include_database": False,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            )
            with open(os.path.join(self.module.SITE_BACKUP_DIR, f"{backup_id}.tar.gz"), "wb") as fh:
                fh.write(b"backup-data")

            backups = self.module.list_site_backups("app", x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(len(backups.get("backups", [])), 1)

            updated = self.module.update_site(
                "app",
                self.module.SiteUpdateRequest(docroot="/srv/www/app"),
                x_api_key=None,
                x_user_token="token-sites-manage",
            )
            self.assertEqual(updated.get("site", {}).get("docroot"), "/srv/www/app")
            runtime_updated = self.module.update_site(
                "app",
                self.module.SiteUpdateRequest(
                    runtime={"fpm_pool": {"name": "www", "pm": "dynamic", "max_children": 50}}
                ),
                x_api_key=None,
                x_user_token="token-sites-manage",
            )
            self.assertIn("runtime", runtime_updated)
            self.assertIn("fpm_pool", runtime_updated.get("runtime", {}))
            self._expect_denied(
                lambda: self.module.site_tls_status("app", x_api_key=None, x_user_token="token-none")
            )

            deleted = self.module.delete_site("app", x_api_key=None, x_user_token="token-sites-manage")
            self.assertIsInstance(deleted, dict)

            self._expect_denied(
                lambda: self.module.create_site(
                    self.module.SiteCreateRequest(
                        name="deny",
                        primary_domain="deny.example.com",
                        container_name="alpha",
                        docroot="/var/www/deny",
                    ),
                    x_api_key=None,
                    x_user_token="token-sites-read",
                )
            )
            self._expect_denied(
                lambda: self.module.create_site(
                    self.module.SiteCreateRequest(
                        name="scope-deny",
                        primary_domain="scope.example.com",
                        container_name="beta",
                        docroot="/var/www/scope",
                    ),
                    x_api_key=None,
                    x_user_token="token-sites-manage",
                )
            )
            self._expect_denied(
                lambda: self.module.list_sites(x_api_key=None, x_user_token="token-none")
            )

    def _seed_site_operations(self):
        self._write_users({
            "token-sites": {"username": "operator", "permissions": ["sites_manage"], "allowed_containers": ["alpha"]},
        })
        self._write_json(self.module.SITES_DB, {
            "app": {"name": "app", "container_name": "alpha", "docroot": "/srv/app"},
            "other": {"name": "other", "container_name": "alpha", "docroot": "/srv/other"},
            "outside": {"name": "outside", "container_name": "beta", "docroot": "/srv/outside"},
        })
        return {"x_api_key": None, "x_user_token": "token-sites"}

    def test_same_site_backup_waits_for_deploy_while_another_site_proceeds(self) -> None:
        auth = self._seed_site_operations()
        deploy_started = threading.Event()
        finish_deploy = threading.Event()
        backup_requested_lock = threading.Event()
        app_lock = os.path.join(f"{self.module.SITES_DB}.locks", hashlib.sha256(b"app").hexdigest())
        real_lock = self.module.json_store_lock

        def observe_lock(path):
            if path == app_lock and deploy_started.is_set():
                backup_requested_lock.set()
            return real_lock(path)

        def pause_deploy(*args):
            deploy_started.set()
            if not finish_deploy.wait(10):
                raise TimeoutError("test did not release deploy")

        def fake_lxc(command):
            if command[:3] == ["lxc", "file", "pull"]:
                Path(command[-1]).write_bytes(b"test archive")

        deploy = self.module.SiteDeployRequest(source_type="archive", source="https://example.test/demo.tar.gz", restart_services=False)
        backup = self.module.SiteBackupRequest(include_database=False)
        with (
            mock.patch.object(self.module, "json_store_lock", side_effect=observe_lock),
            mock.patch.object(self.module, "exec_in_container") as container,
            mock.patch.object(self.module, "_extract_site_archive", side_effect=pause_deploy),
            mock.patch.object(self.module, "run_command", side_effect=fake_lxc) as run,
            ThreadPoolExecutor(max_workers=3) as pool,
        ):
            deployment = pool.submit(self.module.deploy_site, "app", deploy, **auth)
            try:
                self.assertTrue(deploy_started.wait(10))
                same_site = pool.submit(self.module.backup_site, "app", backup, **auth)
                self.assertTrue(backup_requested_lock.wait(10))
                other_site = pool.submit(self.module.backup_site, "other", backup, **auth)
                other_result = other_site.result(timeout=10)
                self.assertFalse(same_site.done())
                self.assertTrue(Path(other_result["path"]).is_file())
                self.assertEqual([call.args[0][2] for call in run.call_args_list], ["pull"])
            finally:
                finish_deploy.set()
            self.assertEqual(deployment.result(timeout=10)["message"], "Site deployed")
            same_result = same_site.result(timeout=10)
            self.assertTrue(Path(same_result["path"]).is_file())

        staging_dirs = [call.args[1][-1] for call in container.call_args_list if call.args[1][0] == "mkdir"]
        removed_dirs = [call.args[1][-1] for call in container.call_args_list if call.args[1][0] == "rm"]
        self.assertEqual(len(set(staging_dirs)), 3)
        self.assertCountEqual(removed_dirs, staging_dirs)

    def test_site_backup_publication_and_rollback_ownership(self) -> None:
        auth = self._seed_site_operations()
        backup = self.module.SiteBackupRequest(include_database=False, label="release 1")
        backup_dir = Path(self.module.SITE_BACKUP_DIR)

        def fake_lxc(command):
            if command[:3] == ["lxc", "file", "pull"]:
                Path(command[-1]).write_bytes(b"test archive")

        with (
            mock.patch.object(self.module, "exec_in_container") as container,
            mock.patch.object(self.module, "run_command", side_effect=fake_lxc),
            mock.patch.object(self.module, "_extract_site_archive") as extract,
        ):
            first = self.module.backup_site("app", backup, **auth)
            second = self.module.backup_site("app", backup, **auth)
            self.assertNotEqual(first["backup_id"], second["backup_id"])
            self.assertEqual(Path(first["path"]).stat().st_mode & 0o777, 0o600)

            rollback = self.module.SiteRollbackRequest(backup_id=first["backup_id"], restart_services=False)
            with self.assertRaises(HTTPException) as caught:
                self.module.rollback_site("other", rollback, **auth)
            self.assertEqual(caught.exception.status_code, 404)
            self._expect_denied(lambda: self.module.rollback_site("outside", rollback, **auth))
            extract.assert_not_called()

            self.module.rollback_site("app", rollback, **auth)
            self.assertEqual(extract.call_args.args[2], "/srv/app")
            self.assertEqual(container.call_args.args[1][:3], ["rm", "-rf", "--"])

            files = set(backup_dir.glob("*.tar.gz"))
            with (
                mock.patch.object(self.module, "save_json", side_effect=OSError("placeholder-secret")),
                mock.patch.object(self.module, "audit_api") as audit,
                self.assertRaises(OSError),
            ):
                self.module.backup_site("app", backup, **auth)
            audit.assert_called_once_with("sites_backup", target="app", details={"error_type": "OSError"}, status="error")
            self.assertEqual(set(backup_dir.glob("*.tar.gz")), files)
            self.assertEqual(list(backup_dir.glob(".site-backup-*")), [])

    def test_site_delete_keeps_record_when_nginx_removal_fails(self) -> None:
        auth = self._seed_site_operations()
        sites = self.module._load_site_store()
        sites["app"]["primary_domain"] = "app.example.test"
        self._write_json(self.module.SITES_DB, sites)
        with mock.patch.object(self.module, "_remove_nginx_route", side_effect=HTTPException(500, "reload failed")):
            with self.assertRaises(HTTPException):
                self.module.delete_site("app", **auth)
        self.assertEqual(self.module._load_site_store()["app"]["primary_domain"], "app.example.test")

    def test_permission_matrix_terminal_create_permissions(self) -> None:
        self._write_users(
            {
                "token-host": {"username": "hostuser", "permissions": ["terminal_host"], "allowed_containers": None},
                "token-container": {
                    "username": "containeruser",
                    "permissions": ["terminal_container"],
                    "allowed_containers": ["alpha"],
                },
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        with (
            mock.patch.object(self.module.terminal_manager, "validate_shell", return_value="/bin/bash"),
            mock.patch.object(
                self.module.terminal_manager,
                "create_host_session",
                return_value={"session_id": "host-session", "target": "host", "os_user": "hostuser"},
            ),
            mock.patch.object(
                self.module.terminal_manager,
                "create_container_session",
                return_value={
                    "session_id": "container-session",
                    "target": "container",
                    "container_name": "alpha",
                    "os_user": "containeruser",
                },
            ),
        ):
            host_result = self.module.create_terminal_session(
                self.module.TerminalSessionCreateRequest(target="host", shell="/bin/bash"),
                x_api_key=None,
                x_user_token="token-host",
            )
            self.assertEqual(host_result["session"]["session_id"], "host-session")

            container_result = self.module.create_terminal_session(
                self.module.TerminalSessionCreateRequest(target="container", container_name="alpha", shell="/bin/bash"),
                x_api_key=None,
                x_user_token="token-container",
            )
            self.assertEqual(container_result["session"]["session_id"], "container-session")

            self._expect_denied(
                lambda: self.module.create_terminal_session(
                    self.module.TerminalSessionCreateRequest(target="host", shell="/bin/bash"),
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )
            self._expect_denied(
                lambda: self.module.create_terminal_session(
                    self.module.TerminalSessionCreateRequest(target="container", container_name="beta", shell="/bin/bash"),
                    x_api_key=None,
                    x_user_token="token-container",
                )
            )

    def test_permission_matrix_terminal_session_access_permissions(self) -> None:
        self._write_users(
            {
                "token-host": {"username": "hostuser", "permissions": ["terminal_host"], "allowed_containers": None},
                "token-container": {
                    "username": "containeruser",
                    "permissions": ["terminal_container"],
                    "allowed_containers": ["alpha"],
                },
            }
        )

        def describe_side_effect(session_id, owner_id, allow_any=False):
            if session_id == "host-session":
                return {"session_id": session_id, "target": "host", "container_name": None}
            if session_id == "container-session":
                return {"session_id": session_id, "target": "container", "container_name": "alpha"}
            if session_id == "container-session-out-of-scope":
                return {"session_id": session_id, "target": "container", "container_name": "beta"}
            raise self.module.HTTPException(status_code=404, detail="missing")

        with (
            mock.patch.object(self.module.terminal_manager, "describe", side_effect=describe_side_effect),
            mock.patch.object(
                self.module.terminal_manager,
                "read",
                return_value={"session_id": "host-session", "output": b"ok", "running": True, "exit_code": None},
            ),
            mock.patch.object(
                self.module.terminal_manager,
                "write",
                return_value={"session_id": "container-session", "written": 2},
            ),
            mock.patch.object(
                self.module.terminal_manager,
                "resize",
                return_value={"session_id": "container-session", "cols": 120, "rows": 32},
            ),
            mock.patch.object(
                self.module.terminal_manager,
                "close",
                return_value={"session_id": "container-session", "exit_code": 0, "closed_reason": "closed_by_client"},
            ),
        ):
            host_read = self.module.read_terminal_session_output(
                "host-session",
                x_api_key=None,
                x_user_token="token-host",
            )
            self.assertTrue(host_read["running"])

            container_write = self.module.write_terminal_session_input(
                "container-session",
                self.module.TerminalSessionInputRequest(data_b64="aGk="),
                x_api_key=None,
                x_user_token="token-container",
            )
            self.assertEqual(container_write["written"], 2)

            container_resize = self.module.resize_terminal_session(
                "container-session",
                self.module.TerminalSessionResizeRequest(cols=120, rows=32),
                x_api_key=None,
                x_user_token="token-container",
            )
            self.assertEqual(container_resize["cols"], 120)

            container_close = self.module.close_terminal_session(
                "container-session",
                x_api_key=None,
                x_user_token="token-container",
            )
            self.assertIn("session", container_close)

            self._expect_denied(
                lambda: self.module.read_terminal_session_output(
                    "host-session",
                    x_api_key=None,
                    x_user_token="token-container",
                )
            )
            self._expect_denied(
                lambda: self.module.read_terminal_session_output(
                    "container-session-out-of-scope",
                    x_api_key=None,
                    x_user_token="token-container",
                )
            )


if __name__ == "__main__":
    unittest.main()
