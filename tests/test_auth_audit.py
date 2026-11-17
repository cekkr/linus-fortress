import os
import subprocess
import sys
import unittest
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.auth import enforce_container_scope, enforce_container_scopes
from fortress.containers import configure_audit, exec_in_container
from fortress.system import run_command


class ContainerScopeTests(unittest.TestCase):
    def test_enforce_container_scope_allows_unrestricted(self) -> None:
        enforce_container_scope({"actor": "tester", "allowed_containers": None}, "alpha")

    def test_enforce_container_scope_allows_in_scope(self) -> None:
        enforce_container_scope({"actor": "tester", "allowed_containers": ["alpha"]}, "alpha")

    def test_enforce_container_scope_blocks_outside_scope(self) -> None:
        with self.assertRaises(HTTPException):
            enforce_container_scope({"actor": "tester", "allowed_containers": ["alpha"]}, "beta")

    def test_enforce_container_scopes_blocks_any_outside_scope(self) -> None:
        with self.assertRaises(HTTPException):
            enforce_container_scopes({"actor": "tester", "allowed_containers": ["alpha"]}, ["alpha", "beta"])


class AuditLoggingTests(unittest.TestCase):
    def tearDown(self) -> None:
        configure_audit(None)

    def test_exec_in_container_audits_success(self) -> None:
        events = []

        def capture(category, action, target, details, status):
            events.append(
                {
                    "category": category,
                    "action": action,
                    "target": target,
                    "details": details,
                    "status": status,
                }
            )

        configure_audit(capture)

        with mock.patch("fortress.containers.run_command", return_value="ok") as mocked:
            output = exec_in_container("demo", ["echo", "hello"])

        self.assertEqual(output, "ok")
        mocked.assert_called_once()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["category"], "container_exec")
        self.assertEqual(events[0]["status"], "success")
        self.assertEqual(events[0]["target"], "demo")
        self.assertEqual(events[0]["details"]["command"], "echo")

    def test_exec_in_container_audits_failure(self) -> None:
        events = []

        def capture(category, action, target, details, status):
            events.append(
                {
                    "category": category,
                    "action": action,
                    "target": target,
                    "details": details,
                    "status": status,
                }
            )

        configure_audit(capture)

        error = HTTPException(status_code=500, detail="failure included secret=123")
        with mock.patch("fortress.containers.run_command", side_effect=error):
            with self.assertRaises(HTTPException):
                exec_in_container("demo", ["echo", "secret=123"])

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["category"], "container_exec")
        self.assertEqual(events[0]["status"], "error")
        self.assertEqual(events[0]["target"], "demo")
        self.assertEqual(events[0]["details"]["status_code"], 500)
        self.assertNotIn("secret=123", str(events[0]["details"]))

    def test_command_failure_logs_exit_status_without_arguments_or_stderr(self) -> None:
        command = ["lxc", "exec", "demo", "--env", "APP_TOKEN=placeholder-secret", "--", "false"]
        failure = subprocess.CalledProcessError(1, command, stderr="stderr with placeholder-secret")
        with (
            mock.patch("fortress.system.subprocess.run", side_effect=failure),
            self.assertLogs(level="ERROR") as recorded,
            self.assertRaises(HTTPException) as caught,
        ):
            run_command(command)
        self.assertEqual(caught.exception.status_code, 500)
        self.assertEqual(recorded.output, ["ERROR:root:lxc exited with status 1"])


if __name__ == "__main__":
    unittest.main()
