import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import tls_schedule
from fortress.audit import CommandLogger


class ScheduledRenewalTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "audit.db"
        self.logger = CommandLogger(str(self.path))

    def test_partial_failure_reloads_and_next_run_clears_alert(self):
        def invoke(args, **kwargs):
            if args[0] == "certbot":
                raise subprocess.CalledProcessError(1, args, stderr="sensitive stderr")
            return subprocess.CompletedProcess(args, 0, stdout="")

        with mock.patch("fortress.tls.shutil.which", return_value="/usr/bin/certbot"), \
                mock.patch("fortress.system.subprocess.run", side_effect=invoke) as run, \
                self.assertLogs(level="ERROR") as journal:
            self.assertEqual(tls_schedule.run_scheduled_renewal(self.logger), 1)
        failed = self.logger.scheduled_tls_renewal()
        self.assertEqual(failed["status"], "error")
        self.assertEqual(failed["failed_steps"], ["certbot"])
        self.assertIn(failed["run_id"], journal.output[-1])
        self.assertNotIn("sensitive stderr", "\n".join(journal.output))
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [["certbot", "renew", "--non-interactive"], ["nginx", "-t"], ["systemctl", "reload", "nginx"]],
        )
        with closing(sqlite3.connect(self.path)) as conn:
            events = conn.execute(
                "SELECT category, status, details FROM command_log WHERE request_id = ? ORDER BY id",
                (failed["run_id"],),
            ).fetchall()
        self.assertEqual([(row[0], row[1]) for row in events], [
            ("command", "error"), ("command", "success"), ("command", "success"), ("internal", "error"),
        ])
        self.assertNotIn("sensitive stderr", str(events))

        with mock.patch("fortress.tls.shutil.which", return_value="/usr/bin/certbot"), \
                mock.patch("fortress.system.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout="")):
            self.assertEqual(tls_schedule.run_scheduled_renewal(self.logger), 0)
        latest = self.logger.scheduled_tls_renewal()
        self.assertEqual(latest["status"], "success")
        self.assertEqual(latest["failed_steps"], [])
        self.assertNotEqual(latest["run_id"], failed["run_id"])

    def test_invalid_nginx_config_blocks_reload(self):
        with mock.patch.object(tls_schedule, "renew_letsencrypt"), \
                mock.patch.object(tls_schedule, "test_nginx_config", side_effect=OSError), \
                mock.patch.object(tls_schedule, "reload_nginx") as reload, self.assertLogs(level="ERROR"):
            self.assertEqual(tls_schedule.run_scheduled_renewal(self.logger), 1)
        reload.assert_not_called()
        self.assertEqual(self.logger.scheduled_tls_renewal()["failed_steps"], ["nginx_config"])

    def test_reload_or_audit_write_failure_returns_nonzero(self):
        with mock.patch.object(tls_schedule, "renew_letsencrypt"), \
                mock.patch.object(tls_schedule, "test_nginx_config"), \
                mock.patch.object(tls_schedule, "reload_nginx") as reload, self.assertLogs(level="ERROR"):
            reload.side_effect = OSError
            self.assertEqual(tls_schedule.run_scheduled_renewal(self.logger), 1)
            self.assertEqual(self.logger.scheduled_tls_renewal()["failed_steps"], ["nginx_reload"])
            reload.side_effect = None
            self.path.unlink()
            self.assertEqual(tls_schedule.run_scheduled_renewal(self.logger), 1)
            self.assertEqual(self.logger.scheduled_tls_renewal(), {"status": "unavailable"})
