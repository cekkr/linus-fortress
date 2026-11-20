import io
import os
import sys
import unittest
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import qmp


class QmpSnapshotTests(unittest.TestCase):
    def test_command_ignores_events_until_correlated_response(self):
        connection = mock.Mock()
        frames = io.BytesIO(b'{"event":"JOB_STATUS_CHANGE"}\r\n{"return":{},"id":1}\r\n')
        self.assertEqual(qmp._QMP(connection, frames).call("qmp_capabilities"), {})
        connection.sendall.assert_called_once_with(b'{"execute": "qmp_capabilities", "id": 1}\n')

    def test_rejects_monitor_for_another_disk_or_vm(self):
        disk = {"inserted": {"node-name": qmp.DISK_NODE, "file": "/lab/web.qcow2", "drv": "qcow2"}}
        iso = {"inserted": {"file": "/media/install.iso", "ro": True}}
        monitor = mock.Mock()
        monitor.call.side_effect = [{"name": "web"}, [disk, iso]]
        qmp._require_managed_disk(monitor, "web", "/lab/web.qcow2")
        for responses in (
            [{"name": "other"}],
            [{"name": "web"}, [disk, disk]],
            [{"name": "web"}, [disk]],
        ):
            with self.subTest(responses=responses), self.assertRaises(HTTPException) as error:
                monitor.call.side_effect = responses
                qmp._require_managed_disk(monitor, "web", "/lab/other.qcow2")
            self.assertEqual(error.exception.status_code, 409)

    def test_failed_job_is_dismissed_and_reported_without_qemu_error_details(self):
        monitor = mock.Mock()

        def respond(command, arguments=None):
            if command == "query-jobs":
                return [job.copy()] if job else []
            if command == "query-named-block-nodes":
                return [{"node-name": qmp.DISK_NODE, "image": {}}]
            if command == "snapshot-save":
                self.assertEqual(arguments["vmstate"], qmp.DISK_NODE)
                self.assertEqual(arguments["devices"], [qmp.DISK_NODE])
                job.update(id=arguments["job-id"], status="concluded", error="private host path")
            if command == "job-dismiss":
                self.assertEqual(arguments, {"id": job["id"]})
                job.clear()

        job = {}
        monitor.call.side_effect = respond
        with self.assertRaises(HTTPException) as error:
            qmp._run_job(monitor, "create", "checkpoint")
        self.assertEqual(error.exception.status_code, 409)
        self.assertNotIn("private host path", error.exception.detail)
        self.assertEqual(job, {})

    def test_retry_adopts_unregistered_memory_snapshot_and_rejects_disk_only_restore(self):
        monitor = mock.Mock()
        for action, memory_size in (("create", 1024), ("restore", 0)):
            monitor.call.reset_mock()
            monitor.call.side_effect = [
                [],
                [{
                    "node-name": qmp.DISK_NODE,
                    "image": {"snapshots": [{"name": "checkpoint", "vm-state-size": memory_size}]},
                }],
            ]
            if action == "restore":
                with self.assertRaises(HTTPException) as error:
                    qmp._run_job(monitor, action, "checkpoint")
                self.assertEqual(error.exception.status_code, 409)
            else:
                qmp._run_job(monitor, action, "checkpoint")
            self.assertEqual(monitor.call.call_args_list, [
                mock.call("query-jobs"), mock.call("query-named-block-nodes"),
            ])
