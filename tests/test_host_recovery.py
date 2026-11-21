import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "host-recovery.sh"


class HostRecoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.env = {
            **os.environ,
            "PATH": f"{self.root}:{os.environ['PATH']}",
            "FORTRESS_TEST_RESTIC_ARGS": str(self.root / "args"),
            "FORTRESS_TEST_JOURNAL": str(self.root / "journal"),
            "FORTRESS_TEST_SSH_ARGS": str(self.root / "ssh-args"),
        }
        for name, code in (
            ("restic", 'printf "%s\\0" "$@" > "$FORTRESS_TEST_RESTIC_ARGS"\nexit "${FORTRESS_TEST_RESTIC_EXIT:-0}"'),
            ("logger", 'printf "%s\\n" "$*" > "$FORTRESS_TEST_JOURNAL"'),
            ("ssh", 'printf "%s\\0" "$@" > "$FORTRESS_TEST_SSH_ARGS"\nfor command do :; done\nexec sh -c "$command"'),
        ):
            command = self.root / name
            command.write_text("#!/bin/sh\n" + code + "\n")
            command.chmod(0o700)

    def invoke(self, *args, restic_exit=0):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env={**self.env, "FORTRESS_TEST_RESTIC_EXIT": str(restic_exit)},
            capture_output=True,
            text=True,
        )

    def recorded_args(self):
        return (self.root / "args").read_bytes().decode().rstrip("\0").split("\0")

    def test_incomplete_backup_is_reported_as_failure(self):
        result = self.invoke("backup", "/srv/shared files", restic_exit=3)
        self.assertEqual(result.returncode, 3, result.stderr)
        args = self.recorded_args()
        self.assertEqual(args[:3], ["backup", "--tag", "fortress-host-v1"])
        self.assertIn("/etc/fortress", args)
        self.assertIn("/var/lib/fortress", args)
        self.assertIn(str(SCRIPT.parents[1] / "schemas"), args)
        self.assertEqual(args[-1], "/srv/shared files")
        self.assertIn("exit_code=3", (self.root / "journal").read_text())

    def test_restore_requires_explicit_snapshot_and_stages_with_verification(self):
        invalid = self.invoke("restore", "latest", str(self.root))
        self.assertEqual(invalid.returncode, 2)
        self.assertFalse((self.root / "args").exists())

        result = self.invoke("restore", "123abcde", str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        restore, snapshot, target, staging, verify = self.recorded_args()
        self.assertEqual([restore, snapshot, target, verify], ["restore", "123abcde", "--target", "--verify"])
        stage = Path(staging)
        self.assertEqual(stage.parent.resolve(), self.root.resolve())
        self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
        self.assertIn(str(stage), result.stdout)

    def test_client_files_stage_into_a_private_remote_directory(self):
        source = self.root / "source"
        source.mkdir()
        (source / "vms.json").write_text('{"lab": {}}')
        (source / "schema.json").symlink_to("vms.json")
        remote = self.root / "remote ' staging"
        remote.mkdir()
        result = self.invoke("stage-ssh", str(source), "fortress-lab", str(remote))
        self.assertEqual(result.returncode, 0, result.stderr)
        stage = Path(result.stdout.strip().split(": ", 1)[1])
        self.assertEqual(stage.parent.parent, remote.resolve())
        self.assertEqual(stage.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual((stage / "vms.json").read_text(), '{"lab": {}}')
        self.assertEqual(os.readlink(stage / "schema.json"), "vms.json")
        ssh_args = (self.root / "ssh-args").read_bytes().split(b"\0")
        self.assertIn(b"StrictHostKeyChecking=yes", ssh_args)
        self.assertIn(b"fortress-lab", ssh_args)

    def test_failed_snapshot_verification_never_connects_to_ssh(self):
        failed = self.invoke("restore-ssh", "123abcde", str(self.root), "fortress-lab", str(self.root), restic_exit=1)
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertFalse((self.root / "ssh-args").exists())
        self.assertEqual(self.recorded_args()[-2:], ["--verify", "--sparse"])
        self.assertIn("exit_code=1", (self.root / "journal").read_text())

    def test_ssh_option_and_nonabsolute_staging_paths_are_rejected(self):
        for host, parent in (("-bad-host", str(self.root)), ("lab", "relative")):
            with self.subTest(host=host, parent=parent):
                result = self.invoke("stage-ssh", str(self.root), host, parent)
                self.assertEqual(result.returncode, 2)
                self.assertFalse((self.root / "ssh-args").exists())

    def test_failed_remote_extraction_discards_partial_staging(self):
        source = self.root / "source"
        source.mkdir()
        remote = self.root / "remote"
        remote.mkdir()
        (self.root / "ssh").write_text('#!/bin/sh\nfor command do :; done\nprintf "not a tar" | sh -c "$command"\n')
        failed = self.invoke("stage-ssh", str(source), "fortress-lab", str(remote))
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertNotIn("Remote recovery staging directory", failed.stdout)
        self.assertEqual(list(remote.iterdir()), [])
