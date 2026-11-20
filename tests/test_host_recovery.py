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
        }
        for name, code in (
            ("restic", 'printf "%s\\0" "$@" > "$FORTRESS_TEST_RESTIC_ARGS"\nexit "${FORTRESS_TEST_RESTIC_EXIT:-0}"'),
            ("logger", 'printf "%s\\n" "$*" > "$FORTRESS_TEST_JOURNAL"'),
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
