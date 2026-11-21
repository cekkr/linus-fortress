import subprocess
import unittest
from pathlib import Path


RUN_SERVER = Path(__file__).resolve().parents[1] / "run-server.sh"
SQUASHFS_FAILURE = 'error: cannot mount squashfs image using "squashfs"'


class SnapBootstrapTests(unittest.TestCase):
    def run_snap_install(self, output, status, *, mode="Enforcing", modules="snapper", release="10.2"):
        return subprocess.run(
            [
                "bash", "-c", r"""
source "$1"
command() {
  case "$*" in
    '-v lxc'|'-v lxd') return 1 ;;
  esac
  builtin command "$@"
}
snap() {
  case "$*" in
    'list lxd') return 1 ;;
    'install lxd') printf '%s\n' "$snap_output"; return "$snap_status" ;;
    *) return 99 ;;
  esac
}
getenforce() { printf '%s\n' "$selinux_mode"; }
semodule() { printf '%s\n' "$selinux_modules"; }
detect_os_version() { printf '%s\n' "$os_version"; }
snap_output=$2 snap_status=$3 selinux_mode=$4 selinux_modules=$5 os_version=$6
ensure_snap_lxd
""",
                "bootstrap-test", str(RUN_SERVER), output, str(status), mode, modules, release,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def test_missing_policy_on_squashfs_failure_reports_the_minor_release(self):
        result = self.run_snap_install(SQUASHFS_FAILURE, 7)
        self.assertEqual(result.returncode, 7)
        self.assertIn(SQUASHFS_FAILURE, result.stderr)
        self.assertIn("snappy SELinux policy is missing on AlmaLinux 10.2", result.stderr)
        self.assertIn("signed snapd, snap-confine, and snapd-selinux RPMs from EPEL 10.2", result.stderr)

    def test_other_install_failures_keep_the_original_diagnostic(self):
        for output, mode, modules, release in (
            ("error: Snap Store unavailable", "Enforcing", "", "10.2"),
            (SQUASHFS_FAILURE, "Enforcing", "snappy\nother-policy", "10.2"),
            (SQUASHFS_FAILURE, "Disabled", "", "10.2"),
            (SQUASHFS_FAILURE, "Enforcing", "", "10"),
        ):
            with self.subTest(output=output, mode=mode, modules=modules, release=release):
                result = self.run_snap_install(output, 1, mode=mode, modules=modules, release=release)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stderr.strip(), output)

    def test_success_retains_snap_output(self):
        result = self.run_snap_install("lxd installed", 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lxd installed", result.stdout)
        self.assertEqual(result.stderr, "")
