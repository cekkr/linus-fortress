import subprocess
import tempfile
import unittest
from pathlib import Path


RUN_SERVER = Path(__file__).resolve().parents[1] / "run-server.sh"
SQUASHFS_FAILURE = 'error: cannot mount squashfs image using "squashfs"'


class NginxBootstrapTests(unittest.TestCase):
    def run_bootstrap(self, *, fallback="loaded", existing=False, collision=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "conf.d").mkdir()
        managed = root / "conf.d" / "fortress-sites.conf"
        if collision:
            managed.write_text("# operator configuration\n")
        result = subprocess.run(
            [
                "bash", "-c", r"""
source "$1"
nginx_root=$2
fallback=$3
existing=$4
ln() {
  [[ "$#" == 4 && "$1" == "-T" && "$2" == "--" ]] || return 99
  [[ ! -e "$4" && ! -L "$4" ]] || return 1
  command ln "$3" "$4"
}
nginx() {
  [[ "$*" == "-T" ]] || return 99
  printf '%s\n' '# fixture configuration contents'
  if [[ -f "$nginx_root/conf.d/fortress-sites.conf" && "$fallback" == "invalid" ]]; then return 1; fi
  if [[ "$existing" == "true" || ( -f "$nginx_root/conf.d/fortress-sites.conf" && "$fallback" != "ignored" ) ]]; then
    local file
    for file in "$nginx_root"/sites-enabled/*; do
      printf '# configuration file %s:\n' "$file"
    done
  fi
}
systemctl() {
  case "$*" in
    'is-active --quiet nginx') return 0 ;;
    'reload nginx')
      printf 'reload\n' >> "$nginx_root/reloads"
      if [[ "$fallback" == "reload-failure" && -f "$nginx_root/conf.d/fortress-sites.conf" ]]; then return 1; fi
      ;;
    *) return 99 ;;
  esac
}
ensure_nginx_sites_include "$nginx_root"
""",
                "nginx-bootstrap-test", str(RUN_SERVER), str(root), fallback, str(existing).lower(),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(list((root / "sites-enabled").iterdir()), [])
        self.assertEqual(list((root / "conf.d").glob(".fortress-sites.*")), [])
        self.assertNotIn("fixture configuration contents", result.stdout)
        return result, root, managed

    def test_publishes_include_and_reloads_nginx(self):
        result, root, managed = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(managed.read_text(), f"include {root}/sites-enabled/*;\n")
        self.assertEqual((root / "reloads").read_text(), "reload\n")

    def test_honors_an_existing_include_or_config_file(self):
        result, root, managed = self.run_bootstrap(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(managed.exists())
        self.assertFalse((root / "reloads").exists())

        result, root, managed = self.run_bootstrap(collision=True, fallback="ignored")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(managed.read_text(), "# operator configuration\n")
        self.assertFalse((root / "reloads").exists())

    def test_rolls_back_if_config_is_invalid_ignored_or_reload_fails(self):
        for fallback in ("invalid", "ignored", "reload-failure"):
            with self.subTest(fallback=fallback):
                result, root, managed = self.run_bootstrap(fallback=fallback)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(managed.exists())
                reloads = root / "reloads"
                if fallback == "reload-failure":
                    self.assertEqual(reloads.read_text(), "reload\nreload\n")
                else:
                    self.assertFalse(reloads.exists())


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
