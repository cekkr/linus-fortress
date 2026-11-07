"""Focused tests for fortress.remote (SSH command building) and fortress.tls (certbot wrappers)."""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import remote, tls


class SSHCommandTests(unittest.TestCase):
    def test_builds_argument_list_with_option_terminator(self):
        cmd = remote.build_ssh_command({"host": "10.0.0.5", "username": "deploy", "port": 2222, "key_path": "/root/.ssh/id"})
        self.assertEqual(
            cmd,
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", "2222", "-i", "/root/.ssh/id", "--", "deploy@10.0.0.5"],
        )

    def test_accepts_hostnames_and_ipv6(self):
        for host in ("vm.example.com", "fortress-alma", "::1", "[fe80::1]", "192.168.1.1"):
            with self.subTest(host=host):
                self.assertEqual(remote.build_ssh_command({"host": host, "username": "root"})[-2], "--")

    def test_rejects_option_injection_and_malformed_values(self):
        bad_configs = [
            {"host": "h", "username": "-oProxyCommand=touch /tmp/pwn"},
            {"host": "-oProxyCommand=id", "username": "root"},
            {"host": "h;id", "username": "root"},
            {"host": "h", "username": "root@evil"},
            {"host": "h", "username": "a b"},
            {"host": "", "username": "root"},
            {"host": "h", "username": ""},
            {"host": "h", "username": "root", "port": 0},
            {"host": "h", "username": "root", "port": "22; id"},
            {"host": "h", "username": "root", "key_path": "-oProxyCommand=id"},
            {"host": "h", "username": "root", "key_path": "relative/key"},
            "not-a-dict",
        ]
        for config in bad_configs:
            with self.subTest(config=config):
                with self.assertRaises(HTTPException) as ctx:
                    remote.build_ssh_command(config)  # type: ignore[arg-type]
                self.assertEqual(ctx.exception.status_code, 400)

    def test_run_ssh_script_quotes_env_and_pipes_script(self):
        with mock.patch.object(remote, "_run_subprocess", return_value="ok") as run:
            out = remote.run_ssh_script(
                {"host": "h", "username": "root"},
                "echo hi",
                env={"REPO_URL": "https://x/y; rm -rf /", "SKIP": None, "PORT": 8443},
            )
        self.assertEqual(out, "ok")
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], "REPO_URL='https://x/y; rm -rf /' PORT=8443 bash -s")
        self.assertEqual(run.call_args.kwargs["input_text"], "echo hi")

    def test_run_ssh_script_rejects_bad_env_names(self):
        with mock.patch.object(remote, "_run_subprocess") as run:
            with self.assertRaises(HTTPException):
                remote.run_ssh_script({"host": "h", "username": "root"}, "x", env={"A;id": "1"})
        run.assert_not_called()

    def test_password_auth_requires_sshpass(self):
        with mock.patch.object(remote.shutil, "which", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                remote.run_ssh_script({"host": "h", "username": "root", "password": "pw"}, "x")
        self.assertIn("sshpass", ctx.exception.detail)

    def test_subprocess_failure_becomes_http_500(self):
        err = subprocess.CalledProcessError(255, ["ssh"], stderr="Permission denied\n")
        with mock.patch.object(remote.subprocess, "run", side_effect=err):
            with self.assertRaises(HTTPException) as ctx:
                remote._run_subprocess(["ssh"])
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("Permission denied", ctx.exception.detail)

    def test_load_provision_script_validates_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "provision_ubuntu.sh"), "w") as fh:
                fh.write("#!/bin/sh\n")
            self.assertEqual(remote.load_provision_script("ubuntu", scripts_dir=tmp), "#!/bin/sh\n")
            for profile in ("../ubuntu", "ubuntu/../../x", "", "UBUNTU"):
                with self.subTest(profile=profile):
                    with self.assertRaises(HTTPException) as ctx:
                        remote.load_provision_script(profile, scripts_dir=tmp)
                    self.assertEqual(ctx.exception.status_code, 400)
            with self.assertRaises(HTTPException) as ctx:
                remote.load_provision_script("fedora", scripts_dir=tmp)
            self.assertEqual(ctx.exception.status_code, 500)

    def test_shipped_provision_profiles_load(self):
        for profile in ("ubuntu", "fedora"):
            self.assertIn("#!", remote.load_provision_script(profile))

    def test_probe_script_quotes_service_name(self):
        script = remote.build_probe_script("fortress'; id; '")
        self.assertNotIn("fortress'; id; '\n", script)
        self.assertIn(remote.shlex.quote("fortress'; id; '"), script)


class HostVmSSHValidationTests(unittest.TestCase):
    def test_create_and_update_host_reject_injected_username(self):
        from fortress import hosts

        payload = hosts.HostCreateRequest(name="h1", ssh={"host": "10.0.0.1", "username": "-oProxyCommand=id"})
        with self.assertRaises(HTTPException):
            hosts.create_host(payload, {})
        store = {}
        hosts.create_host(hosts.HostCreateRequest(name="h1", ssh={"host": "10.0.0.1", "username": "root"}), store)
        with self.assertRaises(HTTPException):
            hosts.update_host("h1", hosts.HostUpdateRequest(ssh={"host": "-oX", "username": "root"}), store)
        self.assertEqual(store["h1"]["ssh"]["host"], "10.0.0.1")

    def test_create_vm_rejects_injected_host(self):
        from fortress import vms

        payload = vms.VMCreateRequest(name="v1", provider="qemu", ssh={"host": "-oProxyCommand=id", "username": "root"})
        with self.assertRaises(HTTPException):
            vms.create_vm(payload, {})


class TLSTests(unittest.TestCase):
    def test_validate_letsencrypt_domains(self):
        self.assertEqual(tls.validate_letsencrypt_domains([" a.example.com ", "a.example.com", "b.example.com"]), ["a.example.com", "b.example.com"])
        for domains in ([], ["", "  "], ["*.example.com"], ["bad domain"]):
            with self.subTest(domains=domains):
                with self.assertRaises(HTTPException) as ctx:
                    tls.validate_letsencrypt_domains(domains)
                self.assertEqual(ctx.exception.status_code, 400)

    def test_ensure_acme_challenge_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tls.ensure_acme_challenge_dir(tmp), tmp)
            self.assertTrue(os.path.isdir(os.path.join(tmp, ".well-known", "acme-challenge")))
        for bad in ("", "relative/dir"):
            with self.subTest(bad=bad), self.assertRaises(HTTPException):
                tls.ensure_acme_challenge_dir(bad)

    def test_certbot_missing(self):
        with mock.patch.object(tls.shutil, "which", return_value=None), self.assertRaises(HTTPException) as ctx:
            tls.renew_letsencrypt()
        self.assertIn("certbot", ctx.exception.detail)

    def test_issue_certificate_command_and_output_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            live = os.path.join(tmp, "live")
            webroot = os.path.join(tmp, "acme")
            os.makedirs(os.path.join(live, "a.example.com"))
            with mock.patch.object(tls, "LE_LIVE_DIR", live), \
                    mock.patch.object(tls.shutil, "which", return_value="/usr/bin/certbot"), \
                    mock.patch.object(tls, "run_command", return_value="") as run:
                with self.assertRaises(HTTPException) as ctx:
                    tls.issue_letsencrypt_certificate(["a.example.com", "www.a.example.com"], "ops@example.com", webroot, staging=True)
                self.assertEqual(ctx.exception.status_code, 500)  # certbot "succeeded" but wrote no files
                cmd = run.call_args.args[0]
                self.assertEqual(cmd[:2], ["certbot", "certonly"])
                self.assertIn("--staging", cmd)
                self.assertEqual(cmd[cmd.index("--cert-name") + 1], "a.example.com")
                self.assertEqual([cmd[i + 1] for i, v in enumerate(cmd) if v == "-d"], ["a.example.com", "www.a.example.com"])

                for name in ("fullchain.pem", "privkey.pem"):
                    open(os.path.join(live, "a.example.com", name), "w").close()
                paths = tls.issue_letsencrypt_certificate(["a.example.com"], "ops@example.com", webroot)
                self.assertEqual(paths["cert_path"], os.path.join(live, "a.example.com", "fullchain.pem"))

                run.reset_mock()
                tls.issue_letsencrypt_certificate(["new.example.com"], "ops@example.com", webroot, dry_run=True)
                self.assertIn("--dry-run", run.call_args.args[0])

    def test_issue_requires_email(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(tls.shutil, "which", return_value="/usr/bin/certbot"):
            with self.assertRaises(HTTPException) as ctx:
                tls.issue_letsencrypt_certificate(["a.example.com"], "  ", tmp)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_renew_command(self):
        with mock.patch.object(tls.shutil, "which", return_value="/usr/bin/certbot"), \
                mock.patch.object(tls, "run_command", return_value="renewed") as run:
            self.assertEqual(tls.renew_letsencrypt("a.example.com", dry_run=True), "renewed")
        run.assert_called_once_with(["certbot", "renew", "--cert-name", "a.example.com", "--dry-run"])


if __name__ == "__main__":
    unittest.main()
