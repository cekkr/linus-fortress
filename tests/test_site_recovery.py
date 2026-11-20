import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

from test_permissions_matrix import load_server_module


class SiteRecoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.docroot = self.root / "site files"
        self.docroot.mkdir(mode=0o751)
        (self.docroot / "index.html").write_text("old release")
        (self.docroot / ".env").write_text("old settings")
        (self.docroot / ".env").chmod(0o600)
        (self.docroot / "link").symlink_to("index.html")
        self.archive = self.root / "new-release.tar.gz"
        release = self.root / "new.html"
        release.write_text("new release")
        with tarfile.open(self.archive, "w:gz") as tar:
            tar.add(release, arcname="new.html")

        with mock.patch.dict(os.environ, {
            "FORTRESS_LOG_PATH": str(self.root / "fortress.log"),
            "FORTRESS_COMMAND_LOG_DB": str(self.root / "command_log.db"),
        }):
            self.server, name = load_server_module(str(self.root))
        self.addCleanup(sys.modules.pop, name, None)
        self.server.API_USERS_DB = str(self.root / "api_users.json")
        Path(self.server.API_USERS_DB).write_text(json.dumps({
            "scoped": {"permissions": ["sites_manage"], "allowed_containers": ["alpha"]},
            "scoped-local": {"permissions": ["sites_manage", "sites_deploy_local"], "allowed_containers": ["alpha"]},
            "global": {"permissions": ["sites_manage"]},
            "local-importer": {"permissions": ["sites_manage", "sites_deploy_local"]},
        }))
        self.server.SITES_DB = str(self.root / "sites.json")
        Path(self.server.SITES_DB).write_text(json.dumps({
            "app": {
                "name": "app", "container_name": "alpha", "docroot": str(self.docroot),
                "database": {"name": "app", "username": "operator"},
            },
        }))
        self.server.SITE_BACKUP_DIR = str(self.root / "backups")
        Path(self.server.SITE_BACKUP_DIR).mkdir()

        container = mock.patch.object(self.server, "exec_in_container", side_effect=self.exec_container)
        self.exec_mock = container.start()
        self.addCleanup(container.stop)
        transport = mock.patch.object(self.server, "run_command", side_effect=self.push)
        self.push_mock = transport.start()
        self.addCleanup(transport.stop)

    def guest_path(self, path):
        prefix = "/tmp/fortress-site-"
        if path.startswith(prefix):
            return str(self.root / f"fortress-site-{path[len(prefix):]}")
        return path

    def exec_container(self, container, command, **kwargs):
        self.assertEqual(container, "alpha")
        argv = [self.guest_path(arg) for arg in command]
        if argv[0] == "curl":
            shutil.copyfile(self.archive, argv[3])
            return ""
        if argv[:2] == ["sh", "-c"] and argv[2].startswith("systemctl restart "):
            if "httpd" in argv[2]:
                return ""
            self.assertNotIn("|| true", argv[2])
            raise HTTPException(500, "Restart command failed")
        result = subprocess.run(argv, cwd=self.root, capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise HTTPException(500, result.stderr.strip() or "Guest command failed")
        return result.stdout.strip()

    def push(self, command):
        self.assertEqual(command[:3], ["lxc", "file", "push"])
        self.assertTrue(command[-1].startswith("alpha/"))
        shutil.copyfile(command[-2], self.guest_path(command[-1][len("alpha"):]))
        return ""

    def deploy(self, token="scoped", **changes):
        payload = {"source_type": "archive", "source": "https://example.test/archive", "restart_services": False}
        payload.update(changes)
        return self.server.deploy_site("app", self.server.SiteDeployRequest(**payload), x_api_key=None, x_user_token=token)

    def assert_previous_release(self):
        self.assertCountEqual([file.name for file in self.docroot.iterdir()], ["index.html", ".env", "link"])
        self.assertEqual((self.docroot / "index.html").read_text(), "old release")
        self.assertEqual((self.docroot / ".env").read_text(), "old settings")
        self.assertEqual((self.docroot / ".env").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.docroot.stat().st_mode & 0o777, 0o751)
        self.assertEqual(os.readlink(self.docroot / "link"), "index.html")

    def assert_audit(self, action, status):
        with sqlite3.connect(self.server.COMMAND_LOG_DB) as db:
            self.assertIsNotNone(db.execute(
                "SELECT 1 FROM command_log WHERE action = ? AND target = 'app' AND status = ?",
                (action, status),
            ).fetchone())

    def test_failed_post_deploy_restores_complete_previous_tree(self):
        with self.assertRaises(HTTPException):
            self.deploy(post_deploy_commands=["exit 1"])
        self.assert_previous_release()
        self.assertEqual(list(self.root.glob("fortress-site-*")), [])
        self.assert_audit("site_docroot_restored", "success")
        self.assert_audit("sites_deploy", "error")

    def test_first_deploy_failure_removes_new_docroot(self):
        shutil.rmtree(self.docroot)
        with self.assertRaises(HTTPException):
            self.deploy(post_deploy_commands=["exit 1"])
        self.assertFalse(self.docroot.exists())
        self.assertEqual(list(self.root.glob("fortress-site-*")), [])

    def test_successful_deploy_keeps_existing_dotfiles_and_removes_checkpoint(self):
        self.assertEqual(self.deploy()["message"], "Site deployed")
        self.assertCountEqual([file.name for file in self.docroot.iterdir()], ["new.html", ".env"])
        self.assertEqual((self.docroot / "new.html").read_text(), "new release")
        self.assertEqual(list(self.root.glob("fortress-site-*")), [])

    def test_invalid_archive_restores_the_previous_tree(self):
        self.archive.write_bytes(b"not a gzip archive")
        with self.assertRaises(HTTPException):
            self.deploy()
        self.assert_previous_release()
        self.assert_audit("site_docroot_restored", "success")

    def test_failed_recursive_host_copy_restores_the_previous_tree(self):
        def fail_after_copy(command):
            self.assertEqual(command[:5], ["lxc", "file", "push", "-r", "--"])
            self.assertEqual(command[-1], f"alpha{self.docroot}")
            (self.docroot / "partial.html").write_text("partial copy")
            raise HTTPException(500, "File transfer failed")

        self.push_mock.side_effect = fail_after_copy
        with self.assertRaises(HTTPException):
            self.deploy(token="local-importer", source_type="local", source=str(self.root))
        self.assert_previous_release()

    def test_symlink_docroot_leaves_its_target_untouched(self):
        target = self.root / "actual tree"
        self.docroot.rename(target)
        self.docroot.symlink_to(target, target_is_directory=True)
        with self.assertRaises(HTTPException):
            self.deploy()
        self.assertEqual(self.docroot.resolve(), target)
        self.assert_previous_release()
        self.assertEqual(list(self.root.glob("fortress-site-*")), [])

    def test_unsafe_legacy_docroot_is_rejected_before_any_guest_command(self):
        site_path = Path(self.server.SITES_DB)
        sites = json.loads(site_path.read_text())
        for docroot in ("/", "/srv/..", "relative/path"):
            sites["app"]["docroot"] = docroot
            site_path.write_text(json.dumps(sites))
            with self.subTest(docroot=docroot), self.assertRaises(HTTPException) as caught:
                self.deploy()
            self.assertEqual(caught.exception.status_code, 400)
        self.exec_mock.assert_not_called()

    def test_create_rejects_invalid_root_and_audits_before_provisioning(self):
        payload = self.server.SiteCreateRequest(
            name="invalid", container_name="alpha", docroot="/", primary_domain="invalid.example.test",
        )
        with self.assertRaises(HTTPException) as caught:
            self.server.create_site(payload, x_api_key=None, x_user_token="scoped")
        self.assertEqual(caught.exception.status_code, 400)
        self.exec_mock.assert_not_called()
        with sqlite3.connect(self.server.COMMAND_LOG_DB) as db:
            self.assertEqual(db.execute(
                "SELECT target, status FROM command_log WHERE action = 'sites_create'"
            ).fetchall(), [("invalid", "error")])

    def test_restart_failure_tries_fallbacks_and_restores_previous_files(self):
        with self.assertRaises(HTTPException) as caught:
            self.deploy(restart_services=True)
        self.assertEqual(caught.exception.detail["restarted"], ["httpd"])
        self.assertEqual(caught.exception.detail["failed"], ["php-fpm"])
        self.assert_previous_release()
        restart = self.server.restart_site_services(
            "app", self.server.SiteServiceActionRequest(), x_api_key=None, x_user_token="scoped",
        )
        self.assertEqual(restart["failed"], ["php-fpm"])
        self.assert_audit("sites_restart", "error")

    def test_failed_compensation_keeps_the_checkpoint(self):
        def fail_recovery(container, command, **kwargs):
            if command[:2] == ["sh", "-ec"] and 'rmdir -- "$root"' in command[2]:
                raise HTTPException(500, "Injected restore failure")
            return self.exec_container(container, command, **kwargs)

        self.exec_mock.side_effect = fail_recovery
        with self.assertRaises(HTTPException) as caught:
            self.deploy(post_deploy_commands=["exit 1"])
        checkpoint = Path(self.guest_path(caught.exception.detail["staging_path"])) / "previous-docroot"
        self.assertEqual((checkpoint / ".env").read_text(), "old settings")
        self.assertEqual(checkpoint.parent.stat().st_mode & 0o777, 0o700)
        self.assert_audit("site_docroot_restore_failed", "error")

    def test_db_failure_during_rollback_restores_previous_document_root(self):
        backup_id = "app-with-db"
        backup = Path(self.server.SITE_BACKUP_DIR)
        dump = self.root / "dump.sql"
        dump.write_text("example sql")
        with tarfile.open(backup / f"{backup_id}.tar.gz", "w:gz") as tar:
            tar.add(dump, arcname=f"{backup_id}.sql")
            tar.add(self.root / "new.html", arcname="new.html")
        (backup / f"{backup_id}.json").write_text(json.dumps({
            "site_id": "app", "container_name": "alpha", "include_database": True,
        }))

        # The shell checkpoint is exercised against real files. Stub the archive
        # extraction with a DB member exclusion, which requires GNU tar.
        def replace_files(container, archive, docroot, **kwargs):
            self.assertEqual(kwargs["dump_name"], f"{backup_id}.sql")
            Path(docroot, "new.html").write_text("restored files")

        with (
            mock.patch.object(self.server, "_extract_site_archive", side_effect=replace_files),
            mock.patch.object(self.server, "_restore_site_db", side_effect=HTTPException(500, "DB import failed")),
            self.assertRaises(HTTPException),
        ):
            payload = self.server.SiteRollbackRequest(backup_id=backup_id, restart_services=False)
            self.server.rollback_site("app", payload, x_api_key=None, x_user_token="scoped")
        self.assert_previous_release()
        self.assert_audit("sites_rollback", "error")

    def test_host_source_permission_and_scope_are_checked_before_access(self):
        for token in ("scoped", "scoped-local", "global"):
            for source_type in ("local", "archive"):
                with self.subTest(token=token, source_type=source_type), self.assertRaises(HTTPException) as caught:
                    self.deploy(token=token, source_type=source_type, source=str(self.archive))
                self.assertEqual(caught.exception.status_code, 403)
        self.exec_mock.assert_not_called()
        self.push_mock.assert_not_called()
        result = self.deploy(token="local-importer", source=str(self.archive))
        self.assertEqual(result["message"], "Site deployed")
        self.assertEqual(self.push_mock.call_args.args[0][:4], ["lxc", "file", "push", "--"])
