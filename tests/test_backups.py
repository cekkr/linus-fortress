import json
import os
import sys
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.fernet import Fernet
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from test_permissions_matrix import load_server_module  # noqa: E402

BACKUP_PASSWORD = "integration-backup-password"


class _ServerRouteTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        env = {
            "FORTRESS_LOG_PATH": os.path.join(self.tmpdir.name, "fortress.log"),
            "FORTRESS_COMMAND_LOG_DB": os.path.join(self.tmpdir.name, "command_log.db"),
            "FORTRESS_API_KEY": "integration-master-key",
            "FORTRESS_BACKUP_PASSWORD": BACKUP_PASSWORD,
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.module, module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(lambda: sys.modules.pop(module_name, None))
        self.module.API_USERS_DB = os.path.join(self.tmpdir.name, "api_users.json")
        # Not created on purpose: routes must create BACKUP_DIR on demand.
        self.module.BACKUP_DIR = os.path.join(self.tmpdir.name, "backups")
        with open(self.module.API_USERS_DB, "w") as fh:
            json.dump(
                {
                    "token-web": {"username": "web", "permissions": ["manage_backups", "restore_container", "read_status"], "allowed_containers": ["web01"]},
                    "token-all": {"username": "all", "permissions": ["manage_backups", "restore_container", "read_status"], "allowed_containers": []},
                    "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
                },
                fh,
            )
        self.client = TestClient(self.module.app)
        self.fernet = Fernet(self.module.get_fernet_key(BACKUP_PASSWORD))

    def _get(self, path: str, token: str):
        return self.client.get(path, headers={"X-User-Token": token})


class BackupRouteTests(_ServerRouteTestBase):
    def _seed_backups(self) -> None:
        os.makedirs(self.module.BACKUP_DIR, exist_ok=True)
        for name in ("web01_20260101_010101.tar.gz.enc", "db01_20260101_010101.tar.gz.enc", "legacy.enc", "notes.txt"):
            with open(os.path.join(self.module.BACKUP_DIR, name), "wb") as fh:
                fh.write(b"payload-" + name.encode())

    def test_list_creates_dir_and_is_empty(self) -> None:
        response = self._get("/backup/list", "token-all")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["backups"], [])
        self.assertTrue(os.path.isdir(self.module.BACKUP_DIR))

    def test_list_is_scoped_by_allowed_containers(self) -> None:
        self._seed_backups()
        scoped = self._get("/backup/list", "token-web").json()
        self.assertEqual(scoped["backups"], ["web01_20260101_010101.tar.gz.enc"])
        self.assertEqual(scoped["items"][0]["container"], "web01")
        unscoped = self._get("/backup/list", "token-all").json()
        self.assertEqual(sorted(unscoped["backups"]), sorted(["web01_20260101_010101.tar.gz.enc", "db01_20260101_010101.tar.gz.enc", "legacy.enc"]))
        filtered = self._get("/backup/list?container=db01", "token-all").json()
        self.assertEqual(filtered["backups"], ["db01_20260101_010101.tar.gz.enc"])
        self.assertEqual(self._get("/backup/list?container=db01", "token-web").status_code, 403)
        self.assertEqual(self._get("/backup/list", "token-none").status_code, 403)

    def test_download_returns_file_and_enforces_scope(self) -> None:
        self._seed_backups()
        ok = self._get("/backup/download/web01_20260101_010101.tar.gz.enc", "token-web")
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.content, b"payload-web01_20260101_010101.tar.gz.enc")
        self.assertIn("attachment", ok.headers.get("content-disposition", ""))
        self.assertEqual(self._get("/backup/download/db01_20260101_010101.tar.gz.enc", "token-web").status_code, 403)
        self.assertEqual(self._get("/backup/download/web01_20990101_010101.tar.gz.enc", "token-web").status_code, 404)

    def test_download_rejects_invalid_and_traversal_names(self) -> None:
        self._seed_backups()
        for name in ("legacy.enc", "notes.txt", "..%2Fapi_users.json", "web01_20260101_010101.tar.gz.enc%00"):
            response = self._get(f"/backup/download/{name}", "token-all")
            self.assertIn(response.status_code, (400, 404), name)
        with self.assertRaises(HTTPException) as ctx:
            self.module.download_backup("../web01_20260101_010101.tar.gz.enc", x_api_key=None, x_user_token="token-all")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_trigger_backup_validates_name_and_scope(self) -> None:
        headers = {"X-User-Token": "token-all"}
        with mock.patch.object(self.module, "perform_encrypted_backup") as task:
            self.assertEqual(self.client.post("/backup/bad_name!", headers=headers).status_code, 400)
            self.assertEqual(self.client.post("/backup/db01", headers={"X-User-Token": "token-web"}).status_code, 403)
            self.assertEqual(self.client.post("/backup/web01", headers=headers).status_code, 200)
        task.assert_called_once()

    def test_perform_backup_writes_encrypted_owner_only_file(self) -> None:
        def fake_export(cmd):
            with open(cmd[3], "wb") as fh:
                fh.write(b"raw-archive")
            return ""

        with mock.patch.object(self.module, "run_command", side_effect=fake_export):
            self.module.perform_encrypted_backup("web01", "tester")
        names = os.listdir(self.module.BACKUP_DIR)
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], self.module.BACKUP_FILENAME_PATTERN)
        path = os.path.join(self.module.BACKUP_DIR, names[0])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "rb") as fh:
            self.assertEqual(self.fernet.decrypt(fh.read()), b"raw-archive")

    def test_perform_backup_failure_leaves_no_partial_files(self) -> None:
        def fake_export(cmd):
            with open(cmd[3], "wb") as fh:
                fh.write(b"raw")
            return ""

        with mock.patch.object(self.module, "run_command", side_effect=fake_export), \
                mock.patch.object(self.module, "Fernet", side_effect=RuntimeError("bad key")):
            self.module.perform_encrypted_backup("web01", "tester")
        self.assertEqual(os.listdir(self.module.BACKUP_DIR), [])

    def _restore(self, token: str, container: str, payload: bytes):
        return self.client.post(
            f"/restore?container_name={container}",
            headers={"X-User-Token": token},
            files={"file": ("backup.enc", payload, "application/octet-stream")},
        )

    def test_restore_decrypts_into_unique_staging_and_cleans_up(self) -> None:
        seen = []

        def fake_import(cmd):
            self.assertEqual(cmd[:2], ["lxc", "import"])
            with open(cmd[2], "rb") as fh:
                seen.append((cmd[2], fh.read()))
            return ""

        token = self.fernet.encrypt(b"archive-bytes")
        with mock.patch.object(self.module, "run_command", side_effect=fake_import):
            first = self._restore("token-web", "web01", token)
            second = self._restore("token-web", "web01", token)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200)
        self.assertEqual([data for _, data in seen], [b"archive-bytes", b"archive-bytes"])
        self.assertNotEqual(os.path.dirname(seen[0][0]), os.path.dirname(seen[1][0]))
        self.assertEqual(os.listdir(self.module.BACKUP_DIR), [])

    def test_concurrent_restores_do_not_collide(self) -> None:
        barrier = threading.Barrier(2, timeout=5)
        seen = []

        def fake_import(cmd):
            barrier.wait()
            with open(cmd[2], "rb") as fh:
                seen.append(fh.read())
            return ""

        results = []
        with mock.patch.object(self.module, "run_command", side_effect=fake_import):
            threads = [
                threading.Thread(target=lambda data=data: results.append(self._restore("token-all", "web01", self.fernet.encrypt(data)).status_code))
                for data in (b"alpha", b"beta")
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(results, [200, 200])
        self.assertEqual(sorted(seen), [b"alpha", b"beta"])

    def test_restore_rejects_bad_payload_scope_and_size(self) -> None:
        with mock.patch.object(self.module, "run_command") as run:
            bad = self._restore("token-web", "web01", b"not-a-fernet-token")
            self.assertEqual(bad.status_code, 500)
            self.assertIn("FORTRESS_BACKUP_PASSWORD", bad.json()["detail"])
            self.assertEqual(self._restore("token-web", "db01", b"x").status_code, 403)
            self.assertEqual(self._restore("token-all", "bad_name", b"x").status_code, 400)
            self.module.RESTORE_MAX_BYTES = 4
            self.assertEqual(self._restore("token-all", "web01", b"0123456789").status_code, 413)
            run.assert_not_called()
        self.assertEqual(os.listdir(self.module.BACKUP_DIR), [])


class StatusScopeTests(_ServerRouteTestBase):
    LXC_LIST = json.dumps([{"name": "web01", "status": "Running"}, {"name": "db01", "status": "Running"}])

    def _fake_run(self, cmd):
        return self.LXC_LIST if cmd[0] == "lxc" else "header\nline"

    def test_status_filters_containers_for_scoped_token(self) -> None:
        with mock.patch.object(self.module, "run_command", side_effect=self._fake_run):
            scoped = self._get("/status", "token-web").json()
            unscoped = self._get("/status", "token-all").json()
        self.assertEqual([c["name"] for c in json.loads(scoped["containers"])], ["web01"])
        self.assertEqual(len(json.loads(unscoped["containers"])), 2)

    def test_status_unparseable_output_is_hidden_from_scoped_token(self) -> None:
        self.assertEqual(self.module._filter_status_containers("not json", {"allowed_containers": ["web01"]}), "[]")
        self.assertEqual(self.module._filter_status_containers("not json", {"allowed_containers": None}), "not json")


if __name__ == "__main__":
    unittest.main()
