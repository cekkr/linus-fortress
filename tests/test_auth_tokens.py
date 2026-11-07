"""Token expiry and 401-vs-403 semantics (ROADMAP Path 4).

401 = no credential / unknown credential / expired token (re-authenticate).
403 = valid credential that lacks the permission or container scope (do not retry with the same token).
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.auth import format_expiry, is_token_expired, parse_expiry, verify_token

SERVER_PATH = Path(__file__).resolve().parents[1] / "py" / "server.py"
MASTER = "integration-master-key"
NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _users(**records):
    return lambda: records


class VerifyTokenStatusTests(unittest.TestCase):
    def _verify(self, api_key=None, user_token=None, permission=None, users=None, now=NOW):
        return verify_token(
            api_key,
            user_token,
            required_permission=permission,
            master_key=MASTER,
            load_users=users or _users(),
            now=lambda: now,
        )

    def _status(self, **kwargs):
        with self.assertRaises(HTTPException) as ctx:
            self._verify(**kwargs)
        return ctx.exception

    def test_missing_credentials_is_401_with_challenge(self):
        exc = self._status()
        self.assertEqual(exc.status_code, 401)
        self.assertIn("WWW-Authenticate", exc.headers)

    def test_wrong_master_key_is_401(self):
        self.assertEqual(self._status(api_key="not-the-key").status_code, 401)

    def test_unknown_user_token_is_401(self):
        self.assertEqual(self._status(user_token="nope").status_code, 401)

    def test_expired_token_is_401(self):
        users = _users(tok={"username": "a", "permissions": ["*"], "expires_at": "2026-06-01T11:59:59Z"})
        exc = self._status(user_token="tok", users=users)
        self.assertEqual(exc.status_code, 401)
        self.assertEqual(exc.detail, "API token expired")

    def test_expiry_boundary_is_exclusive(self):
        users = _users(tok={"username": "a", "permissions": ["*"], "expires_at": "2026-06-01T12:00:00Z"})
        self.assertEqual(self._status(user_token="tok", users=users).status_code, 401)

    def test_corrupt_expiry_fails_closed(self):
        users = _users(tok={"username": "a", "permissions": ["*"], "expires_at": "tomorrow-ish"})
        self.assertEqual(self._status(user_token="tok", users=users).status_code, 401)

    def test_future_or_missing_expiry_is_accepted(self):
        users = _users(
            fut={"username": "f", "permissions": ["x"], "expires_at": "2026-06-02T00:00:00+00:00"},
            never={"username": "n", "permissions": ["x"], "expires_at": None},
            legacy={"username": "l", "permissions": ["x"]},
        )
        for token in ("fut", "never", "legacy"):
            self.assertEqual(self._verify(user_token=token, permission="x", users=users)["permissions"], ["x"])

    def test_valid_token_without_permission_is_403(self):
        users = _users(tok={"username": "a", "permissions": ["read_status"]})
        self.assertEqual(self._status(user_token="tok", permission="manage_routing", users=users).status_code, 403)

    def test_expired_token_is_401_even_when_permission_also_missing(self):
        users = _users(tok={"username": "a", "permissions": [], "expires_at": "2020-01-01T00:00:00Z"})
        self.assertEqual(self._status(user_token="tok", permission="manage_routing", users=users).status_code, 401)

    def test_master_key_still_wins(self):
        self.assertTrue(self._verify(api_key=MASTER, user_token="whatever")["is_master"])
        self.assertTrue(self._verify(api_key=f"api-key:{MASTER}")["is_master"])

    def test_expiry_helpers(self):
        self.assertIsNone(parse_expiry(None))
        self.assertEqual(parse_expiry("2026-06-01T12:00:00"), NOW)  # naive -> UTC
        self.assertEqual(parse_expiry("2026-06-01T14:00:00+02:00"), NOW)
        self.assertEqual(format_expiry(NOW), "2026-06-01T12:00:00Z")
        self.assertFalse(is_token_expired({}, NOW))
        self.assertTrue(is_token_expired({"expires_at": 12345}, NOW))


def load_server_module(temp_dir: str):
    module_name = f"fortress_server_auth_tokens_{os.getpid()}_{Path(temp_dir).name}"
    spec = importlib.util.spec_from_file_location(module_name, str(SERVER_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class TokenLifecycleRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        saved = {k: os.environ.get(k) for k in ("FORTRESS_LOG_PATH", "FORTRESS_COMMAND_LOG_DB", "FORTRESS_API_KEY")}

        def _restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

        self.addCleanup(_restore)
        os.environ["FORTRESS_LOG_PATH"] = os.path.join(self.tmpdir.name, "fortress.log")
        os.environ["FORTRESS_COMMAND_LOG_DB"] = os.path.join(self.tmpdir.name, "command_log.db")
        os.environ["FORTRESS_API_KEY"] = MASTER
        self.module, module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(lambda: sys.modules.pop(module_name, None))
        for attr, name in (
            ("API_USERS_DB", "api_users.json"),
            ("ROUTING_DB", "routes.json"),
            ("RECIPES_DB", "recipes.json"),
            ("SITES_DB", "sites.json"),
            ("RECIPE_HEALTH_HISTORY_DB", "recipe_health_history.json"),
        ):
            setattr(self.module, attr, os.path.join(self.tmpdir.name, name))
        with open(self.module.API_USERS_DB, "w") as fh:
            json.dump(
                {
                    "tok-reader": {"username": "reader", "permissions": ["read_status"]},
                    "tok-expired": {
                        "username": "old",
                        "permissions": ["*"],
                        "expires_at": "2020-01-01T00:00:00Z",
                    },
                },
                fh,
            )
        self.client = TestClient(self.module.app)
        self.master = {"X-API-Key": MASTER}

    def _users_store(self):
        with open(self.module.API_USERS_DB) as fh:
            return json.load(fh)

    def test_create_with_ttl_sets_expiry(self):
        before = datetime.now(timezone.utc)
        resp = self.client.post("/api-users", json={"username": "ci", "permissions": ["read_status"], "ttl_seconds": 3600}, headers=self.master)
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        expires = parse_expiry(body["user"]["expires_at"])
        self.assertGreaterEqual(expires, before + timedelta(seconds=3599))
        self.assertLessEqual(expires, before + timedelta(seconds=3602))
        self.assertIsNotNone(body["user"]["created_at"])
        self.assertEqual(self._users_store()[body["token"]]["expires_at"], body["user"]["expires_at"])
        # The new token authenticates (403 = authenticated but lacks api_user_admin, not 401).
        self.assertEqual(self.client.get("/api-users", headers={"X-User-Token": body["token"]}).status_code, 403)

    def test_create_rejects_past_expiry_and_conflicting_fields(self):
        past = self.client.post("/api-users", json={"username": "x", "expires_at": "2020-01-01T00:00:00Z"}, headers=self.master)
        self.assertEqual(past.status_code, 400)
        both = self.client.post(
            "/api-users",
            json={"username": "x", "expires_at": "2099-01-01T00:00:00Z", "ttl_seconds": 60},
            headers=self.master,
        )
        self.assertEqual(both.status_code, 400)
        bad_ttl = self.client.post("/api-users", json={"username": "x", "ttl_seconds": 0}, headers=self.master)
        self.assertEqual(bad_ttl.status_code, 422)
        self.assertEqual(set(self._users_store()), {"tok-reader", "tok-expired"})

    def test_create_without_expiry_never_expires(self):
        resp = self.client.post("/api-users", json={"username": "svc"}, headers=self.master)
        self.assertIsNone(resp.json()["user"]["expires_at"])

    def test_list_flags_expired_tokens(self):
        users = {u["username"]: u for u in self.client.get("/api-users", headers=self.master).json()["users"]}
        self.assertTrue(users["old"]["expired"])
        self.assertFalse(users["reader"]["expired"])

    def test_update_extends_and_clears_expiry(self):
        resp = self.client.put("/api-users/tok-expired", json={"ttl_seconds": 600}, headers=self.master)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(is_token_expired(self._users_store()["tok-expired"]))
        self.assertNotEqual(self.client.get("/api-users", headers={"X-User-Token": "tok-expired"}).status_code, 401)

        resp = self.client.put("/api-users/tok-expired", json={"expires_at": None}, headers=self.master)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(self._users_store()["tok-expired"]["expires_at"])

        # Unrelated updates leave expiry untouched.
        self.client.put("/api-users/tok-reader", json={"ttl_seconds": 60}, headers=self.master)
        expiry = self._users_store()["tok-reader"]["expires_at"]
        self.client.put("/api-users/tok-reader", json={"permissions": ["read_status", "monitoring"]}, headers=self.master)
        self.assertEqual(self._users_store()["tok-reader"]["expires_at"], expiry)

    def test_update_and_delete_unknown_token_is_404(self):
        self.assertEqual(self.client.put("/api-users/missing", json={"permissions": []}, headers=self.master).status_code, 404)
        self.assertEqual(self.client.delete("/api-users/missing", headers=self.master).status_code, 404)

    def test_status_matrix_401_vs_403(self):
        cases = [
            ("get", "/api-users", None),
            ("get", "/routing", None),
            ("get", "/recipes", None),
            ("get", "/sites", None),
            ("get", "/migrations/status", None),
            ("post", "/firewall/open", {"port": 8080, "protocol": "tcp"}),
            ("post", "/routing/add", {"domain": "a.example.com", "container_name": "web01", "container_port": 80}),
            ("post", "/api-users", {"username": "x"}),
        ]
        for method, path, body in cases:
            call = getattr(self.client, method)
            kwargs = {"json": body} if body is not None else {}
            with self.subTest(path=path, auth="none"):
                self.assertEqual(call(path, **kwargs).status_code, 401)
            with self.subTest(path=path, auth="bogus"):
                self.assertEqual(call(path, headers={"X-User-Token": "bogus"}, **kwargs).status_code, 401)
            with self.subTest(path=path, auth="bad-master"):
                self.assertEqual(call(path, headers={"X-API-Key": "wrong"}, **kwargs).status_code, 401)
            with self.subTest(path=path, auth="expired"):
                resp = call(path, headers={"X-User-Token": "tok-expired"}, **kwargs)
                self.assertEqual(resp.status_code, 401)
                self.assertIn("WWW-Authenticate", resp.headers)
            with self.subTest(path=path, auth="insufficient"):
                self.assertEqual(call(path, headers={"X-User-Token": "tok-reader"}, **kwargs).status_code, 403)

    def test_concurrent_creates_do_not_lose_tokens(self):
        errors = []

        def _create(i):
            try:
                resp = self.client.post("/api-users", json={"username": f"u{i}"}, headers=self.master)
                if resp.status_code != 200:
                    errors.append(resp.text)
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(repr(exc))

        threads = [threading.Thread(target=_create, args=(i,)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        names = {record["username"] for record in self._users_store().values()}
        self.assertTrue({f"u{i}" for i in range(16)} <= names)


if __name__ == "__main__":
    unittest.main()
