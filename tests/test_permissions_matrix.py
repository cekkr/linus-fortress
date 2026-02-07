import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.recipes import build_recipe_export_bundle


SERVER_PATH = Path(__file__).resolve().parents[1] / "py" / "server.py"


def load_server_module(temp_dir: str):
    module_name = f"fortress_server_test_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(module_name, str(SERVER_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class PermissionMatrixIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self._original_env = {
            "FORTRESS_LOG_PATH": os.environ.get("FORTRESS_LOG_PATH"),
            "FORTRESS_COMMAND_LOG_DB": os.environ.get("FORTRESS_COMMAND_LOG_DB"),
            "FORTRESS_RECIPE_BUNDLE_SIGNING_KEY": os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEY"),
            "FORTRESS_API_KEY": os.environ.get("FORTRESS_API_KEY"),
        }
        os.environ["FORTRESS_LOG_PATH"] = os.path.join(self.tmpdir.name, "fortress.log")
        os.environ["FORTRESS_COMMAND_LOG_DB"] = os.path.join(self.tmpdir.name, "command_log.db")
        os.environ["FORTRESS_RECIPE_BUNDLE_SIGNING_KEY"] = "integration-signing-key"
        os.environ["FORTRESS_API_KEY"] = "integration-master-key"
        self.module, self.module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(self._cleanup_module)
        self.addCleanup(self._restore_env)

        self.module.API_USERS_DB = os.path.join(self.tmpdir.name, "api_users.json")
        self.module.RECIPES_DB = os.path.join(self.tmpdir.name, "recipes.json")
        with open(self.module.RECIPES_DB, "w") as fh:
            json.dump(
                {
                    "base": {
                        "name": "base",
                        "dependencies": [],
                        "packages": ["curl"],
                        "commands": [],
                        "parameters": {},
                        "required_parameters": [],
                    }
                },
                fh,
            )
        with open(self.module.API_USERS_DB, "w") as fh:
            json.dump({}, fh)

    def _cleanup_module(self) -> None:
        sys.modules.pop(self.module_name, None)

    def _restore_env(self) -> None:
        for key, value in self._original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_users(self, users: dict) -> None:
        with open(self.module.API_USERS_DB, "w") as fh:
            json.dump(users, fh)

    def _expect_denied(self, fn) -> None:
        with self.assertRaises(HTTPException) as exc:
            fn()
        self.assertEqual(exc.exception.status_code, 403)

    def test_permission_matrix_recipes_endpoints(self) -> None:
        self._write_users(
            {
                "token-manage": {"username": "manage", "permissions": ["recipes_manage"], "allowed_containers": None},
                "token-apply": {"username": "apply", "permissions": ["recipes_apply"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        signed_bundle = build_recipe_export_bundle({}, signing_key="integration-signing-key")
        matrix = [
            (
                lambda token: self.module.list_recipes(x_api_key=None, x_user_token=token),
                "token-manage",
                "token-none",
            ),
            (
                lambda token: self.module.export_recipes(
                    self.module.RecipeExportRequest(),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-manage",
                "token-apply",
            ),
            (
                lambda token: self.module.import_recipes(
                    self.module.RecipeImportRequest(bundle=signed_bundle),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-manage",
                "token-apply",
            ),
            (
                lambda token: self.module.apply_recipe(
                    self.module.RecipeApplyRequest(recipe_name="base", dry_run=True),
                    x_api_key=None,
                    x_user_token=token,
                ),
                "token-apply",
                "token-manage",
            ),
        ]

        for call, allowed_token, denied_token in matrix:
            result = call(allowed_token)
            self.assertIsInstance(result, dict)
            self._expect_denied(lambda: call(denied_token))

    def test_permission_matrix_container_scope_for_recipe_apply(self) -> None:
        self._write_users(
            {
                "token-scoped": {
                    "username": "scoped",
                    "permissions": ["recipes_apply"],
                    "allowed_containers": ["alpha"],
                }
            }
        )

        allowed = self.module.apply_recipe(
            self.module.RecipeApplyRequest(recipe_name="base", container_name="alpha", dry_run=True),
            x_api_key=None,
            x_user_token="token-scoped",
        )
        self.assertIsInstance(allowed, dict)
        self._expect_denied(
            lambda: self.module.apply_recipe(
                self.module.RecipeApplyRequest(recipe_name="base", container_name="beta", dry_run=True),
                x_api_key=None,
                x_user_token="token-scoped",
            )
        )

    def test_permission_matrix_system_upgrade_permissions(self) -> None:
        self._write_users(
            {
                "token-migration": {"username": "migrate", "permissions": ["migration_admin"], "allowed_containers": None},
                "token-full": {
                    "username": "full",
                    "permissions": ["migration_admin", "package_manage"],
                    "allowed_containers": None,
                },
            }
        )

        preflight = self.module.SystemUpgradeRequest(dry_run=True, update_packages=False, apply_migrations=False)
        packages_only = self.module.SystemUpgradeRequest(dry_run=True, update_packages=True, apply_migrations=False)

        migration_ok = self.module.system_upgrade(preflight, x_api_key=None, x_user_token="token-migration")
        self.assertIsInstance(migration_ok, dict)
        self._expect_denied(lambda: self.module.system_upgrade(packages_only, x_api_key=None, x_user_token="token-migration"))
        with mock.patch.object(self.module, "detect_package_manager", return_value="apt"):
            full_ok = self.module.system_upgrade(packages_only, x_api_key=None, x_user_token="token-full")
        self.assertIsInstance(full_ok, dict)
        self.assertIn("packages", full_ok)


if __name__ == "__main__":
    unittest.main()
