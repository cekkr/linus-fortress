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
    module_name = f"fortress_server_test_{os.getpid()}_{Path(temp_dir).name}"
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
            "FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS": os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS"),
            "FORTRESS_API_KEY": os.environ.get("FORTRESS_API_KEY"),
        }
        os.environ["FORTRESS_LOG_PATH"] = os.path.join(self.tmpdir.name, "fortress.log")
        os.environ["FORTRESS_COMMAND_LOG_DB"] = os.path.join(self.tmpdir.name, "command_log.db")
        os.environ["FORTRESS_RECIPE_BUNDLE_SIGNING_KEY"] = "integration-signing-key"
        os.environ["FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS"] = "integration-previous-signing-key"
        os.environ["FORTRESS_API_KEY"] = "integration-master-key"
        self.module, self.module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(self._cleanup_module)
        self.addCleanup(self._restore_env)

        self.module.API_USERS_DB = os.path.join(self.tmpdir.name, "api_users.json")
        self.module.RECIPES_DB = os.path.join(self.tmpdir.name, "recipes.json")
        self.module.ROUTING_DB = os.path.join(self.tmpdir.name, "routes.json")
        self.module.SITES_DB = os.path.join(self.tmpdir.name, "sites.json")
        self.module.SITE_BACKUP_DIR = os.path.join(self.tmpdir.name, "site_backups")
        self.module.FIREWALL_ROLLBACK_DIR = os.path.join(self.tmpdir.name, "firewall_rollbacks")
        self.module.FIREWALL_DDOS_POLICY_PATH = os.path.join(self.tmpdir.name, "ddos_policy.json")

        os.makedirs(self.module.SITE_BACKUP_DIR, exist_ok=True)
        os.makedirs(self.module.FIREWALL_ROLLBACK_DIR, exist_ok=True)

        self._write_json(
            self.module.RECIPES_DB,
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
        )
        self._write_json(self.module.API_USERS_DB, {})
        self._write_json(self.module.ROUTING_DB, {})
        self._write_json(self.module.SITES_DB, {})
        self._write_json(self.module.FIREWALL_DDOS_POLICY_PATH, {"enabled": False})

    def _cleanup_module(self) -> None:
        sys.modules.pop(self.module_name, None)

    def _restore_env(self) -> None:
        for key, value in self._original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _write_json(self, path: str, payload: dict) -> None:
        with open(path, "w") as fh:
            json.dump(payload, fh)

    def _write_users(self, users: dict) -> None:
        self._write_json(self.module.API_USERS_DB, users)

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

        signed_bundle = build_recipe_export_bundle({}, signing_key="integration-previous-signing-key")
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

    def test_permission_matrix_system_update_reload_permissions(self) -> None:
        self._write_users(
            {
                "token-migration": {"username": "migrate", "permissions": ["migration_admin"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        request = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="auto")
        background_tasks = self.module.BackgroundTasks()
        with mock.patch.object(
            self.module,
            "_run_system_update_reload",
            return_value={"updated": False, "reload": {"scheduled": False}},
        ):
            allowed = self.module.system_update_reload(
                request,
                background_tasks,
                x_api_key=None,
                x_user_token="token-migration",
            )
            self.assertIsInstance(allowed, dict)
            self._expect_denied(
                lambda: self.module.system_update_reload(
                    request,
                    background_tasks,
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_system_update_reload_skips_restart_when_no_new_commit(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="auto")
        background_tasks = self.module.BackgroundTasks()
        pull_result = mock.Mock(stdout="Already up to date.\n", stderr="")
        with (
            mock.patch.object(self.module, "_git_has_uncommitted_changes", return_value=False),
            mock.patch.object(self.module, "_git_head_commit", side_effect=["abc123", "abc123"]),
            mock.patch.object(self.module, "_run_local_checked", return_value=pull_result),
        ):
            response = self.module._run_system_update_reload(payload, background_tasks)
        self.assertFalse(response["updated"])
        self.assertEqual(response["migrations"].get("reason"), "no_updates")
        self.assertFalse(response["reload"].get("scheduled"))
        self.assertEqual(len(background_tasks.tasks), 0)

    def test_system_update_reload_applies_migrations_and_schedules_restart(self) -> None:
        payload = self.module.SystemUpdateReloadRequest(apply_migrations=True, restart_mode="screen")
        background_tasks = self.module.BackgroundTasks()
        pull_result = mock.Mock(stdout="Updating abc..def\n", stderr="")
        migration_result = {"message": "Migration apply complete", "patch_id": "patch-1", "applied": ["recipes"], "backups": []}
        with (
            mock.patch.object(self.module, "_git_has_uncommitted_changes", return_value=False),
            mock.patch.object(self.module, "_git_head_commit", side_effect=["abc123", "def456"]),
            mock.patch.object(self.module, "_run_local_checked", return_value=pull_result),
            mock.patch.object(self.module, "MIGRATION_ENGINE") as migration_engine,
            mock.patch.object(self.module.os.path, "isfile", return_value=True),
        ):
            migration_engine.status.return_value = {"pending": True}
            migration_engine.apply.return_value = migration_result
            response = self.module._run_system_update_reload(payload, background_tasks)
        self.assertTrue(response["updated"])
        self.assertEqual(response["migrations"], migration_result)
        self.assertTrue(response["reload"].get("scheduled"))
        self.assertEqual(response["reload"].get("mode"), "screen")
        self.assertEqual(len(background_tasks.tasks), 1)

    def test_permission_matrix_routing_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-routing": {"username": "routing", "permissions": ["manage_routing"], "allowed_containers": None},
                "token-routing-scoped": {
                    "username": "routing-scoped",
                    "permissions": ["manage_routing"],
                    "allowed_containers": ["alpha"],
                },
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        route = self.module.DomainRoute(domain="app.example.com", container_name="alpha", container_port=8080)

        with (
            mock.patch.object(self.module, "get_container_ip", return_value="10.8.0.20"),
            mock.patch.object(self.module, "_read_nginx_config", return_value=None),
            mock.patch.object(self.module, "_apply_nginx_config"),
            mock.patch.object(self.module, "write_nginx_config"),
            mock.patch.object(self.module, "ensure_nginx_site"),
            mock.patch.object(self.module, "test_nginx_config"),
            mock.patch.object(self.module, "reload_nginx"),
            mock.patch.object(self.module, "remove_nginx_site"),
        ):
            created = self.module.add_domain_routing(route, x_api_key=None, x_user_token="token-routing")
            self.assertIsInstance(created, dict)

            listed = self.module.list_domain_routing(x_api_key=None, x_user_token="token-routing-scoped")
            self.assertEqual(len(listed.get("routes", [])), 1)
            self.assertEqual(listed["routes"][0]["domain"], "app.example.com")

            refreshed = self.module.refresh_domain_routing(
                domain="app.example.com",
                x_api_key=None,
                x_user_token="token-routing-scoped",
            )
            self.assertEqual(refreshed.get("refreshed"), ["app.example.com"])

            removed = self.module.remove_domain_routing("app.example.com", x_api_key=None, x_user_token="token-routing")
            self.assertIsInstance(removed, dict)

            self._expect_denied(
                lambda: self.module.add_domain_routing(
                    self.module.DomainRoute(domain="blocked.example.com", container_name="beta", container_port=80),
                    x_api_key=None,
                    x_user_token="token-routing-scoped",
                )
            )
            self._expect_denied(
                lambda: self.module.add_domain_routing(
                    self.module.DomainRoute(domain="deny.example.com", container_name="alpha", container_port=80),
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_permission_matrix_firewall_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-firewall": {"username": "fw", "permissions": ["firewall_admin"], "allowed_containers": None},
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )
        current_rules = [
            {"port": 22, "protocol": "tcp", "source": None, "action": "allow", "direction": "in"},
            {"port": 443, "protocol": "tcp", "source": None, "action": "allow", "direction": "in"},
        ]
        apply_result = {"applied": 2, "skipped": 0, "rollback_id": "fw-test-1"}

        with (
            mock.patch.object(self.module, "apply_firewall_rule"),
            mock.patch.object(self.module, "get_firewall_status", return_value={"backend": "ufw", "active": True}),
            mock.patch.object(self.module, "list_firewall_rules", return_value=current_rules),
            mock.patch.object(self.module, "apply_firewall_rules", return_value=apply_result),
            mock.patch.object(self.module, "rollback_firewall_rules"),
            mock.patch.object(self.module, "get_ddos_policy", return_value={"enabled": False}),
            mock.patch.object(self.module, "remove_ddos_policy"),
            mock.patch.object(self.module, "apply_ddos_policy", return_value=(["rate_limit enabled"], [])),
            mock.patch.object(self.module, "update_ddos_policy"),
        ):
            status = self.module.firewall_status(x_api_key=None, x_user_token="token-firewall")
            self.assertEqual(status.get("backend"), "ufw")

            opened = self.module.open_firewall(
                self.module.FirewallRule(port=443, protocol="tcp"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            closed = self.module.close_firewall(
                self.module.FirewallRule(port=443, protocol="tcp"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertIsInstance(opened, dict)
            self.assertIsInstance(closed, dict)

            listed = self.module.firewall_rules(x_api_key=None, x_user_token="token-firewall")
            self.assertEqual(len(listed.get("rules", [])), 2)

            applied = self.module.firewall_rules_apply(
                self.module.FirewallRulesApplyRequest(
                    rules=[self.module.FirewallRuleEntry(port=80, protocol="tcp", action="allow", direction="in")]
                ),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertEqual(applied.get("rollback_id"), "fw-test-1")

            diff = self.module.firewall_rules_diff(
                self.module.FirewallRulesDiffRequest(baseline=[current_rules[0]]),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertEqual(len(diff.get("added", [])), 1)

            rollback = self.module.firewall_rollback(
                self.module.FirewallRollbackRequest(rollback_id="fw-test-1"),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertIsInstance(rollback, dict)

            ddos_status = self.module.firewall_ddos_status(x_api_key=None, x_user_token="token-firewall")
            self.assertIn("policy", ddos_status)
            ddos_update = self.module.firewall_ddos_update(
                self.module.DdosPolicyRequest(enabled=True, rate_limit_per_sec=120, dry_run=False),
                x_api_key=None,
                x_user_token="token-firewall",
            )
            self.assertTrue(ddos_update.get("policy", {}).get("enabled"))

            self._expect_denied(
                lambda: self.module.firewall_status(x_api_key=None, x_user_token="token-none")
            )
            self._expect_denied(
                lambda: self.module.open_firewall(
                    self.module.FirewallRule(port=53, protocol="udp"),
                    x_api_key=None,
                    x_user_token="token-none",
                )
            )

    def test_permission_matrix_sites_endpoint_sequence(self) -> None:
        self._write_users(
            {
                "token-sites-manage": {
                    "username": "sites-manage",
                    "permissions": ["sites_manage", "sites_read"],
                    "allowed_containers": ["alpha"],
                },
                "token-sites-read": {
                    "username": "sites-read",
                    "permissions": ["sites_read"],
                    "allowed_containers": ["alpha"],
                },
                "token-none": {"username": "none", "permissions": [], "allowed_containers": None},
            }
        )

        with (
            mock.patch.object(self.module, "_resolve_runtime_identity", return_value=("www-data", "www-data")),
            mock.patch.object(self.module, "_ensure_docroot"),
            mock.patch.object(self.module, "_apply_site_routing"),
            mock.patch.object(self.module, "_remove_nginx_route"),
            mock.patch.object(self.module, "load_routes", return_value={}),
            mock.patch.object(self.module, "save_routes"),
        ):
            created = self.module.create_site(
                self.module.SiteCreateRequest(
                    name="app",
                    primary_domain="app.example.com",
                    container_name="alpha",
                    docroot="/var/www/app",
                ),
                x_api_key=None,
                x_user_token="token-sites-manage",
            )
            self.assertEqual(created.get("site", {}).get("name"), "app")

            listed = self.module.list_sites(x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(len(listed.get("sites", [])), 1)

            fetched = self.module.get_site("app", x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(fetched.get("site", {}).get("container_name"), "alpha")

            backup_id = "app-test-backup"
            self._write_json(
                os.path.join(self.module.SITE_BACKUP_DIR, f"{backup_id}.json"),
                {
                    "backup_id": backup_id,
                    "site_id": "app",
                    "include_database": False,
                    "created_at": "2026-01-01T00:00:00Z",
                },
            )
            with open(os.path.join(self.module.SITE_BACKUP_DIR, f"{backup_id}.tar.gz"), "wb") as fh:
                fh.write(b"backup-data")

            backups = self.module.list_site_backups("app", x_api_key=None, x_user_token="token-sites-read")
            self.assertEqual(len(backups.get("backups", [])), 1)

            updated = self.module.update_site(
                "app",
                self.module.SiteUpdateRequest(docroot="/srv/www/app"),
                x_api_key=None,
                x_user_token="token-sites-manage",
            )
            self.assertEqual(updated.get("site", {}).get("docroot"), "/srv/www/app")

            deleted = self.module.delete_site("app", x_api_key=None, x_user_token="token-sites-manage")
            self.assertIsInstance(deleted, dict)

            self._expect_denied(
                lambda: self.module.create_site(
                    self.module.SiteCreateRequest(
                        name="deny",
                        primary_domain="deny.example.com",
                        container_name="alpha",
                        docroot="/var/www/deny",
                    ),
                    x_api_key=None,
                    x_user_token="token-sites-read",
                )
            )
            self._expect_denied(
                lambda: self.module.create_site(
                    self.module.SiteCreateRequest(
                        name="scope-deny",
                        primary_domain="scope.example.com",
                        container_name="beta",
                        docroot="/var/www/scope",
                    ),
                    x_api_key=None,
                    x_user_token="token-sites-manage",
                )
            )
            self._expect_denied(
                lambda: self.module.list_sites(x_api_key=None, x_user_token="token-none")
            )


if __name__ == "__main__":
    unittest.main()
