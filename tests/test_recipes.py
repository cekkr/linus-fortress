import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.recipes import (
    RECIPE_BUNDLE_FORMAT,
    build_recipe_execution,
    build_recipe_export_bundle,
    bump_semver,
    collect_lamp_health_targets,
    create_recipe_record,
    extract_recipe_bundle,
    prepare_import_recipe_record,
    resolve_recipe_plan,
    update_recipe_record,
    validate_recipe_name,
    verify_recipe_bundle,
)


class RecipeValidationTests(unittest.TestCase):
    def test_validate_recipe_name_accepts(self) -> None:
        for name in ["base", "web-01", "a_b.c", "Z9"]:
            validate_recipe_name(name)

    def test_validate_recipe_name_rejects(self) -> None:
        invalid = ["", "bad name", "@foo", "a" * 65]
        for name in invalid:
            with self.assertRaises(ValueError):
                validate_recipe_name(name)


class RecipeResolutionTests(unittest.TestCase):
    def test_resolve_recipe_plan_orders_dependencies(self) -> None:
        recipes = {
            "base": {"dependencies": []},
            "db": {"dependencies": ["base"]},
            "app": {"dependencies": ["base", "db"]},
        }
        plan = resolve_recipe_plan("app", recipes, include_dependencies=True)
        self.assertEqual(plan, ["base", "db", "app"])

    def test_resolve_recipe_plan_detects_cycle(self) -> None:
        recipes = {
            "alpha": {"dependencies": ["beta"]},
            "beta": {"dependencies": ["alpha"]},
        }
        with self.assertRaises(ValueError):
            resolve_recipe_plan("alpha", recipes, include_dependencies=True)

    def test_resolve_recipe_plan_missing_dependency(self) -> None:
        recipes = {"alpha": {"dependencies": ["missing"]}}
        with self.assertRaises(ValueError):
            resolve_recipe_plan("alpha", recipes, include_dependencies=True)


class RecipeExecutionTests(unittest.TestCase):
    def test_build_recipe_execution_renders_and_orders(self) -> None:
        recipes = {
            "base": {
                "dependencies": [],
                "packages": ["{{lang}}3", "pip"],
                "commands": ["echo {{lang}}"],
                "parameters": {"lang": "python"},
                "required_parameters": [],
            },
            "app": {
                "dependencies": ["base"],
                "packages": [],
                "commands": ["useradd -m {{user}}"],
                "parameters": {"user": "deploy"},
                "required_parameters": ["user"],
            },
        }
        plan, steps = build_recipe_execution("app", recipes, include_dependencies=True, overrides={"user": "alice"})
        self.assertEqual(plan, ["base", "app"])
        self.assertEqual(steps[0]["packages"], ["python3", "pip"])
        self.assertEqual(steps[0]["commands"], ["echo python"])
        self.assertEqual(steps[1]["commands"], ["useradd -m alice"])

    def test_build_recipe_execution_requires_parameters(self) -> None:
        recipes = {
            "app": {
                "dependencies": [],
                "packages": [],
                "commands": ["echo {{user}}"],
                "parameters": {},
                "required_parameters": ["user"],
            }
        }
        with self.assertRaises(ValueError):
            build_recipe_execution("app", recipes, include_dependencies=True, overrides={})

    def test_build_recipe_execution_missing_template_param(self) -> None:
        recipes = {
            "app": {
                "dependencies": [],
                "packages": [],
                "commands": ["echo {{missing}}"],
                "parameters": {},
                "required_parameters": [],
            }
        }
        with self.assertRaises(ValueError):
            build_recipe_execution("app", recipes, include_dependencies=True, overrides={})


class RecipeHealthTargetTests(unittest.TestCase):
    def test_collect_lamp_health_targets_returns_expected_checks(self) -> None:
        targets = collect_lamp_health_targets(["lamp-apache", "lamp-mysql"])
        self.assertTrue(targets["detected"])
        self.assertEqual(targets["recipes"], ["lamp-apache", "lamp-mysql"])
        self.assertEqual(targets["service_keys"], ["apache", "mysql"])
        self.assertEqual(targets["ports"], [80, 3306])
        check_ids = [item["id"] for item in targets["config_checks"]]
        self.assertIn("apache-config", check_ids)
        self.assertIn("php-runtime", check_ids)
        self.assertIn("mysql-config", check_ids)

    def test_collect_lamp_health_targets_expands_lamp_stack(self) -> None:
        targets = collect_lamp_health_targets(["lamp-stack"])
        self.assertTrue(targets["detected"])
        self.assertEqual(
            targets["recipes"],
            ["lamp-apache", "lamp-mysql", "lamp-ftp", "lamp-filemanager"],
        )
        self.assertIn("filemanager", targets["service_keys"])
        check_ids = [item["id"] for item in targets["config_checks"]]
        self.assertIn("filemanager-php-lint", check_ids)

    def test_collect_lamp_health_targets_non_lamp_recipe(self) -> None:
        targets = collect_lamp_health_targets(["base-python"])
        self.assertFalse(targets["detected"])
        self.assertEqual(targets["service_keys"], [])
        self.assertEqual(targets["config_checks"], [])


class RecipeLifecycleTests(unittest.TestCase):
    def test_bump_semver_variants(self) -> None:
        self.assertEqual(bump_semver("1.2.3", "patch"), "1.2.4")
        self.assertEqual(bump_semver("1.2.3", "minor"), "1.3.0")
        self.assertEqual(bump_semver("1.2.3", "major"), "2.0.0")
        self.assertEqual(bump_semver("1.2.3", "none"), "1.2.3")
        with self.assertRaises(ValueError):
            bump_semver("1.2.3", "invalid")

    def test_create_recipe_record_initializes_metadata(self) -> None:
        record = create_recipe_record(
            {
                "name": "app-bootstrap",
                "dependencies": ["base"],
                "commands": ["echo ok"],
            }
        )
        self.assertEqual(record["name"], "app-bootstrap")
        self.assertEqual(record["version"], "1.0.0")
        self.assertTrue(record["created_at"])
        self.assertTrue(record["updated_at"])
        self.assertEqual(len(record["history"]), 1)
        self.assertEqual(record["history"][0]["action"], "create")
        self.assertEqual(record["history"][0]["to_version"], "1.0.0")

    def test_update_recipe_record_bumps_version_and_tracks_fields(self) -> None:
        base = create_recipe_record({"name": "base", "packages": ["python3"]})
        updated, changed_fields = update_recipe_record(
            "base",
            base,
            {"packages": ["python3", "curl"]},
            version_bump="minor",
            note="Add curl utility",
        )
        self.assertEqual(changed_fields, ["packages"])
        self.assertEqual(updated["version"], "1.1.0")
        self.assertEqual(len(updated["history"]), 2)
        last = updated["history"][-1]
        self.assertEqual(last["from_version"], "1.0.0")
        self.assertEqual(last["to_version"], "1.1.0")
        self.assertEqual(last["changed_fields"], ["packages"])
        self.assertEqual(last["note"], "Add curl utility")

    def test_build_recipe_export_bundle_subset_without_history(self) -> None:
        recipes = {
            "base": create_recipe_record({"name": "base", "packages": ["python3"]}),
            "app": create_recipe_record({"name": "app", "dependencies": ["base"]}),
        }
        bundle = build_recipe_export_bundle(recipes, names=["base"], include_history=False)
        self.assertEqual(bundle["format"], RECIPE_BUNDLE_FORMAT)
        self.assertEqual(bundle["count"], 1)
        self.assertEqual(bundle["recipes"][0]["name"], "base")
        self.assertEqual(bundle["recipes"][0]["history"], [])
        self.assertTrue(bundle["checksum"])

    def test_verify_recipe_bundle_checksum_detects_tampering(self) -> None:
        recipes = {"base": create_recipe_record({"name": "base", "packages": ["python3"]})}
        bundle = build_recipe_export_bundle(recipes, include_history=True)
        verify = verify_recipe_bundle(bundle, require_signature=False)
        self.assertFalse(verify["signed"])
        bundle["recipes"][0]["packages"].append("curl")
        with self.assertRaises(ValueError):
            verify_recipe_bundle(bundle, require_signature=False)

    def test_verify_recipe_bundle_signature(self) -> None:
        recipes = {"base": create_recipe_record({"name": "base", "packages": ["python3"]})}
        bundle = build_recipe_export_bundle(recipes, signing_key="bundle-secret")
        verify = verify_recipe_bundle(bundle, signing_key="bundle-secret", require_signature=True)
        self.assertTrue(verify["signed"])
        with self.assertRaises(ValueError):
            verify_recipe_bundle(bundle, signing_key="wrong-key", require_signature=True)

    def test_extract_recipe_bundle_and_import_record(self) -> None:
        bundle = {
            "format": RECIPE_BUNDLE_FORMAT,
            "recipes": [
                {
                    "name": "app",
                    "dependencies": ["base"],
                    "commands": ["echo app"],
                    "version": "2.3.4",
                }
            ],
        }
        extracted = extract_recipe_bundle(bundle)
        self.assertIn("app", extracted)
        imported = prepare_import_recipe_record("app", extracted["app"], preserve_history=False)
        self.assertEqual(imported["version"], "2.3.4")
        self.assertEqual(len(imported["history"]), 1)
        self.assertEqual(imported["history"][0]["action"], "import")

    def test_prepare_import_recipe_record_overwrite_keeps_created_at(self) -> None:
        existing = create_recipe_record({"name": "app", "commands": ["echo old"]})
        incoming = {"name": "app", "commands": ["echo new"], "version": "1.5.0"}
        merged = prepare_import_recipe_record("app", incoming, existing=existing, preserve_history=True)
        self.assertEqual(merged["created_at"], existing["created_at"])
        self.assertEqual(merged["version"], "1.5.0")
        self.assertEqual(merged["history"][-1]["action"], "import_overwrite")


if __name__ == "__main__":
    unittest.main()
