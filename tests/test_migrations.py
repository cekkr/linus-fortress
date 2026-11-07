import json
import os
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress.migrations import MigrationEngine, load_ledger_entries, migrate_record, migrate_store_payload


class MigrationRecordTests(unittest.TestCase):
    def test_migrate_record_applies_defaults_and_aliases(self) -> None:
        schema = {
            "fields": ["name", "role"],
            "defaults": {"role": "user"},
            "aliases": {"username": "name"},
            "prune_unknown": False,
        }
        record = {"username": "alice", "extra": "legacy"}
        migrated, actions = migrate_record(record, schema)
        self.assertEqual(migrated["name"], "alice")
        self.assertEqual(migrated["role"], "user")
        self.assertIn("_legacy", migrated)
        self.assertEqual(migrated["_legacy"]["extra"], "legacy")
        self.assertTrue(actions)

    def test_migrate_store_payload_mapping(self) -> None:
        schema = {
            "fields": ["name"],
            "defaults": {},
            "aliases": {},
            "prune_unknown": True,
            "record_type": "mapping",
        }
        payload = {"alpha": {"name": "alpha", "extra": "drop"}}
        migrated, actions, changed = migrate_store_payload(payload, schema)
        self.assertEqual(changed, 1)
        self.assertEqual(migrated["alpha"], {"name": "alpha"})

    def test_migrate_store_payload_list(self) -> None:
        schema = {
            "fields": ["name", "status"],
            "defaults": {"status": "ok"},
            "aliases": {},
            "prune_unknown": False,
            "record_type": "list",
        }
        payload = [{"name": "alpha"}]
        migrated, actions, changed = migrate_store_payload(payload, schema)
        self.assertEqual(changed, 1)
        self.assertEqual(migrated[0]["status"], "ok")

    def test_migrate_store_payload_object(self) -> None:
        schema = {
            "fields": ["popular"],
            "defaults": {"popular": []},
            "aliases": {"images": "popular"},
            "prune_unknown": False,
            "record_type": "object",
        }
        payload = {"images": [{"name": "ubuntu:lts"}], "note": "legacy"}
        migrated, actions, changed = migrate_store_payload(payload, schema)
        self.assertEqual(changed, 1)
        self.assertEqual(migrated["popular"], [{"name": "ubuntu:lts"}])
        self.assertEqual(migrated["_legacy"]["note"], "legacy")
        self.assertTrue(actions)


class MigrationEngineTests(unittest.TestCase):
    def test_apply_updates_versions_even_when_no_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_dir = os.path.join(tmpdir, "schemas")
            migrations_dir = os.path.join(tmpdir, "migrations")
            os.makedirs(schema_dir, exist_ok=True)
            store_path = os.path.join(tmpdir, "store.json")
            with open(store_path, "w") as fh:
                json.dump({"alpha": {"name": "alpha"}}, fh)
            schema = {
                "store": "sample",
                "schema_version": "1",
                "record_type": "mapping",
                "fields": ["name"],
                "defaults": {},
                "aliases": {},
                "prune_unknown": False,
            }
            with open(os.path.join(schema_dir, "sample.json"), "w") as fh:
                json.dump(schema, fh)
            engine = MigrationEngine(schema_dir, migrations_dir, {"sample": store_path})
            result = engine.apply()
            self.assertIn("sample", result["applied"])
            versions_path = os.path.join(migrations_dir, "versions.json")
            with open(versions_path, "r") as fh:
                versions = json.load(fh)
            self.assertEqual(versions.get("sample"), "1")
            entries = load_ledger_entries(migrations_dir)
            self.assertTrue(entries)
            self.assertEqual(entries[-1]["store"], "sample")

    def test_rollback_restores_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_dir = os.path.join(tmpdir, "schemas")
            migrations_dir = os.path.join(tmpdir, "migrations")
            os.makedirs(schema_dir, exist_ok=True)
            store_path = os.path.join(tmpdir, "store.json")
            original = {"alpha": {"name": "alpha", "extra": "keep"}}
            with open(store_path, "w") as fh:
                json.dump(original, fh)
            schema = {
                "store": "sample",
                "schema_version": "2",
                "record_type": "mapping",
                "fields": ["name"],
                "defaults": {},
                "aliases": {},
                "prune_unknown": True,
            }
            with open(os.path.join(schema_dir, "sample.json"), "w") as fh:
                json.dump(schema, fh)
            engine = MigrationEngine(schema_dir, migrations_dir, {"sample": store_path})
            result = engine.apply()
            with open(store_path, "r") as fh:
                migrated = json.load(fh)
            self.assertNotIn("extra", migrated["alpha"])
            engine.rollback(result["patch_id"])
            with open(store_path, "r") as fh:
                restored = json.load(fh)
            self.assertEqual(restored, original)

    def test_apply_object_store_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_dir = os.path.join(tmpdir, "schemas")
            migrations_dir = os.path.join(tmpdir, "migrations")
            os.makedirs(schema_dir, exist_ok=True)
            store_path = os.path.join(tmpdir, "container_images.json")
            with open(store_path, "w") as fh:
                json.dump({}, fh)
            schema = {
                "store": "container_images",
                "schema_version": "1",
                "record_type": "object",
                "fields": ["popular"],
                "defaults": {"popular": []},
                "aliases": {},
                "prune_unknown": False,
            }
            with open(os.path.join(schema_dir, "container_images.json"), "w") as fh:
                json.dump(schema, fh)
            engine = MigrationEngine(schema_dir, migrations_dir, {"container_images": store_path})
            result = engine.apply()
            self.assertIn("container_images", result["applied"])
            with open(store_path, "r") as fh:
                migrated = json.load(fh)
            self.assertEqual(migrated.get("popular"), [])


if __name__ == "__main__":
    unittest.main()


class SchemaFieldCoverageTests(unittest.TestCase):
    """Every field the code writes must be listed in ``schemas/<store>.json``.

    Otherwise ``migrate_record`` parks it under ``_legacy`` on the next apply (e.g. revoking terminal policies or
    wiping recipe history from the live record).
    """

    SCHEMA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "schemas"))
    PY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py"))

    def setUp(self) -> None:
        from fortress.migrations import load_schema_registry

        self.registry = load_schema_registry(self.SCHEMA_DIR)

    def _assert_no_legacy(self, store: str, record: dict) -> None:
        migrated, actions = migrate_record(record, self.registry[store])
        self.assertNotIn("_legacy", migrated, f"{store}: unknown fields {sorted(set(record) - set(migrated))}")
        self.assertFalse([a for a in actions if a.startswith(("legacy", "prune"))], actions)

    def test_api_user_record_fields_are_known(self) -> None:
        record = {
            "username": "ops",
            "permissions": ["terminal_host"],
            "allowed_containers": None,
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2027-01-01T00:00:00Z",
            "terminal_host": {"os_user": "ops"},
            "terminal_container": {"os_user": "root"},
        }
        self._assert_no_legacy("api_users", record)

    def test_recipe_record_fields_are_known(self) -> None:
        from fortress.recipes import create_recipe_record

        self._assert_no_legacy("recipes", create_recipe_record({"name": "demo", "packages": ["curl"]}))

    def test_site_record_fields_are_known(self) -> None:
        from fortress.sites import SiteCreateRequest, create_site_record

        record = create_site_record(
            SiteCreateRequest(name="s1", primary_domain="a.example.com", container_name="c1", docroot="/var/www"),
            {},
        )
        self._assert_no_legacy("sites", record)

    def test_vm_and_host_assigned_fields_are_known(self) -> None:
        import re

        pattern = re.compile(r'\b(?:vm|record|host)\["([a-z_]+)"\]\s*=(?!=)')
        for store, module in (("vms", "vms.py"), ("hosts", "hosts.py")):
            with open(os.path.join(self.PY_DIR, "fortress", module)) as fh:
                assigned = set(pattern.findall(fh.read()))
            known = set(self.registry[store]["fields"])
            with self.subTest(store=store):
                self.assertEqual(sorted(assigned - known), [])

    def test_known_fields_are_promoted_out_of_legacy(self) -> None:
        schema = {"fields": ["name", "history", "version"], "defaults": {"history": []}, "prune_unknown": False}
        record = {"name": "demo", "_legacy": {"history": [{"v": "1.0.0"}], "version": "1.0.0", "extra": 1}}
        migrated, actions = migrate_record(record, schema)
        self.assertEqual(migrated["history"], [{"v": "1.0.0"}])
        self.assertEqual(migrated["version"], "1.0.0")
        self.assertEqual(migrated["_legacy"], {"extra": 1})
        self.assertIn("promote:2", actions)
        # A live top-level value wins over the parked copy.
        migrated, _ = migrate_record({"name": "d", "version": "2.0.0", "_legacy": {"version": "1.0.0"}}, schema)
        self.assertEqual(migrated["version"], "2.0.0")
        self.assertNotIn("_legacy", migrated)
