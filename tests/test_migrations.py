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
