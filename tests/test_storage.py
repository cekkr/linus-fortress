import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "nested", "store.json")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_save_creates_parent_and_owner_only_file(self) -> None:
        storage.save_json(self.path, {"a": 1})
        self.assertEqual(storage.load_json(self.path, {}), {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_save_preserves_existing_mode(self) -> None:
        storage.save_json(self.path, {"a": 1})
        os.chmod(self.path, 0o640)
        storage.save_json(self.path, {"a": 2})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o640)

    def test_failed_write_keeps_previous_content_and_no_temp_files(self) -> None:
        storage.save_json(self.path, {"keep": True})
        with mock.patch.object(storage.json, "dump", side_effect=RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                storage.save_json(self.path, {"keep": False})
        with open(self.path) as fh:
            self.assertEqual(json.load(fh), {"keep": True})
        leftovers = [name for name in os.listdir(os.path.dirname(self.path)) if name.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_unserializable_payload_does_not_truncate_store(self) -> None:
        storage.save_json(self.path, {"keep": True})
        with self.assertRaises(TypeError):
            storage.save_json(self.path, {"bad": object()})
        self.assertEqual(storage.load_json(self.path, {}), {"keep": True})

    def test_update_json_concurrent_increments_are_not_lost(self) -> None:
        def bump(data):
            data["count"] = data.get("count", 0) + 1

        threads = [threading.Thread(target=lambda: [storage.update_json(self.path, {}, bump) for _ in range(25)]) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(storage.load_json(self.path, {}), {"count": 200})

    def test_update_json_does_not_mutate_default(self) -> None:
        default = {"items": []}
        storage.update_json(self.path, default, lambda data: data["items"].append(1))
        self.assertEqual(default, {"items": []})
        self.assertEqual(storage.load_json(self.path, {}), {"items": [1]})

    def test_load_json_dict_resets_non_dict(self) -> None:
        storage.save_json(self.path, [1, 2])
        self.assertEqual(storage.load_json_dict(self.path, label="test"), {})


if __name__ == "__main__":
    unittest.main()
