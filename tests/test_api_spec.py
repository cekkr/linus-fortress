"""Guards api-v1.yaml against drift from the FastAPI route registry (AGENTS.md documentation-sync rule)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from test_permissions_matrix import load_server_module  # noqa: E402

SPEC_PATH = Path(__file__).resolve().parents[1] / "api-v1.yaml"
HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
# FastAPI's built-in documentation routes are not part of the contract.
IGNORED_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


class ApiSpecSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmpdir = tempfile.TemporaryDirectory()
        env = {
            "FORTRESS_LOG_PATH": os.path.join(cls.tmpdir.name, "fortress.log"),
            "FORTRESS_COMMAND_LOG_DB": os.path.join(cls.tmpdir.name, "command_log.db"),
        }
        with mock.patch.dict(os.environ, env):
            module, cls.module_name = load_server_module(cls.tmpdir.name)
        cls.app = module.app
        with open(SPEC_PATH) as fh:
            cls.spec = yaml.safe_load(fh)

    @classmethod
    def tearDownClass(cls) -> None:
        sys.modules.pop(cls.module_name, None)
        cls.tmpdir.cleanup()

    def _code_operations(self) -> set:
        # Use FastAPI's generated schema rather than walking app.routes: newer FastAPI releases wrap
        # included routers in internal objects, while app.openapi() lists every route on all versions.
        ops = set()
        for path, item in self.app.openapi().get("paths", {}).items():
            if path in IGNORED_PATHS:
                continue
            for method in item:
                if method in HTTP_METHODS:
                    ops.add((method, path))
        self.assertGreater(len(ops), 50, "route discovery looks broken")
        return ops

    def _spec_operations(self) -> set:
        ops = set()
        for path, item in (self.spec.get("paths") or {}).items():
            for method in item:
                if method in HTTP_METHODS:
                    ops.add((method, path))
        return ops

    def test_every_route_is_documented(self) -> None:
        missing = sorted(self._code_operations() - self._spec_operations())
        self.assertEqual(missing, [], "Routes missing from api-v1.yaml")

    def test_spec_has_no_stale_operations(self) -> None:
        stale = sorted(self._spec_operations() - self._code_operations())
        self.assertEqual(stale, [], "api-v1.yaml documents routes that do not exist")

    def test_all_refs_resolve(self) -> None:
        schemas = (self.spec.get("components") or {}).get("schemas") or {}
        broken = []

        def walk(node, where):
            if isinstance(node, dict):
                ref = node.get("$ref")
                if isinstance(ref, str):
                    name = ref.rsplit("/", 1)[-1]
                    if not ref.startswith("#/components/schemas/") or name not in schemas:
                        broken.append((where, ref))
                for key, value in node.items():
                    walk(value, f"{where}/{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{where}[{index}]")

        walk(self.spec, "")
        self.assertEqual(broken, [])


if __name__ == "__main__":
    unittest.main()
