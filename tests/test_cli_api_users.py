import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

CLI_PATH = Path(__file__).resolve().parents[1] / "fortress-cli.py"


def load_cli_module():
    module_name = f"fortress_cli_api_users_test_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(module_name, str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class CliApiUserExpiryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module, self.module_name = load_cli_module()
        self.parser = self.module.build_parser()
        self.addCleanup(sys.modules.pop, self.module_name, None)

    def _run(self, argv):
        args = self.parser.parse_args(argv)
        client = mock.Mock()
        client.request.return_value = {}
        with mock.patch.object(self.module, "load_config", return_value={"server_url": "https://f.local:8443"}), \
                mock.patch.object(self.module, "FortressClient", return_value=client), \
                mock.patch("builtins.print"):
            args.func(args)
        return client.request.call_args

    def test_parse_duration(self) -> None:
        parse = self.module.parse_duration_seconds
        self.assertEqual(parse("3600"), 3600)
        self.assertEqual(parse("90m"), 5400)
        self.assertEqual(parse("12h"), 43200)
        self.assertEqual(parse("30D"), 2592000)
        self.assertEqual(parse("2w"), 1209600)
        for bad in ("", "0", "-5m", "1.5h", "abc", "10y"):
            with self.subTest(bad=bad), self.assertRaises(self.module.FortressCLIError):
                parse(bad)

    def test_create_with_ttl(self) -> None:
        call = self._run(["api-users", "create", "ci", "--permissions", "read_status", "--ttl", "12h"])
        self.assertEqual(call.args, ("POST", "/api-users"))
        self.assertEqual(call.kwargs["json_body"]["ttl_seconds"], 43200)
        self.assertNotIn("expires_at", call.kwargs["json_body"])

    def test_create_without_expiry_sends_no_expiry_fields(self) -> None:
        body = self._run(["api-users", "create", "svc", "--permissions", "read_status"]).kwargs["json_body"]
        self.assertNotIn("ttl_seconds", body)
        self.assertNotIn("expires_at", body)

    def test_expire_variants(self) -> None:
        call = self._run(["api-users", "expire", "tok", "--expires-at", "2027-01-01T00:00:00Z"])
        self.assertEqual(call.args, ("PUT", "/api-users/tok"))
        self.assertEqual(call.kwargs["json_body"], {"expires_at": "2027-01-01T00:00:00Z"})
        self.assertEqual(self._run(["api-users", "expire", "tok", "--never"]).kwargs["json_body"], {"expires_at": None})
        self.assertEqual(self._run(["api-users", "expire", "tok", "--ttl", "1d"]).kwargs["json_body"], {"ttl_seconds": 86400})

    def test_expire_requires_exactly_one_option(self) -> None:
        with self.assertRaises(self.module.FortressCLIError):
            self._run(["api-users", "expire", "tok"])
        with self.assertRaises(self.module.FortressCLIError):
            self._run(["api-users", "expire", "tok", "--ttl", "1h", "--never"])


if __name__ == "__main__":
    unittest.main()
