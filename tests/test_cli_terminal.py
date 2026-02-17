import base64
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


CLI_PATH = Path(__file__).resolve().parents[1] / "fortress-cli.py"


def load_cli_module():
    module_name = f"fortress_cli_terminal_test_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(module_name, str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class CliTerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module, self.module_name = load_cli_module()
        self.parser = self.module.build_parser()

    def tearDown(self) -> None:
        sys.modules.pop(self.module_name, None)

    def test_terminal_open_builds_payload(self) -> None:
        args = self.parser.parse_args(
            [
                "terminal",
                "open",
                "--target",
                "container",
                "--container",
                "alpha",
                "--requested-os-user",
                "deploy",
                "--shell",
                "/bin/sh",
                "--cols",
                "132",
                "--rows",
                "41",
            ]
        )
        mock_client = mock.Mock()
        mock_client.request.return_value = {"session": {"session_id": "s-1"}}
        with (
            mock.patch.object(self.module, "load_config", return_value={"server_url": "https://fortress.local:8443"}),
            mock.patch.object(self.module, "FortressClient", return_value=mock_client),
            mock.patch("builtins.print"),
        ):
            args.func(args)

        mock_client.request.assert_called_once_with(
            "POST",
            "/terminal/sessions",
            json_body={
                "target": "container",
                "container_name": "alpha",
                "requested_os_user": "deploy",
                "shell": "/bin/sh",
                "cols": 132,
                "rows": 41,
            },
            auth_override=None,
        )

    def test_terminal_write_utf8_encodes_to_base64(self) -> None:
        args = self.parser.parse_args(["terminal", "write", "sess-1", "echo hello"])
        mock_client = mock.Mock()
        mock_client.request.return_value = {"session_id": "sess-1", "written": 10}
        with (
            mock.patch.object(self.module, "load_config", return_value={"server_url": "https://fortress.local:8443"}),
            mock.patch.object(self.module, "FortressClient", return_value=mock_client),
            mock.patch("builtins.print"),
        ):
            args.func(args)

        expected = base64.b64encode("echo hello".encode("utf-8")).decode("ascii")
        mock_client.request.assert_called_once_with(
            "POST",
            "/terminal/sessions/sess-1/input",
            json_body={"data_b64": expected},
            auth_override=None,
        )

    def test_terminal_write_invalid_base64_rejected(self) -> None:
        args = self.parser.parse_args(["terminal", "write", "sess-1", "@@@", "--base64"])
        mock_client = mock.Mock()
        with (
            mock.patch.object(self.module, "load_config", return_value={"server_url": "https://fortress.local:8443"}),
            mock.patch.object(self.module, "FortressClient", return_value=mock_client),
        ):
            with self.assertRaises(self.module.FortressCLIError):
                args.func(args)
        mock_client.request.assert_not_called()

    def test_terminal_resize_requires_dimensions_without_json(self) -> None:
        args = self.parser.parse_args(["terminal", "resize", "sess-1"])
        mock_client = mock.Mock()
        with (
            mock.patch.object(self.module, "load_config", return_value={"server_url": "https://fortress.local:8443"}),
            mock.patch.object(self.module, "FortressClient", return_value=mock_client),
        ):
            with self.assertRaises(self.module.FortressCLIError):
                args.func(args)
        mock_client.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
