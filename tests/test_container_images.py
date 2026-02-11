import json
import os
import sys
import unittest
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import containers


class ContainerImageRemoteTests(unittest.TestCase):
    def test_list_lxd_remotes_accepts_uppercase_name_fields(self) -> None:
        payload = json.dumps(
            [
                {"NAME": "local"},
                {"Name": "images"},
                {"name": "ubuntu"},
                {"name": "debian"},
            ]
        )
        with mock.patch.object(containers, "run_command", return_value=payload):
            remotes = containers.list_lxd_remotes()
        self.assertEqual(remotes, {"local", "images", "ubuntu", "debian"})

    def test_list_lxd_remotes_accepts_mapping_payload(self) -> None:
        payload = json.dumps(
            {
                "images": {"Addr": "https://images.linuxcontainers.org"},
                "ubuntu": {"NAME": "ubuntu"},
            }
        )
        with mock.patch.object(containers, "run_command", return_value=payload):
            remotes = containers.list_lxd_remotes()
        self.assertEqual(remotes, {"images", "ubuntu"})

    def test_ensure_image_available_uses_remote_and_alias_lookup(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd[:3] == ["lxc", "remote", "list"]:
                return json.dumps([{"NAME": "images"}])
            if cmd[:3] == ["lxc", "image", "list"]:
                self.assertEqual(cmd[3], "images:")
                self.assertEqual(cmd[4], "almalinux/9/cloud")
                return json.dumps(
                    [
                        {
                            "architecture": "x86_64",
                            "type": "container",
                            "aliases": [{"name": "almalinux/9/cloud"}],
                            "properties": {"os": "AlmaLinux", "release": "9"},
                        }
                    ]
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with mock.patch.object(containers, "run_command", side_effect=fake_run):
            image = containers.ensure_image_available("images:almalinux/9/cloud")

        self.assertEqual(image.get("architecture"), "x86_64")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][:6], ["lxc", "image", "list", "images:", "almalinux/9/cloud", "--format"])

    def test_ensure_image_available_rejects_unknown_remote(self) -> None:
        with mock.patch.object(containers, "run_command", return_value=json.dumps([{"name": "local"}])):
            with self.assertRaises(HTTPException) as exc:
                containers.ensure_image_available("images:ubuntu/24.04/cloud")
        self.assertEqual(exc.exception.status_code, 400)
        self.assertIn("LXD remote 'images' is not configured", exc.exception.detail)


if __name__ == "__main__":
    unittest.main()
