import json
import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import containers


class ContainerImageDiscoveryTests(unittest.TestCase):
    def test_discover_popular_images_from_lxd_cli_catalog(self) -> None:
        remotes_payload = [
            {"name": "ubuntu"},
            {"name": "debian"},
            {"name": "images"},
        ]
        ubuntu_images_latest = [
            {
                "aliases": [{"name": "22.04"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Ubuntu", "release": "jammy"},
            },
            {
                "aliases": [{"name": "24.04"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Ubuntu", "release": "noble"},
            },
        ]
        ubuntu_images_full = list(ubuntu_images_latest)
        debian_images = [
            {
                "aliases": [{"name": "12"}, {"name": "bookworm"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Debian", "release": "bookworm"},
            },
            {
                "aliases": [{"name": "13"}, {"name": "trixie"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Debian", "release": "trixie"},
            },
        ]
        images_remote = [
            {
                "aliases": [{"name": "almalinux/8/cloud"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "AlmaLinux", "release": "8"},
            },
            {
                "aliases": [{"name": "almalinux/9/cloud"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "AlmaLinux", "release": "9"},
            },
            {
                "aliases": [{"name": "rockylinux/9/cloud"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Rocky Linux", "release": "9"},
            },
            {
                "aliases": [{"name": "fedora/41/cloud"}],
                "architecture": "x86_64",
                "type": "container",
                "properties": {"os": "Fedora", "release": "41"},
            },
        ]

        def fake_run_command(cmd):
            if cmd == ["lxc", "remote", "list", "--format", "json"]:
                return json.dumps(remotes_payload)
            if cmd == ["lxc", "image", "list", "ubuntu:", "--format", "json", "--limit", "100"]:
                return json.dumps(ubuntu_images_latest)
            if cmd == ["lxc", "image", "list", "ubuntu:", "--format", "json", "--limit", "300"]:
                return json.dumps(ubuntu_images_full)
            if cmd == ["lxc", "image", "list", "debian:", "--format", "json", "--limit", "260"]:
                return json.dumps(debian_images)
            if cmd == ["lxc", "image", "list", "images:", "--format", "json", "--limit", "450"]:
                return json.dumps(images_remote)
            raise AssertionError(f"Unexpected command: {cmd}")

        with mock.patch("fortress.containers.run_command", side_effect=fake_run_command):
            discovered = containers.discover_popular_images()

        by_name = {entry["name"]: entry for entry in discovered}
        self.assertEqual(by_name["ubuntu:lts"]["resolved_name"], "ubuntu:24.04")
        self.assertEqual(by_name["debian:13"]["label"], "Debian 13 (stable)")
        self.assertEqual(by_name["images:almalinux/9/cloud"]["source"], "lxd-cli")
        self.assertEqual(by_name["images:rockylinux/9/cloud"]["resolved_name"], "images:rockylinux/9/cloud")
        self.assertEqual(by_name["images:fedora/41/cloud"]["available"], True)

    def test_list_remote_images_returns_empty_on_bad_json(self) -> None:
        with mock.patch("fortress.containers.run_command", return_value="{bad-json"):
            self.assertEqual(containers.list_remote_images("ubuntu"), [])


if __name__ == "__main__":
    unittest.main()
