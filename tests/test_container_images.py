import json
import os
import sys
import unittest
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import containers


class ContainerImageDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        containers._PUBLIC_IMAGE_INDEX_CACHE["expires_at"] = 0.0
        containers._PUBLIC_IMAGE_INDEX_CACHE["products"] = []

    @staticmethod
    def _public_index_response(products):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"index": {"images": {"products": products}}}
        return response

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

    def test_list_lxd_remotes_supports_object_payload(self) -> None:
        remotes_payload = {
            "local": {"Name": "local"},
            "ubuntu": {"Addr": "https://cloud-images.ubuntu.com/releases"},
            "images": {"Protocol": "simplestreams"},
        }
        with mock.patch("fortress.containers.run_command", return_value=json.dumps(remotes_payload)):
            remotes = containers.list_lxd_remotes()
        self.assertEqual(remotes, {"local", "ubuntu", "images"})

    def test_resolve_image_alias_uses_public_catalog_when_ubuntu_remote_missing(self) -> None:
        products = [
            "ubuntu:jammy:amd64:cloud",
            "ubuntu:noble:amd64:cloud",
            "debian:bookworm:amd64:cloud",
            "debian:trixie:amd64:cloud",
            "almalinux:9:amd64:cloud",
        ]
        response = self._public_index_response(products)
        with (
            mock.patch("fortress.containers.find_latest_ubuntu_lts_alias", return_value=None),
            mock.patch("fortress.containers.requests.get", return_value=response),
        ):
            self.assertEqual(containers.resolve_image_alias("ubuntu:lts"), "images:ubuntu/noble/cloud")
            self.assertEqual(containers.resolve_image_alias("ubuntu:24.04"), "images:ubuntu/noble/cloud")
            self.assertEqual(containers.resolve_image_alias("debian:12"), "images:debian/bookworm/cloud")
            self.assertEqual(containers.resolve_image_alias("images:almalinux/9/cloud"), "images:almalinux/9/cloud")

    def test_discover_popular_images_uses_public_catalog_fallback(self) -> None:
        products = [
            "ubuntu:jammy:amd64:cloud",
            "ubuntu:noble:amd64:cloud",
            "debian:bookworm:amd64:cloud",
            "debian:trixie:amd64:cloud",
            "almalinux:9:amd64:cloud",
            "rockylinux:9:amd64:cloud",
            "fedora:41:amd64:cloud",
        ]

        def fake_run_command(cmd):
            if cmd == ["lxc", "remote", "list", "--format", "json"]:
                return json.dumps([{"name": "images"}])
            if cmd == ["lxc", "image", "list", "images:", "--format", "json", "--limit", "450"]:
                return "[]"
            raise AssertionError(f"Unexpected command: {cmd}")

        response = self._public_index_response(products)
        with (
            mock.patch("fortress.containers.run_command", side_effect=fake_run_command),
            mock.patch("fortress.containers.requests.get", return_value=response),
        ):
            discovered = containers.discover_popular_images()

        by_name = {entry["name"]: entry for entry in discovered}
        self.assertEqual(by_name["ubuntu:lts"]["resolved_name"], "images:ubuntu/noble/cloud")
        self.assertEqual(by_name["ubuntu:lts"]["source"], "lxd-repo")
        self.assertEqual(by_name["debian:13"]["resolved_name"], "images:debian/trixie/cloud")
        self.assertEqual(by_name["images:almalinux/9/cloud"]["source"], "lxd-repo")
        self.assertEqual(by_name["images:fedora/41/cloud"]["available"], True)


if __name__ == "__main__":
    unittest.main()
