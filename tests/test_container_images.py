import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import containers as container_ops
from fortress.api import containers as container_api
from fortress.api.containers import build_container_router


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
        with mock.patch.object(container_ops, "run_command", return_value=payload):
            remotes = container_ops.list_lxd_remotes()
        self.assertEqual(remotes, {"local", "images", "ubuntu", "debian"})

    def test_list_lxd_remotes_accepts_mapping_payload(self) -> None:
        payload = json.dumps(
            {
                "images": {"Addr": "https://images.linuxcontainers.org"},
                "ubuntu": {"NAME": "ubuntu"},
            }
        )
        with mock.patch.object(container_ops, "run_command", return_value=payload):
            remotes = container_ops.list_lxd_remotes()
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

        with mock.patch.object(container_ops, "run_command", side_effect=fake_run):
            image = container_ops.ensure_image_available("images:almalinux/9/cloud")

        self.assertEqual(image.get("architecture"), "x86_64")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][:6], ["lxc", "image", "list", "images:", "almalinux/9/cloud", "--format"])

    def test_ensure_image_available_rejects_unknown_remote(self) -> None:
        with mock.patch.object(container_ops, "run_command", return_value=json.dumps([{"name": "local"}])):
            with self.assertRaises(HTTPException) as exc:
                container_ops.ensure_image_available("images:ubuntu/24.04/cloud")
        self.assertEqual(exc.exception.status_code, 400)
        self.assertIn("LXD remote 'images' is not configured", exc.exception.detail)

    def test_list_remote_images_retries_without_limit_on_old_lxc(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if "--limit" in cmd:
                raise HTTPException(status_code=500, detail="System Error: Error: unknown flag: --limit")
            return json.dumps(
                [
                    {
                        "architecture": "x86_64",
                        "aliases": [{"name": "22.04"}],
                        "properties": {"os": "Ubuntu"},
                    }
                ]
            )

        with mock.patch.object(container_ops, "run_command", side_effect=fake_run):
            images = container_ops.list_remote_images("ubuntu", limit=25)
        self.assertEqual(len(images), 1)
        self.assertGreaterEqual(len(calls), 2)
        self.assertIn("--limit", calls[0])
        self.assertNotIn("--limit", calls[1])

    def test_ensure_image_available_retries_without_limit_on_old_lxc(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd[:3] == ["lxc", "remote", "list"]:
                return json.dumps([{"name": "images"}])
            if "--limit" in cmd:
                raise HTTPException(status_code=500, detail="System Error: Error: unknown flag: --limit")
            return json.dumps(
                [
                    {
                        "architecture": "x86_64",
                        "type": "container",
                        "aliases": [{"name": "ubuntu/noble/cloud"}],
                        "properties": {"os": "Ubuntu", "release": "24.04"},
                    }
                ]
            )

        with mock.patch.object(container_ops, "run_command", side_effect=fake_run):
            image = container_ops.ensure_image_available("images:ubuntu/noble/cloud")

        self.assertEqual(image.get("properties", {}).get("release"), "24.04")
        self.assertGreaterEqual(len(calls), 3)
        self.assertIn("--limit", calls[1])
        self.assertNotIn("--limit", calls[2])


class ContainerCreateLaunchTests(unittest.TestCase):
    def test_create_container_retries_with_storage_pool_when_root_device_missing(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd == ["lxc", "launch", "ubuntu:24.04", "demo"]:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "System Error: Error: Failed instance creation: Failed creating instance record: "
                        "Failed initialising instance: Failed getting root disk: No root device could be found"
                    ),
                )
            if cmd == ["lxc", "storage", "list", "--format", "json"]:
                return json.dumps([{"name": "default"}])
            if cmd == ["lxc", "launch", "--storage", "default", "ubuntu:24.04", "demo"]:
                return ""
            if cmd[:4] == ["lxc", "config", "set", "demo"]:
                return ""
            if cmd[:5] == ["lxc", "config", "device", "set", "demo"]:
                return ""
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            mock.patch.object(container_ops, "resolve_image_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_ops, "ensure_image_available", return_value={}),
            mock.patch.object(container_ops, "run_command", side_effect=fake_run),
        ):
            container_ops.create_container("demo", "ubuntu:lts", "2", "1GB", "10GB")

        self.assertIn(["lxc", "launch", "ubuntu:24.04", "demo"], calls)
        self.assertIn(["lxc", "storage", "list", "--format", "json"], calls)
        self.assertIn(["lxc", "launch", "--storage", "default", "ubuntu:24.04", "demo"], calls)

    def test_create_container_returns_actionable_error_when_no_storage_pool(self) -> None:
        def fake_run(cmd):
            if cmd == ["lxc", "launch", "ubuntu:24.04", "demo"]:
                raise HTTPException(
                    status_code=500,
                    detail="System Error: Error: Failed getting root disk: No root device could be found",
                )
            if cmd == ["lxc", "storage", "list", "--format", "json"]:
                return json.dumps([])
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            mock.patch.object(container_ops, "resolve_image_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_ops, "ensure_image_available", return_value={}),
            mock.patch.object(container_ops, "run_command", side_effect=fake_run),
        ):
            with self.assertRaises(HTTPException) as exc:
                container_ops.create_container("demo", "ubuntu:lts", "2", "1GB", "10GB")

        self.assertEqual(exc.exception.status_code, 500)
        self.assertIn("no usable storage pool", str(exc.exception.detail).lower())

    def test_create_container_does_not_retry_for_unrelated_launch_error(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd == ["lxc", "launch", "ubuntu:24.04", "demo"]:
                raise HTTPException(status_code=500, detail="System Error: launch failed: random failure")
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            mock.patch.object(container_ops, "resolve_image_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_ops, "ensure_image_available", return_value={}),
            mock.patch.object(container_ops, "run_command", side_effect=fake_run),
        ):
            with self.assertRaises(HTTPException) as exc:
                container_ops.create_container("demo", "ubuntu:lts", "2", "1GB", "10GB")

        self.assertIn("random failure", str(exc.exception.detail))
        self.assertEqual(calls, [["lxc", "launch", "ubuntu:24.04", "demo"]])


class ContainerCreateDiskLimitTests(unittest.TestCase):
    def test_create_container_overrides_profile_root_device_when_root_from_profile(self) -> None:
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            if cmd == ["lxc", "launch", "ubuntu:24.04", "demo"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "limits.cpu", "2"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "limits.memory", "1GB"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "security.nesting", "true"]:
                return ""
            if cmd == ["lxc", "config", "device", "set", "demo", "root", "size", "10GB"]:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        'System Error: Error: Device "root" from profile(s) ["default"] cannot be modified '
                        'for individual instance "demo": Override device or modify profile instead'
                    ),
                )
            if cmd == ["lxc", "config", "device", "override", "demo", "root", "size=10GB"]:
                return ""
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            mock.patch.object(container_ops, "resolve_image_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_ops, "ensure_image_available", return_value={}),
            mock.patch.object(container_ops, "run_command", side_effect=fake_run),
        ):
            container_ops.create_container("demo", "ubuntu:lts", "2", "1GB", "10GB")

        self.assertIn(["lxc", "config", "device", "override", "demo", "root", "size=10GB"], calls)

    def test_create_container_fails_when_profile_root_override_fails(self) -> None:
        def fake_run(cmd):
            if cmd == ["lxc", "launch", "ubuntu:24.04", "demo"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "limits.cpu", "2"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "limits.memory", "1GB"]:
                return ""
            if cmd == ["lxc", "config", "set", "demo", "security.nesting", "true"]:
                return ""
            if cmd == ["lxc", "config", "device", "set", "demo", "root", "size", "10GB"]:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        'System Error: Error: Device "root" from profile(s) ["default"] cannot be modified '
                        'for individual instance "demo": Override device or modify profile instead'
                    ),
                )
            if cmd == ["lxc", "config", "device", "override", "demo", "root", "size=10GB"]:
                raise HTTPException(status_code=500, detail="System Error: override failed")
            raise AssertionError(f"Unexpected command: {cmd}")

        with (
            mock.patch.object(container_ops, "resolve_image_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_ops, "ensure_image_available", return_value={}),
            mock.patch.object(container_ops, "run_command", side_effect=fake_run),
        ):
            with self.assertRaises(HTTPException) as exc:
                container_ops.create_container("demo", "ubuntu:lts", "2", "1GB", "10GB")
        self.assertEqual(exc.exception.status_code, 500)
        self.assertIn("Retry via profile device override failed", str(exc.exception.detail))


class PopularImageEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.store_path = os.path.join(self.tmpdir.name, "container_images.json")
        self.router = build_container_router(
            authorize=lambda *args, **kwargs: {},
            audit_api=lambda *args, **kwargs: None,
            sanitize_payload=lambda payload: payload if isinstance(payload, dict) else {},
            shared_storage_dir=self.tmpdir.name,
            popular_images_db=self.store_path,
        )

    def _write_store(self, payload) -> None:
        with open(self.store_path, "w") as fh:
            json.dump(payload, fh)

    def _get_endpoint(self, path: str, method: str):
        method = method.upper()
        for route in self.router.routes:
            if getattr(route, "path", None) == path and method in (getattr(route, "methods", None) or set()):
                return route.endpoint
        self.fail(f"Endpoint not found for {method} {path}")

    def test_list_popular_images_accepts_legacy_store_payloads(self) -> None:
        self._write_store(
            [
                "ubuntu:lts",
                {"alias": "debian:12", "label": "Debian 12 (stable)"},
                {"name": 2404, "label": "numeric-name"},
                {"name": "   "},
            ]
        )
        endpoint = self._get_endpoint("/containers/images/popular", "GET")
        sample_meta = {"architecture": "amd64", "type": "container", "properties": {"release": "24.04", "os": "Ubuntu"}}
        with (
            mock.patch.object(container_api.container_ops, "discover_popular_images", return_value=[]),
            mock.patch.object(container_api.container_ops, "list_lxd_remotes", return_value=set()),
            mock.patch.object(container_api.container_ops, "find_latest_ubuntu_lts_alias", return_value=None),
            mock.patch.object(container_api.container_ops, "resolve_image_alias", side_effect=lambda value: value),
            mock.patch.object(container_api.container_ops, "ensure_image_available", return_value=sample_meta),
        ):
            payload = endpoint()
        names = [entry.get("name") for entry in payload["images"]]
        self.assertIn("ubuntu:lts", names)
        self.assertIn("debian:12", names)
        self.assertIn("2404", names)

    def test_list_popular_images_falls_back_when_discovery_fails(self) -> None:
        endpoint = self._get_endpoint("/containers/images/popular", "GET")
        sample_meta = {"architecture": "amd64", "type": "container", "properties": {"release": "24.04", "os": "Ubuntu"}}
        with (
            mock.patch.object(container_api.container_ops, "discover_popular_images", side_effect=RuntimeError("boom")),
            mock.patch.object(container_api.container_ops, "list_lxd_remotes", return_value={"images"}),
            mock.patch.object(container_api.container_ops, "find_latest_ubuntu_lts_alias", return_value="ubuntu:24.04"),
            mock.patch.object(container_api.container_ops, "resolve_image_alias", side_effect=lambda value: value),
            mock.patch.object(container_api.container_ops, "ensure_image_available", return_value=sample_meta),
        ):
            payload = endpoint()
        names = [entry.get("name") for entry in payload["images"]]
        self.assertIn("ubuntu:lts", names)


class UbuntuAliasDiscoveryTests(unittest.TestCase):
    def test_find_latest_ubuntu_lts_alias_accepts_wrapped_payload(self) -> None:
        wrapped_payload = {
            "metadata": [
                {
                    "aliases": [
                        {"name": "22.04"},
                        {"name": "24.04"},
                    ]
                }
            ]
        }
        with (
            mock.patch.object(container_ops, "list_lxd_remotes", return_value={"ubuntu"}),
            mock.patch.object(container_ops, "_run_lxc_image_list_json", return_value=wrapped_payload),
        ):
            resolved = container_ops.find_latest_ubuntu_lts_alias()
        self.assertEqual(resolved, "ubuntu:24.04")

    def test_find_latest_ubuntu_lts_alias_ignores_invalid_payload(self) -> None:
        with (
            mock.patch.object(container_ops, "list_lxd_remotes", return_value={"ubuntu"}),
            mock.patch.object(container_ops, "_run_lxc_image_list_json", return_value={"unexpected": "shape"}),
        ):
            resolved = container_ops.find_latest_ubuntu_lts_alias()
        self.assertIsNone(resolved)


if __name__ == "__main__":
    unittest.main()
