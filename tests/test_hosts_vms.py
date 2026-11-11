"""Hosts/VMs lifecycle and VM input hardening (ROADMAP Path 11).

`vm_manage` used to imply arbitrary command execution on the API host via `qemu_binary`,
`extra_args`, `bridge_name` (`-netdev bridge,...,helper=`) and unconstrained disk/vm_dir paths
(`purge` ran `rmtree(vm_dir)`). These tests pin the allowlists and the lifecycle with all host
commands mocked.
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from fastapi import HTTPException

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "py")))

from fortress import hosts as hosts_mod
from fortress import vms as vms_mod
from fortress.storage import json_store_lock

SERVER_PATH = Path(__file__).resolve().parents[1] / "py" / "server.py"
MASTER = "integration-master-key"


def _which(name):
    return f"/usr/bin/{name}"


class VMRootMixin:
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = os.path.realpath(os.path.join(self.tmpdir.name, "vms"))
        os.makedirs(self.root)
        patcher = mock.patch.dict(os.environ, {"FORTRESS_VM_ROOT": self.root})
        patcher.start()
        self.addCleanup(patcher.stop)


class QemuArgValidationTests(VMRootMixin, unittest.TestCase):
    def assert400(self, func, *args):
        with self.assertRaises(HTTPException) as ctx:
            func(*args)
        self.assertEqual(ctx.exception.status_code, 400)
        return ctx.exception

    def test_qemu_binary_allowlist(self):
        self.assertIsNone(vms_mod.validate_qemu_binary(None))
        self.assertEqual(vms_mod.validate_qemu_binary("qemu-system-aarch64"), "qemu-system-aarch64")
        self.assertEqual(vms_mod.validate_qemu_binary("qemu-kvm"), "qemu-kvm")
        for bad in ("/bin/sh", "sh", "/usr/bin/qemu-system-x86_64", "qemu-system-x86_64 -monitor", "../qemu-system-x86_64", "python3"):
            self.assert400(vms_mod.validate_qemu_binary, bad)

    def test_qemu_executable_resolution(self):
        with mock.patch("fortress.vms.shutil.which", side_effect=lambda name: "/usr/bin/x" if name == "qemu-system-x86_64" else None):
            self.assertEqual(vms_mod.resolve_qemu_executable(None), "/usr/bin/x")
        # AlmaLinux/RHEL: no qemu-system-* on PATH, QEMU lives at /usr/libexec/qemu-kvm.
        with mock.patch("fortress.vms.shutil.which", return_value=None), mock.patch(
            "fortress.vms.os.path.isfile", side_effect=lambda p: p == "/usr/libexec/qemu-kvm"
        ), mock.patch("fortress.vms.os.access", return_value=True):
            self.assertEqual(vms_mod.resolve_qemu_executable(None), "/usr/libexec/qemu-kvm")
            self.assertEqual(vms_mod.resolve_qemu_executable("qemu-kvm"), "/usr/libexec/qemu-kvm")
            self.assertIsNone(vms_mod.resolve_qemu_executable("qemu-system-aarch64"))

    def test_allowed_extra_args(self):
        args = [
            "-cpu", "host,+avx2",
            "-M", "q35,accel=kvm",
            "-vga", "virtio",
            "-device", "virtio-rng-pci,id=rng0",
            "-rtc", "base=utc,clock=host",
            "-boot", "order=c,menu=on",
            "--nodefaults",
            "-snapshot",
            "-accel", "kvm",
        ]
        normalized = vms_mod.validate_extra_args(args)
        self.assertIn("-machine", normalized)
        self.assertIn("-nodefaults", normalized)
        self.assertNotIn("-M", normalized)

    def test_dangerous_extra_args_rejected(self):
        rejected = [
            ["-netdev", "user,id=n1,smb=/"],
            ["-netdev", "tap,id=t,script=/tmp/evil.sh"],
            ["-chardev", "socket,id=c,path=/tmp/s"],
            ["-monitor", "stdio"],
            ["-qmp", "unix:/tmp/q,server"],
            ["-plugin", "/tmp/evil.so"],
            ["-drive", "file=/etc/shadow,format=raw"],
            ["-kernel", "/etc/shadow"],
            ["-device", "loader,file=/etc/shadow"],
            ["-device", "virtio-rng-pci,romfile=/etc/shadow"],
            ["-machine", "q35,dumpdtb=/etc/passwd"],
            ["-cpu", "-monitor"],
            ["-cpu"],
            ["-readconfig", "/tmp/x.cfg"],
            ["-object", "memory-backend-file,id=m,mem-path=/etc"],
            ["-D", "/etc/cron.d/x"],
            ["-serial", "file:/etc/cron.d/x"],
            ["-cpu", "host\n-monitor"],
            ["-vga", "std\n"],
            [123],
        ]
        for args in rejected:
            with self.subTest(args=args):
                self.assert400(vms_mod.validate_extra_args, args)
        self.assert400(vms_mod.validate_extra_args, ["-snapshot"] * (vms_mod.MAX_EXTRA_ARGS + 1))

    def test_bridge_name_cannot_inject_netdev_options(self):
        self.assertEqual(vms_mod.validate_bridge_name("br0"), "br0")
        for bad in ("br0,helper=/tmp/evil", "-br", "a" * 16, "br 0", "br0\n"):
            self.assert400(vms_mod.validate_bridge_name, bad)

    def test_paths_confined_to_vm_root(self):
        inside = os.path.join(self.root, "web", "disk.qcow2")
        self.assertEqual(vms_mod.validate_disk_path(inside), inside)
        self.assertEqual(vms_mod.validate_vm_dir(os.path.join(self.root, "web")), os.path.join(self.root, "web"))
        for bad in ("/etc/shadow", "relative/disk.qcow2", os.path.join(self.root, "..", "x.qcow2"), os.path.join(self.root, "a,format=raw")):
            self.assert400(vms_mod.validate_disk_path, bad)
        self.assert400(vms_mod.validate_vm_dir, self.root)  # the root itself would be rmtree'd on purge
        self.assert400(vms_mod.validate_vm_dir, "/")
        self.assertEqual(vms_mod.validate_iso_path("/srv/iso/alma.ISO"), "/srv/iso/alma.ISO")
        self.assert400(vms_mod.validate_iso_path, "/etc/shadow")

    def test_resource_bounds(self):
        for field, value in (("cpu_cores", 0), ("memory_mb", -1), ("disk_gb", 10 ** 9), ("ssh_forward_port", 70000), ("cpu_cores", True)):
            with self.subTest(field=field):
                self.assert400(vms_mod.validate_vm_resources, {field: value})
        self.assert400(vms_mod.validate_vm_resources, {"os_type": "--ostype"})


class VMLifecycleTests(VMRootMixin, unittest.TestCase):
    def _create(self, vms, **overrides):
        payload = {"name": "web", "provider": "qemu", "disk_gb": 5}
        payload.update(overrides)
        return vms_mod.create_vm(vms_mod.VMCreateRequest(**payload), vms)

    @mock.patch("fortress.vms.shutil.which", side_effect=_which)
    @mock.patch("fortress.vms.run_command", return_value="")
    def test_qemu_create_start_snapshot_purge(self, run_command, _which_mock):
        vms = {}
        record = self._create(vms, extra_args=["-cpu", "host"], ssh_forward_port=2222)
        disk = os.path.join(self.root, "web", "web.qcow2")
        self.assertEqual(record["disk_path"], disk)
        self.assertIsNone(record["qemu_binary"])
        run_command.assert_called_with(["qemu-img", "create", "-f", "qcow2", disk, "5G"])

        vms_mod.start_vm("web", vms_mod.VMStartRequest(), vms)
        cmd = run_command.call_args[0][0]
        self.assertEqual(cmd[0], "/usr/bin/qemu-system-x86_64")
        self.assertIn("user,id=net0,hostfwd=tcp::2222-:22", cmd)
        self.assertEqual(cmd[-2:], ["-cpu", "host"])
        self.assertEqual(vms["web"]["state"], "running")

        with mock.patch("fortress.vms._status_qemu_vm", return_value="running"):
            for call in (
                lambda: vms_mod.create_snapshot("web", vms_mod.VMSnapshotRequest(name="s0"), vms),
                lambda: vms_mod.restore_snapshot("web", "s0", vms),
                lambda: vms_mod.delete_snapshot("web", "s0", vms),
            ):
                with self.assertRaises(HTTPException) as ctx:
                    call()
                self.assertEqual(ctx.exception.status_code, 409)
        vms["web"]["state"] = "stopped"
        snap = vms_mod.create_snapshot("web", vms_mod.VMSnapshotRequest(name="s1"), vms)
        self.assertEqual(snap["name"], "s1")
        with self.assertRaises(HTTPException) as ctx:
            vms_mod.create_snapshot("web", vms_mod.VMSnapshotRequest(name="s1"), vms)
        self.assertEqual(ctx.exception.status_code, 409)
        vms_mod.delete_snapshot("web", "s1", vms)
        self.assertEqual(vms_mod.list_snapshots("web", vms), [])

        os.makedirs(os.path.dirname(disk), exist_ok=True)
        Path(disk).write_text("disk")
        vms_mod.delete_vm("web", vms, purge=True)
        self.assertFalse(os.path.exists(os.path.join(self.root, "web")))
        self.assertTrue(os.path.isdir(self.root))
        self.assertNotIn("web", vms)

    @mock.patch("fortress.vms.shutil.which", side_effect=_which)
    @mock.patch("fortress.vms.run_command", return_value="")
    def test_create_rejects_bad_input_before_any_command(self, run_command, _which_mock):
        for overrides in (
            {"qemu_binary": "/bin/sh"},
            {"extra_args": ["-netdev", "tap,script=/tmp/x"]},
            {"network_mode": "bridge", "bridge_name": "br0,helper=/tmp/x"},
            {"network_mode": "bridge"},
            {"disk_path": "/etc/shadow"},
            {"vm_dir": "/"},
        ):
            with self.subTest(overrides=overrides):
                vms = {}
                with self.assertRaises(HTTPException) as ctx:
                    self._create(vms, **overrides)
                self.assertEqual(ctx.exception.status_code, 400)
                self.assertEqual(vms, {})
        run_command.assert_not_called()

    @mock.patch("fortress.vms.shutil.which", side_effect=_which)
    @mock.patch("fortress.vms.run_command", return_value="")
    def test_update_is_validated_and_atomic(self, run_command, _which_mock):
        vms = {}
        self._create(vms)
        before = dict(vms["web"])
        with self.assertRaises(HTTPException):
            vms_mod.update_vm("web", vms_mod.VMUpdateRequest(memory_mb=4096, extra_args=["-monitor", "stdio"]), vms)
        self.assertEqual(vms["web"], before)
        vms_mod.update_vm("web", vms_mod.VMUpdateRequest(memory_mb=4096, extra_args=["-vga", "std"]), vms)
        self.assertEqual(vms["web"]["memory_mb"], 4096)
        self.assertEqual(vms["web"]["extra_args"], ["-vga", "std"])

    @mock.patch("fortress.vms.shutil.which", side_effect=_which)
    @mock.patch("fortress.vms.run_command", return_value="")
    def test_legacy_record_is_revalidated_on_start(self, run_command, _which_mock):
        vms = {
            "old": {
                "name": "old",
                "provider": "qemu",
                "cpu_cores": 1,
                "memory_mb": 512,
                "disk_path": os.path.join(self.root, "old", "old.qcow2"),
                "qemu_binary": "/bin/sh",
                "extra_args": ["-c", "id"],
            }
        }
        with self.assertRaises(HTTPException) as ctx:
            vms_mod.start_vm("old", vms_mod.VMStartRequest(), vms)
        self.assertEqual(ctx.exception.status_code, 400)
        run_command.assert_not_called()

    @mock.patch("fortress.vms.run_command", return_value="")
    def test_purge_refuses_paths_outside_root(self, run_command):
        outside = tempfile.mkdtemp()
        self.addCleanup(lambda: os.path.isdir(outside) and os.rmdir(outside))
        vms = {"legacy": {"name": "legacy", "provider": "qemu", "vm_dir": outside}}
        with self.assertRaises(HTTPException) as ctx:
            vms_mod.delete_vm("legacy", vms, purge=True)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertTrue(os.path.isdir(outside))
        self.assertIn("legacy", vms)
        vms_mod.delete_vm("legacy", vms, purge=False)
        self.assertNotIn("legacy", vms)

    @mock.patch("fortress.vms.shutil.which", side_effect=_which)
    @mock.patch("fortress.vms.run_command", return_value='name="box"\nVMState="running"\n')
    def test_virtualbox_create_and_status(self, run_command, _which_mock):
        vms = {}
        record = vms_mod.create_vm(
            vms_mod.VMCreateRequest(name="box", provider="virtualbox", os_type="Ubuntu_64", ssh_forward_port=2200), vms
        )
        commands = [call[0][0] for call in run_command.call_args_list]
        self.assertEqual(commands[0][:2], ["VBoxManage", "createhd"])
        self.assertIn(["VBoxManage", "createvm", "--name", "box", "--register"], commands)
        self.assertIn("ssh,tcp,,2200,,22", commands[-1])
        self.assertIsNone(record.get("qemu_binary"))
        self.assertEqual(vms_mod.vm_status("box", vms)["state"], "running")
        with self.assertRaises(HTTPException):
            vms_mod.create_vm(vms_mod.VMCreateRequest(name="box2", provider="virtualbox", extra_args=["-snapshot"]), vms)
        with self.assertRaises(HTTPException):
            vms_mod.create_vm(vms_mod.VMCreateRequest(name="box3", provider="virtualbox", qemu_binary="qemu-kvm"), vms)

    @mock.patch("fortress.vms.run_ssh_script", return_value='{"service": "active"}')
    def test_probe_saves_state_and_provision_passes_env(self, run_ssh):
        vms = {"web": {"name": "web", "provider": "qemu", "ssh": {"host": "10.0.0.5", "username": "alma", "port": 22}}}
        payload = vms_mod.probe_vm("web", vms_mod.VMProbeRequest(save_as="baseline"), vms)
        self.assertEqual(payload, {"service": "active"})
        self.assertEqual(vms["web"]["saved_states"][0]["name"], "baseline")
        vms_mod.provision_vm("web", vms_mod.VMProvisionRequest(profile="fedora", api_key="placeholder-key"), vms)
        env = run_ssh.call_args.kwargs["env"]
        self.assertEqual(env["FORTRESS_API_KEY"], "placeholder-key")
        self.assertEqual(vms["web"]["last_provision_profile"], "fedora")
        run_ssh.return_value = "not json"
        with self.assertRaises(HTTPException):
            vms_mod.probe_vm("web", vms_mod.VMProbeRequest(), vms)

    def test_sanitize_masks_password(self):
        out = vms_mod.sanitize_vm_record({"ssh": {"password": "placeholder-pass"}})
        self.assertEqual(out["ssh"]["password"], "***")
        self.assertTrue(out["ssh"]["has_password"])


class HostLifecycleTests(unittest.TestCase):
    def test_crud_and_validation(self):
        hosts = {}
        hosts_mod.create_host(hosts_mod.HostCreateRequest(name="edge1", ssh={"host": "edge1.example", "username": "ops"}), hosts)
        with self.assertRaises(HTTPException) as ctx:
            hosts_mod.create_host(hosts_mod.HostCreateRequest(name="edge1"), hosts)
        self.assertEqual(ctx.exception.status_code, 409)
        for bad in ("-edge", "edge 1", "", "edge\n"):
            with self.assertRaises(HTTPException):
                hosts_mod.create_host(hosts_mod.HostCreateRequest(name=bad), hosts)
        with self.assertRaises(HTTPException):
            hosts_mod.create_host(hosts_mod.HostCreateRequest(name="evil", ssh={"host": "-oProxyCommand=id", "username": "x"}), hosts)
        hosts_mod.update_host("edge1", hosts_mod.HostUpdateRequest(notes="n", labels={"env": "prod"}), hosts)
        self.assertEqual(hosts["edge1"]["labels"], {"env": "prod"})
        self.assertEqual(hosts_mod.build_host_summary(hosts["edge1"])["ssh_host"], "edge1.example")
        hosts_mod.delete_host("edge1", hosts)
        with self.assertRaises(HTTPException) as ctx:
            hosts_mod.delete_host("edge1", hosts)
        self.assertEqual(ctx.exception.status_code, 404)

    @mock.patch("fortress.hosts.run_ssh_script", return_value='{"ok": true}')
    def test_probe_and_provision(self, run_ssh):
        hosts = {"edge1": {"name": "edge1", "ssh": {"host": "edge1.example", "username": "ops"}}}
        hosts_mod.probe_host("edge1", hosts_mod.HostProbeRequest(save_as="s"), hosts)
        self.assertEqual(hosts_mod.list_saved_states("edge1", hosts)[0]["data"], {"ok": True})
        hosts_mod.provision_host("edge1", hosts_mod.HostProvisionRequest(skip_service=True), hosts)
        self.assertEqual(run_ssh.call_args.kwargs["env"]["SKIP_SERVICE"], "1")
        with self.assertRaises(HTTPException):
            hosts_mod.probe_host("edge1", hosts_mod.HostProbeRequest(), {"edge1": {"name": "edge1"}})


class ReentrantStoreLockTests(unittest.TestCase):
    def test_nested_lock_in_same_thread_does_not_deadlock(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "store.json")
        done = threading.Event()

        def _nested():
            with json_store_lock(path):
                with json_store_lock(path):
                    pass
                with json_store_lock(path):
                    pass
            done.set()

        thread = threading.Thread(target=_nested, daemon=True)
        thread.start()
        thread.join(5)
        self.assertTrue(done.is_set(), "nested json_store_lock deadlocked")


def load_server_module(temp_dir: str):
    module_name = f"fortress_server_hosts_vms_{os.getpid()}_{Path(temp_dir).name}"
    spec = importlib.util.spec_from_file_location(module_name, str(SERVER_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module, module_name


class HostVMRouteTests(VMRootMixin, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient

        env = {
            "FORTRESS_LOG_PATH": os.path.join(self.tmpdir.name, "fortress.log"),
            "FORTRESS_COMMAND_LOG_DB": os.path.join(self.tmpdir.name, "command_log.db"),
            "FORTRESS_API_KEY": MASTER,
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.module, module_name = load_server_module(self.tmpdir.name)
        self.addCleanup(lambda: sys.modules.pop(module_name, None))
        for attr, name in (
            ("API_USERS_DB", "api_users.json"),
            ("VMS_DB", "vms.json"),
            ("HOSTS_DB", "hosts.json"),
            ("RECIPES_DB", "recipes.json"),
            ("SITES_DB", "sites.json"),
            ("ROUTING_DB", "routes.json"),
        ):
            setattr(self.module, attr, os.path.join(self.tmpdir.name, name))
        with open(self.module.API_USERS_DB, "w") as fh:
            json.dump({"tok-vm-read": {"username": "viewer", "permissions": ["vm_read", "host_read"]}}, fh)
        self.client = TestClient(self.module.app)
        self.master = {"X-API-Key": MASTER}

    def _store(self, attr):
        path = getattr(self.module, attr)
        if not os.path.exists(path):
            return {}
        with open(path) as fh:
            return json.load(fh)

    def _audit_rows(self, endpoint):
        import sqlite3

        with sqlite3.connect(os.environ["FORTRESS_COMMAND_LOG_DB"]) as conn:
            return conn.execute("select status from command_log where endpoint = ?", (endpoint,)).fetchall()

    def test_vm_create_rejects_injection_and_audits_error(self):
        with mock.patch("fortress.vms.run_command") as run_command, mock.patch("fortress.vms.shutil.which", side_effect=_which):
            resp = self.client.post(
                "/vms",
                json={"name": "web", "provider": "qemu", "extra_args": ["-netdev", "tap,id=x,script=/tmp/pwn"]},
                headers=self.master,
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            run_command.assert_not_called()
        self.assertEqual(self._store("VMS_DB"), {})
        self.assertIn(("error",), self._audit_rows("vms_create"))

    def test_vm_permissions_and_lifecycle(self):
        with mock.patch("fortress.vms.run_command", return_value=""), mock.patch("fortress.vms.shutil.which", side_effect=_which):
            denied = self.client.post("/vms", json={"name": "web", "provider": "qemu"}, headers={"X-User-Token": "tok-vm-read"})
            self.assertEqual(denied.status_code, 403)
            created = self.client.post("/vms", json={"name": "web", "provider": "qemu", "disk_gb": 2}, headers=self.master)
            self.assertEqual(created.status_code, 200, created.text)
            dup = self.client.post("/vms", json={"name": "web", "provider": "qemu"}, headers=self.master)
            self.assertEqual(dup.status_code, 409)
            bad_update = self.client.put("/vms/web", json={"qemu_binary": "/bin/sh"}, headers=self.master)
            self.assertEqual(bad_update.status_code, 400)
            self.assertIsNone(self._store("VMS_DB")["web"]["qemu_binary"])
            ok = self.client.put("/vms/web", json={"memory_mb": 1024}, headers=self.master)
            self.assertEqual(ok.status_code, 200)
            listing = self.client.get("/vms", headers={"X-User-Token": "tok-vm-read"})
            self.assertEqual([vm["name"] for vm in listing.json()["vms"]], ["web"])
            self.assertEqual(self.client.delete("/vms/web", headers=self.master).status_code, 200)
            self.assertEqual(self.client.get("/vms/web", headers=self.master).status_code, 404)

    def test_host_probe_merges_into_current_record(self):
        self.client.post("/hosts", json={"name": "edge1", "ssh": {"host": "edge1.example", "username": "ops"}}, headers=self.master)

        def _slow_probe(*_args, **_kwargs):
            # A concurrent update lands while the (lock-free) SSH probe is running.
            resp = self.client.put("/hosts/edge1", json={"notes": "changed meanwhile"}, headers=self.master)
            assert resp.status_code == 200, resp.text
            return '{"ok": true}'

        with mock.patch("fortress.hosts.run_ssh_script", side_effect=_slow_probe):
            resp = self.client.post("/hosts/edge1/probe", json={"save_as": "s1"}, headers={"X-User-Token": "tok-vm-read"})
        self.assertEqual(resp.status_code, 200, resp.text)
        record = self._store("HOSTS_DB")["edge1"]
        self.assertEqual(record["notes"], "changed meanwhile")
        self.assertEqual(record["saved_states"][0]["name"], "s1")
        self.assertEqual(self.client.post("/hosts/missing/probe", json={}, headers=self.master).status_code, 404)
        self.assertIn(("error",), self._audit_rows("hosts_probe"))

    def test_concurrent_host_and_recipe_creates_are_not_lost(self):
        errors = []

        def _create(i):
            for path, body in (
                ("/hosts", {"name": f"h{i}"}),
                ("/recipes", {"name": f"r{i}", "commands": ["true"]}),
            ):
                resp = self.client.post(path, json=body, headers=self.master)
                if resp.status_code != 200:
                    errors.append((path, resp.status_code, resp.text))

        threads = [threading.Thread(target=_create, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(set(self._store("HOSTS_DB")), {f"h{i}" for i in range(12)})
        self.assertTrue({f"r{i}" for i in range(12)} <= set(self._store("RECIPES_DB")))


if __name__ == "__main__":
    unittest.main()
