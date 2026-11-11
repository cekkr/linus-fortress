import json
import logging
import os
import re
import shutil
import signal
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field

from fortress.remote import SSHConfig, build_probe_script, load_provision_script, run_ssh_script, validate_ssh_config
from fortress.storage import ensure_parent_dir, load_json_dict, save_json
from fortress.system import run_command

VM_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DEFAULT_VM_DIR = "/var/lib/fortress/vms"

# --- Input constraints -------------------------------------------------------
# `vm_manage` must not imply arbitrary command execution on the API host, so every
# record field that reaches a qemu/VBoxManage argv is validated here (on create,
# update, *and* again before use, so legacy records cannot bypass it).

QEMU_BINARY_ALLOWLIST = frozenset(
    {
        "qemu-system-x86_64",
        "qemu-system-aarch64",
        "qemu-system-i386",
        "qemu-system-arm",
        "qemu-system-riscv64",
        "qemu-system-ppc64",
        "qemu-system-s390x",
        "qemu-kvm",
    }
)
DEFAULT_QEMU_BINARY = "qemu-system-x86_64"
# RHEL/AlmaLinux ship QEMU as /usr/libexec/qemu-kvm (not on PATH); only these fixed paths are searched.
QEMU_KVM_FALLBACK_PATHS = ("/usr/libexec/qemu-kvm", "/usr/bin/qemu-kvm")
BRIDGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
OS_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_EXTRA_ARGS = 32
MAX_CPU_CORES = 256
MAX_MEMORY_MB = 1024 * 1024
MAX_DISK_GB = 64 * 1024

_TOKEN = r"[A-Za-z0-9_.:-]+"


def _kv_list(keys: str) -> re.Pattern:
    return re.compile(rf"^({keys})={_TOKEN}(,({keys})={_TOKEN})*$")


# Allowlisted qemu options -> value validator (None = flag without a value).
# Anything that can name a host file, socket, helper program, or monitor
# (-netdev/-chardev/-monitor/-qmp/-plugin/-drive/-kernel/-object/-add-fd/
# -readconfig/-serial/-incoming/-D/-L/-bios/-pflash/...) is deliberately absent.
QEMU_EXTRA_ARG_RULES: Dict[str, Optional[re.Pattern]] = {
    "-cpu": re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+=,-]{0,255}$"),
    "-machine": re.compile(
        rf"^[A-Za-z0-9][A-Za-z0-9_.-]*(,(accel|usb|smm|kernel-irqchip|gic-version|hpet|vmport|pic|pit)={_TOKEN})*$"
    ),
    "-accel": re.compile(r"^(kvm|tcg|hvf|whpx)(,thread=(single|multi))?$"),
    "-vga": re.compile(r"^(std|virtio|qxl|cirrus|none)$"),
    "-rtc": _kv_list("base|clock|driftfix"),
    "-boot": _kv_list("order|once|menu|strict|reboot-timeout"),
    "-k": re.compile(r"^[a-z]{2}(-[a-z]{2})?$"),
    "-overcommit": re.compile(r"^(mem-lock|cpu-pm)=(on|off)$"),
    "-device": re.compile(
        r"^(virtio-rng-pci|virtio-balloon-pci|virtio-keyboard-pci|virtio-mouse-pci|virtio-tablet-pci|"
        r"virtio-gpu-pci|qemu-xhci|usb-ehci|usb-tablet|usb-kbd|usb-mouse|i6300esb)"
        rf"(,(id|bus|addr)={_TOKEN})*$"
    ),
    "-watchdog-action": re.compile(r"^(reset|shutdown|poweroff|pause|debug|none|inject-nmi)$"),
    "-no-reboot": None,
    "-no-shutdown": None,
    "-nodefaults": None,
    "-snapshot": None,
}
QEMU_EXTRA_ARG_ALIASES = {"-M": "-machine"}


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def get_vm_root() -> str:
    """Directory that must contain every VM's vm_dir and disk (``FORTRESS_VM_ROOT``)."""
    return os.path.realpath(os.environ.get("FORTRESS_VM_ROOT") or DEFAULT_VM_DIR)


def _is_within(path: str, root: str) -> bool:
    return os.path.commonpath([path, root]) == root and path != root


def validate_qemu_binary(binary: Optional[str]) -> Optional[str]:
    """Return the allowlisted bare name, or ``None`` for "auto" (qemu-system-x86_64, then qemu-kvm)."""
    if binary is None or binary == "":
        return None
    if binary not in QEMU_BINARY_ALLOWLIST:
        raise _bad_request(
            "qemu_binary must be one of: " + ", ".join(sorted(QEMU_BINARY_ALLOWLIST)) + " (bare name, resolved via PATH)"
        )
    return binary


def resolve_qemu_executable(binary: Optional[str]) -> Optional[str]:
    """Map a validated qemu_binary to an executable path (``None`` when not installed)."""
    name = validate_qemu_binary(binary)
    candidates = [name] if name else [DEFAULT_QEMU_BINARY, "qemu-kvm"]
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
        if candidate == "qemu-kvm":
            for path in QEMU_KVM_FALLBACK_PATHS:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    return path
    return None


def validate_extra_args(extra_args: Optional[List[str]]) -> List[str]:
    args = list(extra_args or [])
    if len(args) > MAX_EXTRA_ARGS:
        raise _bad_request(f"extra_args accepts at most {MAX_EXTRA_ARGS} items")
    normalized: List[str] = []
    index = 0
    while index < len(args):
        option = args[index]
        if not isinstance(option, str):
            raise _bad_request("extra_args items must be strings")
        canonical = QEMU_EXTRA_ARG_ALIASES.get(option, option)
        if canonical.startswith("--"):
            canonical = canonical[1:]
        if canonical not in QEMU_EXTRA_ARG_RULES:
            raise _bad_request(
                f"extra_args option not allowed: {option!r}; allowed: " + ", ".join(sorted(QEMU_EXTRA_ARG_RULES))
            )
        rule = QEMU_EXTRA_ARG_RULES[canonical]
        normalized.append(canonical)
        index += 1
        if rule is None:
            continue
        if index >= len(args):
            raise _bad_request(f"extra_args option {option} requires a value")
        value = args[index]
        if not isinstance(value, str) or not rule.fullmatch(value):
            raise _bad_request(f"extra_args value not allowed for {option}: {value!r}")
        normalized.append(value)
        index += 1
    return normalized


def validate_bridge_name(bridge: Optional[str]) -> Optional[str]:
    if bridge is None or bridge == "":
        return None
    if not BRIDGE_NAME_PATTERN.fullmatch(bridge):
        raise _bad_request("bridge_name must be 1-15 chars using letters, digits, ., _, or -")
    return bridge


def _validate_plain_path(path: str, field: str) -> str:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise _bad_request(f"{field} must be an absolute path")
    if "," in path or "\x00" in path or "\n" in path:
        raise _bad_request(f"{field} must not contain commas, NUL, or newlines")
    return os.path.realpath(path)


def validate_vm_dir(vm_dir: Optional[str]) -> Optional[str]:
    if not vm_dir:
        return None
    resolved = _validate_plain_path(vm_dir, "vm_dir")
    if not _is_within(resolved, get_vm_root()):
        raise _bad_request(f"vm_dir must be inside {get_vm_root()}")
    return resolved


def validate_disk_path(disk_path: Optional[str]) -> Optional[str]:
    if not disk_path:
        return None
    resolved = _validate_plain_path(disk_path, "disk_path")
    if not _is_within(resolved, get_vm_root()):
        raise _bad_request(f"disk_path must be inside {get_vm_root()}")
    return resolved


def validate_iso_path(iso_path: Optional[str]) -> Optional[str]:
    if not iso_path:
        return None
    resolved = _validate_plain_path(iso_path, "iso_path")
    if not resolved.lower().endswith(".iso"):
        raise _bad_request("iso_path must point to a .iso file")
    return resolved


def validate_vm_resources(record: Dict[str, Any]) -> None:
    limits = {"cpu_cores": MAX_CPU_CORES, "memory_mb": MAX_MEMORY_MB, "disk_gb": MAX_DISK_GB}
    for field, maximum in limits.items():
        value = record.get(field)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > maximum:
            raise _bad_request(f"{field} must be an integer between 1 and {maximum}")
    port = record.get("ssh_forward_port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
        raise _bad_request("ssh_forward_port must be between 1 and 65535")
    os_type = record.get("os_type")
    if os_type and not OS_TYPE_PATTERN.fullmatch(os_type):
        raise _bad_request("os_type must be 1-64 chars using letters, digits, ., _, or -")


def validate_vm_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Validate (and normalize in place) every record field that reaches a host command."""
    validate_vm_resources(record)
    if record.get("qemu_binary") and record.get("provider") not in (None, "qemu"):
        raise _bad_request("qemu_binary is only supported for the qemu provider")
    record["qemu_binary"] = validate_qemu_binary(record.get("qemu_binary"))
    record["extra_args"] = validate_extra_args(record.get("extra_args"))
    if record.get("extra_args") and record.get("provider") not in (None, "qemu"):
        raise _bad_request("extra_args is only supported for the qemu provider")
    record["bridge_name"] = validate_bridge_name(record.get("bridge_name"))
    if record.get("network_mode") == "bridge" and not record.get("bridge_name"):
        raise _bad_request("bridge_name is required for bridge networking")
    record["vm_dir"] = validate_vm_dir(record.get("vm_dir"))
    record["disk_path"] = validate_disk_path(record.get("disk_path"))
    record["iso_path"] = validate_iso_path(record.get("iso_path"))
    return record


class VMSSHConfig(SSHConfig):
    pass


class VMCreateRequest(BaseModel):
    name: str
    provider: Literal["qemu", "utm", "virtualbox"]
    cpu_cores: int = 2
    memory_mb: int = 2048
    disk_gb: int = 20
    disk_path: Optional[str] = None
    iso_path: Optional[str] = None
    os_type: Optional[str] = None
    vm_dir: Optional[str] = None
    qemu_binary: Optional[str] = None
    network_mode: Literal["user", "bridge"] = "user"
    bridge_name: Optional[str] = None
    ssh_forward_port: Optional[int] = None
    extra_args: List[str] = Field(default_factory=list)
    ssh: Optional[VMSSHConfig] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    notes: Optional[str] = None
    installed: bool = False


class VMUpdateRequest(BaseModel):
    cpu_cores: Optional[int] = None
    memory_mb: Optional[int] = None
    disk_gb: Optional[int] = None
    disk_path: Optional[str] = None
    iso_path: Optional[str] = None
    os_type: Optional[str] = None
    vm_dir: Optional[str] = None
    qemu_binary: Optional[str] = None
    network_mode: Optional[Literal["user", "bridge"]] = None
    bridge_name: Optional[str] = None
    ssh_forward_port: Optional[int] = None
    extra_args: Optional[List[str]] = None
    ssh: Optional[VMSSHConfig] = None
    labels: Optional[Dict[str, str]] = None
    notes: Optional[str] = None
    installed: Optional[bool] = None


class VMStartRequest(BaseModel):
    headless: bool = True
    use_iso: bool = False
    iso_path: Optional[str] = None


class VMStopRequest(BaseModel):
    force: bool = False


class VMSnapshotRequest(BaseModel):
    name: str
    description: Optional[str] = None


class VMProvisionRequest(BaseModel):
    profile: Literal["ubuntu", "fedora"] = "ubuntu"
    repo_url: Optional[str] = None
    branch: str = "main"
    install_dir: str = "/opt/linus-fortress"
    service_name: str = "fortress"
    fortress_port: int = 8443
    api_key: Optional[str] = None
    user_token: Optional[str] = None
    backup_password: Optional[str] = None
    skip_service: bool = False
    force_reset: bool = False
    ssh: Optional[VMSSHConfig] = None


class VMProbeRequest(BaseModel):
    save_as: Optional[str] = None
    ssh: Optional[VMSSHConfig] = None


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def validate_vm_name(name: str) -> None:
    if not name or not VM_NAME_PATTERN.fullmatch(name):
        raise HTTPException(status_code=400, detail="VM name must be 1-64 chars using letters, digits, ., _, or -")


def normalize_provider(provider: str) -> str:
    if provider == "utm":
        return "qemu"
    return provider


def load_vms(path: str) -> Dict[str, Dict[str, Any]]:
    return load_json_dict(path, label="VM")


def save_vms(path: str, vms: Dict[str, Dict[str, Any]]) -> None:
    save_json(path, vms)


def sanitize_vm_record(record: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(record)
    ssh = sanitized.get("ssh")
    if isinstance(ssh, dict):
        ssh_copy = dict(ssh)
        if ssh_copy.get("password"):
            ssh_copy["password"] = "***"
            ssh_copy["has_password"] = True
        else:
            ssh_copy["has_password"] = False
        sanitized["ssh"] = ssh_copy
    return sanitized


def build_vm_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    ssh = record.get("ssh") or {}
    return {
        "name": record.get("name"),
        "provider": record.get("provider_display", record.get("provider")),
        "state": record.get("state", "unknown"),
        "os_type": record.get("os_type"),
        "installed": record.get("installed", False),
        "ssh_host": ssh.get("host"),
        "ssh_port": ssh.get("port"),
        "labels": record.get("labels", {}),
        "updated_at": record.get("updated_at"),
    }


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def _resolve_vm_dir(record: Dict[str, Any]) -> str:
    vm_dir = record.get("vm_dir")
    if vm_dir:
        return vm_dir
    return os.path.join(get_vm_root(), record["name"])


def _ensure_disk_path(record: Dict[str, Any]) -> None:
    vm_dir = _resolve_vm_dir(record)
    record["vm_dir"] = vm_dir
    if not record.get("disk_path"):
        extension = "qcow2" if record["provider"] == "qemu" else "vdi"
        record["disk_path"] = os.path.join(vm_dir, f"{record['name']}.{extension}")
    ensure_parent_dir(record["disk_path"])


def _ensure_iso_path(record: Dict[str, Any], iso_path: Optional[str]) -> Optional[str]:
    resolved = validate_iso_path(iso_path or record.get("iso_path"))
    if resolved and not os.path.isfile(resolved):
        raise HTTPException(status_code=400, detail=f"ISO not found at {resolved}")
    return resolved


def _ensure_qemu_tools(record: Dict[str, Any]) -> str:
    binary = resolve_qemu_executable(record.get("qemu_binary"))
    if binary is None:
        wanted = record.get("qemu_binary") or f"{DEFAULT_QEMU_BINARY} or qemu-kvm"
        raise HTTPException(status_code=500, detail=f"QEMU binary not found: {wanted}")
    if shutil.which("qemu-img") is None:
        raise HTTPException(status_code=500, detail="qemu-img not found; install qemu-utils")
    return binary


def _ensure_virtualbox_tools() -> None:
    if shutil.which("VBoxManage") is None:
        raise HTTPException(status_code=500, detail="VBoxManage not found; install VirtualBox")


def _create_qemu_disk(record: Dict[str, Any]) -> None:
    if os.path.exists(record["disk_path"]):
        raise HTTPException(status_code=409, detail="Disk path already exists")
    run_command(["qemu-img", "create", "-f", "qcow2", record["disk_path"], f"{record['disk_gb']}G"])


def _create_virtualbox_disk(record: Dict[str, Any]) -> None:
    if os.path.exists(record["disk_path"]):
        raise HTTPException(status_code=409, detail="Disk path already exists")
    size_mb = int(record["disk_gb"]) * 1024
    run_command(["VBoxManage", "createhd", "--filename", record["disk_path"], "--size", str(size_mb)])


def _create_virtualbox_vm(record: Dict[str, Any]) -> None:
    _ensure_virtualbox_tools()
    run_command(["VBoxManage", "createvm", "--name", record["name"], "--register"])
    modify_cmd = [
        "VBoxManage",
        "modifyvm",
        record["name"],
        "--memory",
        str(record["memory_mb"]),
        "--cpus",
        str(record["cpu_cores"]),
    ]
    if record.get("os_type"):
        modify_cmd.extend(["--ostype", record["os_type"]])
    run_command(modify_cmd)
    run_command(["VBoxManage", "storagectl", record["name"], "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"])
    run_command([
        "VBoxManage",
        "storageattach",
        record["name"],
        "--storagectl",
        "SATA",
        "--port",
        "0",
        "--device",
        "0",
        "--type",
        "hdd",
        "--medium",
        record["disk_path"],
    ])
    iso_path = record.get("iso_path")
    if iso_path:
        run_command([
            "VBoxManage",
            "storageattach",
            record["name"],
            "--storagectl",
            "SATA",
            "--port",
            "1",
            "--device",
            "0",
            "--type",
            "dvddrive",
            "--medium",
            iso_path,
        ])
    if record.get("ssh_forward_port"):
        port = record["ssh_forward_port"]
        run_command([
            "VBoxManage",
            "modifyvm",
            record["name"],
            "--natpf1",
            f"ssh,tcp,,{port},,22",
        ])


def _qemu_pid_file(record: Dict[str, Any]) -> str:
    return os.path.join(_resolve_vm_dir(record), f"{record['name']}.pid")


def _build_qemu_network(record: Dict[str, Any]) -> List[str]:
    mode = record.get("network_mode", "user")
    if mode == "bridge":
        bridge = validate_bridge_name(record.get("bridge_name"))
        if not bridge:
            raise HTTPException(status_code=400, detail="bridge_name is required for bridge networking")
        return ["-netdev", f"bridge,id=net0,br={bridge}", "-device", "virtio-net-pci,netdev=net0"]
    ssh_forward = record.get("ssh_forward_port")
    if ssh_forward:
        return ["-netdev", f"user,id=net0,hostfwd=tcp::{ssh_forward}-:22", "-device", "virtio-net-pci,netdev=net0"]
    return ["-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0"]


def _start_qemu_vm(record: Dict[str, Any], request: VMStartRequest) -> None:
    validate_vm_record(record)  # re-check stored values; legacy records predate validation
    binary = _ensure_qemu_tools(record)
    pid_file = _qemu_pid_file(record)
    iso_path = _ensure_iso_path(record, request.iso_path if request.use_iso else None)
    cmd = [
        binary,
        "-name",
        record["name"],
        "-m",
        str(record["memory_mb"]),
        "-smp",
        str(record["cpu_cores"]),
        "-drive",
        f"file={record['disk_path']},format=qcow2,if=virtio",
        "-daemonize",
        "-pidfile",
        pid_file,
    ]
    if os.path.exists("/dev/kvm"):
        cmd.append("-enable-kvm")
    if request.headless:
        cmd.extend(["-display", "none"])
    if iso_path:
        cmd.extend(["-cdrom", iso_path, "-boot", "order=d"])
    cmd.extend(_build_qemu_network(record))
    cmd.extend(validate_extra_args(record.get("extra_args")))
    run_command(cmd)
    record["pid_file"] = pid_file


def _stop_qemu_vm(record: Dict[str, Any], force: bool) -> None:
    pid_file = record.get("pid_file") or _qemu_pid_file(record)
    if not os.path.exists(pid_file):
        return
    try:
        with open(pid_file, "r") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return
    if not _pid_is_running(pid):
        return
    os.kill(pid, signal.SIGTERM)
    for _ in range(10):
        if not _pid_is_running(pid):
            return
        time.sleep(0.5)
    if force:
        os.kill(pid, signal.SIGKILL)


def _status_qemu_vm(record: Dict[str, Any]) -> str:
    pid_file = record.get("pid_file") or _qemu_pid_file(record)
    if not os.path.exists(pid_file):
        return "stopped"
    try:
        with open(pid_file, "r") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return "unknown"
    return "running" if _pid_is_running(pid) else "stopped"


def _start_virtualbox_vm(record: Dict[str, Any], request: VMStartRequest) -> None:
    _ensure_virtualbox_tools()
    run_command(["VBoxManage", "startvm", record["name"], "--type", "headless" if request.headless else "gui"])


def _stop_virtualbox_vm(record: Dict[str, Any], force: bool) -> None:
    _ensure_virtualbox_tools()
    cmd = ["VBoxManage", "controlvm", record["name"], "poweroff" if force else "acpipowerbutton"]
    run_command(cmd)


def _status_virtualbox_vm(record: Dict[str, Any]) -> str:
    _ensure_virtualbox_tools()
    output = run_command(["VBoxManage", "showvminfo", record["name"], "--machinereadable"])
    state = "unknown"
    for line in output.splitlines():
        if line.startswith("VMState="):
            state = line.split("=", 1)[1].strip().strip('"')
            break
    return "running" if state == "running" else "stopped"


def _require_qemu_stopped(record: Dict[str, Any], action: str) -> None:
    # qemu-img needs the image write lock; a running guest holds it (and restoring under it would corrupt the disk).
    if _status_qemu_vm(record) == "running":
        raise HTTPException(status_code=409, detail=f"Stop the VM before {action} a QEMU snapshot")


def _snapshot_qemu(record: Dict[str, Any], snapshot_name: str) -> None:
    _require_qemu_stopped(record, "creating")
    if not record.get("disk_path"):
        raise HTTPException(status_code=400, detail="disk_path missing for QEMU snapshot")
    run_command(["qemu-img", "snapshot", "-c", snapshot_name, record["disk_path"]])


def _snapshot_qemu_restore(record: Dict[str, Any], snapshot_name: str) -> None:
    _require_qemu_stopped(record, "restoring")
    run_command(["qemu-img", "snapshot", "-a", snapshot_name, record["disk_path"]])


def _snapshot_qemu_delete(record: Dict[str, Any], snapshot_name: str) -> None:
    _require_qemu_stopped(record, "deleting")
    run_command(["qemu-img", "snapshot", "-d", snapshot_name, record["disk_path"]])


def _snapshot_virtualbox(record: Dict[str, Any], snapshot_name: str, description: Optional[str]) -> None:
    cmd = ["VBoxManage", "snapshot", record["name"], "take", snapshot_name]
    if description:
        cmd.extend(["--description", description])
    run_command(cmd)


def _snapshot_virtualbox_restore(record: Dict[str, Any], snapshot_name: str) -> None:
    run_command(["VBoxManage", "snapshot", record["name"], "restore", snapshot_name])


def _snapshot_virtualbox_delete(record: Dict[str, Any], snapshot_name: str) -> None:
    run_command(["VBoxManage", "snapshot", record["name"], "delete", snapshot_name])


def _resolve_vm(vms: Dict[str, Dict[str, Any]], name: str) -> Dict[str, Any]:
    record = vms.get(name)
    if not record:
        raise HTTPException(status_code=404, detail="VM not found")
    return record


def create_vm(payload: VMCreateRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    validate_vm_name(payload.name)
    if payload.name in vms:
        raise HTTPException(status_code=409, detail="VM already exists")
    record = payload.dict()
    if record.get("ssh"):
        validate_ssh_config(record["ssh"])
    record["provider"] = normalize_provider(payload.provider)
    record["provider_display"] = payload.provider
    validate_vm_record(record)
    record["created_at"] = utc_now()
    record["updated_at"] = record["created_at"]
    record["state"] = "stopped"
    record["snapshots"] = []
    record["saved_states"] = []
    _ensure_disk_path(record)
    _ensure_iso_path(record, record.get("iso_path"))
    if record["provider"] == "qemu":
        _ensure_qemu_tools(record)
        _create_qemu_disk(record)
    elif record["provider"] == "virtualbox":
        _create_virtualbox_disk(record)
        _create_virtualbox_vm(record)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    vms[payload.name] = record
    return record


def update_vm(name: str, payload: VMUpdateRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    updates = payload.dict(exclude_unset=True)
    candidate = dict(record)  # validate before touching the stored record
    if "ssh" in updates and updates["ssh"] is not None:
        candidate["ssh"] = validate_ssh_config(updates["ssh"])
    for key in [
        "cpu_cores",
        "memory_mb",
        "disk_gb",
        "disk_path",
        "iso_path",
        "os_type",
        "vm_dir",
        "qemu_binary",
        "network_mode",
        "bridge_name",
        "ssh_forward_port",
        "extra_args",
        "labels",
        "notes",
        "installed",
    ]:
        if key in updates and updates[key] is not None:
            candidate[key] = updates[key]
    validate_vm_record(candidate)
    if "iso_path" in updates:
        _ensure_iso_path(candidate, candidate.get("iso_path"))
    record.clear()
    record.update(candidate)
    record["updated_at"] = utc_now()
    return record


def delete_vm(name: str, vms: Dict[str, Dict[str, Any]], purge: bool = False, force: bool = False) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if purge:
        if record.get("provider") == "virtualbox":
            _stop_virtualbox_vm(record, force=True)
            run_command(["VBoxManage", "unregistervm", name, "--delete"])
        elif record.get("provider") == "qemu":
            root = get_vm_root()
            disk_path = os.path.realpath(record["disk_path"]) if record.get("disk_path") else None
            vm_dir = os.path.realpath(record["vm_dir"]) if record.get("vm_dir") else None
            for label, path in (("disk_path", disk_path), ("vm_dir", vm_dir)):
                if path and not _is_within(path, root):
                    raise _bad_request(
                        f"Refusing to purge {label} outside {root}; delete without purge and clean up manually"
                    )
            _stop_qemu_vm(record, force=True)
            if disk_path and os.path.isfile(disk_path):
                os.remove(disk_path)
            if vm_dir and os.path.isdir(vm_dir):
                shutil.rmtree(vm_dir, ignore_errors=True)
    vms.pop(name, None)
    return record


def start_vm(name: str, request: VMStartRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if record.get("provider") == "qemu":
        _start_qemu_vm(record, request)
    elif record.get("provider") == "virtualbox":
        _start_virtualbox_vm(record, request)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    record["state"] = "running"
    record["last_start_at"] = utc_now()
    record["updated_at"] = record["last_start_at"]
    return record


def stop_vm(name: str, request: VMStopRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if record.get("provider") == "qemu":
        _stop_qemu_vm(record, request.force)
    elif record.get("provider") == "virtualbox":
        _stop_virtualbox_vm(record, request.force)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    record["state"] = "stopped"
    record["last_stop_at"] = utc_now()
    record["updated_at"] = record["last_stop_at"]
    return record


def vm_status(name: str, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if record.get("provider") == "qemu":
        state = _status_qemu_vm(record)
    elif record.get("provider") == "virtualbox":
        state = _status_virtualbox_vm(record)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    record["state"] = state
    record["updated_at"] = utc_now()
    return {"name": name, "state": state, "provider": record.get("provider_display", record.get("provider"))}


def create_snapshot(name: str, request: VMSnapshotRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    for existing in record.get("snapshots", []):
        if existing.get("name") == request.name:
            raise HTTPException(status_code=409, detail="Snapshot already exists")
    if record.get("provider") == "qemu":
        _snapshot_qemu(record, request.name)
    elif record.get("provider") == "virtualbox":
        _snapshot_virtualbox(record, request.name, request.description)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    snapshot = {"name": request.name, "description": request.description, "created_at": utc_now()}
    record.setdefault("snapshots", []).append(snapshot)
    record["last_snapshot"] = snapshot
    record["updated_at"] = snapshot["created_at"]
    return snapshot


def restore_snapshot(name: str, snapshot_name: str, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if record.get("provider") == "qemu":
        _snapshot_qemu_restore(record, snapshot_name)
    elif record.get("provider") == "virtualbox":
        _snapshot_virtualbox_restore(record, snapshot_name)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    record["last_snapshot_restore"] = {"name": snapshot_name, "restored_at": utc_now()}
    record["updated_at"] = record["last_snapshot_restore"]["restored_at"]
    return record["last_snapshot_restore"]


def delete_snapshot(name: str, snapshot_name: str, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    if record.get("provider") == "qemu":
        _snapshot_qemu_delete(record, snapshot_name)
    elif record.get("provider") == "virtualbox":
        _snapshot_virtualbox_delete(record, snapshot_name)
    else:
        raise HTTPException(status_code=400, detail="Unsupported VM provider")
    snapshots = [snap for snap in record.get("snapshots", []) if snap.get("name") != snapshot_name]
    record["snapshots"] = snapshots
    record["updated_at"] = utc_now()
    return {"deleted": snapshot_name}


def list_snapshots(name: str, vms: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    record = _resolve_vm(vms, name)
    return record.get("snapshots", [])


def _resolve_ssh_config(record: Dict[str, Any], override: Optional[VMSSHConfig]) -> Dict[str, Any]:
    if override is not None:
        return override.dict()
    ssh = record.get("ssh")
    if not ssh:
        raise HTTPException(status_code=400, detail="SSH config missing for VM")
    return ssh


def provision_vm(name: str, request: VMProvisionRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    script = load_provision_script(request.profile)
    ssh_config = _resolve_ssh_config(record, request.ssh)
    env = {
        "REPO_URL": request.repo_url,
        "BRANCH": request.branch,
        "INSTALL_DIR": request.install_dir,
        "SERVICE_NAME": request.service_name,
        "FORTRESS_HOST_PORT": request.fortress_port,
        "FORTRESS_API_KEY": request.api_key,
        "FORTRESS_USER_TOKEN": request.user_token,
        "FORTRESS_BACKUP_PASSWORD": request.backup_password,
        "SKIP_SERVICE": "1" if request.skip_service else None,
        "FORCE_RESET": "1" if request.force_reset else None,
    }
    output = run_ssh_script(ssh_config, script, env=env)
    record["last_provisioned_at"] = utc_now()
    record["last_provision_profile"] = request.profile
    record["service_name"] = request.service_name
    record["updated_at"] = record["last_provisioned_at"]
    return {"output": output.strip(), "profile": request.profile}


def probe_vm(name: str, request: VMProbeRequest, vms: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_vm(vms, name)
    ssh_config = _resolve_ssh_config(record, request.ssh)
    script = build_probe_script(record.get("service_name", "fortress"))
    output = run_ssh_script(ssh_config, script)
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Probe returned invalid JSON: {exc}")
    timestamp = utc_now()
    record["last_probe"] = payload
    record["last_probe_at"] = timestamp
    if request.save_as:
        record.setdefault("saved_states", []).append({
            "name": request.save_as,
            "timestamp": timestamp,
            "data": payload,
        })
    record["updated_at"] = timestamp
    return payload
