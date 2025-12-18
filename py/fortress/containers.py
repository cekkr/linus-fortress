import json
import logging
import os
import shlex
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional

from fastapi import HTTPException

from fortress.system import run_command

SERVICE_DEFAULT_PORTS = {"ssh": 22, "ftp": 21}
SENSITIVE_KEYWORDS = {"password", "passwd", "secret", "token", "key", "chpasswd"}

AuditCallback = Callable[[str, str, Optional[str], Optional[Dict[str, Any]], str], None]
_AUDIT_CALLBACK: Optional[AuditCallback] = None


def configure_audit(callback: Optional[AuditCallback]) -> None:
    global _AUDIT_CALLBACK
    _AUDIT_CALLBACK = callback


def _audit(
    category: str,
    action: str,
    target: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status: str = "success",
) -> None:
    if not _AUDIT_CALLBACK:
        return
    try:
        _AUDIT_CALLBACK(category, action, target, details, status)
    except Exception:
        logging.exception("Audit callback failed")


def sanitize_command_details(command: List[str]) -> Dict[str, Any]:
    if not command:
        return {"command": "", "arg_preview": [], "arg_length": 0}
    preview = []
    for arg in command[1:6]:
        if any(keyword in arg.lower() for keyword in SENSITIVE_KEYWORDS):
            preview.append("***")
        else:
            preview.append(arg[:64])
    return {
        "command": command[0],
        "arg_preview": preview,
        "arg_length": max(len(command) - 1, 0),
    }


def get_container_ip(container_name: str, interface: str = "eth0") -> str:
    info_json = run_command(["lxc", "list", container_name, "--format", "json"])
    info = json.loads(info_json)
    try:
        return info[0]["state"]["network"][interface]["addresses"][0]["address"]
    except (IndexError, KeyError):
        raise HTTPException(status_code=404, detail="Container IP not found. Is it running?")


def exec_in_container(container_name: str, command: List[str]) -> str:
    cmd = ["lxc", "exec", container_name, "--"] + command
    details = sanitize_command_details(command)
    try:
        result = run_command(cmd)
        _audit("container_exec", f"exec:{details['command']}", target=container_name, details=details)
        return result
    except HTTPException as exc:
        error_details = dict(details)
        error_details["error"] = exc.detail
        _audit(
            "container_exec",
            f"exec:{details['command']}",
            target=container_name,
            details=error_details,
            status="error",
        )
        raise


def set_container_password(container_name: str, username: str, password: str) -> None:
    credential = f"{username}:{password}"
    exec_in_container(container_name, ["bash", "-c", f"echo {shlex.quote(credential)} | chpasswd"])


def container_has_binary(container_name: str, binary: str) -> bool:
    test_cmd = ["lxc", "exec", container_name, "--", "sh", "-c", f"command -v {shlex.quote(binary)}"]
    result = subprocess.run(test_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode == 0


def detect_package_manager(container_name: Optional[str] = None) -> str:
    candidates = [("apt", "apt-get"), ("dnf", "dnf")]
    for name, binary in candidates:
        if container_name:
            if container_has_binary(container_name, binary):
                return name
        else:
            if shutil.which(binary):
                return name
    raise HTTPException(status_code=500, detail="No supported package manager (apt or dnf) detected")


def run_package_command(cmd: List[str], container_name: Optional[str]) -> None:
    if container_name:
        exec_in_container(container_name, cmd)
    else:
        run_command(cmd)


def update_package_index(manager: str, container_name: Optional[str]) -> None:
    if manager == "apt":
        run_package_command(["apt-get", "update"], container_name)
    elif manager == "dnf":
        run_package_command(["dnf", "makecache"], container_name)


def create_container(
    name: str,
    distro: str,
    cpu_limit: str,
    ram_limit: str,
    disk_limit: Optional[str],
) -> None:
    run_command(["lxc", "launch", distro, name])
    run_command(["lxc", "config", "set", name, "limits.cpu", cpu_limit])
    run_command(["lxc", "config", "set", name, "limits.memory", ram_limit])
    run_command(["lxc", "config", "set", name, "security.nesting", "true"])
    if disk_limit:
        run_command(["lxc", "config", "device", "set", name, "root", "size", disk_limit])


def delete_container(name: str) -> None:
    run_command(["lxc", "delete", name, "--force"])


def resolve_device_name(service: str, host_port: Optional[int], device_name: Optional[str]) -> str:
    port = host_port or SERVICE_DEFAULT_PORTS[service]
    return device_name or f"{service}-{port}"


def add_proxy_device(container_name: str, device_name: str, listen_arg: str, connect_arg: str) -> None:
    run_command(["lxc", "config", "device", "add", container_name, device_name, "proxy", listen_arg, connect_arg])


def remove_device(container_name: str, device_name: str) -> None:
    run_command(["lxc", "config", "device", "remove", container_name, device_name])


def open_external_access(
    container_name: str,
    service: str,
    host_port: Optional[int],
    connect_port: Optional[int],
    bind_address: str,
    connect_address: str,
    device_name: Optional[str],
) -> Dict[str, Any]:
    service_port = SERVICE_DEFAULT_PORTS[service]
    actual_host_port = host_port or service_port
    actual_connect_port = connect_port or service_port
    resolved_device = resolve_device_name(service, actual_host_port, device_name)
    listen_arg = f"listen=tcp:{bind_address}:{actual_host_port}"
    connect_arg = f"connect=tcp:{connect_address}:{actual_connect_port}"
    add_proxy_device(container_name, resolved_device, listen_arg, connect_arg)
    return {
        "device_name": resolved_device,
        "host_port": actual_host_port,
        "connect_port": actual_connect_port,
    }


def connect_containers_network(
    source_container: str,
    target_container: str,
    listen_port: int,
    target_port: int,
    bind_address: str,
    protocol: str,
    device_name: Optional[str],
) -> str:
    target_ip = get_container_ip(target_container)
    resolved_device = device_name or f"link-{target_container}-{listen_port}"
    listen = f"listen={protocol}:{bind_address}:{listen_port}"
    connect = f"connect={protocol}:{target_ip}:{target_port}"
    add_proxy_device(source_container, resolved_device, listen, connect)
    return resolved_device


def add_disk_device(container_name: str, device_name: str, source: str, path: str) -> None:
    run_command(
        [
            "lxc",
            "config",
            "device",
            "add",
            container_name,
            device_name,
            "disk",
            f"source={source}",
            f"path={path}",
        ]
    )


def remove_disk_device(container_name: str, device_name: str) -> None:
    run_command(["lxc", "config", "device", "remove", container_name, device_name])


def create_shared_mount(
    share_name: str,
    containers: List[str],
    mount_path: str,
    source_path: Optional[str],
    shared_storage_dir: str,
) -> List[Dict[str, str]]:
    host_path = source_path or os.path.join(shared_storage_dir, share_name)
    os.makedirs(host_path, exist_ok=True)
    attached: List[Dict[str, str]] = []
    for container in containers:
        device_name = f"{share_name}-{container}"
        add_disk_device(container, device_name, host_path, mount_path)
        attached.append({"container": container, "device_name": device_name})
    return attached


def remove_shared_mount(share_name: str, containers: List[str]) -> None:
    for container in containers:
        device_name = f"{share_name}-{container}"
        remove_disk_device(container, device_name)
