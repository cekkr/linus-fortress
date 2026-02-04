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
SENSITIVE_KEYWORDS = {"password", "passwd", "secret", "token", "key", "chpasswd", "pwd", "identified"}
MAX_PORT = 65535
MIN_PORT = 1
MAX_PROXY_DEVICES_PER_REQUEST = 50

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


def validate_port(port: int, field: str) -> None:
    """Ensure port numbers are sane before configuring LXD proxy devices."""
    if port < MIN_PORT or port > MAX_PORT:
        raise HTTPException(status_code=400, detail=f"{field} must be between {MIN_PORT}-{MAX_PORT}")


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


CONTAINER_SERVICE_PROBES = {
    "apache": {"bins": ["apache2", "httpd"]},
    "nginx": {"bins": ["nginx"]},
    "mysql": {"bins": ["mysqld", "mariadbd", "mysql"]},
    "ftp": {"bins": ["vsftpd"]},
    "filemanager": {"paths": ["/var/www/html/filemanager/index.php", "/var/www/html/tinyfilemanager.php"]},
}


def probe_container_services(container_name: str, services: Optional[List[str]] = None) -> Dict[str, bool]:
    requested = [service.lower() for service in services] if services else list(CONTAINER_SERVICE_PROBES.keys())
    unknown = [service for service in requested if service not in CONTAINER_SERVICE_PROBES]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown services: {', '.join(sorted(unknown))}")
    script_lines = [
        "check_cmd() { command -v \"$1\" >/dev/null 2>&1; }",
        "emit() { printf '%s=%s\\n' \"$1\" \"$2\"; }",
    ]
    for service in requested:
        probe = CONTAINER_SERVICE_PROBES[service]
        checks: List[str] = []
        for binary in probe.get("bins", []):
            checks.append(f"check_cmd {shlex.quote(binary)}")
        for path in probe.get("paths", []):
            checks.append(f"test -f {shlex.quote(path)}")
        condition = " || ".join(checks) if checks else "false"
        script_lines.append(f"if {condition}; then emit {service} 1; else emit {service} 0; fi")
    output = exec_in_container(container_name, ["sh", "-c", "; ".join(script_lines)])
    results: Dict[str, bool] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.strip().split("=", 1)
        results[key] = value.strip() == "1"
    for service in requested:
        results.setdefault(service, False)
    return results


def set_container_services_label(container_name: str, services: Dict[str, bool]) -> str:
    available = sorted([name for name, status in services.items() if status])
    value = ",".join(available)
    for key in ("user.lizard.services", "user.fortress.services"):
        run_command(["lxc", "config", "set", container_name, key, value])
    return value


def detect_package_manager(container_name: Optional[str] = None) -> str:
    candidates = [("apt", "apt-get"), ("dnf", "dnf"), ("yum", "yum")]
    for name, binary in candidates:
        if container_name:
            if container_has_binary(container_name, binary):
                return name
        else:
            if shutil.which(binary):
                return name
    raise HTTPException(status_code=500, detail="No supported package manager (apt, dnf, or yum) detected")


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
    elif manager == "yum":
        run_package_command(["yum", "makecache"], container_name)


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


def start_container(name: str) -> None:
    run_command(["lxc", "start", name])


def stop_container(name: str, force: bool = False) -> None:
    cmd = ["lxc", "stop", name]
    if force:
        cmd.append("--force")
    run_command(cmd)


def restart_container(name: str, force: bool = False) -> None:
    try:
        stop_container(name, force=force)
    finally:
        start_container(name)


def list_snapshots(name: str) -> List[str]:
    info_json = run_command(["lxc", "info", name, "--format", "json"])
    try:
        info = json.loads(info_json)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse snapshot list: {exc}")
    snapshots = info.get("Snapshots") or info.get("snapshots") or []
    names: List[str] = []
    for snap in snapshots:
        if isinstance(snap, dict):
            snap_name = snap.get("name") or snap.get("Name")
            if snap_name:
                names.append(snap_name)
        elif isinstance(snap, str):
            names.append(snap)
    return names


def create_snapshot(name: str, snapshot_name: str, stateful: bool = False) -> None:
    cmd = ["lxc", "snapshot", name, snapshot_name]
    if stateful:
        cmd.append("--stateful")
    run_command(cmd)


def restore_snapshot(name: str, snapshot_name: str, stateful: bool = False) -> None:
    cmd = ["lxc", "restore", name, snapshot_name]
    if stateful:
        cmd.append("--stateful")
    run_command(cmd)


def delete_snapshot(name: str, snapshot_name: str) -> None:
    run_command(["lxc", "delete", f"{name}/{snapshot_name}"])


def get_container_logs(name: str) -> str:
    return run_command(["lxc", "info", name, "--show-log"])


def exec_in_container_advanced(
    container_name: str,
    command: List[str],
    *,
    user: Optional[str] = None,
    workdir: Optional[str] = None,
    environment: Optional[Dict[str, str]] = None,
) -> str:
    if not command:
        raise HTTPException(status_code=400, detail="Command is required")
    base_cmd = ["lxc", "exec", container_name]
    env = environment or {}
    for key, value in env.items():
        base_cmd.extend(["--env", f"{key}={value}"])
    if workdir:
        base_cmd.extend(["--cwd", workdir])
    if user:
        base_cmd.extend(["--user", user])
    base_cmd.append("--")
    base_cmd += command
    details = sanitize_command_details(command)
    try:
        result = run_command(base_cmd)
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


def resolve_device_name(service: str, host_port: Optional[int], device_name: Optional[str]) -> str:
    port = host_port or SERVICE_DEFAULT_PORTS[service]
    return device_name or f"{service}-{port}"


def add_proxy_device(container_name: str, device_name: str, listen_arg: str, connect_arg: str) -> None:
    run_command(["lxc", "config", "device", "add", container_name, device_name, "proxy", listen_arg, connect_arg])


def remove_device(container_name: str, device_name: str) -> None:
    run_command(["lxc", "config", "device", "remove", container_name, device_name])


def _expand_port_inputs(host_ports: Optional[List[int]], port_range: Optional[Dict[str, int]], fallback_port: Optional[int]) -> List[int]:
    """Normalize host port inputs into a unique, sorted list with sane limits."""
    ports: List[int] = []
    if host_ports:
        ports.extend(host_ports)
    if port_range:
        start = port_range.get("start")
        end = port_range.get("end")
        if start is None or end is None:
            raise HTTPException(status_code=400, detail="port_range requires start and end")
        if start > end:
            raise HTTPException(status_code=400, detail="port_range start must be <= end")
        ports.extend(list(range(start, end + 1)))
    if not ports and fallback_port:
        ports.append(fallback_port)
    unique_ports = sorted(set(ports))
    if not unique_ports:
        raise HTTPException(status_code=400, detail="No host ports provided")
    if len(unique_ports) > MAX_PROXY_DEVICES_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Requested ports exceed limit of {MAX_PROXY_DEVICES_PER_REQUEST}")
    for port in unique_ports:
        validate_port(port, "host_port")
    return unique_ports


def open_external_access(
    container_name: str,
    service: str,
    host_port: Optional[int],
    connect_port: Optional[int],
    bind_address: str,
    connect_address: Optional[str],
    connect_interface: Optional[str],
    device_name: Optional[str],
) -> Dict[str, Any]:
    service_port = SERVICE_DEFAULT_PORTS[service]
    actual_host_port = host_port or service_port
    actual_connect_port = connect_port or service_port
    validate_port(actual_host_port, "host_port")
    validate_port(actual_connect_port, "connect_port")
    if connect_interface:
        connect_address = get_container_ip(container_name, connect_interface)
    connect_addr = connect_address or "127.0.0.1"
    resolved_device = resolve_device_name(service, actual_host_port, device_name)
    listen_arg = f"listen=tcp:{bind_address}:{actual_host_port}"
    connect_arg = f"connect=tcp:{connect_addr}:{actual_connect_port}"
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
    target_interface: Optional[str],
    target_address: Optional[str],
    device_name: Optional[str],
) -> str:
    validate_port(listen_port, "listen_port")
    validate_port(target_port, "target_port")
    target_ip = target_address or get_container_ip(target_container, target_interface or "eth0")
    resolved_device = device_name or f"link-{target_container}-{listen_port}"
    listen = f"listen={protocol}:{bind_address}:{listen_port}"
    connect = f"connect={protocol}:{target_ip}:{target_port}"
    add_proxy_device(source_container, resolved_device, listen, connect)
    return resolved_device


def expose_ports(
    container_name: str,
    protocol: str,
    bind_address: str,
    host_ports: Optional[List[int]],
    port_range: Optional[Dict[str, int]],
    container_port: Optional[int],
    target_interface: Optional[str],
    target_address: Optional[str],
    device_name_prefix: Optional[str],
) -> List[Dict[str, Any]]:
    """Expose one or more host ports to a container interface via LXD proxy devices."""
    ports = _expand_port_inputs(host_ports, port_range, container_port)
    target_ip = target_address or get_container_ip(container_name, target_interface or "eth0")
    prefix = device_name_prefix or f"expose-{protocol}"
    created: List[Dict[str, Any]] = []
    try:
        for host_port in ports:
            connect_port = container_port or host_port
            validate_port(connect_port, "container_port")
            device_name = f"{prefix}-{host_port}"
            listen = f"listen={protocol}:{bind_address}:{host_port}"
            connect = f"connect={protocol}:{target_ip}:{connect_port}"
            add_proxy_device(container_name, device_name, listen, connect)
            created.append(
                {
                    "device_name": device_name,
                    "host_port": host_port,
                    "connect_port": connect_port,
                    "target_ip": target_ip,
                    "protocol": protocol,
                    "bind_address": bind_address,
                }
            )
        return created
    except Exception as exc:
        for item in created:
            try:
                remove_device(container_name, item["device_name"])
            except Exception:
                logging.exception("Failed to rollback device %s on %s", item["device_name"], container_name)
        raise exc


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
