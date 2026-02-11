import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests
from fastapi import HTTPException

from fortress.system import run_command

SERVICE_DEFAULT_PORTS = {"ssh": 22, "ftp": 21}
SENSITIVE_KEYWORDS = {"password", "passwd", "secret", "token", "key", "chpasswd", "pwd", "identified"}
MAX_PORT = 65535
MIN_PORT = 1
MAX_PROXY_DEVICES_PER_REQUEST = 50
UBUNTU_LTS_PATTERN = re.compile(r"^(?P<year>\d{2})\.04$")
DEBIAN_VERSION_PATTERN = re.compile(r"^(?P<version>\d+)$")
PUBLIC_IMAGE_PRODUCT_PATTERN = re.compile(r"^(?P<distro>[^:]+):(?P<release>[^:]+):(?P<arch>[^:]+):(?P<variant>[^:]+)$")
PUBLIC_IMAGE_INDEX_URL = os.environ.get("FORTRESS_PUBLIC_IMAGE_INDEX_URL", "https://images.linuxcontainers.org/streams/v1/index.json")
PUBLIC_IMAGE_ARCHES = {"amd64", "x86_64"}
MISSING_ROOT_DEVICE_MARKERS = ("failed getting root disk", "no root device could be found")

try:
    PUBLIC_IMAGE_INDEX_TIMEOUT_SECONDS = float(os.environ.get("FORTRESS_PUBLIC_IMAGE_INDEX_TIMEOUT_SECONDS", "4"))
except ValueError:
    PUBLIC_IMAGE_INDEX_TIMEOUT_SECONDS = 4.0

try:
    PUBLIC_IMAGE_INDEX_CACHE_SECONDS = int(os.environ.get("FORTRESS_PUBLIC_IMAGE_INDEX_CACHE_SECONDS", "300"))
except ValueError:
    PUBLIC_IMAGE_INDEX_CACHE_SECONDS = 300

UBUNTU_VERSION_TO_CODENAME = {
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
}
UBUNTU_CODENAME_TO_VERSION = {codename: version for version, codename in UBUNTU_VERSION_TO_CODENAME.items()}
UBUNTU_LTS_CODENAME_ORDER = {
    codename: index
    for index, codename in enumerate(
        ["xenial", "bionic", "focal", "jammy", "noble"],
        start=1,
    )
}

DEBIAN_VERSION_TO_CODENAME = {
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}
DEBIAN_CODENAME_TO_VERSION = {codename: version for version, codename in DEBIAN_VERSION_TO_CODENAME.items()}
DEBIAN_STABLE_ORDER = {
    codename: index
    for index, codename in enumerate(
        ["buster", "bullseye", "bookworm", "trixie", "forky"],
        start=1,
    )
}
DEBIAN_UNSTABLE_RELEASES = {"sid", "unstable", "testing", "experimental"}

AuditCallback = Callable[[str, str, Optional[str], Optional[Dict[str, Any]], str], None]
_AUDIT_CALLBACK: Optional[AuditCallback] = None
_PUBLIC_IMAGE_INDEX_CACHE: Dict[str, Any] = {"expires_at": 0.0, "products": []}


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
    resolved_alias = resolve_image_alias(distro)
    ensure_image_available(resolved_alias)
    try:
        run_command(["lxc", "launch", resolved_alias, name])
    except HTTPException as exc:
        detail = str(exc.detail or "")
        lowered = detail.lower()
        if not any(marker in lowered for marker in MISSING_ROOT_DEVICE_MARKERS):
            raise
        pools = list_storage_pools()
        selected_pool = _select_launch_storage_pool(pools)
        if not selected_pool:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"{detail.rstrip()} LXD has no usable storage pool for root disks. "
                    "Run `lxd init` (or add a storage pool and root disk device in profile `default`) and retry."
                ),
            ) from exc
        try:
            run_command(["lxc", "launch", "--storage", selected_pool, resolved_alias, name])
        except HTTPException as retry_exc:
            retry_detail = str(retry_exc.detail or "")
            raise HTTPException(
                status_code=500,
                detail=f"{detail.rstrip()} Retry with storage pool '{selected_pool}' failed: {retry_detail}",
            ) from retry_exc
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


def parse_image_alias(alias: str) -> Tuple[str, str]:
    """Split a LXD alias into remote and image components."""
    if ":" in alias:
        remote, image_alias = alias.split(":", 1)
    else:
        remote, image_alias = "", alias
    return remote, image_alias


def _dict_value_case_insensitive(payload: Any, *keys: str) -> Optional[Any]:
    if not isinstance(payload, dict):
        return None
    normalized: Dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(key, str):
            normalized[key.strip().lower()] = value
    for key in keys:
        candidate = normalized.get(key.strip().lower())
        if candidate is not None:
            return candidate
    return None


def _run_lxc_image_list_json(base_args: List[str], limit: Optional[int] = None) -> Any:
    args = list(base_args) + ["--format", "json"]
    use_limit = limit is not None
    if use_limit:
        args.extend(["--limit", str(max(int(limit), 1))])
    try:
        raw = run_command(args)
        return json.loads(raw)
    except HTTPException as exc:
        detail = str(exc.detail).lower()
        if use_limit and "unknown flag" in detail and "--limit" in detail:
            retry_args = list(base_args) + ["--format", "json"]
            raw = run_command(retry_args)
            return json.loads(raw)
        raise


def list_lxd_remotes() -> Set[str]:
    """Return the set of configured LXD remotes."""
    try:
        raw = run_command(["lxc", "remote", "list", "--format", "json"])
        remotes = json.loads(raw)
        names: Set[str] = set()
        if isinstance(remotes, list):
            for remote in remotes:
                if isinstance(remote, dict):
                    candidate = _dict_value_case_insensitive(remote, "name")
                elif isinstance(remote, str):
                    candidate = remote
                else:
                    candidate = None
                if isinstance(candidate, str) and candidate.strip():
                    names.add(candidate.strip())
            return names
        if isinstance(remotes, dict):
            for key, value in remotes.items():
                candidate: Optional[str] = None
                if isinstance(value, dict):
                    raw_name = _dict_value_case_insensitive(value, "name")
                    if isinstance(raw_name, str):
                        candidate = raw_name
                if not candidate and isinstance(key, str):
                    candidate = key
                if isinstance(candidate, str) and candidate.strip():
                    names.add(candidate.strip())
            return names
        if isinstance(remotes, str) and remotes.strip():
            names.add(remotes.strip())
        return names
    except Exception:
        logging.exception("Failed to list LXD remotes")
        return set()


def list_storage_pools() -> List[str]:
    """Return configured LXD storage pool names."""
    try:
        raw = run_command(["lxc", "storage", "list", "--format", "json"])
        pools = json.loads(raw)
    except Exception:
        logging.exception("Failed to list LXD storage pools")
        return []
    names: List[str] = []
    seen: Set[str] = set()

    def add_name(candidate: Optional[str]) -> None:
        if not isinstance(candidate, str):
            return
        normalized = candidate.strip()
        if not normalized:
            return
        lowered = normalized.lower()
        if lowered in seen:
            return
        seen.add(lowered)
        names.append(normalized)

    if isinstance(pools, list):
        for pool in pools:
            if isinstance(pool, dict):
                add_name(_dict_value_case_insensitive(pool, "name"))
            elif isinstance(pool, str):
                add_name(pool)
        return names
    if isinstance(pools, dict):
        for key, value in pools.items():
            candidate = _dict_value_case_insensitive(value, "name") if isinstance(value, dict) else None
            if not candidate and isinstance(key, str):
                candidate = key
            add_name(candidate if isinstance(candidate, str) else None)
        return names
    if isinstance(pools, str):
        add_name(pools)
    return names


def _select_launch_storage_pool(pools: List[str]) -> Optional[str]:
    if not pools:
        return None
    preferred_names = ("default", "local")
    for preferred in preferred_names:
        for pool in pools:
            if pool.strip().lower() == preferred:
                return pool
    return pools[0]


def list_remote_images(remote: str, limit: int = 250) -> List[Dict[str, Any]]:
    """Return image metadata for a single LXD remote."""
    if not remote:
        return []
    try:
        payload = _run_lxc_image_list_json(["lxc", "image", "list", f"{remote}:"], limit=limit)
    except Exception:
        logging.exception("Failed to list images for LXD remote '%s'", remote)
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _image_aliases(image: Dict[str, Any]) -> List[str]:
    aliases = image.get("aliases") or []
    names: List[str] = []
    for alias in aliases:
        if isinstance(alias, dict):
            value = _dict_value_case_insensitive(alias, "name")
        else:
            value = alias
        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                names.append(normalized)
    return names


def _build_remote_alias_index(remote: str, limit: int = 250) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for image in list_remote_images(remote, limit=limit):
        for alias in _image_aliases(image):
            if alias not in index:
                index[alias] = image
    return index


def _version_key(value: str) -> Tuple[int, ...]:
    chunks = [chunk.strip() for chunk in value.split(".") if chunk.strip()]
    numbers: List[int] = []
    for chunk in chunks:
        if not chunk.isdigit():
            return ()
        numbers.append(int(chunk))
    return tuple(numbers)


def _image_metadata_summary(meta: Dict[str, Any]) -> Dict[str, Any]:
    properties = meta.get("properties") or {}
    return {
        "architecture": meta.get("architecture"),
        "type": meta.get("type"),
        "release": properties.get("release") or properties.get("version"),
        "os": properties.get("os"),
    }


def _build_discovered_image(name: str, resolved_name: str, label: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    remote, alias = parse_image_alias(resolved_name)
    payload = {
        "name": name,
        "resolved_name": resolved_name,
        "label": label,
        "remote": remote,
        "alias": alias,
        "available": True,
        "source": "lxd-cli",
    }
    payload.update(_image_metadata_summary(meta))
    return payload


def _latest_alias_for_pattern(
    alias_index: Dict[str, Dict[str, Any]], pattern: re.Pattern
) -> Optional[Tuple[str, str, Dict[str, Any]]]:
    matches: List[Tuple[Tuple[int, ...], str, str, Dict[str, Any]]] = []
    for alias, meta in alias_index.items():
        match = pattern.match(alias)
        if not match:
            continue
        version = match.group("version")
        key = _version_key(version)
        if not key:
            continue
        matches.append((key, alias, version, meta))
    if not matches:
        return None
    matches.sort(key=lambda item: item[0])
    _key, alias, version, meta = matches[-1]
    return alias, version, meta


def _public_image_products() -> List[str]:
    now = time.time()
    cached_expiry = float(_PUBLIC_IMAGE_INDEX_CACHE.get("expires_at") or 0.0)
    cached_products = _PUBLIC_IMAGE_INDEX_CACHE.get("products")
    if cached_expiry > now and isinstance(cached_products, list):
        return [item for item in cached_products if isinstance(item, str)]
    try:
        response = requests.get(PUBLIC_IMAGE_INDEX_URL, timeout=max(PUBLIC_IMAGE_INDEX_TIMEOUT_SECONDS, 1.0))
        response.raise_for_status()
        payload = response.json()
    except Exception:
        logging.exception("Failed to fetch LXD public image index from %s", PUBLIC_IMAGE_INDEX_URL)
        _PUBLIC_IMAGE_INDEX_CACHE["products"] = []
        _PUBLIC_IMAGE_INDEX_CACHE["expires_at"] = now + max(PUBLIC_IMAGE_INDEX_CACHE_SECONDS, 30)
        return []
    index = payload.get("index") if isinstance(payload, dict) else {}
    images = index.get("images") if isinstance(index, dict) else {}
    products = images.get("products") if isinstance(images, dict) else []
    if not isinstance(products, list):
        products = []
    normalized = [item.strip() for item in products if isinstance(item, str) and item.strip()]
    _PUBLIC_IMAGE_INDEX_CACHE["products"] = normalized
    _PUBLIC_IMAGE_INDEX_CACHE["expires_at"] = now + max(PUBLIC_IMAGE_INDEX_CACHE_SECONDS, 30)
    return list(normalized)


def _public_cloud_releases_by_distro() -> Dict[str, Set[str]]:
    releases: Dict[str, Set[str]] = {}
    for product in _public_image_products():
        match = PUBLIC_IMAGE_PRODUCT_PATTERN.match(product)
        if not match:
            continue
        distro = match.group("distro").strip().lower()
        release = match.group("release").strip()
        arch = match.group("arch").strip().lower()
        variant = match.group("variant").strip().lower()
        if variant != "cloud" or arch not in PUBLIC_IMAGE_ARCHES:
            continue
        releases.setdefault(distro, set()).add(release)
    return releases


def _public_cloud_alias_for_release(cloud_releases: Dict[str, Set[str]], distro: str, release: str) -> Optional[str]:
    wanted_distro = distro.strip().lower()
    wanted_release = release.strip().lower()
    for available_release in cloud_releases.get(wanted_distro, set()):
        if available_release.strip().lower() == wanted_release:
            return f"images:{wanted_distro}/{available_release}/cloud"
    return None


def _latest_release_by_version(releases: Set[str]) -> Optional[str]:
    candidates: List[Tuple[Tuple[int, ...], str]] = []
    for release in releases:
        key = _version_key(release)
        if key:
            candidates.append((key, release))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0])
    _key, value = candidates[-1]
    return value


def _latest_ubuntu_lts_release_from_public(releases: Set[str]) -> Optional[str]:
    known_candidates: List[Tuple[int, str]] = []
    for release in releases:
        rank = UBUNTU_LTS_CODENAME_ORDER.get(release.strip().lower())
        if rank is not None:
            known_candidates.append((rank, release))
    if known_candidates:
        known_candidates.sort(key=lambda item: item[0])
        _rank, value = known_candidates[-1]
        return value
    numeric_candidates: List[Tuple[Tuple[int, ...], str]] = []
    for release in releases:
        normalized = release.strip()
        if not UBUNTU_LTS_PATTERN.match(normalized):
            continue
        key = _version_key(normalized)
        if key:
            numeric_candidates.append((key, normalized))
    if not numeric_candidates:
        return None
    numeric_candidates.sort(key=lambda item: item[0])
    _key, value = numeric_candidates[-1]
    return value


def _latest_debian_stable_release_from_public(releases: Set[str]) -> Optional[str]:
    known_candidates: List[Tuple[int, str]] = []
    for release in releases:
        rank = DEBIAN_STABLE_ORDER.get(release.strip().lower())
        if rank is not None:
            known_candidates.append((rank, release))
    if known_candidates:
        known_candidates.sort(key=lambda item: item[0])
        _rank, value = known_candidates[-1]
        return value
    numeric_candidates: List[Tuple[Tuple[int, ...], str]] = []
    for release in releases:
        normalized = release.strip().lower()
        if normalized in DEBIAN_UNSTABLE_RELEASES:
            continue
        key = _version_key(normalized)
        if key:
            numeric_candidates.append((key, release))
    if numeric_candidates:
        numeric_candidates.sort(key=lambda item: item[0])
        _key, value = numeric_candidates[-1]
        return value
    named_candidates = [release for release in releases if release.strip().lower() not in DEBIAN_UNSTABLE_RELEASES]
    if not named_candidates:
        return None
    return sorted(named_candidates)[-1]


def resolve_alias_via_public_catalog(alias: str) -> Optional[str]:
    normalized = alias.strip()
    if not normalized:
        return None
    cloud_releases = _public_cloud_releases_by_distro()
    if not cloud_releases:
        return None
    remote, image_alias = parse_image_alias(normalized)
    remote = remote.strip().lower()
    image_alias = image_alias.strip()
    normalized_input = normalized.lower()

    if remote == "images":
        parts = image_alias.split("/")
        if len(parts) >= 3:
            distro, release, variant = parts[0].lower(), parts[1], parts[2].lower()
            if variant == "cloud":
                return _public_cloud_alias_for_release(cloud_releases, distro, release)
        return None

    if normalized_input in {"ubuntu:lts", "ubuntu:latest-lts", "ubuntu:lts/latest"}:
        latest_lts = _latest_ubuntu_lts_release_from_public(cloud_releases.get("ubuntu", set()))
        if latest_lts:
            return _public_cloud_alias_for_release(cloud_releases, "ubuntu", latest_lts)
        return None

    if remote == "ubuntu":
        mapped_release = UBUNTU_VERSION_TO_CODENAME.get(image_alias.lower(), image_alias.lower())
        return _public_cloud_alias_for_release(cloud_releases, "ubuntu", mapped_release)

    if remote == "debian":
        normalized_debian = image_alias.lower()
        if normalized_debian == "stable":
            latest_stable = _latest_debian_stable_release_from_public(cloud_releases.get("debian", set()))
            if latest_stable:
                return _public_cloud_alias_for_release(cloud_releases, "debian", latest_stable)
            return None
        mapped_release = DEBIAN_VERSION_TO_CODENAME.get(normalized_debian, normalized_debian)
        return _public_cloud_alias_for_release(cloud_releases, "debian", mapped_release)

    return None


def discover_popular_images_from_public_catalog(images_remote_configured: bool = False) -> List[Dict[str, Any]]:
    cloud_releases = _public_cloud_releases_by_distro()
    if not cloud_releases:
        return []

    discovered: List[Dict[str, Any]] = []

    def register(name: str, resolved_name: str, label: str, release: str, os_name: str) -> None:
        remote, alias = parse_image_alias(resolved_name)
        discovered.append(
            {
                "name": name,
                "resolved_name": resolved_name,
                "label": label,
                "remote": remote,
                "alias": alias,
                "available": images_remote_configured,
                "source": "lxd-repo",
                "architecture": "amd64",
                "type": "container",
                "release": release,
                "os": os_name,
            }
        )

    ubuntu_release = _latest_ubuntu_lts_release_from_public(cloud_releases.get("ubuntu", set()))
    if ubuntu_release:
        resolved = _public_cloud_alias_for_release(cloud_releases, "ubuntu", ubuntu_release)
        if resolved:
            ubuntu_label_release = UBUNTU_CODENAME_TO_VERSION.get(ubuntu_release.lower(), ubuntu_release)
            register(
                "ubuntu:lts",
                resolved,
                f"Ubuntu {ubuntu_label_release} LTS",
                ubuntu_label_release,
                "Ubuntu",
            )

    debian_release = _latest_debian_stable_release_from_public(cloud_releases.get("debian", set()))
    if debian_release:
        resolved = _public_cloud_alias_for_release(cloud_releases, "debian", debian_release)
        if resolved:
            debian_label_release = DEBIAN_CODENAME_TO_VERSION.get(debian_release.lower(), debian_release)
            register(
                f"debian:{debian_label_release}",
                resolved,
                f"Debian {debian_label_release} (stable)",
                debian_label_release,
                "Debian",
            )

    for family, label in [("almalinux", "AlmaLinux"), ("rockylinux", "Rocky Linux"), ("fedora", "Fedora")]:
        latest_family = _latest_release_by_version(cloud_releases.get(family, set()))
        if not latest_family:
            continue
        resolved = _public_cloud_alias_for_release(cloud_releases, family, latest_family)
        if not resolved:
            continue
        register(
            f"images:{family}/{latest_family}/cloud",
            resolved,
            f"{label} {latest_family} (cloud)",
            latest_family,
            label,
        )

    return discovered


def _needs_public_catalog_fallback(discovered: List[Dict[str, Any]]) -> bool:
    names = {str(entry.get("name") or "").strip().lower() for entry in discovered}
    return not (
        "ubuntu:lts" in names
        and any(name.startswith("debian:") for name in names)
        and any(name.startswith("images:almalinux/") for name in names)
        and any(name.startswith("images:rockylinux/") for name in names)
        and any(name.startswith("images:fedora/") for name in names)
    )


def discover_popular_images() -> List[Dict[str, Any]]:
    """Discover currently available and commonly used images directly from LXD remotes."""
    remotes = list_lxd_remotes()
    discovered: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    seen_names: Set[str] = set()

    def register(entry: Dict[str, Any]) -> None:
        name = str(entry.get("name") or "").strip().lower()
        if name and name in seen_names:
            return
        resolved = str(entry.get("resolved_name") or entry.get("name") or "").strip().lower()
        if not resolved or resolved in seen:
            return
        if name:
            seen_names.add(name)
        seen.add(resolved)
        discovered.append(entry)

    if "ubuntu" in remotes:
        ubuntu_alias_index = _build_remote_alias_index("ubuntu", limit=300)
        latest_lts = find_latest_ubuntu_lts_alias()
        if latest_lts:
            latest_alias = latest_lts.split(":", 1)[1] if ":" in latest_lts else latest_lts
            meta = ubuntu_alias_index.get(latest_alias)
            if meta is None:
                try:
                    meta = ensure_image_available(latest_lts)
                except Exception:
                    meta = None
            if isinstance(meta, dict):
                register(
                    _build_discovered_image(
                        "ubuntu:lts",
                        latest_lts,
                        f"Ubuntu {latest_alias} LTS",
                        meta,
                    )
                )

    if "debian" in remotes:
        debian_alias_index = _build_remote_alias_index("debian", limit=260)
        latest_debian = _latest_alias_for_pattern(debian_alias_index, DEBIAN_VERSION_PATTERN)
        if latest_debian:
            alias, version, meta = latest_debian
            register(
                _build_discovered_image(
                    f"debian:{alias}",
                    f"debian:{alias}",
                    f"Debian {version} (stable)",
                    meta,
                )
            )

    if "images" in remotes:
        images_alias_index = _build_remote_alias_index("images", limit=450)
        families = [
            ("almalinux", "AlmaLinux"),
            ("rockylinux", "Rocky Linux"),
            ("fedora", "Fedora"),
        ]
        for family, label in families:
            pattern = re.compile(rf"^{family}/(?P<version>\d+(?:\.\d+)?)/cloud$")
            latest_family = _latest_alias_for_pattern(images_alias_index, pattern)
            if not latest_family:
                continue
            alias, version, meta = latest_family
            register(
                _build_discovered_image(
                    f"images:{alias}",
                    f"images:{alias}",
                    f"{label} {version} (cloud)",
                    meta,
                )
            )

    if _needs_public_catalog_fallback(discovered):
        for entry in discover_popular_images_from_public_catalog(images_remote_configured=("images" in remotes)):
            register(entry)

    return discovered


def ensure_image_available(alias: str) -> Dict[str, Any]:
    """Validate that an image alias exists on a configured remote and return metadata."""
    remote, image_alias = parse_image_alias(alias)
    remotes = list_lxd_remotes()
    if remote and remote not in remotes:
        known_remotes = ", ".join(sorted(remotes)) if remotes else "none"
        raise HTTPException(
            status_code=400,
            detail=(
                f"LXD remote '{remote}' is not configured (known remotes: {known_remotes}). "
                f"Add it with `lxc remote add {remote} ...` or choose another image."
            ),
        )
    if remote and image_alias:
        lookup_args = ["lxc", "image", "list", f"{remote}:", image_alias]
    else:
        lookup_args = ["lxc", "image", "list", alias]
    try:
        images = _run_lxc_image_list_json(lookup_args, limit=1)
    except HTTPException as exc:
        detail = str(exc.detail)
        logging.error("Image lookup failed for %s: %s", alias, detail)
        lowered = detail.lower()
        if "not found" in lowered or "no matching" in lowered or "unknown" in lowered:
            raise HTTPException(
                status_code=400,
                detail=f"Image '{alias}' was not found on remote '{remote or 'local'}'. LXD detail: {detail}",
            ) from exc
        raise HTTPException(
            status_code=exc.status_code if isinstance(exc.status_code, int) else 500,
            detail=f"Image lookup failed for '{alias}' on remote '{remote or 'local'}': {detail}",
        ) from exc
    except Exception as exc:
        logging.exception("Image lookup crashed for %s", alias)
        raise HTTPException(
            status_code=500,
            detail=f"Image lookup failed for '{alias}' on remote '{remote or 'local'}': {exc}",
        ) from exc
    if not isinstance(images, list) or not images:
        raise HTTPException(status_code=400, detail=f"Image '{alias}' was not found on remote '{remote or 'local'}'.")
    first = images[0]
    if not isinstance(first, dict):
        raise HTTPException(status_code=500, detail=f"Image lookup returned invalid metadata for '{alias}'.")
    return first


def find_latest_ubuntu_lts_alias() -> Optional[str]:
    """Detect the latest available Ubuntu LTS alias on the ubuntu: remote."""
    remotes = list_lxd_remotes()
    if "ubuntu" not in remotes:
        return None
    try:
        images = _run_lxc_image_list_json(["lxc", "image", "list", "ubuntu:"], limit=100)
    except Exception:
        logging.exception("Failed to query ubuntu: images")
        return None
    if isinstance(images, dict):
        # Some LXD versions/wrappers may return object envelopes instead of a bare list.
        metadata_images = images.get("metadata")
        listed_images = images.get("images")
        if isinstance(metadata_images, list):
            images = metadata_images
        elif isinstance(listed_images, list):
            images = listed_images
    if not isinstance(images, list):
        logging.warning("Unexpected payload type from ubuntu image listing: %s", type(images).__name__)
        return None
    aliases: Set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            continue
        aliases_payload = image.get("aliases") or []
        if not isinstance(aliases_payload, list):
            continue
        for alias in aliases_payload:
            name = alias.get("name") if isinstance(alias, dict) else alias
            if not isinstance(name, str):
                continue
            match = UBUNTU_LTS_PATTERN.match(name.strip())
            if match:
                aliases.add(name.strip())
    if not aliases:
        return None
    latest = sorted(
        aliases,
        key=lambda v: tuple(int(part) for part in v.split(".")),
    )[-1]
    return f"ubuntu:{latest}"


def resolve_image_alias(distro: str) -> str:
    """Resolve pseudo aliases like ubuntu:lts to a concrete image alias."""
    normalized = distro.strip()
    lowered = normalized.lower()
    if lowered in {"ubuntu:lts", "ubuntu:latest-lts", "ubuntu:lts/latest"}:
        latest = find_latest_ubuntu_lts_alias()
        if latest:
            return latest
        from_public = resolve_alias_via_public_catalog(normalized)
        return from_public or "ubuntu:22.04"
    from_public = resolve_alias_via_public_catalog(normalized)
    if from_public:
        return from_public
    return normalized
