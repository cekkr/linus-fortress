import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from fortress import containers as container_ops
from fortress.firewall import apply_firewall_rule
from fortress.storage import load_json, update_json

AuthorizeFn = Callable[..., Dict[str, Any]]
AuditFn = Callable[..., None]
SanitizeFn = Callable[..., Dict[str, Any]]


class ContainerCreate(BaseModel):
    name: str
    distro: str = "ubuntu:lts"
    cpu_limit: str = "1"
    ram_limit: str = "512MB"
    disk_limit: str = "10GB"


class PopularImage(BaseModel):
    name: str
    label: Optional[str] = None


class PopularImageRemove(BaseModel):
    name: str


class ExternalAccessRule(BaseModel):
    container_name: str
    service: Literal["ssh", "ftp"]
    host_port: Optional[int] = None
    connect_port: Optional[int] = None
    bind_address: str = "0.0.0.0"
    connect_address: Optional[str] = None
    connect_interface: Optional[str] = None
    device_name: Optional[str] = None


class ExternalAccessCloseRequest(BaseModel):
    container_name: str
    device_name: Optional[str] = None
    service: Optional[Literal["ssh", "ftp"]] = None
    host_port: Optional[int] = None


class ContainerUserCreate(BaseModel):
    container_name: str
    username: str
    password: Optional[str] = None
    groups: Optional[List[str]] = None


class ContainerUserPasswordUpdate(BaseModel):
    container_name: str
    username: str
    password: str


class ContainerUserGroupUpdate(BaseModel):
    container_name: str
    username: str
    groups: List[str]


class ContainerUserDelete(BaseModel):
    container_name: str
    username: str
    remove_home: bool = False


class ContainerGroupCreate(BaseModel):
    container_name: str
    group_name: str


class ContainerLinkRequest(BaseModel):
    source_container: str
    target_container: str
    listen_port: int
    target_port: int
    bind_address: str = "0.0.0.0"
    protocol: Literal["tcp", "udp"] = "tcp"
    target_interface: Optional[str] = None
    target_address: Optional[str] = None
    device_name: Optional[str] = None


class ContainerLinkRemoval(BaseModel):
    container_name: str
    device_name: str


class SharedMountRequest(BaseModel):
    share_name: str
    containers: List[str]
    mount_path: str = "/mnt/share"
    source_path: Optional[str] = None


class SharedMountRemoval(BaseModel):
    share_name: str
    containers: List[str]


class PortRange(BaseModel):
    start: int
    end: int


class InterfaceExposure(BaseModel):
    protocol: Literal["tcp", "udp"] = "tcp"
    bind_address: str = "0.0.0.0"
    host_ports: Optional[List[int]] = None
    port_range: Optional[PortRange] = None
    container_port: Optional[int] = None
    target_interface: Optional[str] = None
    target_address: Optional[str] = None
    device_name_prefix: Optional[str] = None
    open_firewall: bool = False
    allow_sources: Optional[List[str]] = None


class MultiInterfaceExposeRequest(BaseModel):
    container_name: str
    exposures: List[InterfaceExposure]


class ContainerServiceProbe(BaseModel):
    container_name: str
    services: Optional[List[str]] = None
    update_labels: bool = False


class ContainerLifecycle(BaseModel):
    container_name: str
    force: bool = False


class ContainerSnapshotRequest(BaseModel):
    container_name: str
    snapshot_name: str
    stateful: bool = False


class ContainerSnapshotRestore(BaseModel):
    container_name: str
    snapshot_name: str
    stateful: bool = False


class ContainerExecRequest(BaseModel):
    container_name: str
    command: List[str]
    user: Optional[str] = None
    workdir: Optional[str] = None
    environment: Optional[Dict[str, str]] = None


def build_container_router(
    authorize: AuthorizeFn,
    audit_api: AuditFn,
    sanitize_payload: SanitizeFn,
    shared_storage_dir: str,
    popular_images_db: str,
) -> APIRouter:
    router = APIRouter()
    logger = logging.getLogger(__name__)

    @contextmanager
    def audit_mutation(action: str, target: str, details: Optional[Dict[str, Any]] = None):
        try:
            yield
        except Exception as exc:
            failure = {"status_code": exc.status_code} if isinstance(exc, HTTPException) else {"error_type": type(exc).__name__}
            audit_api(action, target=target, details={**(details or {}), **failure}, status="error")
            raise
        else:
            audit_api(action, target=target, details=details)

    def _load_image_store() -> Any:
        return load_json(popular_images_db, {"popular": []}, label="popular images")

    def _extract_popular_store_entries(store_payload: Any) -> List[Any]:
        if isinstance(store_payload, list):
            # Legacy format: store file was a bare list of entries.
            return store_payload
        if isinstance(store_payload, dict):
            popular = store_payload.get("popular")
            if isinstance(popular, list):
                return popular
        return []

    def _popular_preset_name(item: Any) -> str:
        if isinstance(item, dict):
            item = item.get("name") if item.get("name") is not None else item.get("alias")
        return _normalize_popular_name(item)

    def _normalize_popular_name(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if value is None:
            return ""
        return str(value).strip()

    def _fallback_popular_images(latest: Optional[str]) -> List[Dict[str, str]]:
        latest_label = f"Ubuntu {latest.split(':', 1)[1]} LTS" if latest and ":" in latest else "Ubuntu LTS pinned"
        return [
            {"name": "ubuntu:lts", "label": "Ubuntu (latest LTS)"},
            {"name": latest or "ubuntu:22.04", "label": latest_label},
            {"name": "debian:12", "label": "Debian 12 (stable)"},
            {"name": "images:almalinux/9/cloud", "label": "AlmaLinux 9 (cloud)"},
        ]

    def _list_custom_popular_entries() -> List[Dict[str, str]]:
        store = _load_image_store()
        popular = _extract_popular_store_entries(store)
        seen = set()
        entries: List[Dict[str, str]] = []
        for item in popular:
            normalized = _popular_preset_name(item)
            if not normalized:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            label = _normalize_popular_name(item.get("label")) if isinstance(item, dict) else ""
            resolved = normalized
            try:
                resolved = container_ops.resolve_image_alias(normalized)
            except Exception:
                resolved = normalized
            payload = {"name": normalized, "label": label or normalized, "source": "custom"}
            if resolved and resolved != normalized:
                payload["resolved_name"] = resolved
            entries.append(payload)
        return entries

    def _list_popular_entries(custom: List[Dict[str, str]], latest_lts: Optional[str]) -> List[Dict[str, Any]]:
        try:
            discovered = container_ops.discover_popular_images()
        except Exception:
            logger.exception("Failed to discover popular images from LXD; falling back to saved presets/defaults")
            discovered = []
        seen = set()
        entries: List[Dict[str, Any]] = []

        def add_entry(entry: Dict[str, Any], *, source: str) -> None:
            if not isinstance(entry, dict):
                return
            name = str(entry.get("name") or "").strip()
            if not name:
                return
            resolved = str(entry.get("resolved_name") or name).strip()
            key = resolved.lower()
            if key in seen:
                return
            seen.add(key)
            payload = dict(entry)
            payload["name"] = name
            payload["label"] = str(entry.get("label") or name).strip() or name
            payload["source"] = str(entry.get("source") or source)
            if resolved:
                payload["resolved_name"] = resolved
            entries.append(payload)

        for item in custom:
            add_entry(item, source="custom")
        for item in discovered:
            add_entry(item, source="lxd-cli")
        if not entries:
            for item in _fallback_popular_images(latest_lts):
                add_entry(item, source="fallback")
        return entries

    def _inspect_entry(entry: Dict[str, Any], remotes: Optional[List[str]] = None) -> Dict[str, Any]:
        name = str(entry.get("name") or "").strip()
        resolved_hint = str(entry.get("resolved_name") or "").strip()
        resolved = resolved_hint or container_ops.resolve_image_alias(name)
        remote, alias = container_ops.parse_image_alias(resolved)
        payload: Dict[str, Any] = {
            "name": name,
            "label": entry.get("label") or name,
            "resolved_name": resolved,
            "remote": remote,
            "alias": alias,
            "available": False,
            "source": entry.get("source") or "custom",
        }
        if entry.get("available") is True:
            payload["available"] = True
            for field in ("architecture", "type", "release", "os"):
                if field in entry:
                    payload[field] = entry.get(field)
            return payload

        debug_payload = {
            "requested": name,
            "resolved": resolved,
            "remote": remote,
            "known_remotes": remotes if remotes is not None else sorted(container_ops.list_lxd_remotes()),
        }
        try:
            meta = container_ops.ensure_image_available(resolved)
            props = meta.get("properties") or {}
            payload.update(
                {
                    "available": True,
                    "architecture": meta.get("architecture"),
                    "type": meta.get("type"),
                    "release": props.get("release") or props.get("version"),
                    "os": props.get("os"),
                }
            )
        except HTTPException as exc:
            payload["reason"] = exc.detail
            payload["reason_code"] = exc.status_code
            payload["debug"] = debug_payload
        except Exception as exc:
            payload["reason"] = str(exc)
            payload["reason_code"] = 500
            payload["debug"] = debug_payload
        return payload

    @router.get("/containers/images/popular")
    def list_popular_images(
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        auth_context = authorize("container_create", "manage_containers", x_api_key, x_user_token)
        remotes = sorted(container_ops.list_lxd_remotes())
        latest_lts = container_ops.find_latest_ubuntu_lts_alias()
        custom = _list_custom_popular_entries()
        entries = _list_popular_entries(custom, latest_lts)
        inspected = [_inspect_entry(entry, remotes=remotes) for entry in entries]
        by_resolved_name = {item["resolved_name"].lower(): item for item in inspected}
        presets = []
        for entry in custom:
            resolved = entry.get("resolved_name") or entry["name"]
            status = by_resolved_name[resolved.lower()]
            presets.append({
                **entry, "resolved_name": status["resolved_name"], "available": status["available"], "remote": status["remote"],
            })
        audit_api("container_images_list", details={"count": len(inspected)})
        return {
            "images": inspected,
            "presets": presets,
            "can_manage_presets": not auth_context.get("allowed_containers"),
            "latest": {"ubuntu_lts": latest_lts},
            "remotes": remotes,
            "refreshed_at": datetime.now(timezone.utc).isoformat(),
        }

    @router.post("/containers/images/popular")
    def add_popular_image(
        payload: PopularImage,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        auth_context = authorize("container_create", "manage_containers", x_api_key, x_user_token)
        name = payload.name.strip()
        label = (payload.label or "").strip()

        def upsert(store):
            popular = _extract_popular_store_entries(store)
            previous = next((item for item in popular if _popular_preset_name(item) == name), None)
            if previous is None:
                popular.append({"name": name, "label": label or None})
            elif label:
                index = popular.index(previous)
                popular[index] = {**(previous if isinstance(previous, dict) else {}), "name": name, "label": label}
            return {**(store if isinstance(store, dict) else {}), "popular": popular}

        with audit_mutation("container_images_add", name):
            if auth_context.get("allowed_containers"):
                raise HTTPException(status_code=403, detail="Editing shared image presets requires unrestricted container scope")
            _, alias = container_ops.parse_image_alias(name)
            if not alias or alias.startswith("-") or name.startswith("-") or any(char.isspace() for char in name):
                raise HTTPException(status_code=400, detail="Enter a valid LXD image alias")
            store = update_json(popular_images_db, {"popular": []}, upsert, label="popular images")
        return {"message": "Image preset saved", "popular": store["popular"]}

    @router.post("/containers/images/popular/remove")
    def remove_popular_image(
        payload: PopularImageRemove,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        auth_context = authorize("container_create", "manage_containers", x_api_key, x_user_token)
        name = payload.name.strip()

        def remove(store):
            popular = [item for item in _extract_popular_store_entries(store) if _popular_preset_name(item) != name]
            return {**(store if isinstance(store, dict) else {}), "popular": popular}

        with audit_mutation("container_images_remove", name):
            if auth_context.get("allowed_containers"):
                raise HTTPException(status_code=403, detail="Editing shared image presets requires unrestricted container scope")
            if not name:
                raise HTTPException(status_code=400, detail="Enter an image alias")
            store = update_json(popular_images_db, {"popular": []}, remove, label="popular images")
        return {"message": "Image preset removed", "popular": store["popular"]}

    @router.post("/container/create")
    def create_container(
        config: ContainerCreate,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_create", "manage_containers", x_api_key, x_user_token, containers=config.name)
        logger.info("Creating container %s", config.name)
        try:
            container_ops.create_container(
                config.name,
                config.distro,
                config.cpu_limit,
                config.ram_limit,
                config.disk_limit,
            )
            audit_api("container_create", target=config.name, details=sanitize_payload(config.dict()))
            return {"message": f"Container {config.name} created successfully"}
        except HTTPException as exc:
            audit_api("container_create", target=config.name, details={"error": exc.detail}, status="error")
            raise
        except Exception as exc:
            audit_api("container_create", target=config.name, details={"error": str(exc)}, status="error")
            raise HTTPException(status_code=500, detail=str(exc))

    @router.delete("/container/{name}")
    def delete_container(
        name: str,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_delete", "manage_containers", x_api_key, x_user_token, containers=name)
        logger.info("Deleting container %s", name)
        try:
            container_ops.delete_container(name)
            audit_api("container_delete", target=name)
            return {"message": f"Container {name} deleted"}
        except Exception as exc:
            audit_api("container_delete", target=name, details={"error": str(exc)}, status="error")
            raise HTTPException(status_code=500, detail=str(exc))

    @router.post("/access/external/open")
    def open_external_access(
        rule: ExternalAccessRule,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("external_access_open", "access_control", x_api_key, x_user_token, containers=rule.container_name)
        try:
            result = container_ops.open_external_access(
                container_name=rule.container_name,
                service=rule.service,
                host_port=rule.host_port,
                connect_port=rule.connect_port,
                bind_address=rule.bind_address,
                connect_address=rule.connect_address,
                connect_interface=rule.connect_interface,
                device_name=rule.device_name,
            )
            audit_api(
                "external_access_open",
                target=rule.container_name,
                details={
                    "service": rule.service,
                    "device": result["device_name"],
                    "host_port": result["host_port"],
                    "bind_address": rule.bind_address,
                    "connect_interface": rule.connect_interface,
                },
            )
        except Exception as exc:
            audit_api("external_access_open", target=rule.container_name, details={"error": str(exc)}, status="error")
            raise
        return {
            "message": f"{rule.service.upper()} access exposed on port {result['host_port']}",
            "device_name": result["device_name"],
        }

    @router.post("/access/external/close")
    def close_external_access(
        rule: ExternalAccessCloseRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("external_access_close", "access_control", x_api_key, x_user_token, containers=rule.container_name)
        device_name = rule.device_name
        if not device_name:
            if not rule.service:
                raise HTTPException(status_code=400, detail="Either device_name or service must be provided")
            device_name = container_ops.resolve_device_name(rule.service, rule.host_port, None)
        try:
            container_ops.remove_device(rule.container_name, device_name)
            audit_api("external_access_close", target=rule.container_name, details={"device": device_name})
        except Exception as exc:
            audit_api(
                "external_access_close",
                target=rule.container_name,
                details={"device": device_name, "error": str(exc)},
                status="error",
            )
            raise
        return {"message": f"Device {device_name} removed from {rule.container_name}"}

    @router.post("/container/users/create")
    def create_container_user(
        payload: ContainerUserCreate,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_user_create", "user_management", x_api_key, x_user_token, containers=payload.container_name)
        cmd = ["useradd", "-m", payload.username]
        if payload.groups:
            cmd.extend(["-G", ",".join(payload.groups)])
        try:
            container_ops.exec_in_container(payload.container_name, cmd)
            if payload.password:
                container_ops.set_container_password(payload.container_name, payload.username, payload.password)
            audit_api(
                "container_user_create",
                target=payload.container_name,
                details=sanitize_payload(payload.dict(), sensitive_keys=["password"]),
            )
            return {"message": f"User {payload.username} created in {payload.container_name}"}
        except Exception as exc:
            audit_api(
                "container_user_create",
                target=payload.container_name,
                details={"username": payload.username, "error": str(exc)},
                status="error",
            )
            raise

    @router.post("/container/users/password")
    def update_container_password(
        payload: ContainerUserPasswordUpdate,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_user_password", "user_management", x_api_key, x_user_token, containers=payload.container_name)
        try:
            container_ops.set_container_password(payload.container_name, payload.username, payload.password)
            audit_api(
                "container_user_password",
                target=payload.container_name,
                details=sanitize_payload(payload.dict(), sensitive_keys=["password"]),
            )
            return {"message": f"Password updated for {payload.username} in {payload.container_name}"}
        except Exception as exc:
            audit_api(
                "container_user_password",
                target=payload.container_name,
                details={"username": payload.username, "error": str(exc)},
                status="error",
            )
            raise

    @router.post("/container/users/groups")
    def update_container_groups(
        payload: ContainerUserGroupUpdate,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_user_groups", "user_management", x_api_key, x_user_token, containers=payload.container_name)
        try:
            container_ops.exec_in_container(payload.container_name, ["usermod", "-G", ",".join(payload.groups), payload.username])
            audit_api(
                "container_user_groups",
                target=payload.container_name,
                details={"username": payload.username, "groups": payload.groups},
            )
            return {"message": f"Groups updated for {payload.username} in {payload.container_name}"}
        except Exception as exc:
            audit_api(
                "container_user_groups",
                target=payload.container_name,
                details={"username": payload.username, "error": str(exc)},
                status="error",
            )
            raise

    @router.delete("/container/users")
    def delete_container_user(
        payload: ContainerUserDelete,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_user_delete", "user_management", x_api_key, x_user_token, containers=payload.container_name)
        args = ["userdel"]
        if payload.remove_home:
            args.append("-r")
        args.append(payload.username)
        try:
            container_ops.exec_in_container(payload.container_name, args)
            audit_api(
                "container_user_delete",
                target=payload.container_name,
                details={"username": payload.username, "remove_home": payload.remove_home},
            )
            return {"message": f"User {payload.username} removed from {payload.container_name}"}
        except Exception as exc:
            audit_api(
                "container_user_delete",
                target=payload.container_name,
                details={"username": payload.username, "error": str(exc)},
                status="error",
            )
            raise

    @router.post("/container/groups")
    def create_container_group(
        payload: ContainerGroupCreate,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_group_create", "user_management", x_api_key, x_user_token, containers=payload.container_name)
        try:
            container_ops.exec_in_container(payload.container_name, ["groupadd", "-f", payload.group_name])
            audit_api(
                "container_group_create",
                target=payload.container_name,
                details={"group": payload.group_name},
            )
            return {"message": f"Group {payload.group_name} ensured in {payload.container_name}"}
        except Exception as exc:
            audit_api(
                "container_group_create",
                target=payload.container_name,
                details={"group": payload.group_name, "error": str(exc)},
                status="error",
            )
            raise

    @router.post("/containers/connect/tcp")
    def connect_containers_network(
        payload: ContainerLinkRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize(
            "containers_connect_tcp",
            "connectivity",
            x_api_key,
            x_user_token,
            containers=[payload.source_container, payload.target_container],
        )
        try:
            device_name = container_ops.connect_containers_network(
                payload.source_container,
                payload.target_container,
                payload.listen_port,
                payload.target_port,
                payload.bind_address,
                payload.protocol,
                payload.target_interface,
                payload.target_address,
                payload.device_name,
            )
            audit_api(
                "containers_connect_tcp",
                target=payload.source_container,
                details={
                    "device": device_name,
                    "target": payload.target_container,
                    "listen_port": payload.listen_port,
                    "target_port": payload.target_port,
                    "target_interface": payload.target_interface,
                    "target_address": payload.target_address,
                },
            )
        except Exception as exc:
            audit_api(
                "containers_connect_tcp",
                target=payload.source_container,
                details={"device": payload.device_name, "error": str(exc)},
                status="error",
            )
            raise
        return {
            "message": f"{payload.source_container} now proxies to {payload.target_container}:{payload.target_port}",
            "device_name": device_name,
        }

    @router.post("/containers/connect/tcp/remove")
    def disconnect_container_network(
        payload: ContainerLinkRemoval,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_disconnect_tcp", "connectivity", x_api_key, x_user_token, containers=payload.container_name)
        try:
            container_ops.remove_device(payload.container_name, payload.device_name)
            audit_api("containers_disconnect_tcp", target=payload.container_name, details={"device": payload.device_name})
        except Exception as exc:
            audit_api(
                "containers_disconnect_tcp",
                target=payload.container_name,
                details={"device": payload.device_name, "error": str(exc)},
                status="error",
            )
            raise
        return {"message": f"Device {payload.device_name} removed from {payload.container_name}"}

    @router.post("/containers/expose")
    def expose_container_interfaces(
        payload: MultiInterfaceExposeRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_expose", "connectivity", x_api_key, x_user_token, containers=payload.container_name)
        if not payload.exposures:
            raise HTTPException(status_code=400, detail="exposures cannot be empty")

        created_devices: List[Dict[str, Any]] = []
        applied_firewall_rules: List[Dict[str, Any]] = []
        try:
            for exposure in payload.exposures:
                devices = container_ops.expose_ports(
                    container_name=payload.container_name,
                    protocol=exposure.protocol,
                    bind_address=exposure.bind_address,
                    host_ports=exposure.host_ports,
                    port_range=exposure.port_range.dict() if exposure.port_range else None,
                    container_port=exposure.container_port,
                    target_interface=exposure.target_interface,
                    target_address=exposure.target_address,
                    device_name_prefix=exposure.device_name_prefix,
                )
                created_devices.extend(devices)

                if exposure.open_firewall:
                    unique_ports = {device["host_port"] for device in devices}
                    sources = exposure.allow_sources or [None]
                    for port in unique_ports:
                        for source in sources:
                            apply_firewall_rule(port, exposure.protocol, source, allow=True)
                            applied_firewall_rules.append({"port": port, "protocol": exposure.protocol, "source": source})

            audit_api(
                "containers_expose",
                target=payload.container_name,
                details={
                    "devices": len(created_devices),
                    "firewall_rules": len(applied_firewall_rules),
                },
            )
            return {
                "message": f"Exposed {len(created_devices)} port(s) on {payload.container_name}",
                "devices": created_devices,
                "firewall_rules": applied_firewall_rules,
            }
        except Exception as exc:
            for item in created_devices:
                try:
                    container_ops.remove_device(payload.container_name, item["device_name"])
                except Exception:
                    logger.exception("Failed to rollback device %s on %s", item.get("device_name"), payload.container_name)
            for rule in applied_firewall_rules:
                try:
                    apply_firewall_rule(rule["port"], rule["protocol"], rule["source"], allow=False)
                except Exception:
                    logger.exception(
                        "Failed to rollback firewall rule %s/%s %s", rule["protocol"], rule["port"], rule["source"]
                    )
            audit_api(
                "containers_expose",
                target=payload.container_name,
                details={"error": str(exc), "devices_created": len(created_devices)},
                status="error",
            )
            raise HTTPException(status_code=500, detail=f"Failed to expose ports: {exc}")

    @router.post("/containers/connect/share")
    def create_shared_mount(
        payload: SharedMountRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_connect_share", "connectivity", x_api_key, x_user_token, containers=payload.containers)
        try:
            attached = container_ops.create_shared_mount(
                payload.share_name,
                payload.containers,
                payload.mount_path,
                payload.source_path,
                shared_storage_dir,
            )
        except Exception as err:
            audit_api("containers_connect_share", target=payload.share_name, details={"error": str(err)}, status="error")
            raise HTTPException(status_code=500, detail=f"Failed to create shared mount: {err}")
        audit_api("containers_connect_share", target=payload.share_name, details={"containers": payload.containers})
        return {"message": f"Share {payload.share_name} attached", "attachments": attached}

    @router.post("/containers/connect/share/remove")
    def remove_shared_mount(
        payload: SharedMountRemoval,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_disconnect_share", "connectivity", x_api_key, x_user_token, containers=payload.containers)
        try:
            container_ops.remove_shared_mount(payload.share_name, payload.containers)
            audit_api("containers_disconnect_share", target=payload.share_name, details={"containers": payload.containers})
        except Exception as exc:
            audit_api(
                "containers_disconnect_share",
                target=payload.share_name,
                details={"error": str(exc)},
                status="error",
            )
            raise
        return {"message": f"Share {payload.share_name} detached from requested containers"}

    @router.post("/containers/probe")
    def probe_container_services(
        payload: ContainerServiceProbe,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_probe", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        try:
            results = container_ops.probe_container_services(payload.container_name, payload.services)
            label_value = None
            if payload.update_labels:
                label_value = container_ops.set_container_services_label(payload.container_name, results)
            available = sorted([name for name, status in results.items() if status])
            missing = sorted([name for name, status in results.items() if not status])
            audit_api(
                "containers_probe",
                target=payload.container_name,
                details={"available": available, "missing": missing, "labels_updated": payload.update_labels},
            )
            return {
                "container": payload.container_name,
                "services": results,
                "available": available,
                "missing": missing,
                "labels_updated": payload.update_labels,
                "label_value": label_value,
            }
        except Exception as exc:
            audit_api("containers_probe", target=payload.container_name, details={"error": str(exc)}, status="error")
            raise

    @router.post("/containers/start")
    def start_container(
        payload: ContainerLifecycle,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_start", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        with audit_mutation("containers_start", payload.container_name):
            container_ops.start_container(payload.container_name)
        return {"message": f"Container {payload.container_name} started"}

    @router.post("/containers/stop")
    def stop_container(
        payload: ContainerLifecycle,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_stop", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        with audit_mutation("containers_stop", payload.container_name, {"force": payload.force}):
            container_ops.stop_container(payload.container_name, force=payload.force)
        return {"message": f"Container {payload.container_name} stopped"}

    @router.post("/containers/restart")
    def restart_container(
        payload: ContainerLifecycle,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_restart", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        with audit_mutation("containers_restart", payload.container_name, {"force": payload.force}):
            container_ops.restart_container(payload.container_name, force=payload.force)
        return {"message": f"Container {payload.container_name} restarted"}

    @router.get("/containers/{name}/snapshots")
    def list_container_snapshots(
        name: str,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshots_list", "manage_containers", x_api_key, x_user_token, containers=name)
        snapshots = container_ops.list_snapshots(name)
        audit_api("containers_snapshots_list", target=name, details={"count": len(snapshots)})
        return {"snapshots": snapshots}

    @router.post("/containers/snapshot")
    def create_container_snapshot(
        payload: ContainerSnapshotRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshot_create", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        with audit_mutation("containers_snapshot_create", payload.container_name, {"snapshot": payload.snapshot_name, "stateful": payload.stateful}):
            container_ops.create_snapshot(payload.container_name, payload.snapshot_name, stateful=payload.stateful)
        return {"message": f"Snapshot {payload.snapshot_name} created for {payload.container_name}"}

    @router.post("/containers/snapshots/restore")
    def restore_container_snapshot(
        payload: ContainerSnapshotRestore,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshot_restore", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        with audit_mutation("containers_snapshot_restore", payload.container_name, {"snapshot": payload.snapshot_name, "stateful": payload.stateful}):
            container_ops.restore_snapshot(payload.container_name, payload.snapshot_name, stateful=payload.stateful)
        return {"message": f"Snapshot {payload.snapshot_name} restored for {payload.container_name}"}

    @router.delete("/containers/{name}/snapshots/{snapshot_name}")
    def delete_container_snapshot(
        name: str,
        snapshot_name: str,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshot_delete", "manage_containers", x_api_key, x_user_token, containers=name)
        with audit_mutation("containers_snapshot_delete", name, {"snapshot": snapshot_name}):
            container_ops.delete_snapshot(name, snapshot_name)
        return {"message": f"Snapshot {snapshot_name} deleted for {name}"}

    @router.post("/containers/exec")
    def exec_container_command(
        payload: ContainerExecRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_exec", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        details = sanitize_payload(payload.dict(exclude={"command", "environment"}, exclude_none=True))
        with audit_mutation("containers_exec", payload.container_name, details):
            output = container_ops.exec_in_container_advanced(
                payload.container_name,
                payload.command,
                user=payload.user,
                workdir=payload.workdir,
                environment=payload.environment,
            )
        return {"output": output}

    @router.get("/containers/{name}/logs")
    def get_container_logs(
        name: str,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_logs", "manage_containers", x_api_key, x_user_token, containers=name)
        output = container_ops.get_container_logs(name)
        audit_api("containers_logs", target=name)
        return {"logs": output}

    return router
