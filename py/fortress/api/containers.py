import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from fortress import containers as container_ops
from fortress.firewall import apply_firewall_rule
from fortress.storage import load_json, save_json

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

    def _load_image_store() -> Any:
        return load_json(popular_images_db, {"popular": []}, label="popular images")

    def _save_image_store(payload: Dict[str, Any]) -> None:
        save_json(popular_images_db, payload, indent=2)

    def _extract_popular_store_entries(store_payload: Any) -> List[Any]:
        if isinstance(store_payload, list):
            # Legacy format: store file was a bare list of entries.
            return store_payload
        if isinstance(store_payload, dict):
            popular = store_payload.get("popular")
            if isinstance(popular, list):
                return popular
        return []

    def _normalize_popular_name(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if value is None:
            return ""
        return str(value).strip()

    def _fallback_popular_images() -> List[Dict[str, str]]:
        latest = container_ops.find_latest_ubuntu_lts_alias()
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
            if isinstance(item, dict):
                raw_name = item.get("name")
                if raw_name is None:
                    # Legacy key used by older presets.
                    raw_name = item.get("alias")
                raw_label = item.get("label")
            else:
                raw_name = item
                raw_label = None
            normalized = _normalize_popular_name(raw_name)
            if not normalized:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            label = _normalize_popular_name(raw_label) if raw_label is not None else ""
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

    def _list_popular_entries() -> List[Dict[str, Any]]:
        try:
            discovered = container_ops.discover_popular_images()
        except Exception:
            logger.exception("Failed to discover popular images from LXD; falling back to saved presets/defaults")
            discovered = []
        custom = _list_custom_popular_entries()
        fallback = _fallback_popular_images()
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
            for item in fallback:
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
        authorize("container_create", "manage_containers", x_api_key, x_user_token)
        remotes = sorted(container_ops.list_lxd_remotes())
        latest_lts = container_ops.find_latest_ubuntu_lts_alias()
        entries = _list_popular_entries()
        inspected = [_inspect_entry(entry, remotes=remotes) for entry in entries]
        audit_api("container_images_list", details={"count": len(inspected)})
        return {
            "images": inspected,
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
        authorize("container_create", "manage_containers", x_api_key, x_user_token)
        store = _load_image_store()
        popular = store.get("popular") or []
        updated = False
        for item in popular:
            if isinstance(item, dict) and item.get("name") == payload.name:
                if payload.label:
                    item["label"] = payload.label
                updated = True
                break
        if not updated:
            popular.append(payload.dict())
        _save_image_store({"popular": popular})
        audit_api("container_images_add", target=payload.name)
        return {"message": "Image preset saved", "popular": popular}

    @router.post("/containers/images/popular/remove")
    def remove_popular_image(
        payload: PopularImageRemove,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("container_create", "manage_containers", x_api_key, x_user_token)
        store = _load_image_store()
        popular = store.get("popular") or []
        filtered = [item for item in popular if not (isinstance(item, dict) and item.get("name") == payload.name)]
        _save_image_store({"popular": filtered})
        audit_api("container_images_remove", target=payload.name)
        return {"message": "Image preset removed", "popular": filtered}

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
        container_ops.start_container(payload.container_name)
        audit_api("containers_start", target=payload.container_name)
        return {"message": f"Container {payload.container_name} started"}

    @router.post("/containers/stop")
    def stop_container(
        payload: ContainerLifecycle,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_stop", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        container_ops.stop_container(payload.container_name, force=payload.force)
        audit_api("containers_stop", target=payload.container_name, details={"force": payload.force})
        return {"message": f"Container {payload.container_name} stopped"}

    @router.post("/containers/restart")
    def restart_container(
        payload: ContainerLifecycle,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_restart", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        container_ops.restart_container(payload.container_name, force=payload.force)
        audit_api("containers_restart", target=payload.container_name, details={"force": payload.force})
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
        container_ops.create_snapshot(payload.container_name, payload.snapshot_name, stateful=payload.stateful)
        audit_api(
            "containers_snapshot_create",
            target=payload.container_name,
            details={"snapshot": payload.snapshot_name, "stateful": payload.stateful},
        )
        return {"message": f"Snapshot {payload.snapshot_name} created for {payload.container_name}"}

    @router.post("/containers/snapshots/restore")
    def restore_container_snapshot(
        payload: ContainerSnapshotRestore,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshot_restore", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        container_ops.restore_snapshot(payload.container_name, payload.snapshot_name, stateful=payload.stateful)
        audit_api(
            "containers_snapshot_restore",
            target=payload.container_name,
            details={"snapshot": payload.snapshot_name, "stateful": payload.stateful},
        )
        return {"message": f"Snapshot {payload.snapshot_name} restored for {payload.container_name}"}

    @router.delete("/containers/{name}/snapshots/{snapshot_name}")
    def delete_container_snapshot(
        name: str,
        snapshot_name: str,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_snapshot_delete", "manage_containers", x_api_key, x_user_token, containers=name)
        container_ops.delete_snapshot(name, snapshot_name)
        audit_api("containers_snapshot_delete", target=name, details={"snapshot": snapshot_name})
        return {"message": f"Snapshot {snapshot_name} deleted for {name}"}

    @router.post("/containers/exec")
    def exec_container_command(
        payload: ContainerExecRequest,
        x_api_key: Optional[str] = Header(default=None),
        x_user_token: Optional[str] = Header(default=None),
    ):
        authorize("containers_exec", "manage_containers", x_api_key, x_user_token, containers=payload.container_name)
        output = container_ops.exec_in_container_advanced(
            payload.container_name,
            payload.command,
            user=payload.user,
            workdir=payload.workdir,
            environment=payload.environment,
        )
        audit_api(
            "containers_exec",
            target=payload.container_name,
            details=sanitize_payload(payload.dict(exclude={"command"}, exclude_none=True)),
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
