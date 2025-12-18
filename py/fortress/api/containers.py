import logging
from typing import Any, Callable, Dict, List, Optional, Literal

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from fortress import containers as container_ops

AuthorizeFn = Callable[..., Dict[str, Any]]
AuditFn = Callable[..., None]
SanitizeFn = Callable[..., Dict[str, Any]]


class ContainerCreate(BaseModel):
    name: str
    distro: str = "ubuntu:22.04"
    cpu_limit: str = "1"
    ram_limit: str = "512MB"
    disk_limit: str = "10GB"


class ExternalAccessRule(BaseModel):
    container_name: str
    service: Literal["ssh", "ftp"]
    host_port: Optional[int] = None
    connect_port: Optional[int] = None
    bind_address: str = "0.0.0.0"
    connect_address: str = "127.0.0.1"
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


def build_container_router(
    authorize: AuthorizeFn,
    audit_api: AuditFn,
    sanitize_payload: SanitizeFn,
    shared_storage_dir: str,
) -> APIRouter:
    router = APIRouter()
    logger = logging.getLogger(__name__)

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
                device_name=rule.device_name,
            )
            audit_api(
                "external_access_open",
                target=rule.container_name,
                details={"service": rule.service, "device": result["device_name"], "host_port": result["host_port"]},
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
                payload.device_name,
            )
            audit_api(
                "containers_connect_tcp",
                target=payload.source_container,
                details={
                    "device": device_name,
                    "target": payload.target_container,
                    "listen_port": payload.listen_port,
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

    return router
