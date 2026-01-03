import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Literal

from fastapi import HTTPException
from pydantic import BaseModel, Field

from fortress.remote import SSHConfig, build_probe_script, load_provision_script, run_ssh_script
from fortress.storage import load_json_dict, save_json

HOST_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class HostSSHConfig(SSHConfig):
    pass


class HostCreateRequest(BaseModel):
    name: str
    os_type: Optional[str] = None
    ssh: Optional[HostSSHConfig] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    notes: Optional[str] = None
    installed: bool = False
    service_name: str = "fortress"


class HostUpdateRequest(BaseModel):
    os_type: Optional[str] = None
    ssh: Optional[HostSSHConfig] = None
    labels: Optional[Dict[str, str]] = None
    notes: Optional[str] = None
    installed: Optional[bool] = None
    service_name: Optional[str] = None


class HostProvisionRequest(BaseModel):
    profile: Literal["ubuntu", "fedora"] = "ubuntu"
    repo_url: Optional[str] = None
    branch: str = "main"
    install_dir: str = "/opt/linus-fortress"
    service_name: str = "fortress"
    fortress_port: int = 8443
    api_key: Optional[str] = None
    backup_password: Optional[str] = None
    skip_service: bool = False
    force_reset: bool = False
    ssh: Optional[HostSSHConfig] = None


class HostProbeRequest(BaseModel):
    save_as: Optional[str] = None
    ssh: Optional[HostSSHConfig] = None


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def validate_host_name(name: str) -> None:
    if not name or not HOST_NAME_PATTERN.match(name):
        raise HTTPException(status_code=400, detail="Host name must be 1-64 chars using letters, digits, ., _, or -")


def load_hosts(path: str) -> Dict[str, Dict[str, Any]]:
    return load_json_dict(path, label="Host")


def save_hosts(path: str, hosts: Dict[str, Dict[str, Any]]) -> None:
    save_json(path, hosts)


def sanitize_host_record(record: Dict[str, Any]) -> Dict[str, Any]:
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


def build_host_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    ssh = record.get("ssh") or {}
    return {
        "name": record.get("name"),
        "os_type": record.get("os_type"),
        "installed": record.get("installed", False),
        "ssh_host": ssh.get("host"),
        "ssh_port": ssh.get("port"),
        "labels": record.get("labels", {}),
        "updated_at": record.get("updated_at"),
    }


def _resolve_host(hosts: Dict[str, Dict[str, Any]], name: str) -> Dict[str, Any]:
    record = hosts.get(name)
    if not record:
        raise HTTPException(status_code=404, detail="Host not found")
    return record


def _resolve_ssh_config(record: Dict[str, Any], override: Optional[HostSSHConfig]) -> Dict[str, Any]:
    if override is not None:
        return override.dict()
    ssh = record.get("ssh")
    if not ssh:
        raise HTTPException(status_code=400, detail="SSH config missing for host")
    return ssh


def create_host(payload: HostCreateRequest, hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    validate_host_name(payload.name)
    if payload.name in hosts:
        raise HTTPException(status_code=409, detail="Host already exists")
    record = payload.dict()
    record["created_at"] = utc_now()
    record["updated_at"] = record["created_at"]
    record["saved_states"] = []
    hosts[payload.name] = record
    return record


def update_host(name: str, payload: HostUpdateRequest, hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_host(hosts, name)
    updates = payload.dict(exclude_unset=True)
    if "ssh" in updates and updates["ssh"] is not None:
        record["ssh"] = updates["ssh"]
    for key in ["os_type", "labels", "notes", "installed", "service_name"]:
        if key in updates and updates[key] is not None:
            record[key] = updates[key]
    record["updated_at"] = utc_now()
    return record


def delete_host(name: str, hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_host(hosts, name)
    hosts.pop(name, None)
    return record


def provision_host(name: str, request: HostProvisionRequest, hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_host(hosts, name)
    script = load_provision_script(request.profile)
    ssh_config = _resolve_ssh_config(record, request.ssh)
    env = {
        "REPO_URL": request.repo_url,
        "BRANCH": request.branch,
        "INSTALL_DIR": request.install_dir,
        "SERVICE_NAME": request.service_name,
        "FORTRESS_HOST_PORT": request.fortress_port,
        "FORTRESS_API_KEY": request.api_key,
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


def probe_host(name: str, request: HostProbeRequest, hosts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_host(hosts, name)
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


def list_saved_states(name: str, hosts: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    record = _resolve_host(hosts, name)
    return record.get("saved_states", [])
