import re
import secrets
from datetime import datetime
from typing import Any, Dict, List, Optional, Literal, Tuple, Union

from fastapi import HTTPException
from pydantic import BaseModel, Field

from fortress.storage import load_json_dict, save_json


SITE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class SiteFpmPoolTuning(BaseModel):
    name: Optional[str] = None
    pm: Optional[Literal["static", "dynamic", "ondemand"]] = None
    max_children: Optional[int] = Field(default=None, ge=1, le=4096)
    start_servers: Optional[int] = Field(default=None, ge=0, le=4096)
    min_spare_servers: Optional[int] = Field(default=None, ge=0, le=4096)
    max_spare_servers: Optional[int] = Field(default=None, ge=0, le=4096)
    max_requests: Optional[int] = Field(default=None, ge=0, le=1000000)
    process_idle_timeout: Optional[str] = None
    request_terminate_timeout: Optional[str] = None
    additional_overrides: Dict[str, str] = Field(default_factory=dict)


class SiteRuntime(BaseModel):
    php_version: Optional[str] = None
    fpm_pool: Optional[Union[str, SiteFpmPoolTuning]] = None
    user: Optional[str] = None
    group: Optional[str] = None
    php_ini_overrides: Dict[str, str] = Field(default_factory=dict)


class SiteDatabase(BaseModel):
    engine: Optional[Literal["mysql", "mariadb"]] = None
    name: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    root_password: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None


class SiteTls(BaseModel):
    mode: Literal["disabled", "manual", "letsencrypt"] = "manual"
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    chain_path: Optional[str] = None
    email: Optional[str] = None
    staging: bool = False
    cert_name: Optional[str] = None
    listen_port: Optional[int] = None
    redirect_http: bool = True


class SiteRouting(BaseModel):
    listen_address: Optional[str] = None
    listen_port: Optional[int] = None
    container_port: Optional[int] = None
    container_interface: Optional[str] = None


class SiteSummary(BaseModel):
    id: str
    name: str
    primary_domain: str
    container_name: str
    status: str


class SiteRecord(BaseModel):
    id: str
    name: str
    primary_domain: str
    domains: List[str] = Field(default_factory=list)
    container_name: str
    docroot: str
    runtime: SiteRuntime = Field(default_factory=SiteRuntime)
    database: Optional[SiteDatabase] = None
    routing: SiteRouting = Field(default_factory=SiteRouting)
    tls: Optional[SiteTls] = None
    status: str = "active"
    created_at: str
    updated_at: str


class SiteCreateRequest(BaseModel):
    name: str
    primary_domain: str
    domains: List[str] = Field(default_factory=list)
    container_name: str
    docroot: str
    runtime: Optional[SiteRuntime] = None
    database: Optional[SiteDatabase] = None
    routing: Optional[SiteRouting] = None
    tls: Optional[SiteTls] = None
    create_database: bool = True
    create_user: bool = True


class SiteUpdateRequest(BaseModel):
    name: Optional[str] = None
    primary_domain: Optional[str] = None
    domains: Optional[List[str]] = None
    docroot: Optional[str] = None
    runtime: Optional[SiteRuntime] = None
    database: Optional[SiteDatabase] = None
    routing: Optional[SiteRouting] = None
    tls: Optional[SiteTls] = None
    status: Optional[str] = None


class SiteDeployRequest(BaseModel):
    source_type: Literal["git", "archive", "local"]
    source: str
    ref: Optional[str] = None
    subdir: Optional[str] = None
    strip_components: int = 0
    post_deploy_commands: List[str] = Field(default_factory=list)
    restart_services: bool = True


class SiteBackupRequest(BaseModel):
    include_database: bool = True
    label: Optional[str] = None


class SiteRollbackRequest(BaseModel):
    backup_id: str
    restart_services: bool = True


class SiteServiceActionRequest(BaseModel):
    services: Optional[List[str]] = None


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def validate_site_name(name: str) -> None:
    if not name or not SITE_NAME_PATTERN.match(name):
        raise HTTPException(status_code=400, detail="Site name must be 1-64 chars using letters, digits, ., _, or -")


def load_sites(path: str) -> Dict[str, Dict[str, Any]]:
    return load_json_dict(path, label="Site")


def save_sites(path: str, sites: Dict[str, Dict[str, Any]]) -> None:
    save_json(path, sites)


def sanitize_site_record(record: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(record)
    database = sanitized.get("database")
    if isinstance(database, dict):
        masked = dict(database)
        masked_any = False
        for key, value in list(masked.items()):
            if "password" in key and value:
                masked[key] = "***"
                masked_any = True
        if masked_any:
            masked["has_password"] = True
            sanitized["database"] = masked
    return sanitized


def build_site_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": record.get("id"),
        "name": record.get("name"),
        "primary_domain": record.get("primary_domain"),
        "container_name": record.get("container_name"),
        "status": record.get("status", "unknown"),
    }


def _resolve_site(sites: Dict[str, Dict[str, Any]], site_id: str) -> Dict[str, Any]:
    record = sites.get(site_id)
    if not record:
        raise HTTPException(status_code=404, detail="Site not found")
    return record


def _generate_password() -> str:
    return secrets.token_urlsafe(18)


def create_site_record(payload: SiteCreateRequest, sites: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    validate_site_name(payload.name)
    if payload.name in sites:
        raise HTTPException(status_code=409, detail="Site already exists")
    now = utc_now()
    record = SiteRecord(
        id=payload.name,
        name=payload.name,
        primary_domain=payload.primary_domain,
        domains=payload.domains or [],
        container_name=payload.container_name,
        docroot=payload.docroot,
        runtime=payload.runtime or SiteRuntime(),
        database=payload.database,
        routing=payload.routing or SiteRouting(),
        tls=payload.tls,
        created_at=now,
        updated_at=now,
    ).dict()
    database = record.get("database")
    if isinstance(database, dict) and database.get("username") and not database.get("password"):
        database["password"] = _generate_password()
        record["database"] = database
    sites[payload.name] = record
    return record


def update_site_record(site_id: str, payload: SiteUpdateRequest, sites: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_site(sites, site_id)
    updates = payload.dict(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        validate_site_name(updates["name"])
        if updates["name"] != site_id and updates["name"] in sites:
            raise HTTPException(status_code=409, detail="Site already exists")
    for key in ["name", "primary_domain", "domains", "docroot", "status"]:
        if key in updates and updates[key] is not None:
            record[key] = updates[key]
    if "runtime" in updates and updates["runtime"] is not None:
        runtime_updates = (
            updates["runtime"]
            if isinstance(updates["runtime"], dict)
            else updates["runtime"].dict(exclude_unset=True)
        )
        merged_runtime = dict(record.get("runtime") or {})
        merged_runtime.update(runtime_updates)
        record["runtime"] = merged_runtime
    if "database" in updates and updates["database"] is not None:
        database_updates = (
            updates["database"]
            if isinstance(updates["database"], dict)
            else updates["database"].dict(exclude_unset=True)
        )
        merged_database = dict(record.get("database") or {})
        merged_database.update(database_updates)
        record["database"] = merged_database
    if "routing" in updates and updates["routing"] is not None:
        routing_updates = (
            updates["routing"]
            if isinstance(updates["routing"], dict)
            else updates["routing"].dict(exclude_unset=True)
        )
        merged_routing = dict(record.get("routing") or {})
        merged_routing.update(routing_updates)
        record["routing"] = merged_routing
    if "tls" in updates and updates["tls"] is not None:
        tls_updates = (
            updates["tls"]
            if isinstance(updates["tls"], dict)
            else updates["tls"].dict(exclude_unset=True)
        )
        merged_tls = dict(record.get("tls") or {})
        merged_tls.update(tls_updates)
        record["tls"] = merged_tls
    record["updated_at"] = utc_now()
    if site_id != record.get("name"):
        sites.pop(site_id, None)
        sites[record["name"]] = record
    return record


def delete_site_record(site_id: str, sites: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    record = _resolve_site(sites, site_id)
    sites.pop(site_id, None)
    return record


def extract_service_targets(services: Optional[List[str]]) -> List[str]:
    if not services:
        return ["web", "php-fpm"]
    return services


def build_site_backup_id(site_id: str, label: Optional[str] = None) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    suffix = f"-{label}" if label else ""
    return f"{site_id}-{stamp}{suffix}"


def build_service_names(runtime: Dict[str, Any]) -> Dict[str, List[str]]:
    php_version = runtime.get("php_version")
    php_candidates = []
    if php_version:
        php_candidates.append(f"php{php_version}-fpm")
    php_candidates.extend(["php-fpm", "php8.2-fpm", "php8.1-fpm", "php8.0-fpm"])
    return {
        "web": ["apache2", "httpd", "nginx"],
        "php-fpm": php_candidates,
        "db": ["mariadb", "mysql"],
    }
