import uvicorn
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
import os
import shutil
import secrets
import logging
from typing import Optional, List, Dict, Literal, Union, Any
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib
from contextvars import ContextVar

from fortress.auth import (
    DEFAULT_API_SECRET,
    enforce_container_scope,
    enforce_container_scopes,
    mask_token,
    resolve_master_key,
    verify_token,
)
from fortress.audit import CommandLogger
from fortress.api.containers import build_container_router
from fortress.containers import (
    SENSITIVE_KEYWORDS,
    configure_audit,
    detect_package_manager,
    exec_in_container,
    get_container_ip,
    run_package_command,
    update_package_index,
    validate_port,
)
from fortress.firewall import apply_firewall_rule
from fortress.recipes import (
    RecipeDefinition,
    RecipeUpdate,
    RecipeApplyRequest,
    load_recipes,
    save_recipes,
    resolve_recipe_plan,
    build_recipe_execution,
    validate_recipe_name,
    normalize_parameters,
)
from fortress.system import run_command
from fortress.routing import (
    build_nginx_proxy_config,
    ensure_nginx_site,
    reload_nginx,
    remove_nginx_site,
    test_nginx_config,
    validate_domain,
    validate_tls_paths,
    write_nginx_config,
)
from fortress.monitoring import (
    DEFAULT_ANOMALY_THRESHOLDS,
    DEFAULT_BASELINE_SAMPLES,
    DEFAULT_CONTAINER_THRESHOLDS,
    DEFAULT_HISTORY_LIMIT,
    DEFAULT_HOST_THRESHOLDS,
    gather_resource_snapshot,
    record_resource_snapshot,
)
from fortress.storage import load_json_dict, save_json
from fortress.vms import (
    VMCreateRequest,
    VMUpdateRequest,
    VMStartRequest,
    VMStopRequest,
    VMSnapshotRequest,
    VMProvisionRequest,
    VMProbeRequest,
    load_vms,
    save_vms,
    build_vm_summary,
    sanitize_vm_record,
    create_vm,
    update_vm,
    delete_vm,
    start_vm as start_vm_record,
    stop_vm as stop_vm_record,
    vm_status,
    create_snapshot,
    restore_snapshot,
    delete_snapshot,
    list_snapshots,
    provision_vm,
    probe_vm,
)
from fortress.hosts import (
    HostCreateRequest,
    HostUpdateRequest,
    HostProvisionRequest,
    HostProbeRequest,
    load_hosts,
    save_hosts,
    build_host_summary,
    sanitize_host_record,
    create_host,
    update_host,
    delete_host,
    provision_host,
    probe_host,
)

# --- CONFIGURATION ---
# In production, load these from environment variables
API_SECRET_KEY = os.environ.get("FORTRESS_API_KEY", os.environ.get("API_SECRET_KEY", DEFAULT_API_SECRET))
BACKUP_ENCRYPTION_PASSWORD = os.environ.get("FORTRESS_BACKUP_PASSWORD", "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD")
HOST_INTERFACE = os.environ.get("FORTRESS_HOST_INTERFACE", "0.0.0.0")
HOST_PORT = int(os.environ.get("FORTRESS_HOST_PORT", "8443"))
BACKUP_DIR = "/var/lib/fortress/backups"
NGINX_CONFIG_DIR = "/etc/nginx/sites-available"
NGINX_ENABLED_DIR = "/etc/nginx/sites-enabled"
API_USERS_DB = "/var/lib/fortress/api_users.json"
RECIPES_DB = "/var/lib/fortress/recipes.json"
SHARED_STORAGE_DIR = "/var/lib/fortress/shares"
COMMAND_LOG_DB = "/var/lib/fortress/command_log.db"
VMS_DB = "/var/lib/fortress/vms.json"
HOSTS_DB = "/var/lib/fortress/hosts.json"
ROUTING_DB = "/var/lib/fortress/routes.json"
MONITORING_HISTORY_DB = "/var/lib/fortress/monitoring_history.json"

# Logging setup
logging.basicConfig(filename='/var/log/fortress.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s')

MASTER_API_KEY = resolve_master_key(API_SECRET_KEY, DEFAULT_API_SECRET)
if MASTER_API_KEY is None:
    logging.warning("Master API key disabled or defaulted; only delegated tokens accepted.")

app = FastAPI(title="VPS Fortress Manager")
REQUEST_CONTEXT = ContextVar("REQUEST_CONTEXT", default={"actor": "system", "endpoint": "internal"})
command_logger = CommandLogger(COMMAND_LOG_DB)

# --- SECURITY UTILS ---

def get_fernet_key(password: str) -> bytes:
    """Derive a 32-byte base64 key from the password for AES encryption."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def set_request_context(actor: str, endpoint: str):
    REQUEST_CONTEXT.set({"actor": actor or "system", "endpoint": endpoint})

def get_request_context() -> Dict[str, str]:
    return REQUEST_CONTEXT.get()

def audit_event(category: str, action: str, target: Optional[str] = None, details: Optional[Dict[str, Any]] = None, status: str = "success"):
    ctx = get_request_context()
    actor = ctx.get("actor", "system")
    endpoint = ctx.get("endpoint", "internal")
    command_logger.log(actor, endpoint, category, action, target, details, status)

def audit_api(action: str, target: Optional[str] = None, details: Optional[Dict[str, Any]] = None, status: str = "success"):
    audit_event("api", action, target, details, status)

def audit_internal(action: str, target: Optional[str] = None, details: Optional[Dict[str, Any]] = None, status: str = "success"):
    audit_event("internal", action, target, details, status)

configure_audit(audit_event)

def sanitize_payload(payload: Dict[str, Any], sensitive_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    if not payload:
        return {}
    sensitive = set(sensitive_keys or [])
    redacted = {}
    for key, value in payload.items():
        redacted[key] = "***" if key in sensitive else value
    return redacted

def sanitize_payload_fuzzy(payload: Dict[str, Any], sensitive_keywords: Optional[set[str]] = None) -> Dict[str, Any]:
    if not payload:
        return {}
    keywords = set(sensitive_keywords or [])
    redacted = {}
    for key, value in payload.items():
        if any(keyword in key.lower() for keyword in keywords):
            redacted[key] = "***"
        else:
            redacted[key] = value
    return redacted

def authorize(endpoint: str, required_permission: Optional[str], x_api_key: Optional[str], x_user_token: Optional[str], containers: Optional[Union[str, List[str]]] = None):
    auth_context = verify_token(
        x_api_key,
        x_user_token,
        required_permission=required_permission,
        master_key=MASTER_API_KEY,
        load_users=load_api_users,
    )
    set_request_context(auth_context.get("actor", "system"), endpoint)
    if containers:
        if isinstance(containers, str):
            enforce_container_scope(auth_context, containers)
        else:
            enforce_container_scopes(auth_context, containers)
    return auth_context

def load_api_users() -> Dict[str, Dict]:
    return load_json_dict(
        API_USERS_DB,
        label="API user",
        error_message="Failed to load API user database, falling back to empty set.",
    )

def save_api_users(users: Dict[str, Dict]):
    save_json(API_USERS_DB, users)

def load_routes() -> Dict[str, Dict[str, Any]]:
    return load_json_dict(
        ROUTING_DB,
        label="routing",
        error_message="Failed to load routing store, falling back to empty set.",
    )

def save_routes(routes: Dict[str, Dict[str, Any]]):
    save_json(ROUTING_DB, routes)

def ensure_packages_list(packages: List[str]):
    if not packages:
        raise HTTPException(status_code=400, detail="Package list cannot be empty")

# --- DATA MODELS ---

class DomainRouteTLS(BaseModel):
    cert_path: str
    key_path: str
    chain_path: Optional[str] = None
    listen_port: int = 443
    redirect_http: bool = True

class DomainRoute(BaseModel):
    domain: str
    container_name: str
    container_port: int = 80
    container_interface: str = "eth0"
    listen_address: str = "0.0.0.0"
    listen_port: int = 80
    tls: Optional[DomainRouteTLS] = None

class APIUserCreate(BaseModel):
    username: str
    permissions: List[str] = []
    allowed_containers: Optional[List[str]] = None

class APIUserUpdate(BaseModel):
    permissions: Optional[List[str]] = None
    allowed_containers: Optional[List[str]] = None

class FirewallRule(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    source: Optional[str] = None

class PackageInstallRequest(BaseModel):
    packages: List[str]
    container_name: Optional[str] = None
    update_index: bool = True

class PackageRemoveRequest(BaseModel):
    packages: List[str]
    container_name: Optional[str] = None

class PackageUpdateRequest(BaseModel):
    container_name: Optional[str] = None
    full_upgrade: bool = False
# --- CORE LOGIC ---

app.include_router(build_container_router(authorize, audit_api, sanitize_payload, SHARED_STORAGE_DIR))

@app.get("/status", dependencies=[])
def system_status(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("status", "read_status", x_api_key, x_user_token)
    # Check RAM, Disk, and Load
    ram = run_command(["free", "-h"])
    disk = run_command(["df", "-h"])
    containers = run_command(["lxc", "list", "--format", "json"])
    audit_api("status", details={
        "ram_head": ram.splitlines()[0] if ram else "",
        "disk_head": disk.splitlines()[0] if disk else ""
    })
    return {"status": "operational", "ram": ram, "disk": disk, "containers": containers}

@app.get("/monitoring/resources")
def monitoring_resources(
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
    host_memory_threshold: float = DEFAULT_HOST_THRESHOLDS["memory_percent"],
    host_disk_threshold: float = DEFAULT_HOST_THRESHOLDS["disk_percent"],
    host_load_threshold: float = DEFAULT_HOST_THRESHOLDS["load_per_cpu"],
    container_memory_threshold: float = DEFAULT_CONTAINER_THRESHOLDS["memory_percent"],
    container_disk_threshold: float = DEFAULT_CONTAINER_THRESHOLDS["disk_percent"],
    container_process_threshold: int = DEFAULT_CONTAINER_THRESHOLDS["process_count"],
    container_memory_absolute_mb: int = int(DEFAULT_CONTAINER_THRESHOLDS["memory_absolute_bytes"] / (1024 * 1024)),
    container_disk_absolute_gb: int = int(DEFAULT_CONTAINER_THRESHOLDS["disk_absolute_bytes"] / (1024 * 1024 * 1024)),
    history_limit: int = DEFAULT_HISTORY_LIMIT,
    anomaly_baseline_samples: int = DEFAULT_BASELINE_SAMPLES,
    anomaly_host_cpu_multiplier: float = DEFAULT_ANOMALY_THRESHOLDS["host_cpu"]["multiplier"],
    anomaly_host_cpu_min_percent: float = DEFAULT_ANOMALY_THRESHOLDS["host_cpu"]["min_usage_percent"],
    anomaly_host_network_multiplier: float = DEFAULT_ANOMALY_THRESHOLDS["host_network"]["multiplier"],
    anomaly_host_network_min_bytes_per_sec: int = int(DEFAULT_ANOMALY_THRESHOLDS["host_network"]["min_bytes_per_sec"]),
    anomaly_container_cpu_multiplier: float = DEFAULT_ANOMALY_THRESHOLDS["container_cpu"]["multiplier"],
    anomaly_container_cpu_min_cores: float = DEFAULT_ANOMALY_THRESHOLDS["container_cpu"]["min_cores"],
    anomaly_container_network_multiplier: float = DEFAULT_ANOMALY_THRESHOLDS["container_network"]["multiplier"],
    anomaly_container_network_min_bytes_per_sec: int = int(DEFAULT_ANOMALY_THRESHOLDS["container_network"]["min_bytes_per_sec"]),
):
    authorize("monitoring_resources", "read_status", x_api_key, x_user_token)
    host_thresholds = {
        "memory_percent": host_memory_threshold,
        "disk_percent": host_disk_threshold,
        "load_per_cpu": host_load_threshold,
    }
    container_thresholds = {
        "memory_percent": container_memory_threshold,
        "disk_percent": container_disk_threshold,
        "process_count": container_process_threshold,
        "memory_absolute_bytes": max(container_memory_absolute_mb, 0) * 1024 * 1024,
        "disk_absolute_bytes": max(container_disk_absolute_gb, 0) * 1024 * 1024 * 1024,
    }
    anomaly_thresholds = {
        "host_cpu": {
            "multiplier": max(anomaly_host_cpu_multiplier, 0.0),
            "min_usage_percent": max(anomaly_host_cpu_min_percent, 0.0),
        },
        "host_network": {
            "multiplier": max(anomaly_host_network_multiplier, 0.0),
            "min_bytes_per_sec": max(anomaly_host_network_min_bytes_per_sec, 0),
        },
        "container_cpu": {
            "multiplier": max(anomaly_container_cpu_multiplier, 0.0),
            "min_cores": max(anomaly_container_cpu_min_cores, 0.0),
        },
        "container_network": {
            "multiplier": max(anomaly_container_network_multiplier, 0.0),
            "min_bytes_per_sec": max(anomaly_container_network_min_bytes_per_sec, 0),
        },
    }
    snapshot = gather_resource_snapshot(host_thresholds, container_thresholds)
    snapshot = record_resource_snapshot(
        snapshot,
        MONITORING_HISTORY_DB,
        history_limit=max(history_limit, 0),
        baseline_samples=max(anomaly_baseline_samples, 0),
        anomaly_thresholds=anomaly_thresholds,
    )
    alert_summary = {
        "host_alerts": len(snapshot.get("alerts", {}).get("host", [])),
        "containers": {name: len(alerts) for name, alerts in snapshot.get("alerts", {}).get("containers", {}).items()},
    }
    audit_api("monitoring_resources", details=alert_summary)
    return snapshot

@app.post("/routing/add")
def add_domain_routing(route: DomainRoute, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("routing_add", "manage_routing", x_api_key, x_user_token, containers=route.container_name)

    validate_domain(route.domain)
    validate_port(route.container_port, "container_port")
    validate_port(route.listen_port, "listen_port")
    tls_payload = None
    if route.tls:
        validate_port(route.tls.listen_port, "tls.listen_port")
        if route.tls.listen_port == route.listen_port:
            raise HTTPException(status_code=400, detail="TLS listen_port must differ from listen_port")
        validate_tls_paths(route.tls.cert_path, route.tls.key_path, route.tls.chain_path)
        tls_payload = route.tls.dict()

    # 1. Get Container IP on the requested interface
    ip = get_container_ip(route.container_name, route.container_interface)

    # 2. Generate Nginx config restricted to the listen address/port.
    config_content = build_nginx_proxy_config(
        domain=route.domain,
        listen_address=route.listen_address,
        listen_port=route.listen_port,
        upstream_host=ip,
        upstream_port=route.container_port,
        tls=tls_payload,
    )
    config_path = os.path.join(NGINX_CONFIG_DIR, route.domain)
    previous_config = None
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            previous_config = f.read()

    write_nginx_config(route.domain, config_content, NGINX_CONFIG_DIR)

    # 3. Symlink, validate, and reload.
    try:
        ensure_nginx_site(route.domain, config_path, NGINX_ENABLED_DIR)
        test_nginx_config()
        reload_nginx()
    except Exception as exc:
        if previous_config is not None:
            write_nginx_config(route.domain, previous_config, NGINX_CONFIG_DIR)
            ensure_nginx_site(route.domain, config_path, NGINX_ENABLED_DIR)
        else:
            remove_nginx_site(route.domain, config_path, NGINX_ENABLED_DIR)
        audit_api(
            "routing_add",
            target=route.domain,
            details={
                "container": route.container_name,
                "listen": f"{route.listen_address}:{route.listen_port}",
                "tls": bool(route.tls),
                "error": str(exc),
            },
            status="error",
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(exc))

    routes = load_routes()
    routes[route.domain] = route.dict()
    save_routes(routes)

    audit_api(
        "routing_add",
        target=route.domain,
        details={
            "container": route.container_name,
            "port": route.container_port,
            "listen": f"{route.listen_address}:{route.listen_port}",
            "interface": route.container_interface,
            "tls": bool(route.tls),
            "tls_port": route.tls.listen_port if route.tls else None,
        },
    )
    return {"message": f"Routing set for {route.domain} -> {ip}"}


@app.get("/routing")
def list_domain_routing(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("routing_list", "manage_routing", x_api_key, x_user_token)
    routes = load_routes()
    allowed_containers = auth_context.get("allowed_containers")
    response = []
    for domain, record in routes.items():
        if allowed_containers and record.get("container_name") not in allowed_containers:
            continue
        entry = dict(record)
        entry["domain"] = domain
        enabled_path = os.path.join(NGINX_ENABLED_DIR, domain)
        entry["enabled"] = os.path.exists(enabled_path)
        response.append(entry)
    audit_api("routing_list", details={"count": len(response)})
    return {"routes": response}


@app.delete("/routing/{domain}")
def remove_domain_routing(domain: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("routing_remove", "manage_routing", x_api_key, x_user_token)
    validate_domain(domain)
    routes = load_routes()
    record = routes.get(domain)
    if not record:
        audit_api("routing_remove", target=domain, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Route not found")
    if record.get("container_name"):
        enforce_container_scope(auth_context, record["container_name"])

    config_path = os.path.join(NGINX_CONFIG_DIR, domain)
    previous_config = None
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            previous_config = f.read()

    try:
        remove_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
        test_nginx_config()
        reload_nginx()
    except Exception as exc:
        if previous_config is not None:
            write_nginx_config(domain, previous_config, NGINX_CONFIG_DIR)
            ensure_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
        audit_api(
            "routing_remove",
            target=domain,
            details={"container": record.get("container_name"), "error": str(exc)},
            status="error",
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(exc))

    routes.pop(domain, None)
    save_routes(routes)
    audit_api("routing_remove", target=domain, details={"container": record.get("container_name")})
    return {"message": f"Routing removed for {domain}"}

# --- API USER MANAGEMENT ---

@app.post("/api-users")
def create_api_user(user: APIUserCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("api_user_create", "api_user_admin", x_api_key, x_user_token)
    token = secrets.token_hex(32)
    try:
        users = load_api_users()
        users[token] = {
            "username": user.username,
            "permissions": user.permissions,
            "allowed_containers": user.allowed_containers,
        }
        save_api_users(users)
        audit_api("api_user_create", target=user.username, details={"token": mask_token(token), "permissions": user.permissions})
        return {"token": token, "user": users[token]}
    except Exception as exc:
        audit_api("api_user_create", target=user.username, details={"error": str(exc)}, status="error")
        raise

@app.get("/api-users")
def list_api_users(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("api_user_list", "api_user_admin", x_api_key, x_user_token)
    users = load_api_users()
    response = [{"token": token, **info} for token, info in users.items()]
    audit_api("api_user_list", details={"count": len(response)})
    return {"users": response}

@app.put("/api-users/{token}")
def update_api_user(token: str, update: APIUserUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("api_user_update", "api_user_admin", x_api_key, x_user_token)
    users = load_api_users()
    if token not in users:
        audit_api("api_user_update", target=mask_token(token), details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="API user token not found")
    if update.permissions is not None:
        users[token]["permissions"] = update.permissions
    if update.allowed_containers is not None:
        users[token]["allowed_containers"] = update.allowed_containers
    save_api_users(users)
    audit_api("api_user_update", target=mask_token(token), details={"permissions": update.permissions, "allowed_containers": update.allowed_containers})
    return {"message": "API user updated", "user": users[token]}

@app.delete("/api-users/{token}")
def delete_api_user(token: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("api_user_delete", "api_user_admin", x_api_key, x_user_token)
    users = load_api_users()
    if token not in users:
        audit_api("api_user_delete", target=mask_token(token), details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="API user token not found")
    removed = users.pop(token)
    save_api_users(users)
    audit_api("api_user_delete", target=removed.get("username"), details={"token": mask_token(token)})
    return {"message": f"API user {removed.get('username')} removed"}

# --- FIREWALL MANAGEMENT ---

@app.post("/firewall/open")
def open_firewall(rule: FirewallRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_open", "firewall_admin", x_api_key, x_user_token)
    try:
        apply_firewall_rule(rule.port, rule.protocol, rule.source, allow=True)
        audit_api("firewall_open", target=f"{rule.port}/{rule.protocol}", details={"source": rule.source})
    except Exception as exc:
        audit_api("firewall_open", target=f"{rule.port}/{rule.protocol}", details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Firewall opened for port {rule.port}/{rule.protocol}"}

@app.post("/firewall/close")
def close_firewall(rule: FirewallRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_close", "firewall_admin", x_api_key, x_user_token)
    try:
        apply_firewall_rule(rule.port, rule.protocol, rule.source, allow=False)
        audit_api("firewall_close", target=f"{rule.port}/{rule.protocol}", details={"source": rule.source})
    except Exception as exc:
        audit_api("firewall_close", target=f"{rule.port}/{rule.protocol}", details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Firewall closing rule applied for port {rule.port}/{rule.protocol}"}

# --- PACKAGE MANAGEMENT ---

@app.post("/packages/install")
def install_packages(request: PackageInstallRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("packages_install", "package_manage", x_api_key, x_user_token, containers=request.container_name)
    ensure_packages_list(request.packages)
    manager = detect_package_manager(request.container_name)
    if request.update_index:
        update_package_index(manager, request.container_name)
    if manager == "apt":
        cmd = ["apt-get", "install", "-y"] + request.packages
    else:
        cmd = ["dnf", "install", "-y"] + request.packages
    try:
        run_package_command(cmd, request.container_name)
        audit_api("packages_install", target=request.container_name or "host", details={"packages": request.packages, "manager": manager})
    except Exception as exc:
        audit_api("packages_install", target=request.container_name or "host", details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Installed packages: {', '.join(request.packages)}"}

@app.post("/packages/remove")
def remove_packages(request: PackageRemoveRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("packages_remove", "package_manage", x_api_key, x_user_token, containers=request.container_name)
    ensure_packages_list(request.packages)
    manager = detect_package_manager(request.container_name)
    if manager == "apt":
        cmd = ["apt-get", "remove", "-y"] + request.packages
    else:
        cmd = ["dnf", "remove", "-y"] + request.packages
    try:
        run_package_command(cmd, request.container_name)
        audit_api("packages_remove", target=request.container_name or "host", details={"packages": request.packages, "manager": manager})
    except Exception as exc:
        audit_api("packages_remove", target=request.container_name or "host", details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Removed packages: {', '.join(request.packages)}"}

@app.post("/packages/update")
def update_packages(request: PackageUpdateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("packages_update", "package_manage", x_api_key, x_user_token, containers=request.container_name)
    manager = detect_package_manager(request.container_name)
    update_package_index(manager, request.container_name)
    if manager == "apt":
        command = ["apt-get", "dist-upgrade" if request.full_upgrade else "upgrade", "-y"]
    else:
        command = ["dnf", "upgrade" if request.full_upgrade else "update", "-y"]
    try:
        run_package_command(command, request.container_name)
        audit_api("packages_update", target=request.container_name or "host", details={"manager": manager, "full_upgrade": request.full_upgrade})
    except Exception as exc:
        audit_api("packages_update", target=request.container_name or "host", details={"error": str(exc)}, status="error")
        raise
    return {"message": "Package update completed", "full_upgrade": request.full_upgrade}

# --- VM MANAGEMENT ---

def _load_vm_store() -> Dict[str, Dict[str, Any]]:
    return load_vms(VMS_DB)

@app.get("/vms")
def list_vms(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_list", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    response = [build_vm_summary(record) for _, record in sorted(vms.items())]
    audit_api("vms_list", details={"count": len(response)})
    return {"vms": response}

@app.get("/vms/{name}")
def get_vm(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_get", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = vms.get(name)
    if not record:
        audit_api("vms_get", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="VM not found")
    audit_api("vms_get", target=name)
    return {"vm": sanitize_vm_record(record)}

@app.post("/vms")
def create_vm_record(payload: VMCreateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_create", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = create_vm(payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_create", target=payload.name, details={"provider": payload.provider})
    return {"message": f"VM {payload.name} created", "vm": sanitize_vm_record(record)}

@app.put("/vms/{name}")
def update_vm_record(name: str, payload: VMUpdateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_update", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = update_vm(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_update", target=name, details={"fields": sorted(payload.dict(exclude_unset=True).keys())})
    return {"message": f"VM {name} updated", "vm": sanitize_vm_record(record)}

@app.delete("/vms/{name}")
def delete_vm_record(name: str, purge: bool = False, force: bool = False, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_delete", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = delete_vm(name, vms, purge=purge, force=force)
    save_vms(VMS_DB, vms)
    audit_api("vms_delete", target=name, details={"purge": purge, "force": force})
    return {"message": f"VM {name} removed", "vm": sanitize_vm_record(record)}

@app.post("/vms/{name}/start")
def start_vm_instance(name: str, payload: VMStartRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_start", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = start_vm_record(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_start", target=name, details={"headless": payload.headless, "use_iso": payload.use_iso})
    return {"message": f"VM {name} started", "vm": sanitize_vm_record(record)}

@app.post("/vms/{name}/stop")
def stop_vm_instance(name: str, payload: VMStopRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_stop", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = stop_vm_record(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_stop", target=name, details={"force": payload.force})
    return {"message": f"VM {name} stopped", "vm": sanitize_vm_record(record)}

@app.get("/vms/{name}/status")
def get_vm_status(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_status", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    status = vm_status(name, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_status", target=name, details={"state": status.get("state")})
    return status

@app.get("/vms/{name}/snapshots")
def get_vm_snapshots(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_snapshots_list", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    snapshots = list_snapshots(name, vms)
    audit_api("vms_snapshots_list", target=name, details={"count": len(snapshots)})
    return {"snapshots": snapshots}

@app.post("/vms/{name}/snapshots")
def create_vm_snapshot(name: str, payload: VMSnapshotRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_snapshots_create", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    snapshot = create_snapshot(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_snapshots_create", target=name, details={"snapshot": payload.name})
    return {"message": f"Snapshot {payload.name} created", "snapshot": snapshot}

@app.post("/vms/{name}/snapshots/{snapshot_name}/restore")
def restore_vm_snapshot(name: str, snapshot_name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_snapshots_restore", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    restored = restore_snapshot(name, snapshot_name, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_snapshots_restore", target=name, details={"snapshot": snapshot_name})
    return {"message": f"Snapshot {snapshot_name} restored", "restore": restored}

@app.delete("/vms/{name}/snapshots/{snapshot_name}")
def delete_vm_snapshot(name: str, snapshot_name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_snapshots_delete", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    result = delete_snapshot(name, snapshot_name, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_snapshots_delete", target=name, details={"snapshot": snapshot_name})
    return {"message": f"Snapshot {snapshot_name} deleted", "result": result}

@app.post("/vms/{name}/provision")
def provision_vm_instance(name: str, payload: VMProvisionRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_provision", "vm_manage", x_api_key, x_user_token)
    vms = _load_vm_store()
    result = provision_vm(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_provision", target=name, details={"profile": payload.profile})
    return {"message": "Provisioning complete", "result": result}

@app.post("/vms/{name}/probe")
def probe_vm_instance(name: str, payload: VMProbeRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_probe", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    result = probe_vm(name, payload, vms)
    save_vms(VMS_DB, vms)
    audit_api("vms_probe", target=name, details={"saved_as": payload.save_as})
    return {"probe": result}

@app.get("/vms/{name}/states")
def list_vm_states(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("vms_states", "vm_read", x_api_key, x_user_token)
    vms = _load_vm_store()
    record = vms.get(name)
    if not record:
        audit_api("vms_states", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="VM not found")
    states = record.get("saved_states", [])
    audit_api("vms_states", target=name, details={"count": len(states)})
    return {"states": states}

# --- HOST MANAGEMENT ---


def _load_host_store() -> Dict[str, Dict[str, Any]]:
    return load_hosts(HOSTS_DB)


@app.get("/hosts")
def list_hosts(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_list", "host_read", x_api_key, x_user_token)
    hosts = _load_host_store()
    response = [build_host_summary(record) for _, record in sorted(hosts.items())]
    audit_api("hosts_list", details={"count": len(response)})
    return {"hosts": response}


@app.get("/hosts/{name}")
def get_host(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_get", "host_read", x_api_key, x_user_token)
    hosts = _load_host_store()
    record = hosts.get(name)
    if not record:
        audit_api("hosts_get", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Host not found")
    audit_api("hosts_get", target=name)
    return {"host": sanitize_host_record(record)}


@app.post("/hosts")
def create_host_record(payload: HostCreateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_create", "host_manage", x_api_key, x_user_token)
    hosts = _load_host_store()
    record = create_host(payload, hosts)
    save_hosts(HOSTS_DB, hosts)
    audit_api("hosts_create", target=payload.name)
    return {"message": f"Host {payload.name} created", "host": sanitize_host_record(record)}


@app.put("/hosts/{name}")
def update_host_record(name: str, payload: HostUpdateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_update", "host_manage", x_api_key, x_user_token)
    hosts = _load_host_store()
    record = update_host(name, payload, hosts)
    save_hosts(HOSTS_DB, hosts)
    audit_api("hosts_update", target=name, details={"fields": sorted(payload.dict(exclude_unset=True).keys())})
    return {"message": f"Host {name} updated", "host": sanitize_host_record(record)}


@app.delete("/hosts/{name}")
def delete_host_record(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_delete", "host_manage", x_api_key, x_user_token)
    hosts = _load_host_store()
    record = delete_host(name, hosts)
    save_hosts(HOSTS_DB, hosts)
    audit_api("hosts_delete", target=name)
    return {"message": f"Host {name} removed", "host": sanitize_host_record(record)}


@app.post("/hosts/{name}/provision")
def provision_host_instance(name: str, payload: HostProvisionRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_provision", "host_manage", x_api_key, x_user_token)
    hosts = _load_host_store()
    result = provision_host(name, payload, hosts)
    save_hosts(HOSTS_DB, hosts)
    audit_api("hosts_provision", target=name, details={"profile": payload.profile})
    return {"message": "Provisioning complete", "result": result}


@app.post("/hosts/{name}/probe")
def probe_host_instance(name: str, payload: HostProbeRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_probe", "host_read", x_api_key, x_user_token)
    hosts = _load_host_store()
    result = probe_host(name, payload, hosts)
    save_hosts(HOSTS_DB, hosts)
    audit_api("hosts_probe", target=name, details={"saved_as": payload.save_as})
    return {"probe": result}


@app.get("/hosts/{name}/states")
def list_host_states(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("hosts_states", "host_read", x_api_key, x_user_token)
    hosts = _load_host_store()
    record = hosts.get(name)
    if not record:
        audit_api("hosts_states", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Host not found")
    states = record.get("saved_states", [])
    audit_api("hosts_states", target=name, details={"count": len(states)})
    return {"states": states}


# --- RECIPE AUTOMATION ---

def _load_recipe_store() -> Dict[str, Dict[str, Any]]:
    return load_recipes(RECIPES_DB)

def _ensure_recipe_dependencies(recipes: Dict[str, Dict[str, Any]], dependencies: List[str], recipe_name: str):
    for dep in dependencies:
        if dep == recipe_name:
            raise HTTPException(status_code=400, detail="Recipe cannot depend on itself")
        if dep not in recipes:
            raise HTTPException(status_code=400, detail=f"Missing recipe dependency: {dep}")

@app.get("/recipes")
def list_recipes(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_list", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    response = []
    for name, recipe in sorted(recipes.items()):
        response.append({
            "name": name,
            "description": recipe.get("description"),
            "dependencies": recipe.get("dependencies", []),
            "packages_count": len(recipe.get("packages", [])),
            "commands_count": len(recipe.get("commands", [])),
            "parameter_keys": sorted(recipe.get("parameters", {}).keys()),
        })
    audit_api("recipes_list", details={"count": len(response)})
    return {"recipes": response}

@app.get("/recipes/{name}")
def get_recipe(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_get", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    recipe = recipes.get(name)
    if not recipe:
        audit_api("recipes_get", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Recipe not found")
    audit_api("recipes_get", target=name)
    return {"recipe": recipe}

@app.post("/recipes")
def create_recipe(recipe: RecipeDefinition, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_create", "recipes_manage", x_api_key, x_user_token)
    try:
        validate_recipe_name(recipe.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    recipes = _load_recipe_store()
    if recipe.name in recipes:
        raise HTTPException(status_code=409, detail="Recipe already exists")
    _ensure_recipe_dependencies(recipes, recipe.dependencies, recipe.name)
    recipes[recipe.name] = recipe.dict()
    save_recipes(RECIPES_DB, recipes)
    audit_api(
        "recipes_create",
        target=recipe.name,
        details={
            "dependencies": recipe.dependencies,
            "packages": len(recipe.packages),
            "commands": len(recipe.commands),
            "parameter_keys": sorted(recipe.parameters.keys()),
            "required_parameters": recipe.required_parameters,
        },
    )
    return {"message": f"Recipe {recipe.name} created", "recipe": recipes[recipe.name]}

@app.put("/recipes/{name}")
def update_recipe(name: str, payload: RecipeUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_update", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    if name not in recipes:
        audit_api("recipes_update", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Recipe not found")
    update_data = payload.dict(exclude_unset=True, exclude_none=True)
    if "dependencies" in update_data:
        _ensure_recipe_dependencies(recipes, update_data["dependencies"], name)
    updated = dict(recipes[name])
    updated.update(update_data)
    updated["name"] = name
    staged = dict(recipes)
    staged[name] = updated
    try:
        resolve_recipe_plan(name, staged, include_dependencies=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    recipes[name] = updated
    save_recipes(RECIPES_DB, recipes)
    audit_api("recipes_update", target=name, details={"fields": sorted(update_data.keys())})
    return {"message": f"Recipe {name} updated", "recipe": recipes[name]}

@app.delete("/recipes/{name}")
def delete_recipe(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_delete", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    if name not in recipes:
        audit_api("recipes_delete", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Recipe not found")
    dependents = [recipe_name for recipe_name, record in recipes.items() if name in record.get("dependencies", [])]
    if dependents:
        raise HTTPException(status_code=409, detail=f"Recipe is required by: {', '.join(sorted(dependents))}")
    recipes.pop(name)
    save_recipes(RECIPES_DB, recipes)
    audit_api("recipes_delete", target=name)
    return {"message": f"Recipe {name} removed"}

@app.post("/recipes/apply")
def apply_recipe(payload: RecipeApplyRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_apply", "recipes_apply", x_api_key, x_user_token, containers=payload.container_name)
    recipes = _load_recipe_store()
    if payload.recipe_name not in recipes:
        audit_api("recipes_apply", target=payload.container_name or "host", details={"error": "recipe not found"}, status="error")
        raise HTTPException(status_code=404, detail="Recipe not found")
    overrides = normalize_parameters(payload.parameters)
    try:
        plan, steps = build_recipe_execution(
            payload.recipe_name,
            recipes,
            include_dependencies=payload.include_dependencies,
            overrides=overrides,
        )
    except ValueError as exc:
        audit_api("recipes_apply", target=payload.container_name or "host", details={"error": str(exc)}, status="error")
        raise HTTPException(status_code=400, detail=str(exc))
    audit_api(
        "recipes_apply",
        target=payload.container_name or "host",
        details={
            "recipe": payload.recipe_name,
            "plan": plan,
            "parameters": sanitize_payload_fuzzy(overrides, SENSITIVE_KEYWORDS),
        },
    )
    manager = None
    index_updated = False
    installed_packages: set[str] = set()
    applied: List[str] = []
    for step in steps:
        recipe_name = step["name"]
        packages = [package for package in step["packages"] if package and package not in installed_packages]
        if packages:
            if manager is None:
                manager = detect_package_manager(payload.container_name)
            if payload.update_index and not index_updated:
                update_package_index(manager, payload.container_name)
                index_updated = True
            if manager == "apt":
                cmd = ["apt-get", "install", "-y"] + packages
            else:
                cmd = ["dnf", "install", "-y"] + packages
            run_package_command(cmd, payload.container_name)
            installed_packages.update(packages)
        for command in step["commands"]:
            if payload.container_name:
                exec_in_container(payload.container_name, ["sh", "-c", command])
            else:
                run_command(["sh", "-c", command])
        applied.append(recipe_name)
    audit_api("recipes_apply_complete", target=payload.container_name or "host", details={"recipe": payload.recipe_name, "applied": applied})
    return {"message": "Recipe applied", "recipe": payload.recipe_name, "applied": applied, "container": payload.container_name}

# --- ENCRYPTED BACKUP SYSTEM ---

def perform_encrypted_backup(container_name: str, initiator: str = "system"):
    set_request_context(initiator, "backup_task")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_file = f"{BACKUP_DIR}/{container_name}_{timestamp}.tar.gz"
    enc_file = f"{raw_file}.enc"

    try:
        audit_internal("backup_start", target=container_name, details={"raw_file": raw_file})
        # 1. Export Container (Stop, Backup, Start)
        # Note: 'lxc export' creates a unified backup including config
        run_command(["lxc", "export", container_name, raw_file])
        
        # 2. Encrypt File
        fernet = Fernet(get_fernet_key(BACKUP_ENCRYPTION_PASSWORD))
        
        with open(raw_file, "rb") as f:
            file_data = f.read()
        
        encrypted_data = fernet.encrypt(file_data)
        
        with open(enc_file, "wb") as f:
            f.write(encrypted_data)
            
        # 3. Cleanup Raw File
        os.remove(raw_file)
        logging.info(f"Backup for {container_name} created and encrypted.")
        audit_internal("backup_complete", target=container_name, details={"enc_file": enc_file})
        
    except Exception as e:
        logging.error(f"Backup failed for {container_name}: {e}")
        audit_internal("backup_failed", target=container_name, details={"error": str(e)}, status="error")

@app.post("/backup/{container_name}")
def trigger_backup(container_name: str, background_tasks: BackgroundTasks, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("backup_trigger", "manage_backups", x_api_key, x_user_token, containers=container_name)
    ctx = get_request_context()
    background_tasks.add_task(perform_encrypted_backup, container_name, ctx.get("actor", "system"))
    audit_api("backup_trigger", target=container_name)
    return {"message": "Backup started in background"}

@app.get("/backup/list")
def list_backups(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("backup_list", "manage_backups", x_api_key, x_user_token)
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.enc')]
    audit_api("backup_list", details={"count": len(files)})
    return {"backups": files}

@app.get("/backup/download/{filename}")
def download_backup(filename: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("backup_download", "manage_backups", x_api_key, x_user_token)
    file_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    audit_api("backup_download", target=filename)
    return File(file_path, media_type='application/octet-stream', filename=filename)

# --- RESTORE LOGIC ---

@app.post("/restore")
async def restore_container(file: UploadFile, container_name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("restore_container", "restore_container", x_api_key, x_user_token, containers=container_name)
    
    enc_path = os.path.join(BACKUP_DIR, "restore_temp.enc")
    dec_path = os.path.join(BACKUP_DIR, "restore_temp.tar.gz")
    
    try:
        # 1. Save Uploaded Encrypted File
        with open(enc_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # 2. Decrypt
        fernet = Fernet(get_fernet_key(BACKUP_ENCRYPTION_PASSWORD))
        with open(enc_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        
        with open(dec_path, "wb") as f:
            f.write(decrypted_data)
            
        # 3. Import to LXD
        run_command(["lxc", "import", dec_path, container_name])
        audit_api("restore_container", target=container_name)
        
        return {"message": f"Container {container_name} restored successfully"}
        
    except Exception as e:
        audit_api("restore_container", target=container_name, details={"error": str(e)}, status="error")
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(enc_path): os.remove(enc_path)
        if os.path.exists(dec_path): os.remove(dec_path)

if __name__ == "__main__":
    # In production, run behind a real webserver or use SSL context here
    uvicorn.run(app, host=HOST_INTERFACE, port=HOST_PORT, ssl_keyfile="/etc/fortress/ssl/key.pem", ssl_certfile="/etc/fortress/ssl/cert.pem")
