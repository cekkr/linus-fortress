import uvicorn
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
import subprocess
import os
import shutil
import secrets
import logging
from typing import Optional, List, Dict, Literal, Union, Any
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib
import json
import shlex
from contextvars import ContextVar

from fortress.audit import CommandLogger
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

# --- CONFIGURATION ---
# In production, load these from environment variables
DEFAULT_API_SECRET = "CHANGE_THIS_TO_A_VERY_LONG_RANDOM_STRING"
API_SECRET_KEY = os.environ.get("FORTRESS_API_KEY", os.environ.get("API_SECRET_KEY", DEFAULT_API_SECRET))
BACKUP_ENCRYPTION_PASSWORD = os.environ.get("FORTRESS_BACKUP_PASSWORD", "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD")
HOST_INTERFACE = "0.0.0.0"
HOST_PORT = 8443
BACKUP_DIR = "/var/lib/fortress/backups"
NGINX_CONFIG_DIR = "/etc/nginx/sites-available"
API_USERS_DB = "/var/lib/fortress/api_users.json"
RECIPES_DB = "/var/lib/fortress/recipes.json"
SHARED_STORAGE_DIR = "/var/lib/fortress/shares"
COMMAND_LOG_DB = "/var/lib/fortress/command_log.db"
SERVICE_DEFAULT_PORTS = {"ssh": 22, "ftp": 21}
SENSITIVE_KEYWORDS = {"password", "passwd", "secret", "token", "key", "chpasswd"}

def resolve_master_key() -> Optional[str]:
    if not API_SECRET_KEY:
        return None
    key = API_SECRET_KEY.strip()
    if not key or key == DEFAULT_API_SECRET:
        return None
    return key

# Logging setup
logging.basicConfig(filename='/var/log/fortress.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s')

MASTER_API_KEY = resolve_master_key()
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

def ensure_parent_dir(path: str):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

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

def mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "***"
    return f\"{token[:4]}...{token[-4:]}\"

def sanitize_command_details(command: List[str]) -> Dict[str, Any]:
    if not command:
        return {\"command\": \"\", \"arg_preview\": [], \"arg_length\": 0}
    preview = []
    for arg in command[1:6]:
        if any(keyword in arg.lower() for keyword in SENSITIVE_KEYWORDS):
            preview.append(\"***\")
        else:
            preview.append(arg[:64])
    return {
        \"command\": command[0],
        \"arg_preview\": preview,
        \"arg_length\": max(len(command) - 1, 0)
    }

def authorize(endpoint: str, required_permission: Optional[str], x_api_key: Optional[str], x_user_token: Optional[str], containers: Optional[Union[str, List[str]]] = None):
    auth_context = verify_token(x_api_key, x_user_token, required_permission=required_permission)
    set_request_context(auth_context.get(\"actor\", \"system\"), endpoint)
    if containers:
        if isinstance(containers, str):
            enforce_container_scope(auth_context, containers)
        else:
            enforce_container_scopes(auth_context, containers)
    return auth_context

def load_api_users() -> Dict[str, Dict]:
    if not os.path.exists(API_USERS_DB):
        return {}
    try:
        with open(API_USERS_DB, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        logging.error("Failed to load API user database, falling back to empty set.")
        return {}

def save_api_users(users: Dict[str, Dict]):
    ensure_parent_dir(API_USERS_DB)
    with open(API_USERS_DB, "w") as fh:
        json.dump(users, fh, indent=2)

def verify_token(x_api_key: Optional[str], x_user_token: Optional[str] = None, required_permission: Optional[str] = None):
    """Validate access either via master API key or delegated user token."""
    if MASTER_API_KEY and x_api_key and x_api_key == MASTER_API_KEY:
        return {"actor": "admin", "permissions": ["*"], "allowed_containers": None}

    if x_user_token:
        users = load_api_users()
        record = users.get(x_user_token)
        if not record:
            logging.warning("Unknown API user token attempted.")
            raise HTTPException(status_code=403, detail="Invalid API token")

        permissions = record.get("permissions", [])
        if required_permission and required_permission not in permissions and "*" not in permissions:
            logging.warning("API user lacks permission %s", required_permission)
            raise HTTPException(status_code=403, detail="Permission denied for this API user")

        return {
            "actor": record.get("username", "api-user"),
            "permissions": permissions,
            "allowed_containers": record.get("allowed_containers"),
        }

    logging.warning("Unauthorized access attempt.")
    raise HTTPException(status_code=403, detail="Invalid authentication headers")

def enforce_container_scope(auth_context: Dict, container_name: str):
    allowed = auth_context.get("allowed_containers")
    if allowed and container_name not in allowed:
        logging.warning("User %s attempted to access container %s without scope.", auth_context.get("actor"), container_name)
        raise HTTPException(status_code=403, detail=f"Container {container_name} not in allowed scope")

def enforce_container_scopes(auth_context: Dict, containers: List[str]):
    for container in containers:
        enforce_container_scope(auth_context, container)

def get_container_ip(container_name: str, interface: str = "eth0") -> str:
    info_json = run_command(["lxc", "list", container_name, "--format", "json"])
    info = json.loads(info_json)
    try:
        return info[0]['state']['network'][interface]['addresses'][0]['address']
    except (IndexError, KeyError):
        raise HTTPException(status_code=404, detail="Container IP not found. Is it running?")

def exec_in_container(container_name: str, command: List[str]) -> str:
    cmd = ["lxc", "exec", container_name, "--"] + command
    details = sanitize_command_details(command)
    try:
        result = run_command(cmd)
        audit_event("container_exec", f"exec:{details['command']}", target=container_name, details=details)
        return result
    except HTTPException as exc:
        error_details = dict(details)
        error_details["error"] = exc.detail
        audit_event("container_exec", f"exec:{details['command']}", target=container_name, details=error_details, status="error")
        raise

def set_container_password(container_name: str, username: str, password: str):
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

def run_package_command(cmd: List[str], container_name: Optional[str]):
    if container_name:
        exec_in_container(container_name, cmd)
    else:
        run_command(cmd)

def update_package_index(manager: str, container_name: Optional[str]):
    if manager == "apt":
        run_package_command(["apt-get", "update"], container_name)
    elif manager == "dnf":
        run_package_command(["dnf", "makecache"], container_name)

def detect_firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    raise HTTPException(status_code=500, detail="No supported firewall backend detected (ufw or firewalld)")

def build_firewalld_rich_rule(rule: "FirewallRule", allow: bool) -> str:
    action = "accept" if allow else "drop"
    return f'rule family="ipv4" source address="{rule.source}" port protocol="{rule.protocol}" port="{rule.port}" {action}'

def apply_firewall_rule(rule: "FirewallRule", allow: bool):
    backend = detect_firewall_backend()
    if backend == "ufw":
        action_word = "allow" if allow else "deny"
        if rule.source:
            base_cmd = ["ufw", action_word, "from", rule.source, "to", "any", "port", str(rule.port), "proto", rule.protocol]
        else:
            base_cmd = ["ufw", action_word, f"{rule.port}/{rule.protocol}"]
        if not allow:
            # When closing, use delete allow rather than deny to clean explicit rule if it exists
            if rule.source:
                base_cmd = ["ufw", "--force", "delete", "allow", "from", rule.source, "to", "any", "port", str(rule.port), "proto", rule.protocol]
            else:
                base_cmd = ["ufw", "--force", "delete", "allow", f"{rule.port}/{rule.protocol}"]
        run_command(base_cmd)
        run_command(["ufw", "reload"])
    else:
        if rule.source:
            rich_rule = build_firewalld_rich_rule(rule, allow)
            flag = "--add-rich-rule" if allow else "--remove-rich-rule"
            run_command(["firewall-cmd", "--permanent", flag, rich_rule])
        else:
            flag = "--add-port" if allow else "--remove-port"
            run_command(["firewall-cmd", "--permanent", flag, f"{rule.port}/{rule.protocol}"])
        run_command(["firewall-cmd", "--reload"])

def ensure_packages_list(packages: List[str]):
    if not packages:
        raise HTTPException(status_code=400, detail="Package list cannot be empty")

def run_command(cmd_list):
    """Run a shell command securely and return output."""
    try:
        result = subprocess.run(cmd_list, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e.cmd}. Error: {e.stderr}")
        raise HTTPException(status_code=500, detail=f"System Error: {e.stderr}")

# --- DATA MODELS ---

class ContainerCreate(BaseModel):
    name: str
    distro: str = "ubuntu:22.04"
    cpu_limit: str = "1"
    ram_limit: str = "512MB"
    disk_limit: str = "10GB"

class DomainRoute(BaseModel):
    domain: str
    container_name: str
    container_port: int = 80

class APIUserCreate(BaseModel):
    username: str
    permissions: List[str] = []
    allowed_containers: Optional[List[str]] = None

class APIUserUpdate(BaseModel):
    permissions: Optional[List[str]] = None
    allowed_containers: Optional[List[str]] = None

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

@app.post("/container/create")
def create_container(config: ContainerCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_create", "manage_containers", x_api_key, x_user_token, containers=config.name)
    # 1. Launch Container
    logging.info(f"Creating container {config.name}")
    try:
        run_command(["lxc", "launch", config.distro, config.name])
        
        # 2. Apply Limits (Crucial for low spec VPS)
        run_command(["lxc", "config", "set", config.name, "limits.cpu", config.cpu_limit])
        run_command(["lxc", "config", "set", config.name, "limits.memory", config.ram_limit])
        
        # 3. Enable nesting (needed for some services) and security limits
        run_command(["lxc", "config", "set", config.name, "security.nesting", "true"])
        
        audit_api("container_create", target=config.name, details=sanitize_payload(config.dict()))
        return {"message": f"Container {config.name} created successfully"}
    except Exception as e:
        audit_api("container_create", target=config.name, details={"error": str(e)}, status="error")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/container/{name}")
def delete_container(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_delete", "manage_containers", x_api_key, x_user_token, containers=name)
    logging.info(f"Deleting container {name}")
    try:
        # Force delete (stop and delete)
        run_command(["lxc", "delete", name, "--force"])
        audit_api("container_delete", target=name)
        return {"message": f"Container {name} deleted"}
    except Exception as e:
        audit_api("container_delete", target=name, details={"error": str(e)}, status="error")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/routing/add")
def add_domain_routing(route: DomainRoute, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("routing_add", "manage_routing", x_api_key, x_user_token, containers=route.container_name)
    
    # 1. Get Container IP
    ip = get_container_ip(route.container_name)

    # 2. Generate Nginx Config
    config_content = f"""
server {{
    listen 80;
    server_name {route.domain};

    location / {{
        proxy_pass http://{ip}:{route.container_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
    """
    
    config_path = f"{NGINX_CONFIG_DIR}/{route.domain}"
    with open(config_path, "w") as f:
        f.write(config_content)
    
    # 3. Symlink and Reload
    try:
        if not os.path.exists(f"/etc/nginx/sites-enabled/{route.domain}"):
            os.symlink(config_path, f"/etc/nginx/sites-enabled/{route.domain}")
        run_command(["systemctl", "reload", "nginx"])
        
        # Optional: Auto-certbot could be triggered here
        
        audit_api("routing_add", target=route.domain, details={"container": route.container_name, "port": route.container_port})
        return {"message": f"Routing set for {route.domain} -> {ip}"}
    except Exception as e:
        audit_api("routing_add", target=route.domain, details={"error": str(e)}, status="error")
        raise HTTPException(status_code=500, detail=str(e))

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

# --- EXTERNAL ACCESS CONTROL ---

def _resolve_device_name(service: str, host_port: Optional[int], device_name: Optional[str]) -> str:
    port = host_port or SERVICE_DEFAULT_PORTS[service]
    return device_name or f"{service}-{port}"

@app.post("/access/external/open")
def open_external_access(rule: ExternalAccessRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("external_access_open", "access_control", x_api_key, x_user_token, containers=rule.container_name)
    service_port = SERVICE_DEFAULT_PORTS[rule.service]
    host_port = rule.host_port or service_port
    connect_port = rule.connect_port or service_port
    device_name = _resolve_device_name(rule.service, host_port, rule.device_name)
    listen_arg = f"listen=tcp:{rule.bind_address}:{host_port}"
    connect_arg = f"connect=tcp:{rule.connect_address}:{connect_port}"
    try:
        run_command([
            "lxc", "config", "device", "add", rule.container_name,
            device_name, "proxy", listen_arg, connect_arg
        ])
        audit_api("external_access_open", target=rule.container_name, details={"service": rule.service, "device": device_name, "host_port": host_port})
    except Exception as exc:
        audit_api("external_access_open", target=rule.container_name, details={"error": str(exc)}, status="error")
        raise
    return {"message": f"{rule.service.upper()} access exposed on port {host_port}", "device_name": device_name}

@app.post("/access/external/close")
def close_external_access(rule: ExternalAccessCloseRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("external_access_close", "access_control", x_api_key, x_user_token, containers=rule.container_name)
    device_name = rule.device_name
    if not device_name:
        if not rule.service:
            raise HTTPException(status_code=400, detail="Either device_name or service must be provided")
        device_name = _resolve_device_name(rule.service, rule.host_port, None)
    try:
        run_command(["lxc", "config", "device", "remove", rule.container_name, device_name])
        audit_api("external_access_close", target=rule.container_name, details={"device": device_name})
    except Exception as exc:
        audit_api("external_access_close", target=rule.container_name, details={"device": device_name, "error": str(exc)}, status="error")
        raise
    return {"message": f"Device {device_name} removed from {rule.container_name}"}

# --- CONTAINER USER MANAGEMENT ---

@app.post("/container/users/create")
def create_container_user(payload: ContainerUserCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_user_create", "user_management", x_api_key, x_user_token, containers=payload.container_name)
    cmd = ["useradd", "-m", payload.username]
    if payload.groups:
        cmd.extend(["-G", ",".join(payload.groups)])
    try:
        exec_in_container(payload.container_name, cmd)
        if payload.password:
            set_container_password(payload.container_name, payload.username, payload.password)
        audit_api("container_user_create", target=payload.container_name, details=sanitize_payload(payload.dict(), sensitive_keys=["password"]))
        return {"message": f"User {payload.username} created in {payload.container_name}"}
    except Exception as exc:
        audit_api("container_user_create", target=payload.container_name, details={"username": payload.username, "error": str(exc)}, status="error")
        raise

@app.post("/container/users/password")
def update_container_password(payload: ContainerUserPasswordUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_user_password", "user_management", x_api_key, x_user_token, containers=payload.container_name)
    try:
        set_container_password(payload.container_name, payload.username, payload.password)
        audit_api("container_user_password", target=payload.container_name, details=sanitize_payload(payload.dict(), sensitive_keys=["password"]))
        return {"message": f"Password updated for {payload.username} in {payload.container_name}"}
    except Exception as exc:
        audit_api("container_user_password", target=payload.container_name, details={"username": payload.username, "error": str(exc)}, status="error")
        raise

@app.post("/container/users/groups")
def update_container_groups(payload: ContainerUserGroupUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_user_groups", "user_management", x_api_key, x_user_token, containers=payload.container_name)
    try:
        exec_in_container(payload.container_name, ["usermod", "-G", ",".join(payload.groups), payload.username])
        audit_api("container_user_groups", target=payload.container_name, details={"username": payload.username, "groups": payload.groups})
        return {"message": f"Groups updated for {payload.username} in {payload.container_name}"}
    except Exception as exc:
        audit_api("container_user_groups", target=payload.container_name, details={"username": payload.username, "error": str(exc)}, status="error")
        raise

@app.delete("/container/users")
def delete_container_user(payload: ContainerUserDelete, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_user_delete", "user_management", x_api_key, x_user_token, containers=payload.container_name)
    args = ["userdel"]
    if payload.remove_home:
        args.append("-r")
    args.append(payload.username)
    try:
        exec_in_container(payload.container_name, args)
        audit_api("container_user_delete", target=payload.container_name, details={"username": payload.username, "remove_home": payload.remove_home})
        return {"message": f"User {payload.username} removed from {payload.container_name}"}
    except Exception as exc:
        audit_api("container_user_delete", target=payload.container_name, details={"username": payload.username, "error": str(exc)}, status="error")
        raise

@app.post("/container/groups")
def create_container_group(payload: ContainerGroupCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("container_group_create", "user_management", x_api_key, x_user_token, containers=payload.container_name)
    try:
        exec_in_container(payload.container_name, ["groupadd", "-f", payload.group_name])
        audit_api("container_group_create", target=payload.container_name, details={"group": payload.group_name})
        return {"message": f"Group {payload.group_name} ensured in {payload.container_name}"}
    except Exception as exc:
        audit_api("container_group_create", target=payload.container_name, details={"group": payload.group_name, "error": str(exc)}, status="error")
        raise

# --- INTER-CONTAINER CONNECTIVITY ---

@app.post("/containers/connect/tcp")
def connect_containers_network(payload: ContainerLinkRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("containers_connect_tcp", "connectivity", x_api_key, x_user_token, containers=[payload.source_container, payload.target_container])
    target_ip = get_container_ip(payload.target_container)
    device_name = payload.device_name or f"link-{payload.target_container}-{payload.listen_port}"
    listen = f"listen={payload.protocol}:{payload.bind_address}:{payload.listen_port}"
    connect = f"connect={payload.protocol}:{target_ip}:{payload.target_port}"
    try:
        run_command([
            "lxc", "config", "device", "add", payload.source_container,
            device_name, "proxy", listen, connect
        ])
        audit_api("containers_connect_tcp", target=payload.source_container, details={"device": device_name, "target": payload.target_container, "listen_port": payload.listen_port})
    except Exception as exc:
        audit_api("containers_connect_tcp", target=payload.source_container, details={"device": device_name, "error": str(exc)}, status="error")
        raise
    return {"message": f"{payload.source_container} now proxies to {payload.target_container}:{payload.target_port}", "device_name": device_name}

@app.post("/containers/connect/tcp/remove")
def disconnect_container_network(payload: ContainerLinkRemoval, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("containers_disconnect_tcp", "connectivity", x_api_key, x_user_token, containers=payload.container_name)
    try:
        run_command(["lxc", "config", "device", "remove", payload.container_name, payload.device_name])
        audit_api("containers_disconnect_tcp", target=payload.container_name, details={"device": payload.device_name})
    except Exception as exc:
        audit_api("containers_disconnect_tcp", target=payload.container_name, details={"device": payload.device_name, "error": str(exc)}, status="error")
        raise
    return {"message": f"Device {payload.device_name} removed from {payload.container_name}"}

@app.post("/containers/connect/share")
def create_shared_mount(payload: SharedMountRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("containers_connect_share", "connectivity", x_api_key, x_user_token, containers=payload.containers)
    host_path = payload.source_path or os.path.join(SHARED_STORAGE_DIR, payload.share_name)
    os.makedirs(host_path, exist_ok=True)
    attached = []
    try:
        for container in payload.containers:
            device_name = f"{payload.share_name}-{container}"
            run_command([
                "lxc", "config", "device", "add", container, device_name,
                "disk", f"source={host_path}", f"path={payload.mount_path}"
            ])
            attached.append({"container": container, "device_name": device_name})
    except Exception as err:
        audit_api("containers_connect_share", target=payload.share_name, details={"error": str(err)}, status="error")
        raise HTTPException(status_code=500, detail=f"Failed to create shared mount: {err}")
    audit_api("containers_connect_share", target=payload.share_name, details={"containers": payload.containers})
    return {"message": f"Share {payload.share_name} attached", "attachments": attached}

@app.post("/containers/connect/share/remove")
def remove_shared_mount(payload: SharedMountRemoval, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("containers_disconnect_share", "connectivity", x_api_key, x_user_token, containers=payload.containers)
    try:
        for container in payload.containers:
            device_name = f"{payload.share_name}-{container}"
            run_command(["lxc", "config", "device", "remove", container, device_name])
        audit_api("containers_disconnect_share", target=payload.share_name, details={"containers": payload.containers})
    except Exception as exc:
        audit_api("containers_disconnect_share", target=payload.share_name, details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Share {payload.share_name} detached from requested containers"}

# --- FIREWALL MANAGEMENT ---

@app.post("/firewall/open")
def open_firewall(rule: FirewallRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_open", "firewall_admin", x_api_key, x_user_token)
    try:
        apply_firewall_rule(rule, allow=True)
        audit_api("firewall_open", target=f"{rule.port}/{rule.protocol}", details={"source": rule.source})
    except Exception as exc:
        audit_api("firewall_open", target=f"{rule.port}/{rule.protocol}", details={"error": str(exc)}, status="error")
        raise
    return {"message": f"Firewall opened for port {rule.port}/{rule.protocol}"}

@app.post("/firewall/close")
def close_firewall(rule: FirewallRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_close", "firewall_admin", x_api_key, x_user_token)
    try:
        apply_firewall_rule(rule, allow=False)
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
