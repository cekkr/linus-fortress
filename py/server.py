import uvicorn
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
import subprocess
import os
import shutil
import secrets
import logging
from typing import Optional, List, Dict, Literal
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib
import json
import shlex

# --- CONFIGURATION ---
# In production, load these from environment variables
API_SECRET_KEY = "CHANGE_THIS_TO_A_VERY_LONG_RANDOM_STRING" 
BACKUP_ENCRYPTION_PASSWORD = "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD"
HOST_INTERFACE = "0.0.0.0"
HOST_PORT = 8443
BACKUP_DIR = "/var/lib/fortress/backups"
NGINX_CONFIG_DIR = "/etc/nginx/sites-available"
API_USERS_DB = "/var/lib/fortress/api_users.json"
SHARED_STORAGE_DIR = "/var/lib/fortress/shares"
SERVICE_DEFAULT_PORTS = {"ssh": 22, "ftp": 21}

# Logging setup
logging.basicConfig(filename='/var/log/fortress.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s')

app = FastAPI(title="VPS Fortress Manager")

# --- SECURITY UTILS ---

def get_fernet_key(password: str) -> bytes:
    """Derive a 32-byte base64 key from the password for AES encryption."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def ensure_parent_dir(path: str):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

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
    if x_api_key and x_api_key == API_SECRET_KEY:
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
    return run_command(["lxc", "exec", container_name, "--"] + command)

def set_container_password(container_name: str, username: str, password: str):
    credential = f"{username}:{password}"
    exec_in_container(container_name, ["bash", "-c", f"echo {shlex.quote(credential)} | chpasswd"])

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

# --- CORE LOGIC ---

@app.get("/status", dependencies=[])
def system_status(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="read_status")
    # Check RAM, Disk, and Load
    ram = run_command(["free", "-h"])
    disk = run_command(["df", "-h"])
    containers = run_command(["lxc", "list", "--format", "json"])
    return {"status": "operational", "ram": ram, "disk": disk, "containers": containers}

@app.post("/container/create")
def create_container(config: ContainerCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="manage_containers")
    enforce_container_scope(auth_context, config.name)
    
    # 1. Launch Container
    logging.info(f"Creating container {config.name}")
    try:
        run_command(["lxc", "launch", config.distro, config.name])
        
        # 2. Apply Limits (Crucial for low spec VPS)
        run_command(["lxc", "config", "set", config.name, "limits.cpu", config.cpu_limit])
        run_command(["lxc", "config", "set", config.name, "limits.memory", config.ram_limit])
        
        # 3. Enable nesting (needed for some services) and security limits
        run_command(["lxc", "config", "set", config.name, "security.nesting", "true"])
        
        return {"message": f"Container {config.name} created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/container/{name}")
def delete_container(name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="manage_containers")
    enforce_container_scope(auth_context, name)
    logging.info(f"Deleting container {name}")
    try:
        # Force delete (stop and delete)
        run_command(["lxc", "delete", name, "--force"])
        return {"message": f"Container {name} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/routing/add")
def add_domain_routing(route: DomainRoute, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="manage_routing")
    enforce_container_scope(auth_context, route.container_name)
    
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
        
        return {"message": f"Routing set for {route.domain} -> {ip}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- API USER MANAGEMENT ---

@app.post("/api-users")
def create_api_user(user: APIUserCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="api_user_admin")
    token = secrets.token_hex(32)
    users = load_api_users()
    users[token] = {
        "username": user.username,
        "permissions": user.permissions,
        "allowed_containers": user.allowed_containers,
    }
    save_api_users(users)
    return {"token": token, "user": users[token]}

@app.get("/api-users")
def list_api_users(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="api_user_admin")
    users = load_api_users()
    response = [{"token": token, **info} for token, info in users.items()]
    return {"users": response}

@app.put("/api-users/{token}")
def update_api_user(token: str, update: APIUserUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="api_user_admin")
    users = load_api_users()
    if token not in users:
        raise HTTPException(status_code=404, detail="API user token not found")
    if update.permissions is not None:
        users[token]["permissions"] = update.permissions
    if update.allowed_containers is not None:
        users[token]["allowed_containers"] = update.allowed_containers
    save_api_users(users)
    return {"message": "API user updated", "user": users[token]}

@app.delete("/api-users/{token}")
def delete_api_user(token: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="api_user_admin")
    users = load_api_users()
    if token not in users:
        raise HTTPException(status_code=404, detail="API user token not found")
    removed = users.pop(token)
    save_api_users(users)
    return {"message": f"API user {removed.get('username')} removed"}

# --- EXTERNAL ACCESS CONTROL ---

def _resolve_device_name(service: str, host_port: Optional[int], device_name: Optional[str]) -> str:
    port = host_port or SERVICE_DEFAULT_PORTS[service]
    return device_name or f"{service}-{port}"

@app.post("/access/external/open")
def open_external_access(rule: ExternalAccessRule, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="access_control")
    enforce_container_scope(auth_context, rule.container_name)
    service_port = SERVICE_DEFAULT_PORTS[rule.service]
    host_port = rule.host_port or service_port
    connect_port = rule.connect_port or service_port
    device_name = _resolve_device_name(rule.service, host_port, rule.device_name)
    listen_arg = f"listen=tcp:{rule.bind_address}:{host_port}"
    connect_arg = f"connect=tcp:{rule.connect_address}:{connect_port}"
    run_command([
        "lxc", "config", "device", "add", rule.container_name,
        device_name, "proxy", listen_arg, connect_arg
    ])
    return {"message": f"{rule.service.upper()} access exposed on port {host_port}", "device_name": device_name}

@app.post("/access/external/close")
def close_external_access(rule: ExternalAccessCloseRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="access_control")
    enforce_container_scope(auth_context, rule.container_name)
    device_name = rule.device_name
    if not device_name:
        if not rule.service:
            raise HTTPException(status_code=400, detail="Either device_name or service must be provided")
        device_name = _resolve_device_name(rule.service, rule.host_port, None)
    run_command(["lxc", "config", "device", "remove", rule.container_name, device_name])
    return {"message": f"Device {device_name} removed from {rule.container_name}"}

# --- CONTAINER USER MANAGEMENT ---

@app.post("/container/users/create")
def create_container_user(payload: ContainerUserCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="user_management")
    enforce_container_scope(auth_context, payload.container_name)
    cmd = ["useradd", "-m", payload.username]
    if payload.groups:
        cmd.extend(["-G", ",".join(payload.groups)])
    exec_in_container(payload.container_name, cmd)
    if payload.password:
        set_container_password(payload.container_name, payload.username, payload.password)
    return {"message": f"User {payload.username} created in {payload.container_name}"}

@app.post("/container/users/password")
def update_container_password(payload: ContainerUserPasswordUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="user_management")
    enforce_container_scope(auth_context, payload.container_name)
    set_container_password(payload.container_name, payload.username, payload.password)
    return {"message": f"Password updated for {payload.username} in {payload.container_name}"}

@app.post("/container/users/groups")
def update_container_groups(payload: ContainerUserGroupUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="user_management")
    enforce_container_scope(auth_context, payload.container_name)
    exec_in_container(payload.container_name, ["usermod", "-G", ",".join(payload.groups), payload.username])
    return {"message": f"Groups updated for {payload.username} in {payload.container_name}"}

@app.delete("/container/users")
def delete_container_user(payload: ContainerUserDelete, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="user_management")
    enforce_container_scope(auth_context, payload.container_name)
    args = ["userdel"]
    if payload.remove_home:
        args.append("-r")
    args.append(payload.username)
    exec_in_container(payload.container_name, args)
    return {"message": f"User {payload.username} removed from {payload.container_name}"}

@app.post("/container/groups")
def create_container_group(payload: ContainerGroupCreate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="user_management")
    enforce_container_scope(auth_context, payload.container_name)
    exec_in_container(payload.container_name, ["groupadd", "-f", payload.group_name])
    return {"message": f"Group {payload.group_name} ensured in {payload.container_name}"}

# --- INTER-CONTAINER CONNECTIVITY ---

@app.post("/containers/connect/tcp")
def connect_containers_network(payload: ContainerLinkRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="connectivity")
    enforce_container_scopes(auth_context, [payload.source_container, payload.target_container])
    target_ip = get_container_ip(payload.target_container)
    device_name = payload.device_name or f"link-{payload.target_container}-{payload.listen_port}"
    listen = f"listen={payload.protocol}:{payload.bind_address}:{payload.listen_port}"
    connect = f"connect={payload.protocol}:{target_ip}:{payload.target_port}"
    run_command([
        "lxc", "config", "device", "add", payload.source_container,
        device_name, "proxy", listen, connect
    ])
    return {"message": f"{payload.source_container} now proxies to {payload.target_container}:{payload.target_port}", "device_name": device_name}

@app.post("/containers/connect/tcp/remove")
def disconnect_container_network(payload: ContainerLinkRemoval, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="connectivity")
    enforce_container_scope(auth_context, payload.container_name)
    run_command(["lxc", "config", "device", "remove", payload.container_name, payload.device_name])
    return {"message": f"Device {payload.device_name} removed from {payload.container_name}"}

@app.post("/containers/connect/share")
def create_shared_mount(payload: SharedMountRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="connectivity")
    enforce_container_scopes(auth_context, payload.containers)
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
        raise HTTPException(status_code=500, detail=f"Failed to create shared mount: {err}")
    return {"message": f"Share {payload.share_name} attached", "attachments": attached}

@app.post("/containers/connect/share/remove")
def remove_shared_mount(payload: SharedMountRemoval, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="connectivity")
    enforce_container_scopes(auth_context, payload.containers)
    for container in payload.containers:
        device_name = f"{payload.share_name}-{container}"
        run_command(["lxc", "config", "device", "remove", container, device_name])
    return {"message": f"Share {payload.share_name} detached from requested containers"}

# --- ENCRYPTED BACKUP SYSTEM ---

def perform_encrypted_backup(container_name: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_file = f"{BACKUP_DIR}/{container_name}_{timestamp}.tar.gz"
    enc_file = f"{raw_file}.enc"

    try:
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
        
    except Exception as e:
        logging.error(f"Backup failed for {container_name}: {e}")

@app.post("/backup/{container_name}")
def trigger_backup(container_name: str, background_tasks: BackgroundTasks, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="manage_backups")
    enforce_container_scope(auth_context, container_name)
    background_tasks.add_task(perform_encrypted_backup, container_name)
    return {"message": "Backup started in background"}

@app.get("/backup/list")
def list_backups(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="manage_backups")
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.enc')]
    return {"backups": files}

@app.get("/backup/download/{filename}")
def download_backup(filename: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    verify_token(x_api_key, x_user_token, required_permission="manage_backups")
    file_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return File(file_path, media_type='application/octet-stream', filename=filename)

# --- RESTORE LOGIC ---

@app.post("/restore")
async def restore_container(file: UploadFile, container_name: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = verify_token(x_api_key, x_user_token, required_permission="restore_container")
    enforce_container_scope(auth_context, container_name)
    
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
        
        return {"message": f"Container {container_name} restored successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")
    finally:
        # Cleanup
        if os.path.exists(enc_path): os.remove(enc_path)
        if os.path.exists(dec_path): os.remove(dec_path)

if __name__ == "__main__":
    # In production, run behind a real webserver or use SSL context here
    uvicorn.run(app, host=HOST_INTERFACE, port=HOST_PORT, ssl_keyfile="/etc/fortress/ssl/key.pem", ssl_certfile="/etc/fortress/ssl/cert.pem")
