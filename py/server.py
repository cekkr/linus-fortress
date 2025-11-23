import uvicorn
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
import subprocess
import os
import shutil
import secrets
import logging
from typing import Optional
import crypt
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib

# --- CONFIGURATION ---
# In production, load these from environment variables
API_SECRET_KEY = "CHANGE_THIS_TO_A_VERY_LONG_RANDOM_STRING" 
BACKUP_ENCRYPTION_PASSWORD = "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD"
HOST_INTERFACE = "0.0.0.0"
HOST_PORT = 8443
BACKUP_DIR = "/var/lib/fortress/backups"
NGINX_CONFIG_DIR = "/etc/nginx/sites-available"

# Logging setup
logging.basicConfig(filename='/var/log/fortress.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s')

app = FastAPI(title="VPS Fortress Manager")

# --- SECURITY UTILS ---

def get_fernet_key(password: str) -> bytes:
    """Derive a 32-byte base64 key from the password for AES encryption."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def verify_token(x_api_key: str = Header(...)):
    if x_api_key != API_SECRET_KEY:
        logging.warning(f"Unauthorized access attempt.")
        raise HTTPException(status_code=403, detail="Invalid API Key")

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

# --- CORE LOGIC ---

@app.get("/status", dependencies=[])
def system_status(x_api_key: str = Header(...)):
    verify_token(x_api_key)
    # Check RAM, Disk, and Load
    ram = run_command(["free", "-h"])
    disk = run_command(["df", "-h"])
    containers = run_command(["lxc", "list", "--format", "json"])
    return {"status": "operational", "ram": ram, "disk": disk, "containers": containers}

@app.post("/container/create")
def create_container(config: ContainerCreate, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    
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
def delete_container(name: str, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    logging.info(f"Deleting container {name}")
    try:
        # Force delete (stop and delete)
        run_command(["lxc", "delete", name, "--force"])
        return {"message": f"Container {name} deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/routing/add")
def add_domain_routing(route: DomainRoute, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    
    # 1. Get Container IP
    try:
        info_json = run_command(["lxc", "list", route.container_name, "--format", "json"])
        import json
        info = json.loads(info_json)
        # Assuming eth0 generic setup
        ip = info[0]['state']['network']['eth0']['addresses'][0]['address']
    except Exception:
        raise HTTPException(status_code=404, detail="Container IP not found. Is it running?")

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
def trigger_backup(container_name: str, background_tasks: BackgroundTasks, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    background_tasks.add_task(perform_encrypted_backup, container_name)
    return {"message": "Backup started in background"}

@app.get("/backup/list")
def list_backups(x_api_key: str = Header(...)):
    verify_token(x_api_key)
    files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.enc')]
    return {"backups": files}

@app.get("/backup/download/{filename}")
def download_backup(filename: str, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    file_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return File(file_path, media_type='application/octet-stream', filename=filename)

# --- RESTORE LOGIC ---

@app.post("/restore")
async def restore_container(file: UploadFile, container_name: str, x_api_key: str = Header(...)):
    verify_token(x_api_key)
    
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