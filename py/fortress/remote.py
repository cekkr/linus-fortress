import logging
import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from pydantic import BaseModel

PROVISION_SCRIPTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "provision")
)


class SSHConfig(BaseModel):
    host: str
    username: str
    port: int = 22
    key_path: Optional[str] = None
    password: Optional[str] = None


def _run_subprocess(command: List[str], input_text: Optional[str] = None) -> str:
    try:
        result = subprocess.run(
            command,
            input=input_text,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        logging.error("Command failed: %s. Error: %s", exc.cmd, exc.stderr)
        raise HTTPException(status_code=500, detail=f"System Error: {exc.stderr.strip()}")


def build_ssh_command(ssh_config: Dict[str, Any]) -> List[str]:
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-p", str(ssh_config.get("port", 22))]
    key_path = ssh_config.get("key_path")
    if key_path:
        cmd.extend(["-i", key_path])
    target = f"{ssh_config['username']}@{ssh_config['host']}"
    cmd.append(target)
    return cmd


def run_ssh_script(ssh_config: Dict[str, Any], script: str, env: Optional[Dict[str, str]] = None) -> str:
    env_pairs = []
    for key, value in (env or {}).items():
        if value is None:
            continue
        env_pairs.append(f"{key}={shlex.quote(str(value))}")
    env_prefix = " ".join(env_pairs)
    remote_cmd = f"{env_prefix} bash -s" if env_prefix else "bash -s"
    base_cmd = build_ssh_command(ssh_config)
    password = ssh_config.get("password")
    if password:
        if shutil.which("sshpass") is None:
            raise HTTPException(status_code=500, detail="sshpass is required for password-based SSH")
        base_cmd = ["sshpass", "-p", password] + base_cmd
    return _run_subprocess(base_cmd + [remote_cmd], input_text=script)


def load_provision_script(profile: str, scripts_dir: Optional[str] = None) -> str:
    script_name = f"provision_{profile}.sh"
    script_root = scripts_dir or PROVISION_SCRIPTS_DIR
    script_path = os.path.join(script_root, script_name)
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"Provisioning script not found: {script_name}")
    with open(script_path, "r") as fh:
        return fh.read()


def build_probe_script(service_name: Optional[str] = None) -> str:
    safe_name = shlex.quote(service_name or "fortress")
    script = """#!/usr/bin/env bash
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 missing" >&2
  exit 2
fi
python3 - <<'PY'
import json
import os
import platform
import socket
import subprocess

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()

data = {
    "hostname": socket.gethostname(),
    "kernel": platform.release(),
    "uptime": run("uptime -p || uptime"),
    "ip_address": run("hostname -I | awk '{print $1}'"),
    "cpu_count": os.cpu_count(),
}

os_release = {}
if os.path.exists("/etc/os-release"):
    with open("/etc/os-release", "r", encoding="utf-8") as fh:
        for line in fh:
            if "=" not in line:
                continue
            key, value = line.rstrip().split("=", 1)
            os_release[key] = value.strip('"')

data["os"] = {
    "name": os_release.get("NAME"),
    "version_id": os_release.get("VERSION_ID"),
    "pretty_name": os_release.get("PRETTY_NAME"),
}
try:
    data["memory_mb"] = int(run("free -m | awk '/Mem:/ {print $2}'"))
except Exception:
    data["memory_mb"] = None
try:
    data["disk_root"] = run("df -h / | awk 'NR==2 {print $2, $3, $5}'")
except Exception:
    data["disk_root"] = None
try:
    data["fortress_service"] = run("systemctl is-active __SERVICE_NAME__")
except Exception:
    data["fortress_service"] = "unknown"

print(json.dumps(data))
PY
"""
    return script.replace("__SERVICE_NAME__", safe_name)
