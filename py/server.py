import uvicorn
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, UploadFile, File
from pydantic import BaseModel, Field
import os
import re
import shlex
import shutil
import secrets
import sys
import logging
import subprocess
from typing import Optional, List, Dict, Literal, Union, Any, Tuple
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
from fortress.firewall import (
    apply_ddos_policy,
    apply_firewall_rule,
    apply_firewall_rules,
    detect_connlimit_backend,
    get_ddos_policy,
    get_firewall_status,
    list_firewall_rules,
    remove_ddos_policy,
    rollback_firewall_rules,
    update_ddos_policy,
)
from fortress.recipes import (
    RecipeDefinition,
    RecipeUpdate,
    RecipeApplyRequest,
    RecipeExportRequest,
    RecipeImportRequest,
    build_recipe_export_bundle,
    create_recipe_record,
    collect_lamp_health_targets,
    extract_recipe_bundle,
    load_recipes,
    normalize_recipe_record,
    save_recipes,
    prepare_import_recipe_record,
    resolve_recipe_plan,
    verify_recipe_bundle,
    update_recipe_record,
    build_recipe_execution,
    validate_recipe_name,
    normalize_parameters,
)
from fortress.migrations import MigrationEngine, load_ledger_entries
from fortress.sites import (
    SiteCreateRequest,
    SiteUpdateRequest,
    SiteDeployRequest,
    SiteBackupRequest,
    SiteRollbackRequest,
    SiteServiceActionRequest,
    build_site_backup_id,
    build_site_summary,
    build_service_names,
    create_site_record,
    delete_site_record,
    extract_service_targets,
    load_sites,
    sanitize_site_record,
    save_sites,
    update_site_record,
)
from fortress.system import run_command
from fortress.routing import (
    build_nginx_proxy_config,
    ensure_nginx_site,
    domains_conflict,
    find_domain_conflicts,
    reload_nginx,
    remove_nginx_site,
    test_nginx_config,
    normalize_domains,
    validate_domain,
    validate_tls_paths,
    write_nginx_config,
)
from fortress.tls import (
    build_certificate_paths,
    ensure_acme_challenge_dir,
    issue_letsencrypt_certificate,
    renew_letsencrypt,
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
from fortress.storage import load_json, load_json_dict, save_json
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


def _parse_signing_key_list(value: Optional[str]) -> List[str]:
    if value is None:
        return []
    normalized: List[str] = []
    seen: set[str] = set()
    for chunk in value.split(","):
        key = chunk.strip()
        if not key or key in seen:
            continue
        normalized.append(key)
        seen.add(key)
    return normalized


# --- CONFIGURATION ---
# In production, load these from environment variables
API_SECRET_KEY = os.environ.get("FORTRESS_API_KEY", os.environ.get("API_SECRET_KEY", DEFAULT_API_SECRET))
BACKUP_ENCRYPTION_PASSWORD = os.environ.get("FORTRESS_BACKUP_PASSWORD", "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD")
HOST_INTERFACE = os.environ.get("FORTRESS_HOST_INTERFACE", "0.0.0.0")
HOST_PORT = int(os.environ.get("FORTRESS_HOST_PORT", "8443"))
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESTART_SCRIPT_PATH = os.path.join(BASE_DIR, "restart.sh")
UPDATE_RELOAD_LOG_PATH = os.environ.get("FORTRESS_UPDATE_RELOAD_LOG", os.path.join(BASE_DIR, ".update-reload.log"))
BACKUP_DIR = "/var/lib/fortress/backups"
NGINX_CONFIG_DIR = "/etc/nginx/sites-available"
NGINX_ENABLED_DIR = "/etc/nginx/sites-enabled"
API_USERS_DB = "/var/lib/fortress/api_users.json"
RECIPES_DB = "/var/lib/fortress/recipes.json"
SHARED_STORAGE_DIR = "/var/lib/fortress/shares"
COMMAND_LOG_DB = os.environ.get("FORTRESS_COMMAND_LOG_DB", "/var/lib/fortress/command_log.db")
VMS_DB = "/var/lib/fortress/vms.json"
HOSTS_DB = "/var/lib/fortress/hosts.json"
ROUTING_DB = "/var/lib/fortress/routes.json"
MONITORING_HISTORY_DB = "/var/lib/fortress/monitoring_history.json"
SITES_DB = "/var/lib/fortress/sites.json"
SITE_BACKUP_DIR = "/var/lib/fortress/site_backups"
MIGRATIONS_DIR = "/var/lib/fortress/migrations"
SCHEMA_DIR = os.environ.get("FORTRESS_SCHEMA_DIR", os.path.join(BASE_DIR, "schemas"))
ACME_CHALLENGE_DIR = os.environ.get("FORTRESS_ACME_CHALLENGE_DIR", "/var/lib/fortress/acme-challenges")
FIREWALL_STATE_DIR = "/var/lib/fortress/firewall"
FIREWALL_ROLLBACK_DIR = os.path.join(FIREWALL_STATE_DIR, "rollbacks")
FIREWALL_DDOS_POLICY_PATH = os.path.join(FIREWALL_STATE_DIR, "ddos_policy.json")
POPULAR_IMAGES_DB = "/var/lib/fortress/container_images.json"
RECIPE_BUNDLE_SIGNING_KEY = os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEY")
RECIPE_BUNDLE_SIGNING_KEYS = _parse_signing_key_list(os.environ.get("FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS"))

# Logging setup
LOG_PATH = os.environ.get("FORTRESS_LOG_PATH", "/var/log/fortress.log")
LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
try:
    logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format=LOG_FORMAT)
except OSError:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format=LOG_FORMAT)
    logging.warning("Unable to write log file %s; falling back to stderr logging", LOG_PATH)

MASTER_API_KEY = resolve_master_key(API_SECRET_KEY, DEFAULT_API_SECRET)
if MASTER_API_KEY is None:
    logging.warning("Master API key disabled or defaulted; only delegated tokens accepted.")
if RECIPE_BUNDLE_SIGNING_KEY is not None:
    RECIPE_BUNDLE_SIGNING_KEY = RECIPE_BUNDLE_SIGNING_KEY.strip() or None
if RECIPE_BUNDLE_SIGNING_KEY:
    RECIPE_BUNDLE_SIGNING_KEYS = [RECIPE_BUNDLE_SIGNING_KEY] + [
        key for key in RECIPE_BUNDLE_SIGNING_KEYS if key != RECIPE_BUNDLE_SIGNING_KEY
    ]
elif RECIPE_BUNDLE_SIGNING_KEYS:
    RECIPE_BUNDLE_SIGNING_KEY = RECIPE_BUNDLE_SIGNING_KEYS[0]

app = FastAPI(title="VPS Fortress Manager")
REQUEST_CONTEXT = ContextVar("REQUEST_CONTEXT", default={"actor": "system", "endpoint": "internal"})
command_logger = CommandLogger(COMMAND_LOG_DB)
MIGRATION_ENGINE = MigrationEngine(
    SCHEMA_DIR,
    MIGRATIONS_DIR,
    {
        "api_users": API_USERS_DB,
        "recipes": RECIPES_DB,
        "hosts": HOSTS_DB,
        "vms": VMS_DB,
        "routes": ROUTING_DB,
        "sites": SITES_DB,
        "monitoring_history": MONITORING_HISTORY_DB,
        "container_images": POPULAR_IMAGES_DB,
    },
)

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


def has_permission(auth_context: Dict[str, Any], permission: str) -> bool:
    permissions = auth_context.get("permissions") or []
    return "*" in permissions or permission in permissions

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
    mode: Literal["manual", "letsencrypt"] = "manual"
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    chain_path: Optional[str] = None
    listen_port: int = 443
    redirect_http: bool = True
    email: Optional[str] = None
    staging: bool = False
    cert_name: Optional[str] = None

class DomainRoute(BaseModel):
    domain: str
    domains: Optional[List[str]] = None
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

class FirewallRulesDiffRequest(BaseModel):
    baseline: List[Dict[str, Any]] = Field(default_factory=list)

class FirewallRuleEntry(BaseModel):
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"
    source: Optional[str] = None
    action: Literal["allow", "deny"] = "allow"
    direction: Literal["in", "out"] = "in"
    description: Optional[str] = None

class FirewallRulesApplyRequest(BaseModel):
    rules: List[FirewallRuleEntry]
    mode: Literal["merge", "replace"] = "merge"
    dry_run: bool = False
    comment: Optional[str] = None

class FirewallRollbackRequest(BaseModel):
    rollback_id: str
    dry_run: bool = False

class DdosPolicyRequest(BaseModel):
    enabled: bool = False
    profile: Optional[str] = None
    rate_limit_per_sec: Optional[int] = None
    burst: Optional[int] = None
    conn_limit: Optional[int] = None
    ban_minutes: Optional[int] = None
    allowlist: List[str] = []
    denylist: List[str] = []
    log_only: bool = False
    ports: Optional[List[int]] = None
    protocol: Optional[Literal["tcp", "udp"]] = "tcp"
    dry_run: bool = False

class SystemUpgradeRequest(BaseModel):
    update_packages: bool = True
    full_upgrade: bool = False
    apply_migrations: bool = True
    dry_run: bool = False

class SystemUpdateReloadRequest(BaseModel):
    apply_migrations: bool = True
    restart_mode: Literal["auto", "service", "screen", "process"] = "auto"
    auto_stash: bool = True

class TLSRenewRequest(BaseModel):
    domain: Optional[str] = None
    cert_name: Optional[str] = None
    dry_run: bool = False

class RecipeSeedRequest(BaseModel):
    bundle: str
    overwrite: bool = False

class MigrationPlanRequest(BaseModel):
    stores: Optional[List[str]] = None
    dry_run: bool = True

class MigrationApplyRequest(BaseModel):
    stores: Optional[List[str]] = None
    dry_run: bool = False
    backup: bool = True

class MigrationRollbackRequest(BaseModel):
    patch_id: str
    dry_run: bool = False

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


def _command_for_display(command: List[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _run_local_checked(
    command: List[str],
    cwd: Optional[str] = None,
    allow_return_codes: Optional[List[int]] = None,
) -> subprocess.CompletedProcess:
    allowed = set(allow_return_codes or [0])
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {command[0]}") from exc

    if result.returncode not in allowed:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout or f"exit code {result.returncode}"
        rendered = _command_for_display(command)
        raise RuntimeError(f"Command failed ({rendered}): {detail}")
    return result


def _git_head_commit(repo_path: str) -> str:
    result = _run_local_checked(["git", "rev-parse", "HEAD"], cwd=repo_path)
    return (result.stdout or "").strip()


def _git_has_uncommitted_changes(repo_path: str) -> bool:
    for command in (["git", "diff", "--quiet"], ["git", "diff", "--cached", "--quiet"]):
        result = _run_local_checked(command, cwd=repo_path, allow_return_codes=[0, 1])
        if result.returncode == 1:
            return True
    return False


def _git_has_local_changes(repo_path: str) -> bool:
    result = _run_local_checked(["git", "status", "--porcelain"], cwd=repo_path)
    return bool((result.stdout or "").strip())


def _restore_stashed_changes(repo_path: str) -> Dict[str, Any]:
    pop_result = _run_local_checked(
        ["git", "stash", "pop"],
        cwd=repo_path,
        allow_return_codes=[0, 1],
    )
    restored = pop_result.returncode == 0
    return {
        "restored": restored,
        "restore_conflict": not restored,
        "pop_stdout": (pop_result.stdout or "").strip(),
        "pop_stderr": (pop_result.stderr or "").strip(),
    }


def _launch_restart_script(restart_mode: str) -> None:
    if not os.path.isfile(RESTART_SCRIPT_PATH):
        raise RuntimeError(f"Restart script not found: {RESTART_SCRIPT_PATH}")

    command = ["bash", RESTART_SCRIPT_PATH, "--no-pull", "--mode", restart_mode]
    stream_target: Any = subprocess.DEVNULL
    log_handle = None

    if UPDATE_RELOAD_LOG_PATH:
        try:
            log_parent = os.path.dirname(UPDATE_RELOAD_LOG_PATH)
            if log_parent:
                os.makedirs(log_parent, exist_ok=True)
            log_handle = open(UPDATE_RELOAD_LOG_PATH, "a", encoding="utf-8")
            stream_target = log_handle
        except OSError as exc:
            logging.warning("Unable to open update-reload log %s: %s", UPDATE_RELOAD_LOG_PATH, exc)

    try:
        subprocess.Popen(
            command,
            cwd=BASE_DIR,
            stdin=subprocess.DEVNULL,
            stdout=stream_target,
            stderr=stream_target,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        rendered = _command_for_display(command)
        raise RuntimeError(f"Failed to start restart command ({rendered}): {exc}") from exc
    finally:
        if log_handle:
            log_handle.close()


def _run_system_update_reload(payload: SystemUpdateReloadRequest, background_tasks: BackgroundTasks) -> Dict[str, Any]:
    repo_path = BASE_DIR
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise HTTPException(status_code=500, detail=f"Fortress source is not a git repository: {repo_path}")

    stash_result: Dict[str, Any] = {
        "auto_stash": bool(payload.auto_stash),
        "used": False,
        "label": None,
        "restored": True,
        "restore_conflict": False,
    }

    if payload.auto_stash:
        if _git_has_local_changes(repo_path):
            stash_label = f"fortress-update-reload-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            stash_push_result = _run_local_checked(
                ["git", "stash", "push", "--include-untracked", "--message", stash_label],
                cwd=repo_path,
            )
            stash_stdout = (stash_push_result.stdout or "").strip()
            stash_stderr = (stash_push_result.stderr or "").strip()
            stash_created = "No local changes to save" not in f"{stash_stdout}\n{stash_stderr}"
            stash_result.update(
                {
                    "used": stash_created,
                    "label": stash_label if stash_created else None,
                    "push_stdout": stash_stdout,
                    "push_stderr": stash_stderr,
                }
            )
    elif _git_has_uncommitted_changes(repo_path):
        raise HTTPException(
            status_code=409,
            detail="Working tree has uncommitted changes; commit or stash before update-reload",
        )

    try:
        before_commit = _git_head_commit(repo_path)
        pull_result = _run_local_checked(["git", "pull", "--ff-only"], cwd=repo_path)
        after_commit = _git_head_commit(repo_path)
        updated = before_commit != after_commit

        migrations_result: Dict[str, Any] = {"skipped": True, "reason": "no_updates"}
        if updated:
            if payload.apply_migrations:
                migration_status = MIGRATION_ENGINE.status()
                if migration_status.get("pending"):
                    migrations_result = MIGRATION_ENGINE.apply()
                else:
                    migrations_result = {"skipped": True, "reason": "no_pending"}
            else:
                migrations_result = {"skipped": True, "reason": "disabled"}
    except Exception as exc:
        if stash_result["used"]:
            restored = _restore_stashed_changes(repo_path)
            stash_result.update(restored)
            if restored.get("restore_conflict"):
                raise RuntimeError(
                    f"{exc}; auto-stashed changes could not be restored cleanly (git stash pop reported conflicts)"
                ) from exc
        raise

    if stash_result["used"]:
        stash_result.update(_restore_stashed_changes(repo_path))

    reload_result: Dict[str, Any] = {"scheduled": False, "mode": payload.restart_mode}
    if updated:
        if stash_result.get("restore_conflict"):
            reload_result = {
                "scheduled": False,
                "mode": payload.restart_mode,
                "reason": "stash_restore_conflict",
            }
        else:
            if not os.path.isfile(RESTART_SCRIPT_PATH):
                raise RuntimeError(f"Restart script not found: {RESTART_SCRIPT_PATH}")
            background_tasks.add_task(_launch_restart_script, payload.restart_mode)
            reload_result = {"scheduled": True, "mode": payload.restart_mode}

    message = "Update pulled; migrations handled and reload scheduled." if updated else "Already up to date."
    if stash_result.get("restore_conflict"):
        message = (
            "Update pulled, but local changes could not be restored cleanly after auto-stash; "
            "resolve conflicts and apply the stash manually."
        )

    return {
        "message": message,
        "updated": updated,
        "before_commit": before_commit,
        "after_commit": after_commit,
        "git": {
            "command": ["git", "pull", "--ff-only"],
            "stdout": (pull_result.stdout or "").strip(),
            "stderr": (pull_result.stderr or "").strip(),
        },
        "migrations": migrations_result,
        "reload": reload_result,
        "stash": stash_result,
    }
# --- CORE LOGIC ---

app.include_router(
    build_container_router(
        authorize,
        audit_api,
        sanitize_payload,
        SHARED_STORAGE_DIR,
        POPULAR_IMAGES_DB,
    )
)

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
    include_history: bool = False,
    history_samples: int = 12,
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
    if include_history:
        try:
            history = load_json(MONITORING_HISTORY_DB, default=[], label="Monitoring history")
            if isinstance(history, list) and history_samples > 0:
                snapshot["history_samples"] = history[-max(1, history_samples) :]
        except Exception:
            snapshot["history_samples"] = []
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
    normalized_domains = normalize_domains(route.domain, route.domains)
    domain_aliases = [name for name in normalized_domains if name != route.domain]
    routes = load_routes()
    conflicts = find_domain_conflicts(normalized_domains, routes, ignore_domain=route.domain)
    if conflicts:
        raise HTTPException(status_code=409, detail={"message": "Routing domain conflict detected", "conflicts": conflicts})
    validate_port(route.container_port, "container_port")
    validate_port(route.listen_port, "listen_port")
    tls_payload = None
    tls_mode = None
    ip = get_container_ip(route.container_name, route.container_interface)
    previous_config = _read_nginx_config(route.domain)
    if route.tls:
        tls_mode = route.tls.mode
        validate_port(route.tls.listen_port, "tls.listen_port")
        if route.tls.listen_port == route.listen_port:
            raise HTTPException(status_code=400, detail="TLS listen_port must differ from listen_port")
        if route.tls.mode == "manual":
            if not route.tls.cert_path or not route.tls.key_path:
                raise HTTPException(status_code=400, detail="TLS cert_path and key_path are required")
            validate_tls_paths(route.tls.cert_path, route.tls.key_path, route.tls.chain_path)
            tls_payload = route.tls.dict()
        elif route.tls.mode == "letsencrypt":
            ensure_acme_challenge_dir(ACME_CHALLENGE_DIR)
            cert_name = route.tls.cert_name or route.domain
            cert_paths = build_certificate_paths(cert_name)
            cert_ready = os.path.isfile(cert_paths["cert_path"]) and os.path.isfile(cert_paths["key_path"])
            needs_bootstrap = (not cert_ready) or (previous_config is None) or ("/.well-known/acme-challenge/" not in previous_config)
            if needs_bootstrap:
                bootstrap_content = build_nginx_proxy_config(
                    domain=route.domain,
                    domains=domain_aliases,
                    listen_address=route.listen_address,
                    listen_port=route.listen_port,
                    upstream_host=ip,
                    upstream_port=route.container_port,
                    tls=None,
                    acme_challenge_dir=ACME_CHALLENGE_DIR,
                )
                _apply_nginx_config(route.domain, bootstrap_content, previous_config)
            try:
                cert_paths = issue_letsencrypt_certificate(
                    normalized_domains,
                    route.tls.email,
                    ACME_CHALLENGE_DIR,
                    staging=route.tls.staging,
                    cert_name=cert_name,
                )
            except Exception:
                if needs_bootstrap:
                    _restore_nginx_config(route.domain, previous_config)
                raise
            tls_payload = {
                "mode": "letsencrypt",
                "email": route.tls.email,
                "staging": route.tls.staging,
                "cert_name": cert_name,
                "cert_path": cert_paths["cert_path"],
                "key_path": cert_paths["key_path"],
                "chain_path": cert_paths.get("chain_path"),
                "listen_port": route.tls.listen_port,
                "redirect_http": route.tls.redirect_http,
            }
        else:
            raise HTTPException(status_code=400, detail="Unsupported TLS mode")

    config_content = build_nginx_proxy_config(
        domain=route.domain,
        domains=domain_aliases,
        listen_address=route.listen_address,
        listen_port=route.listen_port,
        upstream_host=ip,
        upstream_port=route.container_port,
        tls=tls_payload,
        acme_challenge_dir=ACME_CHALLENGE_DIR,
    )
    try:
        _apply_nginx_config(route.domain, config_content, previous_config)
    except Exception as exc:
        audit_api(
            "routing_add",
            target=route.domain,
            details={
                "container": route.container_name,
                "listen": f"{route.listen_address}:{route.listen_port}",
                "tls": bool(route.tls),
                "tls_mode": tls_mode,
                "error": str(exc),
            },
            status="error",
        )
        raise

    route_payload = route.dict()
    route_payload["domains"] = domain_aliases or None
    route_payload["tls"] = tls_payload
    routes[route.domain] = route_payload
    save_routes(routes)

    audit_api(
        "routing_add",
        target=route.domain,
        details={
            "container": route.container_name,
            "port": route.container_port,
            "listen": f"{route.listen_address}:{route.listen_port}",
            "interface": route.container_interface,
            "tls": bool(tls_payload),
            "tls_mode": tls_mode,
            "tls_port": route.tls.listen_port if route.tls else None,
            "domains": domain_aliases or None,
        },
    )
    return {"message": f"Routing set for {route.domain} -> {ip}"}


@app.post("/routing/refresh")
def refresh_domain_routing(
    domain: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    auth_context = authorize("routing_refresh", "manage_routing", x_api_key, x_user_token)
    if domain:
        validate_domain(domain)
    routes = load_routes()
    targets = {domain: routes.get(domain)} if domain else dict(routes)
    if domain and not targets.get(domain):
        audit_api("routing_refresh", target=domain, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Route not found")
    allowed_containers = auth_context.get("allowed_containers")
    rendered = []
    for route_domain, record in targets.items():
        if not record:
            continue
        container_name = record.get("container_name")
        if allowed_containers and container_name not in allowed_containers:
            continue
        if container_name:
            enforce_container_scope(auth_context, container_name)
        normalize_domains(route_domain, record.get("domains"))
        ip = get_container_ip(container_name, record.get("container_interface", "eth0"))
        tls_payload = record.get("tls")
        config_content = build_nginx_proxy_config(
            domain=route_domain,
            domains=record.get("domains"),
            listen_address=record.get("listen_address", "0.0.0.0"),
            listen_port=record.get("listen_port", 80),
            upstream_host=ip,
            upstream_port=record.get("container_port", 80),
            tls=tls_payload,
            acme_challenge_dir=ACME_CHALLENGE_DIR,
        )
        rendered.append(
            {
                "domain": route_domain,
                "config": config_content,
                "config_path": os.path.join(NGINX_CONFIG_DIR, route_domain),
            }
        )

    if not rendered:
        return {"message": "No routes eligible for refresh.", "refreshed": []}

    backups = {}
    try:
        for item in rendered:
            config_path = item["config_path"]
            previous_config = None
            if os.path.exists(config_path):
                with open(config_path, "r") as fh:
                    previous_config = fh.read()
            backups[item["domain"]] = previous_config
            write_nginx_config(item["domain"], item["config"], NGINX_CONFIG_DIR)
            ensure_nginx_site(item["domain"], config_path, NGINX_ENABLED_DIR)
        test_nginx_config()
        reload_nginx()
    except Exception as exc:
        for item in rendered:
            previous_config = backups.get(item["domain"])
            config_path = item["config_path"]
            if previous_config is not None:
                write_nginx_config(item["domain"], previous_config, NGINX_CONFIG_DIR)
                ensure_nginx_site(item["domain"], config_path, NGINX_ENABLED_DIR)
            else:
                remove_nginx_site(item["domain"], config_path, NGINX_ENABLED_DIR)
        audit_api(
            "routing_refresh",
            target=domain,
            details={"error": str(exc)},
            status="error",
        )
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(exc))

    refreshed_domains = [item["domain"] for item in rendered]
    audit_api("routing_refresh", target=domain, details={"refreshed": refreshed_domains})
    return {"message": "Routing refreshed.", "refreshed": refreshed_domains}

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


@app.post("/tls/renew")
def renew_tls(payload: TLSRenewRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("tls_renew", "manage_routing", x_api_key, x_user_token)
    if payload.cert_name and not payload.domain:
        output = renew_letsencrypt(payload.cert_name, dry_run=payload.dry_run)
        audit_api("tls_renew", details={"cert_name": payload.cert_name, "dry_run": payload.dry_run})
        return {"message": "TLS renewal complete", "cert_name": payload.cert_name, "output": output}
    if payload.domain:
        validate_domain(payload.domain)
        routes = load_routes()
        cert_name = None
        for route_domain, record in routes.items():
            route_domains = normalize_domains(route_domain, record.get("domains") or [])
            if any(domains_conflict(payload.domain, candidate) for candidate in route_domains):
                tls = record.get("tls") or {}
                if tls.get("mode") != "letsencrypt":
                    raise HTTPException(status_code=400, detail="Route TLS mode is not letsencrypt")
                cert_name = tls.get("cert_name") or route_domain
                break
        if not cert_name:
            sites = _load_site_store()
            for site in sites.values():
                site_domains = normalize_domains(site["primary_domain"], site.get("domains") or [])
                if any(domains_conflict(payload.domain, candidate) for candidate in site_domains):
                    tls = site.get("tls") or {}
                    if tls.get("mode") != "letsencrypt":
                        raise HTTPException(status_code=400, detail="Site TLS mode is not letsencrypt")
                    cert_name = tls.get("cert_name") or site["primary_domain"]
                    break
        if not cert_name:
            raise HTTPException(status_code=404, detail="Domain not found for TLS renewal")
        output = renew_letsencrypt(cert_name, dry_run=payload.dry_run)
        audit_api("tls_renew", details={"cert_name": cert_name, "domain": payload.domain, "dry_run": payload.dry_run})
        return {"message": "TLS renewal complete", "cert_name": cert_name, "output": output}
    output = renew_letsencrypt(dry_run=payload.dry_run)
    audit_api("tls_renew", details={"dry_run": payload.dry_run})
    return {"message": "TLS renewal complete", "output": output}

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

@app.get("/firewall/status")
def firewall_status(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_status", "firewall_admin", x_api_key, x_user_token)
    status = get_firewall_status()
    audit_api("firewall_status", details={"backend": status.get("backend"), "active": status.get("active")})
    return status

@app.get("/firewall/rules")
def firewall_rules(
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    source: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("firewall_rules", "firewall_admin", x_api_key, x_user_token)
    rules = list_firewall_rules()
    if port is not None:
        rules = [rule for rule in rules if rule.get("port") == port]
    if protocol:
        rules = [rule for rule in rules if rule.get("protocol") == protocol]
    if source:
        rules = [rule for rule in rules if rule.get("source") == source]
    audit_api("firewall_rules", details={"count": len(rules)})
    backend = get_firewall_status().get("backend")
    return {"backend": backend, "rules": rules}

@app.post("/firewall/rules/apply")
def firewall_rules_apply(
    payload: FirewallRulesApplyRequest,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("firewall_rules_apply", "firewall_admin", x_api_key, x_user_token)
    rules = [rule.dict() for rule in payload.rules]
    result = apply_firewall_rules(rules, payload.mode, payload.dry_run, FIREWALL_ROLLBACK_DIR)
    audit_api(
        "firewall_rules_apply",
        details={
            "mode": payload.mode,
            "dry_run": payload.dry_run,
            "applied": result.get("applied"),
            "rollback_id": result.get("rollback_id"),
        },
    )
    backend = get_firewall_status().get("backend")
    return {
        "message": "Firewall rules applied",
        "backend": backend,
        "applied_count": result.get("applied"),
        "skipped_count": result.get("skipped"),
        "rollback_id": result.get("rollback_id"),
        "dry_run": payload.dry_run,
    }

@app.post("/firewall/rules/diff")
def firewall_rules_diff(
    payload: FirewallRulesDiffRequest,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("firewall_rules_diff", "firewall_admin", x_api_key, x_user_token)
    current = list_firewall_rules()
    baseline = payload.baseline if isinstance(payload.baseline, list) else []

    def normalize(rule: Dict[str, Any]) -> tuple:
        return (
            rule.get("port"),
            (rule.get("protocol") or "tcp").lower(),
            rule.get("source") or None,
            rule.get("action") or "allow",
            rule.get("direction") or "in",
        )

    current_set = {normalize(rule) for rule in current}
    baseline_set = {normalize(rule) for rule in baseline}
    added = [rule for rule in current if normalize(rule) not in baseline_set]
    removed = [rule for rule in baseline if normalize(rule) not in current_set]
    audit_api("firewall_rules_diff", details={"current": len(current), "added": len(added), "removed": len(removed)})
    return {"current": current, "added": added, "removed": removed}

@app.post("/firewall/rollback")
def firewall_rollback(
    payload: FirewallRollbackRequest,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("firewall_rollback", "firewall_admin", x_api_key, x_user_token)
    rollback_path = os.path.join(FIREWALL_ROLLBACK_DIR, f"{payload.rollback_id}.json")
    rollback_firewall_rules(rollback_path, payload.dry_run)
    audit_api("firewall_rollback", details={"rollback_id": payload.rollback_id, "dry_run": payload.dry_run})
    return {"message": "Firewall rollback complete"}

@app.get("/firewall/ddos")
def firewall_ddos_status(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("firewall_ddos_status", "firewall_admin", x_api_key, x_user_token)
    policy = get_ddos_policy(FIREWALL_DDOS_POLICY_PATH)
    audit_api("firewall_ddos_status", details={"enabled": policy.get("enabled")})
    return {"policy": policy, "effective_rules": [], "warnings": []}

@app.put("/firewall/ddos")
def firewall_ddos_update(
    payload: DdosPolicyRequest,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("firewall_ddos_update", "firewall_admin", x_api_key, x_user_token)
    policy = payload.dict()
    dry_run = bool(policy.pop("dry_run", False))
    existing = get_ddos_policy(FIREWALL_DDOS_POLICY_PATH)
    effective_rules: List[str] = []
    warnings: List[str] = []
    if dry_run:
        if policy.get("conn_limit"):
            if policy.get("protocol", "tcp") != "tcp":
                warnings.append("conn_limit only supported for tcp")
            else:
                conn_backend = detect_connlimit_backend()
                if conn_backend is None:
                    warnings.append("conn_limit requires iptables or nftables")
                else:
                    effective_rules.append(f"conn_limit backend {conn_backend}")
        if policy.get("rate_limit_per_sec"):
            effective_rules.append("rate_limit enabled")
    else:
        remove_ddos_policy(existing)
        effective_rules, warnings = apply_ddos_policy(policy)
        update_ddos_policy(policy, FIREWALL_DDOS_POLICY_PATH)
    audit_api(
        "firewall_ddos_update",
        details={"enabled": policy.get("enabled"), "dry_run": dry_run, "warnings": warnings},
    )
    return {"policy": policy, "effective_rules": effective_rules, "warnings": warnings}

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
    elif manager == "dnf":
        cmd = ["dnf", "install", "-y"] + request.packages
    else:
        cmd = ["yum", "install", "-y"] + request.packages
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
    elif manager == "dnf":
        cmd = ["dnf", "remove", "-y"] + request.packages
    else:
        cmd = ["yum", "remove", "-y"] + request.packages
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
    elif manager == "dnf":
        command = ["dnf", "upgrade" if request.full_upgrade else "update", "-y"]
    else:
        command = ["yum", "upgrade" if request.full_upgrade else "update", "-y"]
    try:
        run_package_command(command, request.container_name)
        audit_api("packages_update", target=request.container_name or "host", details={"manager": manager, "full_upgrade": request.full_upgrade})
    except Exception as exc:
        audit_api("packages_update", target=request.container_name or "host", details={"error": str(exc)}, status="error")
        raise
    return {"message": "Package update completed", "full_upgrade": request.full_upgrade}

@app.post("/system/upgrade")
def system_upgrade(payload: SystemUpgradeRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("system_upgrade", "migration_admin", x_api_key, x_user_token)
    if payload.update_packages and not has_permission(auth_context, "package_manage"):
        raise HTTPException(status_code=403, detail="package_manage permission required for package updates")
    response: Dict[str, Any] = {
        "dry_run": payload.dry_run,
        "update_packages": payload.update_packages,
        "apply_migrations": payload.apply_migrations,
    }
    package_result = None
    if payload.update_packages:
        manager = detect_package_manager(None)
        command = None
        if manager == "apt":
            command = ["apt-get", "dist-upgrade" if payload.full_upgrade else "upgrade", "-y"]
        elif manager == "dnf":
            command = ["dnf", "upgrade" if payload.full_upgrade else "update", "-y"]
        else:
            command = ["yum", "upgrade" if payload.full_upgrade else "update", "-y"]
        if payload.dry_run:
            package_result = {"manager": manager, "command": command, "full_upgrade": payload.full_upgrade}
        else:
            update_package_index(manager, None)
            run_package_command(command, None)
            package_result = {"manager": manager, "command": command, "full_upgrade": payload.full_upgrade}
    response["packages"] = package_result
    if payload.apply_migrations:
        if payload.dry_run:
            plan = MIGRATION_ENGINE.plan()
            response["migrations"] = [
                {"store": entry.store, "from_schema": entry.from_schema, "to_schema": entry.to_schema, "actions": entry.actions}
                for entry in plan
            ]
        else:
            response["migrations"] = MIGRATION_ENGINE.apply()
    else:
        response["migrations"] = {"skipped": True}
    audit_api(
        "system_upgrade",
        details={
            "dry_run": payload.dry_run,
            "packages": bool(payload.update_packages),
            "migrations": bool(payload.apply_migrations),
        },
    )
    return response


@app.post("/system/update-reload")
def system_update_reload(
    payload: SystemUpdateReloadRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    authorize("system_update_reload", "migration_admin", x_api_key, x_user_token)
    try:
        response = _run_system_update_reload(payload, background_tasks)
    except HTTPException as exc:
        audit_api(
            "system_update_reload",
            details={
                "error": str(exc.detail),
                "restart_mode": payload.restart_mode,
                "auto_stash": bool(payload.auto_stash),
            },
            status="error",
        )
        raise
    except Exception as exc:
        audit_api(
            "system_update_reload",
            details={
                "error": str(exc),
                "restart_mode": payload.restart_mode,
                "auto_stash": bool(payload.auto_stash),
            },
            status="error",
        )
        raise HTTPException(status_code=500, detail=str(exc))

    audit_api(
        "system_update_reload",
        details={
            "updated": response.get("updated"),
            "reload_scheduled": response.get("reload", {}).get("scheduled"),
            "apply_migrations": payload.apply_migrations,
            "restart_mode": payload.restart_mode,
            "auto_stash": bool(payload.auto_stash),
            "stash_used": bool(response.get("stash", {}).get("used")),
            "stash_restore_conflict": bool(response.get("stash", {}).get("restore_conflict")),
        },
    )
    return response

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
    recipes = load_recipes(RECIPES_DB)
    normalized: Dict[str, Dict[str, Any]] = {}
    changed = False
    for name, record in recipes.items():
        normalized_record = normalize_recipe_record(
            name,
            record,
            init_history_action="metadata_initialized",
            init_history_note="Recipe metadata was backfilled",
        )
        normalized[name] = normalized_record
        if normalized_record != record:
            changed = True
    if changed:
        save_recipes(RECIPES_DB, normalized)
    return normalized

def _ensure_recipe_dependencies(recipes: Dict[str, Dict[str, Any]], dependencies: List[str], recipe_name: str):
    for dep in dependencies:
        if dep == recipe_name:
            raise HTTPException(status_code=400, detail="Recipe cannot depend on itself")
        if dep not in recipes:
            raise HTTPException(status_code=400, detail=f"Missing recipe dependency: {dep}")

def _validate_recipe_graph(recipes: Dict[str, Dict[str, Any]], targets: Optional[List[str]] = None) -> None:
    recipe_names = sorted(set(targets or recipes.keys()))
    for recipe_name in recipe_names:
        recipe = recipes.get(recipe_name)
        if not recipe:
            continue
        _ensure_recipe_dependencies(recipes, recipe.get("dependencies", []), recipe_name)
        try:
            resolve_recipe_plan(recipe_name, recipes, include_dependencies=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

FILEMANAGER_PHP = (
    r'$file=getenv("FM_FILE"); $user=getenv("FM_USER"); $pass=getenv("FM_PASS"); '
    r'$hash=password_hash($pass, PASSWORD_DEFAULT); '
    r'$u=addcslashes($user, "\\\"\\$"); $h=addcslashes($hash, "\\\"\\$"); '
    r'$replacement="\\$auth_users = array(\\"{$u}\\" => \\"{$h}\\");"; '
    r'$pattern="/\\$auth_users\\s*=\\s*array\\(.*?\\);/s"; '
    r'$content=file_get_contents($file); '
    r'$content=preg_replace_callback($pattern, function() use ($replacement) { return $replacement; }, $content, 1, $count); '
    r'if ($count===0){$content="<?php\\n".$replacement."\\n?>\\n".$content;} '
    r'file_put_contents($file, $content);'
)

FILEMANAGER_COMMAND = " && ".join(
    [
        'FM_DIR="/var/www/html/filemanager"',
        'FM_FILE="$FM_DIR/index.php"',
        'mkdir -p "$FM_DIR"',
        'curl -fsSL https://raw.githubusercontent.com/prasathmani/tinyfilemanager/master/tinyfilemanager.php -o "$FM_FILE"',
        f'FM_USER="{{{{fm_user}}}}" FM_PASS="{{{{fm_password}}}}" FM_FILE="$FM_FILE" php -r \'{FILEMANAGER_PHP}\'',
    ]
)

LAMP_RECIPE_BUNDLE = {
    "lamp-apache": {
        "name": "lamp-apache",
        "description": "Install Apache and PHP runtime.",
        "dependencies": [],
        "packages": [],
        "commands": [
            "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 apache2-utils libapache2-mod-php php{{php_version}} php{{php_version}}-cli php{{php_version}}-mysql php{{php_version}}-curl php{{php_version}}-xml php{{php_version}}-zip php{{php_version}}-mbstring; systemctl enable --now apache2 >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y httpd httpd-tools php php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now httpd >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y httpd httpd-tools php php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now httpd >/dev/null 2>&1 || true; fi",
        ],
        "parameters": {"php_version": ""},
        "required_parameters": [],
    },
    "lamp-nginx": {
        "name": "lamp-nginx",
        "description": "Install Nginx with PHP-FPM.",
        "dependencies": [],
        "packages": [],
        "commands": [
            "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx php{{php_version}}-fpm php{{php_version}}-cli php{{php_version}}-mysql php{{php_version}}-curl php{{php_version}}-xml php{{php_version}}-zip php{{php_version}}-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y nginx php-fpm php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y nginx php-fpm php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; fi",
        ],
        "parameters": {"php_version": ""},
        "required_parameters": [],
    },
    "lamp-mysql": {
        "name": "lamp-mysql",
        "description": "Install MariaDB or MySQL engine.",
        "dependencies": [],
        "packages": [],
        "commands": [
            "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client; systemctl enable --now mariadb >/dev/null 2>&1 || systemctl enable --now mysql >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y mariadb-server mariadb; systemctl enable --now mariadb >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y mariadb-server mariadb; systemctl enable --now mariadb >/dev/null 2>&1 || true; fi; if command -v mysql >/dev/null 2>&1; then ROOT_PWD='{{db_root_password}}'; if [ -n \"$ROOT_PWD\" ]; then mysqladmin -u root status >/dev/null 2>&1 && mysqladmin -u root password \"$ROOT_PWD\" >/dev/null 2>&1 || true; export MYSQL_PWD=\"$ROOT_PWD\"; fi; if [ -n \"{{db_name}}\" ] && [ -n \"{{db_user}}\" ] && [ -n \"{{db_password}}\" ]; then mysql -u root -e \"CREATE DATABASE IF NOT EXISTS \\`{{db_name}}\\`\"; mysql -u root -e \"CREATE USER IF NOT EXISTS '{{db_user}}'@'%' IDENTIFIED BY '{{db_password}}'\"; mysql -u root -e \"GRANT ALL PRIVILEGES ON \\`{{db_name}}\\`.* TO '{{db_user}}'@'%'\"; mysql -u root -e \"FLUSH PRIVILEGES\"; fi; fi",
        ],
        "parameters": {"db_root_password": "", "db_name": "", "db_user": "", "db_password": ""},
        "required_parameters": [],
    },
    "lamp-ftp": {
        "name": "lamp-ftp",
        "description": "Install vsftpd for legacy FTP.",
        "dependencies": [],
        "packages": [],
        "commands": [
            "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; fi",
        ],
        "parameters": {},
        "required_parameters": [],
    },
    "lamp-filemanager": {
        "name": "lamp-filemanager",
        "description": "Install Tiny File Manager web panel.",
        "dependencies": [],
        "packages": ["curl", "php", "php-cli"],
        "commands": [FILEMANAGER_COMMAND],
        "parameters": {"fm_user": "", "fm_password": ""},
        "required_parameters": ["fm_user", "fm_password"],
    },
    "lamp-stack": {
        "name": "lamp-stack",
        "description": "Install Apache, database, FTP, and file manager tools.",
        "dependencies": ["lamp-apache", "lamp-mysql", "lamp-ftp", "lamp-filemanager"],
        "packages": [],
        "commands": [],
        "parameters": {},
        "required_parameters": [],
    },
}

def _format_recipe_plan(steps: List[Dict[str, Any]]) -> List[str]:
    rendered: List[str] = []
    for step in steps:
        rendered.append(
            f"{step['name']} packages={len(step['packages'])} commands={len(step['commands'])}"
        )
    return rendered


RECIPE_HEALTH_RC_MARKER = "__FORTRESS_HEALTH_RC__="


def _run_container_health_command(container_name: str, command: str) -> Tuple[int, str]:
    wrapped = f"set +e; ({command}) 2>&1; rc=$?; echo {RECIPE_HEALTH_RC_MARKER}$rc"
    output = exec_in_container(container_name, ["sh", "-c", wrapped])
    rc = 1
    details: List[str] = []
    for line in output.splitlines():
        if line.startswith(RECIPE_HEALTH_RC_MARKER):
            value = line[len(RECIPE_HEALTH_RC_MARKER) :].strip()
            try:
                rc = int(value)
            except ValueError:
                rc = 1
            continue
        details.append(line)
    return rc, "\n".join(details).strip()


def _build_service_process_probe_command(processes: List[str]) -> str:
    names = " ".join(shlex.quote(name) for name in processes)
    return (
        f'for name in {names}; do '
        'if command -v pgrep >/dev/null 2>&1; then '
        'pgrep -x "$name" >/dev/null 2>&1 && { echo "$name"; exit 0; }; '
        'else '
        'ps -eo comm= | grep -x "$name" >/dev/null 2>&1 && { echo "$name"; exit 0; }; '
        'fi; '
        'done; '
        'echo "no matching process found"; '
        "exit 1"
    )


def _build_port_probe_command(port: int) -> str:
    return (
        f'if command -v ss >/dev/null 2>&1; then ss -ltn "sport = :{port}" | '
        "awk 'NR > 1 {print; found=1} END {exit(found ? 0 : 1)}'; "
        f"elif command -v netstat >/dev/null 2>&1; then netstat -ltn | awk '$4 ~ /:{port}$/ {{print; found=1}} END {{exit(found ? 0 : 1)}}'; "
        'else echo "ss/netstat unavailable"; exit 2; fi'
    )


def _health_status_from_rc(rc: int) -> str:
    if rc == 0:
        return "pass"
    if rc == 2:
        return "skipped"
    return "fail"


def _collect_lamp_health_report(container_name: str, targets: Dict[str, Any]) -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []
    for item in targets.get("service_processes", []):
        service = str(item.get("service", ""))
        processes = [str(name) for name in item.get("processes", []) if name]
        if not service or not processes:
            continue
        command = _build_service_process_probe_command(processes)
        try:
            rc, details = _run_container_health_command(container_name, command)
        except HTTPException as exc:
            rc, details = 1, str(exc.detail)
        checks.append(
            {
                "type": "service_status",
                "name": service,
                "status": _health_status_from_rc(rc),
                "details": details or None,
            }
        )

    for port in targets.get("ports", []):
        port_int = int(port)
        command = _build_port_probe_command(port_int)
        try:
            rc, details = _run_container_health_command(container_name, command)
        except HTTPException as exc:
            rc, details = 1, str(exc.detail)
        checks.append(
            {
                "type": "port_probe",
                "name": str(port_int),
                "status": _health_status_from_rc(rc),
                "details": details or None,
            }
        )

    for config_check in targets.get("config_checks", []):
        check_id = str(config_check.get("id", "config"))
        check_name = str(config_check.get("name", check_id))
        command = str(config_check.get("command", "")).strip()
        if not command:
            continue
        try:
            rc, details = _run_container_health_command(container_name, command)
        except HTTPException as exc:
            rc, details = 1, str(exc.detail)
        checks.append(
            {
                "type": "config_validation",
                "id": check_id,
                "name": check_name,
                "status": _health_status_from_rc(rc),
                "details": details or None,
            }
        )

    summary = {"passed": 0, "failed": 0, "skipped": 0}
    for check in checks:
        status = check.get("status")
        if status == "pass":
            summary["passed"] += 1
        elif status == "skipped":
            summary["skipped"] += 1
        else:
            summary["failed"] += 1

    return {
        "recipes": targets.get("recipes", []),
        "checks": checks,
        "summary": summary,
    }

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
            "version": recipe.get("version", "1.0.0"),
            "history_count": len(recipe.get("history", [])),
            "updated_at": recipe.get("updated_at"),
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
    try:
        recipe_record = create_recipe_record(recipe.dict(), action="create")
        _ensure_recipe_dependencies(recipes, recipe_record.get("dependencies", []), recipe.name)
        staged = dict(recipes)
        staged[recipe.name] = recipe_record
        _validate_recipe_graph(staged, targets=[recipe.name])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    recipes[recipe.name] = recipe_record
    save_recipes(RECIPES_DB, recipes)
    audit_api(
        "recipes_create",
        target=recipe.name,
        details={
            "dependencies": recipe_record.get("dependencies", []),
            "packages": len(recipe_record.get("packages", [])),
            "commands": len(recipe_record.get("commands", [])),
            "parameter_keys": sorted(recipe_record.get("parameters", {}).keys()),
            "required_parameters": recipe_record.get("required_parameters", []),
            "version": recipe_record.get("version"),
        },
    )
    return {"message": f"Recipe {recipe.name} created", "recipe": recipe_record}

@app.post("/recipes/seed")
def seed_recipes(payload: RecipeSeedRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_seed", "recipes_manage", x_api_key, x_user_token)
    bundle = payload.bundle.lower().strip()
    if bundle != "lamp":
        raise HTTPException(status_code=400, detail="Unsupported bundle")
    recipes = _load_recipe_store()
    seeded: List[str] = []
    overwritten: List[str] = []
    skipped: List[str] = []
    for name, definition in LAMP_RECIPE_BUNDLE.items():
        if name in recipes and not payload.overwrite:
            skipped.append(name)
            continue
        if name in recipes:
            updated, _changed_fields = update_recipe_record(
                name,
                recipes[name],
                dict(definition),
                version_bump="minor",
                action="seed_overwrite",
                note="Curated LAMP bundle overwrite",
            )
            overwritten.append(name)
            recipes[name] = updated
            continue
        recipes[name] = create_recipe_record(dict(definition), action="seed", note="Curated LAMP bundle seed")
        seeded.append(name)
    _validate_recipe_graph(recipes, targets=list(LAMP_RECIPE_BUNDLE.keys()))
    save_recipes(RECIPES_DB, recipes)
    audit_api("recipes_seed", details={"bundle": bundle, "seeded": seeded, "overwritten": overwritten, "skipped": skipped})
    return {"message": "Recipes seeded", "recipes": seeded, "overwritten": overwritten, "skipped": skipped}

@app.post("/recipes/export")
def export_recipes(payload: RecipeExportRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_export", "recipes_manage", x_api_key, x_user_token)
    if payload.include_signature and not RECIPE_BUNDLE_SIGNING_KEY:
        raise HTTPException(status_code=400, detail="Recipe bundle signing key is not configured on this server")
    recipes = _load_recipe_store()
    try:
        bundle = build_recipe_export_bundle(
            recipes,
            names=payload.names,
            include_history=payload.include_history,
            signing_key=RECIPE_BUNDLE_SIGNING_KEY if payload.include_signature else None,
        )
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail:
            raise HTTPException(status_code=404, detail=detail)
        raise HTTPException(status_code=400, detail=detail)
    exported_names = [record.get("name") for record in bundle.get("recipes", []) if record.get("name")]
    audit_api(
        "recipes_export",
        details={
            "count": bundle.get("count", len(exported_names)),
            "recipes": exported_names,
            "include_history": payload.include_history,
            "signed": bool(bundle.get("signature")),
        },
    )
    return {"bundle": bundle, "count": bundle.get("count", len(exported_names))}

@app.post("/recipes/import")
def import_recipes(payload: RecipeImportRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_import", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    try:
        verification = verify_recipe_bundle(
            payload.bundle,
            signing_key=RECIPE_BUNDLE_SIGNING_KEY,
            signing_keys=RECIPE_BUNDLE_SIGNING_KEYS,
            require_signature=payload.require_signature,
        )
        bundle_records = extract_recipe_bundle(payload.bundle)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    staged = dict(recipes)
    imported: List[str] = []
    overwritten: List[str] = []
    skipped: List[str] = []
    for name in sorted(bundle_records.keys()):
        existing = staged.get(name)
        if existing and not payload.overwrite:
            skipped.append(name)
            continue
        try:
            staged[name] = prepare_import_recipe_record(
                name,
                bundle_records[name],
                existing=existing,
                preserve_history=payload.preserve_history,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid recipe '{name}': {exc}")
        if existing:
            overwritten.append(name)
        else:
            imported.append(name)
    _validate_recipe_graph(staged, targets=imported + overwritten)
    if imported or overwritten:
        save_recipes(RECIPES_DB, staged)
    audit_api(
        "recipes_import",
        details={
            "imported": imported,
            "overwritten": overwritten,
            "skipped": skipped,
            "preserve_history": payload.preserve_history,
            "require_signature": payload.require_signature,
            "overwrite": payload.overwrite,
            "signed": verification.get("signed", False),
            "verified_with_primary": verification.get("verified_with_primary"),
            "verified_with_index": verification.get("verified_with_index"),
        },
    )
    return {
        "message": "Recipes imported",
        "imported": imported,
        "overwritten": overwritten,
        "skipped": skipped,
        "total_changed": len(imported) + len(overwritten),
    }

@app.put("/recipes/{name}")
def update_recipe(name: str, payload: RecipeUpdate, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_update", "recipes_manage", x_api_key, x_user_token)
    recipes = _load_recipe_store()
    if name not in recipes:
        audit_api("recipes_update", target=name, details={"error": "not found"}, status="error")
        raise HTTPException(status_code=404, detail="Recipe not found")
    update_data = payload.dict(exclude_unset=True, exclude_none=True)
    version_bump = update_data.pop("version_bump", "patch")
    change_note = update_data.pop("change_note", None)
    if "dependencies" in update_data:
        _ensure_recipe_dependencies(recipes, update_data["dependencies"], name)
    try:
        updated, changed_fields = update_recipe_record(
            name,
            recipes[name],
            update_data,
            version_bump=version_bump,
            action="update",
            note=change_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    staged = dict(recipes)
    staged[name] = updated
    _validate_recipe_graph(staged, targets=[name])
    recipes[name] = updated
    if changed_fields or change_note:
        save_recipes(RECIPES_DB, recipes)
    audit_api(
        "recipes_update",
        target=name,
        details={
            "fields": changed_fields,
            "version_bump": version_bump,
            "version": updated.get("version"),
            "change_note": bool(change_note),
        },
    )
    message = f"Recipe {name} updated" if changed_fields or change_note else f"Recipe {name} unchanged"
    return {"message": message, "recipe": recipes[name]}

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
            "dry_run": payload.dry_run,
        },
    )
    if payload.dry_run:
        return {
            "message": "Recipe plan generated",
            "recipe": payload.recipe_name,
            "applied": [],
            "container": payload.container_name,
            "plan": _format_recipe_plan(steps),
            "probe": {},
        }
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
            elif manager == "dnf":
                cmd = ["dnf", "install", "-y"] + packages
            else:
                cmd = ["yum", "install", "-y"] + packages
            run_package_command(cmd, payload.container_name)
            installed_packages.update(packages)
        for command in step["commands"]:
            if payload.container_name:
                exec_in_container(payload.container_name, ["sh", "-c", command])
            else:
                run_command(["sh", "-c", command])
        applied.append(recipe_name)
    probe = {}
    if payload.container_name and payload.probe_services:
        from fortress.containers import probe_container_services

        try:
            probe = probe_container_services(payload.container_name)
        except Exception as exc:
            probe = {"error": str(exc)}
        lamp_targets = collect_lamp_health_targets(applied)
        if lamp_targets.get("detected"):
            probe["health_checks"] = _collect_lamp_health_report(payload.container_name, lamp_targets)
    audit_api(
        "recipes_apply_complete",
        target=payload.container_name or "host",
        details={
            "recipe": payload.recipe_name,
            "applied": applied,
            "probe": bool(probe),
            "health_failures": probe.get("health_checks", {}).get("summary", {}).get("failed"),
        },
    )
    return {
        "message": "Recipe applied",
        "recipe": payload.recipe_name,
        "applied": applied,
        "container": payload.container_name,
        "plan": _format_recipe_plan(steps),
        "probe": probe,
    }

@app.post("/recipes/plan")
def plan_recipe(payload: RecipeApplyRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("recipes_plan", "recipes_apply", x_api_key, x_user_token, containers=payload.container_name)
    recipes = _load_recipe_store()
    if payload.recipe_name not in recipes:
        audit_api("recipes_plan", target=payload.container_name or "host", details={"error": "recipe not found"}, status="error")
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
        audit_api("recipes_plan", target=payload.container_name or "host", details={"error": str(exc)}, status="error")
        raise HTTPException(status_code=400, detail=str(exc))
    audit_api("recipes_plan", target=payload.container_name or "host", details={"recipe": payload.recipe_name, "plan": plan})
    return {"recipe": payload.recipe_name, "container": payload.container_name, "plan": _format_recipe_plan(steps), "dependencies": plan}

# --- WEBSITE MANAGEMENT ---

def _load_site_store() -> Dict[str, Dict[str, Any]]:
    return load_sites(SITES_DB)

def _resolve_site_record(sites: Dict[str, Dict[str, Any]], site_id: str) -> Dict[str, Any]:
    record = sites.get(site_id)
    if not record:
        raise HTTPException(status_code=404, detail="Site not found")
    return record

def _container_user_exists(container_name: str, username: str) -> bool:
    try:
        exec_in_container(container_name, ["id", "-u", username])
        return True
    except HTTPException:
        return False

def _resolve_runtime_identity(container_name: str, runtime: Dict[str, Any]) -> Tuple[str, str]:
    user = runtime.get("user")
    group = runtime.get("group")
    if user and group:
        return user, group
    if _container_user_exists(container_name, "www-data"):
        return "www-data", "www-data"
    if _container_user_exists(container_name, "apache"):
        return "apache", "apache"
    return "root", "root"

def _ensure_docroot(container_name: str, docroot: str, user: str, group: str) -> None:
    docroot_q = shlex.quote(docroot)
    exec_in_container(container_name, ["sh", "-c", f"mkdir -p {docroot_q} && chown -R {user}:{group} {docroot_q}"])

PHP_VERSION_PATTERN = re.compile(r"^\d+\.\d+$")

def _container_dir_exists(container_name: str, path: str) -> bool:
    try:
        exec_in_container(container_name, ["sh", "-c", f"test -d {shlex.quote(path)}"])
        return True
    except HTTPException:
        return False

def _detect_php_version(container_name: str) -> Optional[str]:
    try:
        output = exec_in_container(
            container_name,
            ["sh", "-c", "php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;'"],
        )
        version = output.strip()
        if PHP_VERSION_PATTERN.match(version):
            return version
    except HTTPException:
        pass
    output = exec_in_container(container_name, ["sh", "-c", "ls -1 /etc/php 2>/dev/null || true"])
    candidates = []
    for line in output.splitlines():
        line = line.strip()
        if PHP_VERSION_PATTERN.match(line):
            candidates.append(line)
    if not candidates:
        return None
    candidates.sort(key=lambda value: tuple(int(part) for part in value.split(".")))
    return candidates[-1]

def _resolve_php_ini_dir(container_name: str, php_version: Optional[str]) -> Optional[str]:
    candidates: List[str] = []
    resolved_version = php_version or _detect_php_version(container_name)
    if resolved_version:
        candidates.append(f"/etc/php/{resolved_version}/fpm/conf.d")
        candidates.append(f"/etc/php/{resolved_version}/cli/conf.d")
    candidates.append("/etc/php.d")
    candidates.append("/etc/php/conf.d")
    for path in candidates:
        if _container_dir_exists(container_name, path):
            return path
    return None

def _apply_php_ini_overrides(container_name: str, site_id: str, runtime: Dict[str, Any]) -> Dict[str, Any]:
    overrides = runtime.get("php_ini_overrides") or {}
    if overrides is None:
        overrides = {}
    if not isinstance(overrides, dict):
        raise HTTPException(status_code=400, detail="php_ini_overrides must be an object map")
    php_version = runtime.get("php_version")
    ini_dir = _resolve_php_ini_dir(container_name, php_version)
    if not ini_dir:
        if overrides:
            raise HTTPException(status_code=400, detail="Unable to locate PHP ini directory inside container")
        return {"path": None, "applied": False, "removed": False}
    ini_path = os.path.join(ini_dir, f"99-fortress-{site_id}.ini")
    if not overrides:
        exec_in_container(container_name, ["sh", "-c", f"rm -f {shlex.quote(ini_path)}"])
        return {"path": ini_path, "applied": False, "removed": True}
    lines = [
        f"; Fortress overrides for site {site_id}",
        f"; Generated {datetime.utcnow().isoformat()}Z",
    ]
    for key in sorted(overrides.keys()):
        key_str = str(key).strip()
        value_str = str(overrides[key]).strip()
        if not key_str:
            continue
        if "\n" in key_str or "\n" in value_str:
            raise HTTPException(status_code=400, detail="php_ini_overrides entries cannot contain newlines")
        lines.append(f"{key_str} = {value_str}")
    content = "\n".join(lines) + "\n"
    delimiter = "__FORTRESS_INI__"
    if delimiter in content:
        raise HTTPException(status_code=400, detail="php_ini_overrides contains an unsupported delimiter value")
    cmd = f"mkdir -p {shlex.quote(ini_dir)} && cat <<'{delimiter}' > {shlex.quote(ini_path)}\n{content}{delimiter}\n"
    exec_in_container(container_name, ["sh", "-c", cmd])
    return {"path": ini_path, "applied": True, "removed": False}

def _read_nginx_config(domain: str) -> Optional[str]:
    config_path = os.path.join(NGINX_CONFIG_DIR, domain)
    if os.path.exists(config_path):
        with open(config_path, "r") as fh:
            return fh.read()
    return None

def _restore_nginx_config(domain: str, previous_config: Optional[str]) -> None:
    config_path = os.path.join(NGINX_CONFIG_DIR, domain)
    if previous_config is not None:
        write_nginx_config(domain, previous_config, NGINX_CONFIG_DIR)
        ensure_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
    else:
        remove_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
    test_nginx_config()
    reload_nginx()

def _apply_nginx_config(domain: str, config_content: str, previous_config: Optional[str]) -> None:
    config_path = os.path.join(NGINX_CONFIG_DIR, domain)
    write_nginx_config(domain, config_content, NGINX_CONFIG_DIR)
    try:
        ensure_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
        test_nginx_config()
        reload_nginx()
    except Exception as exc:
        _restore_nginx_config(domain, previous_config)
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=str(exc))

def _apply_nginx_route(
    domain: str,
    domains: Optional[List[str]],
    payload: Dict[str, Any],
    previous_config: Optional[str] = None,
) -> None:
    validate_domain(domain)
    normalize_domains(domain, domains or [])
    validate_port(int(payload["container_port"]), "container_port")
    validate_port(int(payload["listen_port"]), "listen_port")
    tls_payload = payload.get("tls")
    if tls_payload:
        validate_port(int(tls_payload.get("listen_port", 443)), "tls.listen_port")
        if int(tls_payload.get("listen_port", 443)) == int(payload["listen_port"]):
            raise HTTPException(status_code=400, detail="TLS listen_port must differ from listen_port")
        validate_tls_paths(tls_payload["cert_path"], tls_payload["key_path"], tls_payload.get("chain_path"))
    ip = get_container_ip(payload["container_name"], payload["container_interface"])
    config_content = build_nginx_proxy_config(
        domain=domain,
        domains=domains or [],
        listen_address=payload["listen_address"],
        listen_port=payload["listen_port"],
        upstream_host=ip,
        upstream_port=payload["container_port"],
        tls=tls_payload,
        acme_challenge_dir=ACME_CHALLENGE_DIR,
    )
    rollback_config = previous_config if previous_config is not None else _read_nginx_config(domain)
    _apply_nginx_config(domain, config_content, rollback_config)

def _remove_nginx_route(domain: str) -> None:
    config_path = os.path.join(NGINX_CONFIG_DIR, domain)
    previous_config = _read_nginx_config(domain)
    try:
        remove_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
        test_nginx_config()
        reload_nginx()
    except Exception as exc:
        if previous_config is not None:
            write_nginx_config(domain, previous_config, NGINX_CONFIG_DIR)
            ensure_nginx_site(domain, config_path, NGINX_ENABLED_DIR)
        raise HTTPException(status_code=500, detail=str(exc))

def _apply_site_routing(site: Dict[str, Any], previous_domain: Optional[str] = None) -> None:
    tls_config = site.get("tls") or {}
    tls_payload = None
    tls_mode = tls_config.get("mode", "manual")
    routing = site.get("routing") or {}
    normalized_domains = normalize_domains(site["primary_domain"], site.get("domains") or [])
    domain_aliases = [name for name in normalized_domains if name != site["primary_domain"]]
    routes = load_routes()
    ignore_domain = previous_domain or site["primary_domain"]
    conflicts = find_domain_conflicts(normalized_domains, routes, ignore_domain=ignore_domain)
    if conflicts:
        raise HTTPException(status_code=409, detail={"message": "Routing domain conflict detected", "conflicts": conflicts})
    payload = {
        "container_name": site["container_name"],
        "container_port": routing.get("container_port", 80),
        "container_interface": routing.get("container_interface", "eth0"),
        "listen_address": routing.get("listen_address", "0.0.0.0"),
        "listen_port": routing.get("listen_port", 80),
        "tls": None,
    }
    previous_config = _read_nginx_config(site["primary_domain"])
    if tls_mode == "manual" and tls_config.get("cert_path") and tls_config.get("key_path"):
        tls_payload = {
            "mode": "manual",
            "cert_path": tls_config.get("cert_path"),
            "key_path": tls_config.get("key_path"),
            "chain_path": tls_config.get("chain_path"),
            "listen_port": tls_config.get("listen_port", 443),
            "redirect_http": tls_config.get("redirect_http", True),
        }
    elif tls_mode == "disabled":
        tls_payload = None
    elif tls_mode == "letsencrypt":
        ensure_acme_challenge_dir(ACME_CHALLENGE_DIR)
        cert_name = tls_config.get("cert_name") or site["primary_domain"]
        cert_paths = build_certificate_paths(cert_name)
        cert_ready = os.path.isfile(cert_paths["cert_path"]) and os.path.isfile(cert_paths["key_path"])
        needs_bootstrap = (not cert_ready) or (previous_config is None) or ("/.well-known/acme-challenge/" not in previous_config)
        if needs_bootstrap:
            _apply_nginx_route(site["primary_domain"], domain_aliases, payload, previous_config=previous_config)
        try:
            cert_paths = issue_letsencrypt_certificate(
                normalized_domains,
                tls_config.get("email"),
                ACME_CHALLENGE_DIR,
                staging=bool(tls_config.get("staging")),
                cert_name=cert_name,
            )
        except Exception:
            if needs_bootstrap:
                _restore_nginx_config(site["primary_domain"], previous_config)
            raise
        tls_payload = {
            "mode": "letsencrypt",
            "email": tls_config.get("email"),
            "staging": bool(tls_config.get("staging")),
            "cert_name": cert_name,
            "cert_path": cert_paths["cert_path"],
            "key_path": cert_paths["key_path"],
            "chain_path": cert_paths.get("chain_path"),
            "listen_port": tls_config.get("listen_port", 443),
            "redirect_http": tls_config.get("redirect_http", True),
        }
        site["tls"] = tls_payload
    elif tls_mode not in ("manual", "disabled"):
        raise HTTPException(status_code=400, detail="Unsupported TLS mode")
    payload["tls"] = tls_payload
    _apply_nginx_route(site["primary_domain"], domain_aliases, payload, previous_config=previous_config)
    if previous_domain and previous_domain != site["primary_domain"]:
        routes.pop(previous_domain, None)
    routes[site["primary_domain"]] = {
        "domain": site["primary_domain"],
        "domains": domain_aliases or None,
        "container_name": site["container_name"],
        "container_port": payload["container_port"],
        "container_interface": payload["container_interface"],
        "listen_address": payload["listen_address"],
        "listen_port": payload["listen_port"],
        "tls": tls_payload,
    }
    save_routes(routes)
    if previous_domain and previous_domain != site["primary_domain"]:
        _remove_nginx_route(previous_domain)

def _run_db_command(container_name: str, sql: str, database: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None) -> None:
    user = username or "root"
    db_flag = f" {shlex.quote(database)}" if database else ""
    pwd_prefix = f"MYSQL_PWD={shlex.quote(password)} " if password else ""
    command = f"{pwd_prefix}mysql -u {shlex.quote(user)}{db_flag} -e {shlex.quote(sql)}"
    exec_in_container(container_name, ["sh", "-c", command])

def _backup_site_files(container_name: str, docroot: str, backup_path: str, dump_path: Optional[str]) -> None:
    docroot_q = shlex.quote(docroot)
    archive_path = "/tmp/fortress-site-backup.tar.gz"
    if dump_path:
        dump_name = os.path.basename(dump_path)
        cmd = f"tar -czf {archive_path} -C {docroot_q} . -C /tmp {shlex.quote(dump_name)}"
    else:
        cmd = f"tar -czf {archive_path} -C {docroot_q} ."
    exec_in_container(container_name, ["sh", "-c", cmd])
    run_command(["lxc", "file", "pull", f"{container_name}{archive_path}", backup_path])
    exec_in_container(container_name, ["rm", "-f", archive_path])

def _push_site_archive(container_name: str, archive_path: str) -> str:
    target_path = "/tmp/fortress-site-restore.tar.gz"
    run_command(["lxc", "file", "push", archive_path, f"{container_name}{target_path}"])
    return target_path

def _extract_site_archive(container_name: str, archive_path: str, docroot: str, strip_components: int = 0) -> None:
    docroot_q = shlex.quote(docroot)
    strip_flag = f"--strip-components={strip_components}" if strip_components else ""
    cmd = f"mkdir -p {docroot_q} && rm -rf {docroot_q}/* && tar -xzf {shlex.quote(archive_path)} -C {docroot_q} {strip_flag}"
    exec_in_container(container_name, ["sh", "-c", cmd])

def _restore_site_db(container_name: str, database: Dict[str, Any], dump_path: str) -> None:
    if not database.get("name") or not database.get("username"):
        return
    root_password = database.get("root_password")
    if root_password:
        _run_db_command(
            container_name,
            f"CREATE DATABASE IF NOT EXISTS `{database['name']}`",
            username="root",
            password=root_password,
        )
    else:
        _run_db_command(
            container_name,
            f"CREATE DATABASE IF NOT EXISTS `{database['name']}`",
            username=database.get("username"),
            password=database.get("password"),
        )
    import_user = database.get("username") or "root"
    import_password = database.get("password") if database.get("password") else root_password
    pwd_prefix = f"MYSQL_PWD={shlex.quote(import_password)} " if import_password else ""
    cmd = f"{pwd_prefix}mysql -u {shlex.quote(import_user)} {shlex.quote(database['name'])} < {dump_path}"
    exec_in_container(container_name, ["sh", "-c", cmd])

def _restart_site_services(container_name: str, runtime: Dict[str, Any], services: Optional[List[str]]) -> Dict[str, Any]:
    service_sets = build_service_names(runtime)
    targets = extract_service_targets(services)
    restarted: List[str] = []
    failed: List[str] = []
    for target in targets:
        candidates = service_sets.get(target, [target])
        for service in candidates:
            try:
                exec_in_container(container_name, ["sh", "-c", f"systemctl restart {shlex.quote(service)} || service {shlex.quote(service)} restart || true"])
                restarted.append(service)
                break
            except HTTPException:
                continue
        else:
            failed.append(target)
    return {"restarted": restarted, "failed": failed}

@app.get("/sites")
def list_sites(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_list", "sites_read", x_api_key, x_user_token)
    sites = _load_site_store()
    allowed = auth_context.get("allowed_containers")
    response = []
    for site in sites.values():
        if allowed and site.get("container_name") not in allowed:
            continue
        response.append(build_site_summary(site))
    audit_api("sites_list", details={"count": len(response)})
    return {"sites": response}

@app.post("/sites")
def create_site(payload: SiteCreateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("sites_create", "sites_manage", x_api_key, x_user_token, containers=payload.container_name)
    sites = _load_site_store()
    record = create_site_record(payload, sites)
    runtime = record.get("runtime") or {}
    user, group = _resolve_runtime_identity(payload.container_name, runtime)
    runtime.setdefault("user", user)
    runtime.setdefault("group", group)
    record["runtime"] = runtime
    _ensure_docroot(payload.container_name, record["docroot"], user, group)
    if payload.runtime is not None:
        ini_result = _apply_php_ini_overrides(payload.container_name, record["name"], runtime)
        if ini_result.get("applied") or ini_result.get("removed"):
            _restart_site_services(payload.container_name, runtime, ["php-fpm"])
    if record.get("database") and (payload.create_database or payload.create_user):
        database = record["database"]
        if not database.get("name") or not database.get("username"):
            raise HTTPException(status_code=400, detail="database.name and database.username are required for provisioning")
        if not database.get("password"):
            raise HTTPException(status_code=400, detail="database.password is required for provisioning")
        root_password = database.get("root_password")
        _run_db_command(
            payload.container_name,
            f"CREATE DATABASE IF NOT EXISTS `{database.get('name')}`",
            username="root" if root_password else None,
            password=root_password,
        )
        _run_db_command(
            payload.container_name,
            f"CREATE USER IF NOT EXISTS '{database.get('username')}'@'%' IDENTIFIED BY '{database.get('password')}'",
            username="root" if root_password else None,
            password=root_password,
        )
        _run_db_command(
            payload.container_name,
            f"GRANT ALL PRIVILEGES ON `{database.get('name')}`.* TO '{database.get('username')}'@'%'",
            username="root" if root_password else None,
            password=root_password,
        )
        _run_db_command(
            payload.container_name,
            "FLUSH PRIVILEGES",
            username="root" if root_password else None,
            password=root_password,
        )
    _apply_site_routing(record)
    save_sites(SITES_DB, sites)
    audit_api("sites_create", target=record["name"], details={"domain": record["primary_domain"]})
    response = {"message": "Site created", "site": sanitize_site_record(record)}
    return response

@app.get("/sites/{site_id}")
def get_site(site_id: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_get", "sites_read", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    if auth_context.get("allowed_containers"):
        enforce_container_scope(auth_context, record["container_name"])
    audit_api("sites_get", target=site_id)
    return {"site": sanitize_site_record(record)}

@app.get("/sites/{site_id}/backups")
def list_site_backups(site_id: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_backup_list", "sites_read", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    if auth_context.get("allowed_containers"):
        enforce_container_scope(auth_context, record["container_name"])
    backups: List[Dict[str, Any]] = []
    if os.path.isdir(SITE_BACKUP_DIR):
        for entry in os.listdir(SITE_BACKUP_DIR):
            if not entry.endswith(".json"):
                continue
            meta_path = os.path.join(SITE_BACKUP_DIR, entry)
            try:
                meta = load_json_dict(meta_path, label="Site backup metadata")
            except Exception:
                continue
            if meta.get("site_id") != site_id:
                continue
            backup_id = meta.get("backup_id") or entry[:-5]
            archive_path = os.path.join(SITE_BACKUP_DIR, f"{backup_id}.tar.gz")
            size = os.path.getsize(archive_path) if os.path.exists(archive_path) else None
            backups.append(
                {
                    "backup_id": backup_id,
                    "created_at": meta.get("created_at"),
                    "include_database": bool(meta.get("include_database")),
                    "path": archive_path if os.path.exists(archive_path) else None,
                    "size_bytes": size,
                }
            )
    backups.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    audit_api("sites_backup_list", target=site_id, details={"count": len(backups)})
    return {"backups": backups}

@app.put("/sites/{site_id}")
def update_site(site_id: str, payload: SiteUpdateRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_update", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    previous_domain = record.get("primary_domain")
    record = update_site_record(site_id, payload, sites)
    if payload.docroot:
        runtime = record.get("runtime") or {}
        user, group = _resolve_runtime_identity(record["container_name"], runtime)
        _ensure_docroot(record["container_name"], record["docroot"], user, group)
    if payload.runtime is not None:
        runtime = record.get("runtime") or {}
        ini_result = _apply_php_ini_overrides(record["container_name"], record["name"], runtime)
        if ini_result.get("applied") or ini_result.get("removed"):
            _restart_site_services(record["container_name"], runtime, ["php-fpm"])
    if payload.primary_domain or payload.domains or payload.routing or payload.tls:
        _apply_site_routing(record, previous_domain=previous_domain)
    save_sites(SITES_DB, sites)
    audit_api("sites_update", target=record["name"], details={"fields": sorted(payload.dict(exclude_unset=True).keys())})
    return {"message": "Site updated", "site": sanitize_site_record(record)}

@app.delete("/sites/{site_id}")
def delete_site(site_id: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_delete", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    delete_site_record(site_id, sites)
    save_sites(SITES_DB, sites)
    _remove_nginx_route(record["primary_domain"])
    routes = load_routes()
    routes.pop(record["primary_domain"], None)
    save_routes(routes)
    audit_api("sites_delete", target=site_id, details={"domain": record.get("primary_domain")})
    return {"message": "Site removed", "site": sanitize_site_record(record)}

@app.post("/sites/{site_id}/deploy")
def deploy_site(site_id: str, payload: SiteDeployRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_deploy", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    docroot = record["docroot"]
    if payload.source_type == "git":
        tmp_dir = f"/tmp/fortress-{site_id}-src"
        ref = payload.ref or "main"
        clone_cmd = f"rm -rf {tmp_dir} && git clone {shlex.quote(payload.source)} {tmp_dir} && git -C {tmp_dir} checkout {shlex.quote(ref)}"
        exec_in_container(record["container_name"], ["sh", "-c", clone_cmd])
        src_path = tmp_dir
        if payload.subdir:
            src_path = f"{tmp_dir}/{payload.subdir}"
        deploy_cmd = f"mkdir -p {shlex.quote(docroot)} && rm -rf {shlex.quote(docroot)}/* && cp -a {shlex.quote(src_path)}/. {shlex.quote(docroot)}/"
        exec_in_container(record["container_name"], ["sh", "-c", deploy_cmd])
        exec_in_container(record["container_name"], ["sh", "-c", f"rm -rf {tmp_dir}"])
    elif payload.source_type == "archive":
        archive_path = "/tmp/fortress-archive.tar.gz"
        if payload.source.startswith("http://") or payload.source.startswith("https://"):
            exec_in_container(record["container_name"], ["sh", "-c", f"curl -fsSL {shlex.quote(payload.source)} -o {archive_path}"])
        else:
            run_command(["lxc", "file", "push", payload.source, f"{record['container_name']}{archive_path}"])
        _extract_site_archive(record["container_name"], archive_path, docroot, payload.strip_components)
        exec_in_container(record["container_name"], ["rm", "-f", archive_path])
    elif payload.source_type == "local":
        exec_in_container(record["container_name"], ["sh", "-c", f"mkdir -p {shlex.quote(docroot)} && rm -rf {shlex.quote(docroot)}/*"])
        run_command(["lxc", "file", "push", "-r", payload.source, f"{record['container_name']}{docroot}"])
    else:
        raise HTTPException(status_code=400, detail="Unsupported source_type")
    for command in payload.post_deploy_commands:
        exec_in_container(record["container_name"], ["sh", "-c", command])
    restart_result = {}
    if payload.restart_services:
        restart_result = _restart_site_services(record["container_name"], record.get("runtime") or {}, None)
    audit_api("sites_deploy", target=site_id, details={"source_type": payload.source_type, "restart": payload.restart_services})
    return {"message": "Site deployed", "restart": restart_result}

@app.post("/sites/{site_id}/backup")
def backup_site(site_id: str, payload: SiteBackupRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_backup", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    backup_id = build_site_backup_id(site_id, payload.label)
    os.makedirs(SITE_BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(SITE_BACKUP_DIR, f"{backup_id}.tar.gz")
    dump_path = None
    database = record.get("database") or {}
    if payload.include_database and database.get("name") and database.get("username"):
        dump_name = f"{backup_id}.sql"
        dump_path = f"/tmp/{dump_name}"
        pwd_prefix = f"MYSQL_PWD={shlex.quote(database['password'])} " if database.get("password") else ""
        dump_cmd = f"{pwd_prefix}mysqldump -u {shlex.quote(database['username'])} {shlex.quote(database['name'])} > {dump_path}"
        exec_in_container(record["container_name"], ["sh", "-c", dump_cmd])
    _backup_site_files(record["container_name"], record["docroot"], backup_path, dump_path)
    if dump_path:
        exec_in_container(record["container_name"], ["rm", "-f", dump_path])
    meta_path = os.path.join(SITE_BACKUP_DIR, f"{backup_id}.json")
    save_json(meta_path, {"backup_id": backup_id, "site_id": site_id, "include_database": bool(dump_path), "dump_path": dump_path, "created_at": datetime.utcnow().isoformat()})
    audit_api("sites_backup", target=site_id, details={"backup_id": backup_id, "include_db": bool(dump_path)})
    return {"message": "Backup created", "backup_id": backup_id, "path": backup_path}

@app.post("/sites/{site_id}/rollback")
def rollback_site(site_id: str, payload: SiteRollbackRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_rollback", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    backup_path = os.path.join(SITE_BACKUP_DIR, f"{payload.backup_id}.tar.gz")
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup not found")
    archive_path = _push_site_archive(record["container_name"], backup_path)
    _extract_site_archive(record["container_name"], archive_path, record["docroot"])
    meta_path = os.path.join(SITE_BACKUP_DIR, f"{payload.backup_id}.json")
    if os.path.exists(meta_path):
        meta = load_json_dict(meta_path, label="Site backup metadata")
        if meta.get("include_database") and record.get("database"):
            dump_path = f"/tmp/{payload.backup_id}.sql"
            exec_in_container(
                record["container_name"],
                ["sh", "-c", f"tar -xzf {shlex.quote(archive_path)} -C /tmp {shlex.quote(payload.backup_id)}.sql || true"],
            )
            _restore_site_db(record["container_name"], record["database"], dump_path)
            exec_in_container(record["container_name"], ["rm", "-f", dump_path])
    exec_in_container(record["container_name"], ["rm", "-f", archive_path])
    restart_result = {}
    if payload.restart_services:
        restart_result = _restart_site_services(record["container_name"], record.get("runtime") or {}, None)
    audit_api("sites_rollback", target=site_id, details={"backup_id": payload.backup_id})
    return {"message": "Rollback complete", "restart": restart_result}

@app.get("/sites/{site_id}/logs")
def site_logs(
    site_id: str,
    service: Optional[str] = None,
    lines: int = 200,
    since: Optional[str] = None,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    auth_context = authorize("sites_logs", "sites_read", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    service_name = (service or "apache").lower()
    log_candidates = {
        "apache": ["/var/log/apache2/access.log", "/var/log/httpd/access_log"],
        "nginx": ["/var/log/nginx/access.log"],
        "php-fpm": ["/var/log/php-fpm/error.log", "/var/log/php8.2-fpm.log", "/var/log/php8.1-fpm.log"],
        "app": [os.path.join(record["docroot"], "storage/logs/laravel.log")],
    }
    paths = log_candidates.get(service_name, [])
    if not paths:
        raise HTTPException(status_code=400, detail="Unknown log service")
    for path in paths:
        try:
            output = exec_in_container(record["container_name"], ["sh", "-c", f"tail -n {int(lines)} {shlex.quote(path)}"])
            audit_api("sites_logs", target=site_id, details={"service": service_name})
            return {"logs": output, "truncated": False}
        except HTTPException:
            continue
    raise HTTPException(status_code=404, detail="Log file not found")

@app.get("/sites/{site_id}/health")
def site_health(site_id: str, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    auth_context = authorize("sites_health", "sites_read", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    checks = []
    try:
        exec_in_container(record["container_name"], ["test", "-d", record["docroot"]])
        checks.append({"check": "docroot", "status": "ok"})
    except HTTPException as exc:
        checks.append({"check": "docroot", "status": "error", "detail": str(exc.detail)})
    runtime = record.get("runtime") or {}
    services = build_service_names(runtime)
    for label, candidates in services.items():
        ok = False
        for service in candidates:
            try:
                exec_in_container(record["container_name"], ["sh", "-c", f"systemctl is-active {shlex.quote(service)} >/dev/null 2>&1"])
                ok = True
                break
            except HTTPException:
                continue
        checks.append({"check": label, "status": "ok" if ok else "error"})
    status = "ok" if all(item["status"] == "ok" for item in checks) else "error"
    audit_api("sites_health", target=site_id, details={"status": status})
    return {"status": status, "checks": checks}

@app.post("/sites/{site_id}/services/restart")
def restart_site_services(
    site_id: str,
    payload: SiteServiceActionRequest,
    x_api_key: Optional[str] = Header(default=None),
    x_user_token: Optional[str] = Header(default=None),
):
    auth_context = authorize("sites_restart", "sites_manage", x_api_key, x_user_token)
    sites = _load_site_store()
    record = _resolve_site_record(sites, site_id)
    enforce_container_scope(auth_context, record["container_name"])
    result = _restart_site_services(record["container_name"], record.get("runtime") or {}, payload.services)
    audit_api("sites_restart", target=site_id, details={"restarted": result.get("restarted"), "failed": result.get("failed")})
    return {"message": "Services restarted", **result}

# --- MIGRATIONS ---

@app.get("/migrations/status")
def migration_status(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("migrations_status", "migration_admin", x_api_key, x_user_token)
    status = MIGRATION_ENGINE.status()
    audit_api("migrations_status", details={"pending": status.get("pending")})
    return status

@app.post("/migrations/plan")
def migration_plan(payload: Optional[MigrationPlanRequest] = None, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("migrations_plan", "migration_admin", x_api_key, x_user_token)
    resolved = payload or MigrationPlanRequest()
    plan = MIGRATION_ENGINE.plan(stores=resolved.stores)
    audit_api("migrations_plan", details={"count": len(plan), "stores": resolved.stores})
    return {"dry_run": True, "plan": [entry.__dict__ for entry in plan]}

@app.post("/migrations/apply")
def migration_apply(payload: Optional[MigrationApplyRequest] = None, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("migrations_apply", "migration_admin", x_api_key, x_user_token)
    resolved = payload or MigrationApplyRequest()
    result = MIGRATION_ENGINE.apply(stores=resolved.stores, dry_run=resolved.dry_run, backup=resolved.backup)
    audit_api("migrations_apply", details={"patch_id": result.get("patch_id"), "applied": result.get("applied")})
    return result

@app.post("/migrations/rollback")
def migration_rollback(payload: MigrationRollbackRequest, x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("migrations_rollback", "migration_admin", x_api_key, x_user_token)
    result = MIGRATION_ENGINE.rollback(payload.patch_id, dry_run=payload.dry_run)
    audit_api("migrations_rollback", details={"patch_id": payload.patch_id, "restored": result.get("restored")})
    return result

@app.get("/migrations/ledger")
def migration_ledger(x_api_key: Optional[str] = Header(default=None), x_user_token: Optional[str] = Header(default=None)):
    authorize("migrations_ledger", "migration_admin", x_api_key, x_user_token)
    entries = load_ledger_entries(MIGRATIONS_DIR)
    audit_api("migrations_ledger", details={"count": len(entries)})
    return {"entries": entries}

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
