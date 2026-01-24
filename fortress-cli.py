#!/usr/bin/env python3
"""
Fortress CLI

High-level client that automates authenticated API calls to Linus' Fortress,
handles the initial provisioning dance (RSA keys, credential exchange), and
provides helpers for decrypting the encrypted backup archives produced by the
server. Credentials are stored encrypted-at-rest via the generated RSA keypair
so subsequent runs can reuse the configuration without retyping secrets.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import textwrap
from dataclasses import dataclass, field
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import hashlib


CONFIG_DIR = Path(os.environ.get("FORTRESS_HOME", Path.home() / ".fortress-cli"))
CONFIG_PATH = CONFIG_DIR / "config.json"
PRIVATE_KEY_PATH = CONFIG_DIR / "private_key.pem"
PUBLIC_KEY_PATH = CONFIG_DIR / "public_key.pem"
DEFAULT_KEY_BITS = 4096
DEFAULT_TIMEOUT = 60


class FortressCLIError(RuntimeError):
    """Domain specific exception for CLI failures."""


def ensure_storage_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def keys_exist() -> bool:
    return PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists()


def get_passphrase(confirm: bool = False, preset: Optional[str] = None) -> str:
    """Prompt for a passphrase, optionally requiring confirmation."""
    if preset:
        return preset
    env_value = os.environ.get("FORTRESS_PASSPHRASE")
    if env_value:
        return env_value
    first = getpass("Passphrase: ")
    if confirm:
        second = getpass("Confirm passphrase: ")
        if first != second:
            raise FortressCLIError("Passphrases do not match")
    if not first:
        raise FortressCLIError("Passphrase cannot be empty")
    return first


def generate_rsa_keypair(bits: int = DEFAULT_KEY_BITS, passphrase: Optional[str] = None) -> None:
    """Generate a RSA keypair and persist it to disk."""
    ensure_storage_dir()
    passphrase = get_passphrase(confirm=True, preset=passphrase)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
    )
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PUBLIC_KEY_PATH.write_bytes(public_bytes)
    print(f"Generated {bits}-bit RSA keypair under {CONFIG_DIR}")


def prompt(text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or (default or "")


def prompt_secret(text: str) -> str:
    value = getpass(f"{text}: ").strip()
    return value


def load_public_key():
    try:
        return serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
    except FileNotFoundError as exc:
        raise FortressCLIError("Public key missing, run `fortress-cli setup` first") from exc


def load_private_key(passphrase: Optional[str] = None):
    if not PRIVATE_KEY_PATH.exists():
        raise FortressCLIError("Private key missing, run `fortress-cli setup` first")
    pw = passphrase or get_passphrase()
    try:
        return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=pw.encode())
    except ValueError as exc:
        raise FortressCLIError("Unable to unlock private key (wrong passphrase?)") from exc


def encrypt_secret(raw: str, public_key) -> str:
    ciphertext = public_key.encrypt(
        raw.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(ciphertext).decode()


def decrypt_secret(ciphertext: str, private_key) -> str:
    data = base64.b64decode(ciphertext.encode())
    plaintext = private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return plaintext.decode()


def save_config(config: Dict[str, Any]) -> None:
    ensure_storage_dir()
    CONFIG_PATH.write_text(json.dumps(config, indent=2))


def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise FortressCLIError("Configuration not initialized. Run `fortress-cli setup` first.")
    return json.loads(CONFIG_PATH.read_text())


def get_fernet_key(password: str) -> bytes:
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def load_json_payload(text_value: Optional[str], file_path: Optional[str]) -> Optional[Dict[str, Any]]:
    if text_value and file_path:
        raise FortressCLIError("Specify at most one of --json or --json-file")
    if text_value:
        try:
            return json.loads(text_value)
        except json.JSONDecodeError as exc:
            raise FortressCLIError(f"Invalid JSON payload: {exc}") from exc
    if file_path:
        try:
            return json.loads(Path(file_path).read_text())
        except FileNotFoundError as exc:
            raise FortressCLIError(f"JSON file not found: {file_path}") from exc
        except json.JSONDecodeError as exc:
            raise FortressCLIError(f"Invalid JSON file {file_path}: {exc}") from exc
    return None


def parse_kv_pairs(pairs: Optional[Sequence[str]]) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if not pairs:
        return params
    for item in pairs:
        if "=" not in item:
            raise FortressCLIError(f"Invalid key=value pair: {item}")
        key, value = item.split("=", 1)
        params[key] = value
    return params


def parse_rule_specs(specs: Optional[Sequence[str]]) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    if not specs:
        return rules
    for raw in specs:
        parts = raw.split(":")
        port_proto = parts[0]
        action = parts[1] if len(parts) > 1 and parts[1] else "allow"
        direction = parts[2] if len(parts) > 2 and parts[2] else "in"
        source = parts[3] if len(parts) > 3 and parts[3] else None
        protocol = "tcp"
        port_str = port_proto
        if "/" in port_proto:
            port_str, protocol = port_proto.split("/", 1)
        try:
            port = int(port_str)
        except ValueError as exc:
            raise FortressCLIError(f"Invalid rule spec port: {raw}") from exc
        rules.append(
            {
                "port": port,
                "protocol": protocol,
                "source": source,
                "action": action,
                "direction": direction,
            }
        )
    return rules


@dataclass
class CredentialContext:
    config: Dict[str, Any]
    private_key: Optional[Any] = None
    cache: Dict[str, str] = field(default_factory=dict)

    def unlock(self, passphrase: Optional[str] = None):
        if self.private_key is None:
            self.private_key = load_private_key(passphrase)
        return self.private_key

    def get_secret(self, name: str, passphrase: Optional[str] = None) -> Optional[str]:
        stored = self.config.get("stored", {})
        value = stored.get(name)
        if not value:
            return None
        if name in self.cache:
            return self.cache[name]
        private_key = self.unlock(passphrase)
        secret = decrypt_secret(value, private_key)
        self.cache[name] = secret
        return secret


class FortressClient:
    def __init__(self, config: Dict[str, Any], passphrase: Optional[str] = None):
        self.config = config
        self.credentials = CredentialContext(config)
        self.passphrase = passphrase
        self.base_url = config.get("server_url")
        if not self.base_url:
            raise FortressCLIError("server_url missing in config. Re-run setup.")
        self.verify_tls = config.get("verify_tls", True)
        self.timeout = config.get("timeout", DEFAULT_TIMEOUT)

    def _resolve_auth(self, override: Optional[str] = None) -> Dict[str, str]:
        auth_mode = override or self.config.get("preferences", {}).get("auth_mode")
        headers: Dict[str, str] = {}
        if auth_mode == "user-token":
            token = self.credentials.get_secret("user_token", self.passphrase)
            if not token:
                raise FortressCLIError("No stored user token available")
            headers["X-User-Token"] = token
            return headers
        api_key = self.credentials.get_secret("api_key", self.passphrase)
        token = self.credentials.get_secret("user_token", self.passphrase)
        if api_key:
            headers["X-API-Key"] = api_key
        elif token:
            headers["X-User-Token"] = token
        else:
            raise FortressCLIError("No credentials stored. Re-run setup and provide an API key or token.")
        return headers

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        auth_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        headers = self._resolve_auth(auth_override)
        url = self.base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        response = requests.request(
            method.upper(),
            url,
            headers=headers,
            json=json_body,
            params=params,
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        if response.status_code >= 400:
            try:
                payload = response.json()
                detail = payload.get("detail", payload)
            except ValueError:
                detail = response.text
            raise FortressCLIError(f"HTTP {response.status_code}: {detail}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    def stream_download(self, endpoint: str, destination: Path) -> Path:
        headers = self._resolve_auth()
        url = self.base_url.rstrip("/") + "/" + endpoint.lstrip("/")
        with requests.get(url, headers=headers, verify=self.verify_tls, timeout=self.timeout, stream=True) as resp:
            if resp.status_code >= 400:
                raise FortressCLIError(f"Download failed with HTTP {resp.status_code}")
            with destination.open("wb") as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        fh.write(chunk)
        return destination


def setup_command(args: argparse.Namespace) -> None:
    ensure_storage_dir()

    if args.force_keys or not keys_exist():
        generate_rsa_keypair(bits=args.key_bits, passphrase=args.key_passphrase)
    else:
        print("Existing RSA keypair found, keeping current keys.")

    public_key = load_public_key()
    existing_config = load_config() if CONFIG_PATH.exists() else {}

    server_url = args.server or existing_config.get("server_url")
    if not server_url:
        server_url = prompt("Server base URL (e.g. https://host:8443)")

    verify_tls = existing_config.get("verify_tls", True)
    if args.insecure:
        verify_tls = False
    elif args.secure:
        verify_tls = True

    stored: Dict[str, Optional[str]] = existing_config.get("stored", {}).copy()

    def capture_secret(name: str, provided: Optional[str], prompt_label: str) -> Optional[str]:
        if provided == "":
            stored.pop(name, None)
            return None
        if provided:
            stored[name] = encrypt_secret(provided, public_key)
            return stored[name]
        if stored.get(name):
            return stored[name]
        value = prompt_secret(prompt_label + " (leave blank to skip)")
        if value:
            stored[name] = encrypt_secret(value, public_key)
        return stored.get(name)

    capture_secret("api_key", args.api_key, "API master key")
    capture_secret("user_token", args.user_token, "Delegated user token")
    capture_secret("backup_password", args.backup_password, "Backup encryption password")

    auth_mode = args.auth_mode or existing_config.get("preferences", {}).get("auth_mode")
    if not auth_mode:
        auth_mode = "api-key" if stored.get("api_key") else "user-token"

    config = {
        "server_url": server_url,
        "verify_tls": verify_tls,
        "timeout": args.timeout or existing_config.get("timeout", DEFAULT_TIMEOUT),
        "stored": stored,
        "keys": {
            "public": str(PUBLIC_KEY_PATH),
            "private": str(PRIVATE_KEY_PATH),
            "bits": args.key_bits,
        },
        "preferences": {
            "auth_mode": auth_mode,
        },
    }
    save_config(config)
    print(f"Configuration saved to {CONFIG_PATH}")


def info_command(_: argparse.Namespace) -> None:
    config = load_config()
    sanitized = {k: v for k, v in config.items() if k != "stored"}
    print(json.dumps(sanitized, indent=2))


def call_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    payload = load_json_payload(args.json, args.json_file)
    params = parse_kv_pairs(args.params)
    result = client.request(
        args.method,
        args.endpoint,
        json_body=payload,
        params=params,
        auth_override=args.auth_mode,
    )
    print(json.dumps(result, indent=2))


def status_command(args: argparse.Namespace) -> None:
    args.method = "GET"
    args.endpoint = "/status"
    args.json = None
    args.json_file = None
    args.params = None
    call_command(args)


def api_users_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    if args.subcommand == "list":
        result = client.request("GET", "/api-users")
    elif args.subcommand == "create":
        payload = {
            "username": args.username,
            "permissions": args.permissions,
            "allowed_containers": args.containers,
        }
        result = client.request("POST", "/api-users", json_body=payload)
    elif args.subcommand == "delete":
        result = client.request("DELETE", f"/api-users/{args.token}")
    else:
        raise FortressCLIError("Unknown api-users subcommand")
    print(json.dumps(result, indent=2))


def backup_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    if args.subcommand == "list":
        result = client.request("GET", "/backup/list")
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "trigger":
        result = client.request("POST", f"/backup/{args.container}")
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "download":
        dest = Path(args.dest or args.filename)
        client.stream_download(f"/backup/download/{args.filename}", dest)
        print(f"Downloaded to {dest}")
        return
    if args.subcommand == "decrypt":
        config_ctx = CredentialContext(config)
        password = args.password
        if not password:
            password = config_ctx.get_secret("backup_password", args.passphrase)
        if not password:
            password = prompt_secret("Backup password")
        enc_path = Path(args.input)
        out_path = Path(args.output or enc_path.with_suffix(".tar.gz"))
        fernet = Fernet(get_fernet_key(password))
        decrypted = fernet.decrypt(enc_path.read_bytes())
        out_path.write_bytes(decrypted)
        print(f"Decrypted archive written to {out_path}")
        return
    raise FortressCLIError("Unsupported backup subcommand")


def recipes_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "list":
        result = client.request("GET", "/recipes", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "create":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name:
                raise FortressCLIError("Recipe name required when not using --json or --json-file")
            payload = {"name": args.name}
            if args.description is not None:
                payload["description"] = args.description
            if args.dependencies:
                payload["dependencies"] = args.dependencies
            if args.packages:
                payload["packages"] = args.packages
            if args.commands:
                payload["commands"] = args.commands
            params = parse_kv_pairs(args.param)
            if params:
                payload["parameters"] = params
            if args.required:
                payload["required_parameters"] = args.required
        result = client.request("POST", "/recipes", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "apply":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name:
                raise FortressCLIError("Recipe name required when not using --json or --json-file")
            payload = {
                "recipe_name": args.name,
                "include_dependencies": not args.no_deps,
                "update_index": not args.no_update_index,
                "dry_run": args.dry_run,
                "probe_services": not args.no_probe,
            }
            if args.container:
                payload["container_name"] = args.container
            params = parse_kv_pairs(args.param)
            if params:
                payload["parameters"] = params
        result = client.request("POST", "/recipes/apply", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "plan":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name:
                raise FortressCLIError("Recipe name required when not using --json or --json-file")
            payload = {
                "recipe_name": args.name,
                "include_dependencies": not args.no_deps,
            }
            if args.container:
                payload["container_name"] = args.container
            params = parse_kv_pairs(args.param)
            if params:
                payload["parameters"] = params
        result = client.request("POST", "/recipes/plan", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "seed":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.bundle:
                raise FortressCLIError("Bundle name required when not using --json or --json-file")
            payload = {"bundle": args.bundle, "overwrite": args.overwrite}
        result = client.request("POST", "/recipes/seed", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported recipes subcommand")


def firewall_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "status":
        result = client.request("GET", "/firewall/status", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "rules":
        params = {}
        if args.port is not None:
            params["port"] = args.port
        if args.protocol:
            params["protocol"] = args.protocol
        if args.source:
            params["source"] = args.source
        result = client.request("GET", "/firewall/rules", params=params, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "apply":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            rules = parse_rule_specs(args.rule)
            if not rules:
                raise FortressCLIError("Provide --rule entries or use --json/--json-file")
            payload = {"rules": rules, "mode": args.mode, "dry_run": args.dry_run}
        result = client.request("POST", "/firewall/rules/apply", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "rollback":
        payload = {"rollback_id": args.rollback_id, "dry_run": args.dry_run}
        result = client.request("POST", "/firewall/rollback", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "ddos-status":
        result = client.request("GET", "/firewall/ddos", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "ddos":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            enabled = True
            if args.disable:
                enabled = False
            payload = {
                "enabled": enabled,
                "profile": args.profile,
                "rate_limit_per_sec": args.rate,
                "burst": args.burst,
                "conn_limit": args.conn_limit,
                "ban_minutes": args.ban_minutes,
                "allowlist": args.allow or [],
                "denylist": args.deny or [],
                "ports": args.ports,
                "protocol": args.protocol,
                "dry_run": args.dry_run,
            }
        result = client.request("PUT", "/firewall/ddos", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported firewall subcommand")


def sites_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "list":
        result = client.request("GET", "/sites", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "get":
        result = client.request("GET", f"/sites/{args.site_id}", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "create":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name or not args.domain or not args.container or not args.docroot:
                raise FortressCLIError("name, domain, container, and docroot are required when not using --json/--json-file")
            payload = {
                "name": args.name,
                "primary_domain": args.domain,
                "domains": args.aliases or [],
                "container_name": args.container,
                "docroot": args.docroot,
            }
            if args.php_version or args.runtime_user or args.runtime_group or args.php_ini:
                payload["runtime"] = {
                    "php_version": args.php_version,
                    "user": args.runtime_user,
                    "group": args.runtime_group,
                }
                if args.php_ini:
                    payload["runtime"]["php_ini_overrides"] = parse_kv_pairs(args.php_ini)
            if args.db_name or args.db_user or args.db_password or args.db_root_password:
                payload["database"] = {
                    "engine": args.db_engine,
                    "name": args.db_name,
                    "username": args.db_user,
                    "password": args.db_password,
                    "root_password": args.db_root_password,
                    "host": args.db_host,
                    "port": args.db_port,
                }
            if args.no_db_create:
                payload["create_database"] = False
            if args.no_user_create:
                payload["create_user"] = False
            if args.listen_port or args.listen_address or args.container_port or args.container_interface:
                payload["routing"] = {
                    "listen_address": args.listen_address,
                    "listen_port": args.listen_port,
                    "container_port": args.container_port,
                    "container_interface": args.container_interface,
                }
            if args.tls_mode or args.tls_cert or args.tls_key:
                payload["tls"] = {
                    "mode": args.tls_mode,
                    "cert_path": args.tls_cert,
                    "key_path": args.tls_key,
                    "chain_path": args.tls_chain,
                    "listen_port": args.tls_port,
                    "email": args.tls_email,
                    "staging": args.tls_staging,
                    "cert_name": args.tls_cert_name,
                }
        result = client.request("POST", "/sites", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "update":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            raise FortressCLIError("Update requires --json or --json-file")
        result = client.request("PUT", f"/sites/{args.site_id}", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "delete":
        result = client.request("DELETE", f"/sites/{args.site_id}", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "deploy":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.source_type or not args.source:
                raise FortressCLIError("source-type and source are required when not using --json/--json-file")
            payload = {
                "source_type": args.source_type,
                "source": args.source,
                "ref": args.ref,
                "subdir": args.subdir,
                "strip_components": args.strip_components,
                "post_deploy_commands": args.post or [],
                "restart_services": not args.no_restart,
            }
        result = client.request("POST", f"/sites/{args.site_id}/deploy", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "backup":
        payload = {"include_database": not args.no_db, "label": args.label}
        result = client.request("POST", f"/sites/{args.site_id}/backup", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "rollback":
        payload = {"backup_id": args.backup_id, "restart_services": not args.no_restart}
        result = client.request("POST", f"/sites/{args.site_id}/rollback", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "logs":
        params = {}
        if args.service:
            params["service"] = args.service
        if args.lines:
            params["lines"] = args.lines
        result = client.request("GET", f"/sites/{args.site_id}/logs", params=params, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "health":
        result = client.request("GET", f"/sites/{args.site_id}/health", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "restart":
        payload = {"services": args.service}
        result = client.request("POST", f"/sites/{args.site_id}/services/restart", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported sites subcommand")


def migrations_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "status":
        result = client.request("GET", "/migrations/status", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "plan":
        payload = {"stores": args.store or [], "dry_run": True}
        result = client.request("POST", "/migrations/plan", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "apply":
        payload = {"stores": args.store or [], "dry_run": args.dry_run, "backup": not args.no_backup}
        result = client.request("POST", "/migrations/apply", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "rollback":
        payload = {"patch_id": args.patch_id, "dry_run": args.dry_run}
        result = client.request("POST", "/migrations/rollback", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "ledger":
        result = client.request("GET", "/migrations/ledger", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported migrations subcommand")


def system_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = args.auth_mode
    if args.subcommand == "upgrade":
        payload = {
            "update_packages": not args.skip_packages,
            "full_upgrade": args.full_upgrade,
            "apply_migrations": not args.skip_migrations,
            "dry_run": args.dry_run,
        }
        result = client.request("POST", "/system/upgrade", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported system subcommand")


def tls_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = args.auth_mode
    if args.subcommand == "renew":
        payload = {
            "domain": args.domain,
            "cert_name": args.cert_name,
            "dry_run": args.dry_run,
        }
        result = client.request("POST", "/tls/renew", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported tls subcommand")


def vms_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "list":
        result = client.request("GET", "/vms", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "get":
        result = client.request("GET", f"/vms/{args.name}", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "create":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name or not args.provider:
                raise FortressCLIError("name and provider are required when not using --json or --json-file")
            payload = {
                "name": args.name,
                "provider": args.provider,
                "cpu_cores": args.cpu,
                "memory_mb": args.memory,
                "disk_gb": args.disk,
            }
            if args.disk_path:
                payload["disk_path"] = args.disk_path
            if args.iso:
                payload["iso_path"] = args.iso
            if args.os_type:
                payload["os_type"] = args.os_type
            if args.vm_dir:
                payload["vm_dir"] = args.vm_dir
            if args.qemu_bin:
                payload["qemu_binary"] = args.qemu_bin
            if args.network_mode:
                payload["network_mode"] = args.network_mode
            if args.bridge:
                payload["bridge_name"] = args.bridge
            if args.ssh_forward_port:
                payload["ssh_forward_port"] = args.ssh_forward_port
            if args.extra_arg:
                payload["extra_args"] = args.extra_arg
            if args.notes:
                payload["notes"] = args.notes
            labels = parse_kv_pairs(args.label)
            if labels:
                payload["labels"] = labels
            if args.ssh_host or args.ssh_user:
                if not args.ssh_host or not args.ssh_user:
                    raise FortressCLIError("ssh-host and ssh-user must be provided together")
                payload["ssh"] = {
                    "host": args.ssh_host,
                    "username": args.ssh_user,
                    "port": args.ssh_port or 22,
                    "key_path": args.ssh_key,
                    "password": args.ssh_password,
                }
        result = client.request("POST", "/vms", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "update":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            payload = {}
            if args.cpu is not None:
                payload["cpu_cores"] = args.cpu
            if args.memory is not None:
                payload["memory_mb"] = args.memory
            if args.disk is not None:
                payload["disk_gb"] = args.disk
            if args.disk_path:
                payload["disk_path"] = args.disk_path
            if args.iso:
                payload["iso_path"] = args.iso
            if args.os_type:
                payload["os_type"] = args.os_type
            if args.vm_dir:
                payload["vm_dir"] = args.vm_dir
            if args.qemu_bin:
                payload["qemu_binary"] = args.qemu_bin
            if args.network_mode:
                payload["network_mode"] = args.network_mode
            if args.bridge:
                payload["bridge_name"] = args.bridge
            if args.ssh_forward_port:
                payload["ssh_forward_port"] = args.ssh_forward_port
            if args.extra_arg:
                payload["extra_args"] = args.extra_arg
            if args.notes is not None:
                payload["notes"] = args.notes
            if args.installed is not None:
                payload["installed"] = args.installed
            labels = parse_kv_pairs(args.label)
            if labels:
                payload["labels"] = labels
            if args.ssh_host or args.ssh_user:
                if not args.ssh_host or not args.ssh_user:
                    raise FortressCLIError("ssh-host and ssh-user must be provided together")
                payload["ssh"] = {
                    "host": args.ssh_host,
                    "username": args.ssh_user,
                    "port": args.ssh_port or 22,
                    "key_path": args.ssh_key,
                    "password": args.ssh_password,
                }
        result = client.request("PUT", f"/vms/{args.name}", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "delete":
        endpoint = f"/vms/{args.name}"
        params = {}
        if args.purge:
            params["purge"] = "true"
        if args.force:
            params["force"] = "true"
        result = client.request("DELETE", endpoint, params=params, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "start":
        payload = {"headless": not args.gui, "use_iso": args.use_iso}
        if args.iso:
            payload["iso_path"] = args.iso
            payload["use_iso"] = True
        result = client.request("POST", f"/vms/{args.name}/start", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "stop":
        payload = {"force": args.force}
        result = client.request("POST", f"/vms/{args.name}/stop", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "status":
        result = client.request("GET", f"/vms/{args.name}/status", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "snapshot":
        if args.action in {"create", "restore", "delete"} and not args.snapshot:
            raise FortressCLIError("snapshot name required for this action")
        if args.action == "list":
            result = client.request("GET", f"/vms/{args.name}/snapshots", auth_override=auth_override)
            print(json.dumps(result, indent=2))
            return
        if args.action == "create":
            payload = {"name": args.snapshot, "description": args.description}
            result = client.request("POST", f"/vms/{args.name}/snapshots", json_body=payload, auth_override=auth_override)
            print(json.dumps(result, indent=2))
            return
        if args.action == "restore":
            result = client.request("POST", f"/vms/{args.name}/snapshots/{args.snapshot}/restore", auth_override=auth_override)
            print(json.dumps(result, indent=2))
            return
        if args.action == "delete":
            result = client.request("DELETE", f"/vms/{args.name}/snapshots/{args.snapshot}", auth_override=auth_override)
            print(json.dumps(result, indent=2))
            return
        raise FortressCLIError("Unsupported snapshot action")
    if args.subcommand == "probe":
        payload = {"save_as": args.save_as} if args.save_as else {}
        result = client.request("POST", f"/vms/{args.name}/probe", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "states":
        result = client.request("GET", f"/vms/{args.name}/states", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "provision":
        payload = {
            "profile": args.profile,
            "branch": args.branch,
            "install_dir": args.install_dir,
            "service_name": args.service_name,
            "fortress_port": args.port,
            "skip_service": args.skip_service,
            "force_reset": args.force_reset,
        }
        if args.repo_url:
            payload["repo_url"] = args.repo_url
        if args.api_key:
            payload["api_key"] = args.api_key
        if args.backup_password:
            payload["backup_password"] = args.backup_password
        if args.ssh_host or args.ssh_user:
            if not args.ssh_host or not args.ssh_user:
                raise FortressCLIError("ssh-host and ssh-user must be provided together")
            payload["ssh"] = {
                "host": args.ssh_host,
                "username": args.ssh_user,
                "port": args.ssh_port or 22,
                "key_path": args.ssh_key,
                "password": args.ssh_password,
            }
        result = client.request("POST", f"/vms/{args.name}/provision", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported vms subcommand")


def hosts_command(args: argparse.Namespace) -> None:
    config = load_config()
    client = FortressClient(config, passphrase=args.passphrase)
    auth_override = getattr(args, "auth_mode", None)
    if args.subcommand == "list":
        result = client.request("GET", "/hosts", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "get":
        result = client.request("GET", f"/hosts/{args.name}", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "create":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            if not args.name:
                raise FortressCLIError("name is required when not using --json or --json-file")
            payload = {"name": args.name}
            if args.os_type:
                payload["os_type"] = args.os_type
            if args.notes:
                payload["notes"] = args.notes
            if args.service_name:
                payload["service_name"] = args.service_name
            if args.installed is not None:
                payload["installed"] = args.installed
            labels = parse_kv_pairs(args.label)
            if labels:
                payload["labels"] = labels
            if args.ssh_host or args.ssh_user:
                if not args.ssh_host or not args.ssh_user:
                    raise FortressCLIError("ssh-host and ssh-user must be provided together")
                payload["ssh"] = {
                    "host": args.ssh_host,
                    "username": args.ssh_user,
                    "port": args.ssh_port or 22,
                    "key_path": args.ssh_key,
                    "password": args.ssh_password,
                }
        result = client.request("POST", "/hosts", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "update":
        payload = load_json_payload(args.json, args.json_file)
        if payload is None:
            payload = {}
            if args.os_type:
                payload["os_type"] = args.os_type
            if args.notes is not None:
                payload["notes"] = args.notes
            if args.service_name:
                payload["service_name"] = args.service_name
            if args.installed is not None:
                payload["installed"] = args.installed
            labels = parse_kv_pairs(args.label)
            if labels:
                payload["labels"] = labels
            if args.ssh_host or args.ssh_user:
                if not args.ssh_host or not args.ssh_user:
                    raise FortressCLIError("ssh-host and ssh-user must be provided together")
                payload["ssh"] = {
                    "host": args.ssh_host,
                    "username": args.ssh_user,
                    "port": args.ssh_port or 22,
                    "key_path": args.ssh_key,
                    "password": args.ssh_password,
                }
        result = client.request("PUT", f"/hosts/{args.name}", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "delete":
        result = client.request("DELETE", f"/hosts/{args.name}", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "provision":
        payload = {
            "profile": args.profile,
            "branch": args.branch,
            "install_dir": args.install_dir,
            "service_name": args.service_name,
            "fortress_port": args.port,
            "skip_service": args.skip_service,
            "force_reset": args.force_reset,
        }
        if args.repo_url:
            payload["repo_url"] = args.repo_url
        if args.api_key:
            payload["api_key"] = args.api_key
        if args.backup_password:
            payload["backup_password"] = args.backup_password
        if args.ssh_host or args.ssh_user:
            if not args.ssh_host or not args.ssh_user:
                raise FortressCLIError("ssh-host and ssh-user must be provided together")
            payload["ssh"] = {
                "host": args.ssh_host,
                "username": args.ssh_user,
                "port": args.ssh_port or 22,
                "key_path": args.ssh_key,
                "password": args.ssh_password,
            }
        result = client.request("POST", f"/hosts/{args.name}/provision", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "probe":
        payload = {"save_as": args.save_as} if args.save_as else {}
        if args.ssh_host or args.ssh_user:
            if not args.ssh_host or not args.ssh_user:
                raise FortressCLIError("ssh-host and ssh-user must be provided together")
            payload["ssh"] = {
                "host": args.ssh_host,
                "username": args.ssh_user,
                "port": args.ssh_port or 22,
                "key_path": args.ssh_key,
                "password": args.ssh_password,
            }
        result = client.request("POST", f"/hosts/{args.name}/probe", json_body=payload, auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    if args.subcommand == "states":
        result = client.request("GET", f"/hosts/{args.name}/states", auth_override=auth_override)
        print(json.dumps(result, indent=2))
        return
    raise FortressCLIError("Unsupported hosts subcommand")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Client utility for Linus' Fortress",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """Examples:
              fortress-cli setup --server https://fortress.local:8443 --api-key <key>
              fortress-cli status
              fortress-cli call POST /packages/install --json '{"packages": ["vim"]}'
              fortress-cli backup decrypt backup-name.enc --output backup.tar.gz"""
        ),
    )
    parser.add_argument("--passphrase", help="Passphrase used to unlock the stored private key")

    subparsers = parser.add_subparsers(dest="command")

    setup_parser = subparsers.add_parser("setup", help="Initial configuration and key generation")
    setup_parser.add_argument("--server", help="Server base URL, e.g. https://host:8443")
    setup_parser.add_argument("--api-key", help="Master API key (store encrypted). Use empty string to clear.")
    setup_parser.add_argument("--user-token", help="Delegated API user token")
    setup_parser.add_argument("--backup-password", help="Backup encryption password")
    setup_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Default authentication preference")
    setup_parser.add_argument("--key-bits", type=int, default=DEFAULT_KEY_BITS)
    setup_parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds")
    setup_parser.add_argument("--force-keys", action="store_true", help="Regenerate RSA keypair even if one exists")
    setup_parser.add_argument("--secure", action="store_true", help="Enforce TLS verification")
    setup_parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (not recommended)")
    setup_parser.add_argument("--key-passphrase", help="Passphrase for new keys (non-interactive environments)")
    setup_parser.set_defaults(func=setup_command)

    info_parser = subparsers.add_parser("info", help="Show current configuration metadata")
    info_parser.set_defaults(func=info_command)

    call_parser = subparsers.add_parser("call", help="Invoke an arbitrary API endpoint")
    call_parser.add_argument("method", help="HTTP method (GET, POST, ...)")
    call_parser.add_argument("endpoint", help="API path, e.g. /status")
    call_parser.add_argument("--json", help="Inline JSON payload")
    call_parser.add_argument("--json-file", help="Path to JSON file used as payload")
    call_parser.add_argument("--params", nargs="*", help="Query string parameters in key=value form")
    call_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    call_parser.set_defaults(func=call_command)

    status_parser = subparsers.add_parser("status", help="Shortcut for GET /status")
    status_parser.set_defaults(func=status_command)

    api_users_parser = subparsers.add_parser("api-users", help="Manage delegated API users")
    api_users_sub = api_users_parser.add_subparsers(dest="subcommand")
    api_users_list = api_users_sub.add_parser("list", help="List API users")
    api_users_list.set_defaults(func=api_users_command)
    api_users_create = api_users_sub.add_parser("create", help="Create a new API user")
    api_users_create.add_argument("username")
    api_users_create.add_argument("--permissions", nargs="+", required=True)
    api_users_create.add_argument("--containers", nargs="*")
    api_users_create.set_defaults(func=api_users_command)
    api_users_delete = api_users_sub.add_parser("delete", help="Delete an API user by token")
    api_users_delete.add_argument("token")
    api_users_delete.set_defaults(func=api_users_command)

    backup_parser = subparsers.add_parser("backup", help="Backup utilities")
    backup_sub = backup_parser.add_subparsers(dest="subcommand")
    backup_list = backup_sub.add_parser("list", help="List encrypted backups")
    backup_list.set_defaults(func=backup_command)
    backup_trigger = backup_sub.add_parser("trigger", help="Trigger encrypted backup for a container")
    backup_trigger.add_argument("container")
    backup_trigger.set_defaults(func=backup_command)
    backup_download = backup_sub.add_parser("download", help="Download encrypted backup")
    backup_download.add_argument("filename")
    backup_download.add_argument("--dest", help="Destination file path")
    backup_download.set_defaults(func=backup_command)
    backup_decrypt = backup_sub.add_parser("decrypt", help="Decrypt encrypted backup locally")
    backup_decrypt.add_argument("input", help="Encrypted .enc file")
    backup_decrypt.add_argument("--output", help="Decrypted output file path")
    backup_decrypt.add_argument("--password", help="Override backup password instead of stored secret")
    backup_decrypt.set_defaults(func=backup_command)

    recipes_parser = subparsers.add_parser("recipes", help="Manage automation recipes")
    recipes_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    recipes_sub = recipes_parser.add_subparsers(dest="subcommand")
    recipes_list = recipes_sub.add_parser("list", help="List recipes")
    recipes_list.set_defaults(func=recipes_command)
    recipes_create = recipes_sub.add_parser("create", help="Create a new recipe")
    recipes_create.add_argument("--name", help="Recipe name (required unless using --json/--json-file)")
    recipes_create.add_argument("--description", help="Recipe description")
    recipes_create.add_argument("--dependency", dest="dependencies", action="append", default=[], help="Dependency recipe name")
    recipes_create.add_argument("--package", dest="packages", action="append", default=[], help="Package to install")
    recipes_create.add_argument("--command", dest="commands", action="append", default=[], help="Command to run")
    recipes_create.add_argument("--param", action="append", default=[], help="Parameter default in key=value form")
    recipes_create.add_argument("--required", action="append", default=[], help="Required parameter name")
    recipes_create.add_argument("--json", help="Inline JSON payload")
    recipes_create.add_argument("--json-file", help="Path to JSON file used as payload")
    recipes_create.set_defaults(func=recipes_command)
    recipes_apply = recipes_sub.add_parser("apply", help="Apply a recipe to host or container")
    recipes_apply.add_argument("name", nargs="?", help="Recipe name (required unless using --json/--json-file)")
    recipes_apply.add_argument("--container", help="Target container name (omit for host)")
    recipes_apply.add_argument("--param", action="append", default=[], help="Parameter override in key=value form")
    recipes_apply.add_argument("--no-deps", action="store_true", help="Skip dependency recipes")
    recipes_apply.add_argument("--no-update-index", action="store_true", help="Skip package index updates")
    recipes_apply.add_argument("--dry-run", action="store_true", help="Only plan the recipe without executing")
    recipes_apply.add_argument("--no-probe", action="store_true", help="Skip post-apply service probes")
    recipes_apply.add_argument("--json", help="Inline JSON payload")
    recipes_apply.add_argument("--json-file", help="Path to JSON file used as payload")
    recipes_apply.set_defaults(func=recipes_command)
    recipes_plan = recipes_sub.add_parser("plan", help="Plan a recipe apply without executing")
    recipes_plan.add_argument("name", nargs="?", help="Recipe name (required unless using --json/--json-file)")
    recipes_plan.add_argument("--container", help="Target container name (omit for host)")
    recipes_plan.add_argument("--param", action="append", default=[], help="Parameter override in key=value form")
    recipes_plan.add_argument("--no-deps", action="store_true", help="Skip dependency recipes")
    recipes_plan.add_argument("--json", help="Inline JSON payload")
    recipes_plan.add_argument("--json-file", help="Path to JSON file used as payload")
    recipes_plan.set_defaults(func=recipes_command)
    recipes_seed = recipes_sub.add_parser("seed", help="Seed curated recipe bundles")
    recipes_seed.add_argument("bundle", nargs="?", help="Bundle name (e.g. lamp)")
    recipes_seed.add_argument("--overwrite", action="store_true", help="Overwrite existing recipes")
    recipes_seed.add_argument("--json", help="Inline JSON payload")
    recipes_seed.add_argument("--json-file", help="Path to JSON file used as payload")
    recipes_seed.set_defaults(func=recipes_command)

    firewall_parser = subparsers.add_parser("firewall", help="Manage host firewall rules")
    firewall_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    firewall_sub = firewall_parser.add_subparsers(dest="subcommand")
    firewall_status = firewall_sub.add_parser("status", help="Show firewall status")
    firewall_status.set_defaults(func=firewall_command)
    firewall_rules = firewall_sub.add_parser("rules", help="List firewall rules")
    firewall_rules.add_argument("--port", type=int)
    firewall_rules.add_argument("--protocol", choices=["tcp", "udp"])
    firewall_rules.add_argument("--source")
    firewall_rules.set_defaults(func=firewall_command)
    firewall_apply = firewall_sub.add_parser("apply", help="Apply firewall rules")
    firewall_apply.add_argument("--rule", action="append", help="Rule spec port/proto[:action][:direction][:source]")
    firewall_apply.add_argument("--mode", choices=["merge", "replace"], default="merge")
    firewall_apply.add_argument("--dry-run", action="store_true")
    firewall_apply.add_argument("--json")
    firewall_apply.add_argument("--json-file")
    firewall_apply.set_defaults(func=firewall_command)
    firewall_rollback = firewall_sub.add_parser("rollback", help="Rollback firewall changes")
    firewall_rollback.add_argument("rollback_id")
    firewall_rollback.add_argument("--dry-run", action="store_true")
    firewall_rollback.set_defaults(func=firewall_command)
    firewall_ddos_status = firewall_sub.add_parser("ddos-status", help="Show anti-DDoS policy")
    firewall_ddos_status.set_defaults(func=firewall_command)
    firewall_ddos = firewall_sub.add_parser("ddos", help="Update anti-DDoS policy")
    firewall_ddos.add_argument("--enable", action="store_true")
    firewall_ddos.add_argument("--disable", action="store_true")
    firewall_ddos.add_argument("--profile")
    firewall_ddos.add_argument("--rate", type=int)
    firewall_ddos.add_argument("--burst", type=int)
    firewall_ddos.add_argument("--conn-limit", type=int, dest="conn_limit")
    firewall_ddos.add_argument("--ban-minutes", type=int)
    firewall_ddos.add_argument("--allow", action="append")
    firewall_ddos.add_argument("--deny", action="append")
    firewall_ddos.add_argument("--ports", type=int, nargs="*")
    firewall_ddos.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    firewall_ddos.add_argument("--dry-run", action="store_true")
    firewall_ddos.add_argument("--json")
    firewall_ddos.add_argument("--json-file")
    firewall_ddos.set_defaults(func=firewall_command)

    sites_parser = subparsers.add_parser("sites", help="Manage websites")
    sites_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    sites_sub = sites_parser.add_subparsers(dest="subcommand")
    sites_list = sites_sub.add_parser("list", help="List sites")
    sites_list.set_defaults(func=sites_command)
    sites_get = sites_sub.add_parser("get", help="Get a site")
    sites_get.add_argument("site_id")
    sites_get.set_defaults(func=sites_command)
    sites_create = sites_sub.add_parser("create", help="Create a site")
    sites_create.add_argument("--name")
    sites_create.add_argument("--domain")
    sites_create.add_argument("--alias", dest="aliases", action="append")
    sites_create.add_argument("--container")
    sites_create.add_argument("--docroot")
    sites_create.add_argument("--php-version")
    sites_create.add_argument("--runtime-user")
    sites_create.add_argument("--runtime-group")
    sites_create.add_argument("--php-ini", action="append", help="php.ini override key=value")
    sites_create.add_argument("--db-engine", choices=["mysql", "mariadb"])
    sites_create.add_argument("--db-name")
    sites_create.add_argument("--db-user")
    sites_create.add_argument("--db-password")
    sites_create.add_argument("--db-root-password")
    sites_create.add_argument("--db-host")
    sites_create.add_argument("--db-port", type=int)
    sites_create.add_argument("--no-db-create", action="store_true")
    sites_create.add_argument("--no-user-create", action="store_true")
    sites_create.add_argument("--listen-address")
    sites_create.add_argument("--listen-port", type=int)
    sites_create.add_argument("--container-port", type=int)
    sites_create.add_argument("--container-interface")
    sites_create.add_argument("--tls-mode", choices=["manual", "disabled", "letsencrypt"])
    sites_create.add_argument("--tls-cert")
    sites_create.add_argument("--tls-key")
    sites_create.add_argument("--tls-chain")
    sites_create.add_argument("--tls-port", type=int)
    sites_create.add_argument("--tls-email")
    sites_create.add_argument("--tls-staging", action="store_true")
    sites_create.add_argument("--tls-cert-name")
    sites_create.add_argument("--json")
    sites_create.add_argument("--json-file")
    sites_create.set_defaults(func=sites_command)
    sites_update = sites_sub.add_parser("update", help="Update a site")
    sites_update.add_argument("site_id")
    sites_update.add_argument("--json")
    sites_update.add_argument("--json-file")
    sites_update.set_defaults(func=sites_command)
    sites_delete = sites_sub.add_parser("delete", help="Delete a site")
    sites_delete.add_argument("site_id")
    sites_delete.set_defaults(func=sites_command)
    sites_deploy = sites_sub.add_parser("deploy", help="Deploy site content")
    sites_deploy.add_argument("site_id")
    sites_deploy.add_argument("--source-type", choices=["git", "archive", "local"])
    sites_deploy.add_argument("--source")
    sites_deploy.add_argument("--ref")
    sites_deploy.add_argument("--subdir")
    sites_deploy.add_argument("--strip-components", type=int, default=0)
    sites_deploy.add_argument("--post", action="append")
    sites_deploy.add_argument("--no-restart", action="store_true")
    sites_deploy.add_argument("--json")
    sites_deploy.add_argument("--json-file")
    sites_deploy.set_defaults(func=sites_command)
    sites_backup = sites_sub.add_parser("backup", help="Backup a site")
    sites_backup.add_argument("site_id")
    sites_backup.add_argument("--no-db", action="store_true")
    sites_backup.add_argument("--label")
    sites_backup.set_defaults(func=sites_command)
    sites_rollback = sites_sub.add_parser("rollback", help="Rollback a site")
    sites_rollback.add_argument("site_id")
    sites_rollback.add_argument("backup_id")
    sites_rollback.add_argument("--no-restart", action="store_true")
    sites_rollback.set_defaults(func=sites_command)
    sites_logs = sites_sub.add_parser("logs", help="Fetch site logs")
    sites_logs.add_argument("site_id")
    sites_logs.add_argument("--service")
    sites_logs.add_argument("--lines", type=int, default=200)
    sites_logs.set_defaults(func=sites_command)
    sites_health = sites_sub.add_parser("health", help="Check site health")
    sites_health.add_argument("site_id")
    sites_health.set_defaults(func=sites_command)
    sites_restart = sites_sub.add_parser("restart", help="Restart site services")
    sites_restart.add_argument("site_id")
    sites_restart.add_argument("--service", action="append")
    sites_restart.set_defaults(func=sites_command)

    migrations_parser = subparsers.add_parser("migrations", help="Manage data migrations")
    migrations_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    migrations_sub = migrations_parser.add_subparsers(dest="subcommand")
    migrations_status = migrations_sub.add_parser("status", help="Show migration status")
    migrations_status.set_defaults(func=migrations_command)
    migrations_plan = migrations_sub.add_parser("plan", help="Plan migrations")
    migrations_plan.add_argument("--store", action="append")
    migrations_plan.set_defaults(func=migrations_command)
    migrations_apply = migrations_sub.add_parser("apply", help="Apply migrations")
    migrations_apply.add_argument("--store", action="append")
    migrations_apply.add_argument("--dry-run", action="store_true")
    migrations_apply.add_argument("--no-backup", action="store_true")
    migrations_apply.set_defaults(func=migrations_command)
    migrations_rollback = migrations_sub.add_parser("rollback", help="Rollback a migration patch")
    migrations_rollback.add_argument("patch_id")
    migrations_rollback.add_argument("--dry-run", action="store_true")
    migrations_rollback.set_defaults(func=migrations_command)
    migrations_ledger = migrations_sub.add_parser("ledger", help="List migration ledger entries")
    migrations_ledger.set_defaults(func=migrations_command)

    system_parser = subparsers.add_parser("system", help="System maintenance tasks")
    system_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    system_sub = system_parser.add_subparsers(dest="subcommand")
    system_upgrade = system_sub.add_parser("upgrade", help="Update host packages and apply migrations")
    system_upgrade.add_argument("--skip-packages", action="store_true", help="Skip package updates")
    system_upgrade.add_argument("--full-upgrade", action="store_true", help="Use full upgrade (dist-upgrade)")
    system_upgrade.add_argument("--skip-migrations", action="store_true", help="Skip migrations apply")
    system_upgrade.add_argument("--dry-run", action="store_true", help="Preview commands without changes")
    system_upgrade.set_defaults(func=system_command)

    tls_parser = subparsers.add_parser("tls", help="TLS certificate maintenance")
    tls_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    tls_sub = tls_parser.add_subparsers(dest="subcommand")
    tls_renew = tls_sub.add_parser("renew", help="Renew Let's Encrypt certificates")
    tls_renew.add_argument("--domain", help="Domain to renew (matches routes/sites)")
    tls_renew.add_argument("--cert-name", help="Explicit certbot cert name")
    tls_renew.add_argument("--dry-run", action="store_true", help="Run certbot renew in dry-run mode")
    tls_renew.set_defaults(func=tls_command)

    vms_parser = subparsers.add_parser("vms", help="Manage VM testing environments")
    vms_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    vms_sub = vms_parser.add_subparsers(dest="subcommand")
    vms_list = vms_sub.add_parser("list", help="List VM records")
    vms_list.set_defaults(func=vms_command)
    vms_get = vms_sub.add_parser("get", help="Get a VM record")
    vms_get.add_argument("name")
    vms_get.set_defaults(func=vms_command)
    vms_create = vms_sub.add_parser("create", help="Create a VM record")
    vms_create.add_argument("--name", help="VM name (required unless using --json/--json-file)")
    vms_create.add_argument("--provider", choices=["qemu", "utm", "virtualbox"], help="VM provider")
    vms_create.add_argument("--cpu", type=int, default=2)
    vms_create.add_argument("--memory", type=int, default=2048)
    vms_create.add_argument("--disk", type=int, default=20)
    vms_create.add_argument("--disk-path")
    vms_create.add_argument("--iso")
    vms_create.add_argument("--os-type")
    vms_create.add_argument("--vm-dir")
    vms_create.add_argument("--qemu-bin")
    vms_create.add_argument("--network-mode", choices=["user", "bridge"])
    vms_create.add_argument("--bridge")
    vms_create.add_argument("--ssh-forward-port", type=int)
    vms_create.add_argument("--extra-arg", action="append", default=[])
    vms_create.add_argument("--label", action="append", default=[], help="Label in key=value form")
    vms_create.add_argument("--notes")
    vms_create.add_argument("--ssh-host")
    vms_create.add_argument("--ssh-user")
    vms_create.add_argument("--ssh-port", type=int)
    vms_create.add_argument("--ssh-key")
    vms_create.add_argument("--ssh-password")
    vms_create.add_argument("--json")
    vms_create.add_argument("--json-file")
    vms_create.set_defaults(func=vms_command)
    vms_update = vms_sub.add_parser("update", help="Update a VM record")
    vms_update.add_argument("name")
    vms_update.add_argument("--cpu", type=int)
    vms_update.add_argument("--memory", type=int)
    vms_update.add_argument("--disk", type=int)
    vms_update.add_argument("--disk-path")
    vms_update.add_argument("--iso")
    vms_update.add_argument("--os-type")
    vms_update.add_argument("--vm-dir")
    vms_update.add_argument("--qemu-bin")
    vms_update.add_argument("--network-mode", choices=["user", "bridge"])
    vms_update.add_argument("--bridge")
    vms_update.add_argument("--ssh-forward-port", type=int)
    vms_update.add_argument("--extra-arg", action="append", default=[])
    vms_update.add_argument("--label", action="append", default=[], help="Label in key=value form")
    vms_update.add_argument("--notes")
    vms_update.add_argument("--installed", action="store_true")
    vms_update.add_argument("--not-installed", dest="installed", action="store_false")
    vms_update.set_defaults(installed=None)
    vms_update.add_argument("--ssh-host")
    vms_update.add_argument("--ssh-user")
    vms_update.add_argument("--ssh-port", type=int)
    vms_update.add_argument("--ssh-key")
    vms_update.add_argument("--ssh-password")
    vms_update.add_argument("--json")
    vms_update.add_argument("--json-file")
    vms_update.set_defaults(func=vms_command)
    vms_delete = vms_sub.add_parser("delete", help="Delete a VM record")
    vms_delete.add_argument("name")
    vms_delete.add_argument("--purge", action="store_true")
    vms_delete.add_argument("--force", action="store_true")
    vms_delete.set_defaults(func=vms_command)
    vms_start = vms_sub.add_parser("start", help="Start a VM")
    vms_start.add_argument("name")
    vms_start.add_argument("--iso")
    vms_start.add_argument("--use-iso", action="store_true")
    vms_start.add_argument("--gui", action="store_true")
    vms_start.set_defaults(func=vms_command)
    vms_stop = vms_sub.add_parser("stop", help="Stop a VM")
    vms_stop.add_argument("name")
    vms_stop.add_argument("--force", action="store_true")
    vms_stop.set_defaults(func=vms_command)
    vms_status = vms_sub.add_parser("status", help="Get VM status")
    vms_status.add_argument("name")
    vms_status.set_defaults(func=vms_command)
    vms_snapshot = vms_sub.add_parser("snapshot", help="Manage VM snapshots")
    vms_snapshot.add_argument("action", choices=["list", "create", "restore", "delete"])
    vms_snapshot.add_argument("name")
    vms_snapshot.add_argument("--snapshot")
    vms_snapshot.add_argument("--description")
    vms_snapshot.set_defaults(func=vms_command)
    vms_probe = vms_sub.add_parser("probe", help="Probe VM over SSH")
    vms_probe.add_argument("name")
    vms_probe.add_argument("--save-as")
    vms_probe.set_defaults(func=vms_command)
    vms_states = vms_sub.add_parser("states", help="List saved VM probe states")
    vms_states.add_argument("name")
    vms_states.set_defaults(func=vms_command)
    vms_provision = vms_sub.add_parser("provision", help="Provision a VM over SSH")
    vms_provision.add_argument("name")
    vms_provision.add_argument("--profile", choices=["ubuntu", "fedora"], default="ubuntu")
    vms_provision.add_argument("--repo-url")
    vms_provision.add_argument("--branch", default="main")
    vms_provision.add_argument("--install-dir", default="/opt/linus-fortress")
    vms_provision.add_argument("--service-name", default="fortress")
    vms_provision.add_argument("--port", type=int, default=8443)
    vms_provision.add_argument("--api-key")
    vms_provision.add_argument("--backup-password")
    vms_provision.add_argument("--skip-service", action="store_true")
    vms_provision.add_argument("--force-reset", action="store_true")
    vms_provision.add_argument("--ssh-host")
    vms_provision.add_argument("--ssh-user")
    vms_provision.add_argument("--ssh-port", type=int)
    vms_provision.add_argument("--ssh-key")
    vms_provision.add_argument("--ssh-password")
    vms_provision.set_defaults(func=vms_command)

    hosts_parser = subparsers.add_parser("hosts", help="Manage remote hosts")
    hosts_parser.add_argument("--auth-mode", choices=["api-key", "user-token"], help="Override stored auth preference")
    hosts_sub = hosts_parser.add_subparsers(dest="subcommand")
    hosts_list = hosts_sub.add_parser("list", help="List host records")
    hosts_list.set_defaults(func=hosts_command)
    hosts_get = hosts_sub.add_parser("get", help="Get a host record")
    hosts_get.add_argument("name")
    hosts_get.set_defaults(func=hosts_command)
    hosts_create = hosts_sub.add_parser("create", help="Create a host record")
    hosts_create.add_argument("--name", help="Host name (required unless using --json/--json-file)")
    hosts_create.add_argument("--os-type")
    hosts_create.add_argument("--notes")
    hosts_create.add_argument("--service-name", default="fortress")
    hosts_create.add_argument("--installed", action="store_true")
    hosts_create.add_argument("--not-installed", dest="installed", action="store_false")
    hosts_create.set_defaults(installed=None)
    hosts_create.add_argument("--label", action="append", default=[], help="Label in key=value form")
    hosts_create.add_argument("--ssh-host")
    hosts_create.add_argument("--ssh-user")
    hosts_create.add_argument("--ssh-port", type=int)
    hosts_create.add_argument("--ssh-key")
    hosts_create.add_argument("--ssh-password")
    hosts_create.add_argument("--json")
    hosts_create.add_argument("--json-file")
    hosts_create.set_defaults(func=hosts_command)
    hosts_update = hosts_sub.add_parser("update", help="Update a host record")
    hosts_update.add_argument("name")
    hosts_update.add_argument("--os-type")
    hosts_update.add_argument("--notes")
    hosts_update.add_argument("--service-name")
    hosts_update.add_argument("--installed", action="store_true")
    hosts_update.add_argument("--not-installed", dest="installed", action="store_false")
    hosts_update.set_defaults(installed=None)
    hosts_update.add_argument("--label", action="append", default=[], help="Label in key=value form")
    hosts_update.add_argument("--ssh-host")
    hosts_update.add_argument("--ssh-user")
    hosts_update.add_argument("--ssh-port", type=int)
    hosts_update.add_argument("--ssh-key")
    hosts_update.add_argument("--ssh-password")
    hosts_update.add_argument("--json")
    hosts_update.add_argument("--json-file")
    hosts_update.set_defaults(func=hosts_command)
    hosts_delete = hosts_sub.add_parser("delete", help="Delete a host record")
    hosts_delete.add_argument("name")
    hosts_delete.set_defaults(func=hosts_command)
    hosts_provision = hosts_sub.add_parser("provision", help="Provision a host over SSH")
    hosts_provision.add_argument("name")
    hosts_provision.add_argument("--profile", choices=["ubuntu", "fedora"], default="ubuntu")
    hosts_provision.add_argument("--repo-url")
    hosts_provision.add_argument("--branch", default="main")
    hosts_provision.add_argument("--install-dir", default="/opt/linus-fortress")
    hosts_provision.add_argument("--service-name", default="fortress")
    hosts_provision.add_argument("--port", type=int, default=8443)
    hosts_provision.add_argument("--api-key")
    hosts_provision.add_argument("--backup-password")
    hosts_provision.add_argument("--skip-service", action="store_true")
    hosts_provision.add_argument("--force-reset", action="store_true")
    hosts_provision.add_argument("--ssh-host")
    hosts_provision.add_argument("--ssh-user")
    hosts_provision.add_argument("--ssh-port", type=int)
    hosts_provision.add_argument("--ssh-key")
    hosts_provision.add_argument("--ssh-password")
    hosts_provision.set_defaults(func=hosts_command)
    hosts_probe = hosts_sub.add_parser("probe", help="Probe a host over SSH")
    hosts_probe.add_argument("name")
    hosts_probe.add_argument("--save-as")
    hosts_probe.add_argument("--ssh-host")
    hosts_probe.add_argument("--ssh-user")
    hosts_probe.add_argument("--ssh-port", type=int)
    hosts_probe.add_argument("--ssh-key")
    hosts_probe.add_argument("--ssh-password")
    hosts_probe.set_defaults(func=hosts_command)
    hosts_states = hosts_sub.add_parser("states", help="List saved host probe states")
    hosts_states.add_argument("name")
    hosts_states.set_defaults(func=hosts_command)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    try:
        args.func(args)
        return 0
    except FortressCLIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
