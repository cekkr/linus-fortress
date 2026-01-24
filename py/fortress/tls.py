import os
import shutil
from typing import Dict, List, Optional

from fastapi import HTTPException

from fortress.routing import validate_domain
from fortress.system import run_command


LE_LIVE_DIR = "/etc/letsencrypt/live"


def ensure_certbot_available() -> None:
    if shutil.which("certbot"):
        return
    raise HTTPException(status_code=500, detail="certbot not installed; install certbot to use Let's Encrypt")


def ensure_acme_challenge_dir(webroot: str) -> str:
    if not webroot:
        raise HTTPException(status_code=500, detail="ACME challenge directory not configured")
    if not os.path.isabs(webroot):
        raise HTTPException(status_code=500, detail="ACME challenge directory must be an absolute path")
    challenge_dir = os.path.join(webroot, ".well-known", "acme-challenge")
    os.makedirs(challenge_dir, exist_ok=True)
    return webroot


def build_certificate_paths(cert_name: str) -> Dict[str, str]:
    base = os.path.join(LE_LIVE_DIR, cert_name)
    return {
        "cert_path": os.path.join(base, "fullchain.pem"),
        "key_path": os.path.join(base, "privkey.pem"),
        "chain_path": os.path.join(base, "chain.pem"),
    }


def _unique_domains(domains: List[str]) -> List[str]:
    seen = set()
    unique: List[str] = []
    for domain in domains:
        if domain not in seen:
            seen.add(domain)
            unique.append(domain)
    return unique


def validate_letsencrypt_domains(domains: List[str]) -> List[str]:
    if not domains:
        raise HTTPException(status_code=400, detail="At least one domain is required for Let's Encrypt")
    normalized = _unique_domains([domain.strip() for domain in domains if domain and domain.strip()])
    if not normalized:
        raise HTTPException(status_code=400, detail="At least one domain is required for Let's Encrypt")
    for domain in normalized:
        validate_domain(domain)
        if domain.startswith("*."):
            raise HTTPException(status_code=400, detail="Wildcard domains require DNS-01 validation")
    return normalized


def issue_letsencrypt_certificate(
    domains: List[str],
    email: str,
    webroot: str,
    staging: bool = False,
    cert_name: Optional[str] = None,
    dry_run: bool = False,
) -> Dict[str, str]:
    ensure_certbot_available()
    ensure_acme_challenge_dir(webroot)
    if not email or not email.strip():
        raise HTTPException(status_code=400, detail="Let's Encrypt email is required")
    normalized = validate_letsencrypt_domains(domains)
    cert_name = cert_name or normalized[0]
    cmd = [
        "certbot",
        "certonly",
        "--webroot",
        "-w",
        webroot,
        "--agree-tos",
        "--non-interactive",
        "--keep-until-expiring",
        "--expand",
        "--preferred-challenges",
        "http",
        "--email",
        email.strip(),
        "--cert-name",
        cert_name,
    ]
    if staging:
        cmd.append("--staging")
    if dry_run:
        cmd.append("--dry-run")
    for domain in normalized:
        cmd.extend(["-d", domain])
    run_command(cmd)
    paths = build_certificate_paths(cert_name)
    if not dry_run:
        for key in ("cert_path", "key_path"):
            path = paths[key]
            if not os.path.isfile(path):
                raise HTTPException(status_code=500, detail=f"Let's Encrypt output missing {key} at {path}")
    return paths


def renew_letsencrypt(cert_name: Optional[str] = None, dry_run: bool = False) -> str:
    ensure_certbot_available()
    cmd = ["certbot", "renew"]
    if cert_name:
        cmd.extend(["--cert-name", cert_name])
    if dry_run:
        cmd.append("--dry-run")
    return run_command(cmd)
