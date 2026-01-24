import os
import re
from typing import Dict, List, Optional

from fastapi import HTTPException

from fortress.system import run_command


DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
PROXY_HEADERS = [
    "        proxy_set_header Host $host;",
    "        proxy_set_header X-Real-IP $remote_addr;",
    "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
    "        proxy_set_header X-Forwarded-Proto $scheme;",
]


def _validate_domain_name(domain: str) -> None:
    if not domain or not DOMAIN_PATTERN.fullmatch(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    if domain.startswith(("-", ".")) or domain.endswith(("-", ".")) or ".." in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    labels = domain.split(".")
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            raise HTTPException(status_code=400, detail="Invalid domain format")


def validate_domain(domain: str) -> None:
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    if domain.startswith("*."):
        suffix = domain[2:]
        if not suffix or "." not in suffix:
            raise HTTPException(status_code=400, detail="Invalid domain format")
        _validate_domain_name(suffix)
        return
    _validate_domain_name(domain)


def normalize_domains(primary: str, aliases: Optional[List[str]] = None) -> List[str]:
    domains: List[str] = []
    seen = set()

    def add(value: str) -> None:
        if not value:
            return
        validate_domain(value)
        if value not in seen:
            seen.add(value)
            domains.append(value)

    add(primary)
    if aliases:
        for alias in aliases:
            add(alias)
    return domains


def _validate_path(label: str, path: str) -> None:
    if not path:
        raise HTTPException(status_code=400, detail=f"{label} is required for TLS")
    if not os.path.isabs(path):
        raise HTTPException(status_code=400, detail=f"{label} must be an absolute path")
    if not os.path.isfile(path):
        raise HTTPException(status_code=400, detail=f"{label} not found at {path}")


def validate_tls_paths(cert_path: str, key_path: str, chain_path: Optional[str]) -> None:
    _validate_path("cert_path", cert_path)
    _validate_path("key_path", key_path)
    if chain_path:
        _validate_path("chain_path", chain_path)


def _build_proxy_location(upstream_url: str) -> List[str]:
    lines = [
        "    location / {",
        f"        proxy_pass {upstream_url};",
    ]
    lines.extend(PROXY_HEADERS)
    lines.append("    }")
    return lines


def _render_server_block(lines: List[str]) -> str:
    return "\n".join(["server {"] + lines + ["}"])


def build_nginx_proxy_config(
    domain: str,
    listen_address: str,
    listen_port: int,
    upstream_host: str,
    upstream_port: int,
    tls: Optional[Dict[str, object]] = None,
    upstream_scheme: str = "http",
    domains: Optional[List[str]] = None,
) -> str:
    if upstream_scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="upstream_scheme must be http or https")

    upstream_url = f"{upstream_scheme}://{upstream_host}:{upstream_port}"
    server_names = normalize_domains(domain, domains)
    server_name = f"    server_name {' '.join(server_names)};"
    http_lines: List[str] = [
        f"    listen {listen_address}:{listen_port};",
        server_name,
    ]
    redirect_http = False
    if tls:
        redirect_http = bool(tls.get("redirect_http", True))
    if redirect_http:
        http_lines.append("    return 301 https://$host$request_uri;")
    else:
        http_lines.extend(_build_proxy_location(upstream_url))
    blocks = [_render_server_block(http_lines)]

    if tls:
        tls_port = int(tls.get("listen_port", 443))
        tls_lines: List[str] = [
            f"    listen {listen_address}:{tls_port} ssl;",
            server_name,
            f"    ssl_certificate {tls['cert_path']};",
            f"    ssl_certificate_key {tls['key_path']};",
        ]
        chain_path = tls.get("chain_path")
        if chain_path:
            tls_lines.append(f"    ssl_trusted_certificate {chain_path};")
        tls_lines.extend(_build_proxy_location(upstream_url))
        blocks.append(_render_server_block(tls_lines))

    return "\n\n".join(blocks).rstrip() + "\n"


def write_nginx_config(domain: str, content: str, sites_available_dir: str) -> str:
    os.makedirs(sites_available_dir, exist_ok=True)
    config_path = os.path.join(sites_available_dir, domain)
    with open(config_path, "w") as fh:
        fh.write(content)
    return config_path


def ensure_nginx_site(domain: str, config_path: str, sites_enabled_dir: str) -> str:
    os.makedirs(sites_enabled_dir, exist_ok=True)
    symlink_path = os.path.join(sites_enabled_dir, domain)
    if not os.path.exists(symlink_path):
        os.symlink(config_path, symlink_path)
    return symlink_path


def remove_nginx_site(domain: str, config_path: str, sites_enabled_dir: str) -> None:
    symlink_path = os.path.join(sites_enabled_dir, domain)
    if os.path.islink(symlink_path) or os.path.exists(symlink_path):
        os.unlink(symlink_path)
    if os.path.exists(config_path):
        os.remove(config_path)


def test_nginx_config() -> None:
    run_command(["nginx", "-t"])


def reload_nginx() -> None:
    run_command(["systemctl", "reload", "nginx"])
