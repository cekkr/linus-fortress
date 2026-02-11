#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi

REPO_URL=${REPO_URL:-}
BRANCH=${BRANCH:-main}
INSTALL_DIR=${INSTALL_DIR:-/opt/linus-fortress}
SERVICE_NAME=${SERVICE_NAME:-fortress}
FORTRESS_HOST_PORT=${FORTRESS_HOST_PORT:-8443}
FORTRESS_API_KEY=${FORTRESS_API_KEY:-}
FORTRESS_BACKUP_PASSWORD=${FORTRESS_BACKUP_PASSWORD:-}
SKIP_SERVICE=${SKIP_SERVICE:-}
FORCE_RESET=${FORCE_RESET:-}

apt-get update -y
apt-get install -y python3 python3-venv python3-pip git openssl lxd lxc

select_lxd_storage_pool() {
  local raw=""
  raw=$(lxc storage list --format json 2>/dev/null || true)
  if [ -z "${raw}" ]; then
    printf ''
    return 0
  fi
  FORTRESS_STORAGE_POOLS_JSON="${raw}" python3 - <<'PY'
import json
import os

raw = os.environ.get("FORTRESS_STORAGE_POOLS_JSON", "")
if not raw:
    raise SystemExit(0)
try:
    payload = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(0)

names = []
seen = set()

def add(value):
    if not isinstance(value, str):
        return
    normalized = value.strip()
    lowered = normalized.lower()
    if not normalized or lowered in seen:
        return
    seen.add(lowered)
    names.append(normalized)

if isinstance(payload, list):
    for item in payload:
        if isinstance(item, dict):
            add(item.get("name") or item.get("Name"))
        else:
            add(item)
elif isinstance(payload, dict):
    for key, value in payload.items():
        if isinstance(value, dict):
            add(value.get("name") or value.get("Name"))
        add(key)
elif isinstance(payload, str):
    add(payload)

for preferred in ("default", "local"):
    for name in names:
        if name.lower() == preferred:
            print(name)
            raise SystemExit(0)

if names:
    print(names[0])
PY
}

find_default_profile_root_device() {
  local device=""
  while IFS= read -r device; do
    device=$(printf '%s' "${device}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "${device}" ] && continue
    local dtype=""
    local dpath=""
    dtype=$(lxc profile device get default "${device}" type 2>/dev/null || true)
    dpath=$(lxc profile device get default "${device}" path 2>/dev/null || true)
    if [ "${dtype}" = "disk" ] && [ "${dpath}" = "/" ]; then
      printf '%s' "${device}"
      return 0
    fi
  done < <(lxc profile device list default 2>/dev/null || true)
  return 1
}

ensure_lxd_ready() {
  if ! command -v lxc >/dev/null 2>&1 || ! command -v lxd >/dev/null 2>&1; then
    echo "Warning: lxc/lxd not installed; container APIs may be unavailable." >&2
    return 0
  fi
  if ! lxc info >/dev/null 2>&1; then
    echo "Initializing LXD with lxd init --auto"
    if ! lxd init --auto >/dev/null 2>&1; then
      echo "Warning: automatic lxd init failed; continue setup but container APIs may fail." >&2
      return 0
    fi
  fi
  local pool=""
  pool=$(select_lxd_storage_pool)
  if [ -z "${pool}" ]; then
    if lxc storage create default dir >/dev/null 2>&1; then
      pool="default"
    else
      echo "Warning: no LXD storage pool found; container launch may fail." >&2
      return 0
    fi
  fi
  if ! lxc profile show default >/dev/null 2>&1; then
    lxc profile create default >/dev/null 2>&1 || true
  fi
  local root_device=""
  root_device=$(find_default_profile_root_device || true)
  if [ -z "${root_device}" ]; then
    lxc profile device add default root disk path=/ pool="${pool}" >/dev/null 2>&1 || true
    return 0
  fi
  local root_pool=""
  root_pool=$(lxc profile device get default "${root_device}" pool 2>/dev/null || true)
  if [ -z "${root_pool}" ]; then
    lxc profile device set default "${root_device}" pool "${pool}" >/dev/null 2>&1 || true
  fi
}

mkdir -p /var/lib/fortress /etc/fortress/ssl
ensure_lxd_ready

if [ ! -d "${INSTALL_DIR}/.git" ]; then
  if [ -z "${REPO_URL}" ]; then
    echo "REPO_URL is required to clone repository." >&2
    exit 2
  fi
  git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
else
  git -C "${INSTALL_DIR}" fetch --depth 1 origin "${BRANCH}"
  git -C "${INSTALL_DIR}" checkout "${BRANCH}"
  if git -C "${INSTALL_DIR}" diff --quiet; then
    git -C "${INSTALL_DIR}" pull --ff-only origin "${BRANCH}"
  else
    if [ -n "${FORCE_RESET}" ]; then
      git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
    else
      echo "Local changes detected in ${INSTALL_DIR}. Set FORCE_RESET=1 to overwrite." >&2
      exit 3
    fi
  fi
fi

python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

if [ ! -f /etc/fortress/ssl/key.pem ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=fortress" \
    -keyout /etc/fortress/ssl/key.pem -out /etc/fortress/ssl/cert.pem
fi

if [ -n "${SKIP_SERVICE}" ]; then
  echo "SKIP_SERVICE set; skipping systemd setup."
  exit 0
fi

if ! id fortress >/dev/null 2>&1; then
  useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin fortress
fi

chown -R fortress:fortress "${INSTALL_DIR}" /var/lib/fortress /etc/fortress

{
  if [ -n "${FORTRESS_API_KEY}" ]; then
    echo "FORTRESS_API_KEY=${FORTRESS_API_KEY}"
  fi
  if [ -n "${FORTRESS_BACKUP_PASSWORD}" ]; then
    echo "FORTRESS_BACKUP_PASSWORD=${FORTRESS_BACKUP_PASSWORD}"
  fi
  echo "FORTRESS_HOST_PORT=${FORTRESS_HOST_PORT}"
} > /etc/fortress/fortress.env

chmod 640 /etc/fortress/fortress.env

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Linus Fortress API
After=network.target

[Service]
Type=simple
User=fortress
Group=fortress
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=/etc/fortress/fortress.env
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/py/server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"
