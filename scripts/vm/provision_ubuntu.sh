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

apt-get update -y
apt-get install -y python3 python3-venv python3-pip git openssl

mkdir -p /var/lib/fortress /etc/fortress/ssl

if [ ! -d "${INSTALL_DIR}/.git" ]; then
  if [ -z "${REPO_URL}" ]; then
    echo "REPO_URL is required to clone repository." >&2
    exit 2
  fi
  git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${INSTALL_DIR}"
else
  git -C "${INSTALL_DIR}" fetch --depth 1 origin "${BRANCH}"
  git -C "${INSTALL_DIR}" checkout "${BRANCH}"
  git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
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
