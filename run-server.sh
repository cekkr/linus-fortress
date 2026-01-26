#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/etc/fortress/fortress.env"
SSL_DIR="/etc/fortress/ssl"
STATE_DIR="/var/lib/fortress"
LOG_FILE="/var/log/fortress.log"
API_LOG="/var/log/fortress-api.log"
UI_LOG="/var/log/fortress-ui.log"
SELF_SIGNED_MARKER="${SSL_DIR}/self-signed"
ACME_DIR="${STATE_DIR}/acme-challenges"
VENV_DIR="${ROOT_DIR}/.venv"
UI_DIR="${ROOT_DIR}/ui"

RUN_MODE_ARG=""
UI_ENABLED_ARG=""
FORCE_SETUP=""

usage() {
  cat <<'EOF'
Usage: ./run-server.sh [options]

Options:
  --mode foreground|screen|service  Choose how to run the server.
  --foreground                      Shortcut for --mode foreground.
  --screen                          Shortcut for --mode screen.
  --service                         Shortcut for --mode service.
  --skip-ui                         Do not start the admin UI server.
  --enable-ui                       Force-start the admin UI server.
  --configure                       Re-run first-run prompts.
  -h, --help                        Show this help.
EOF
}

log() {
  echo "[fortress] $*"
}

fail() {
  echo "[fortress] Error: $*" >&2
  exit 1
}

prompt_yes_no() {
  local prompt=$1
  local default=${2:-Y}
  local answer=""
  local suffix="[Y/n]"
  if [[ "$default" =~ ^[Nn]$ ]]; then
    suffix="[y/N]"
  fi
  read -r -p "${prompt} ${suffix} " answer || true
  if [[ -z "$answer" ]]; then
    answer="$default"
  fi
  case "$answer" in
    y|Y|yes|YES) return 0 ;;
    n|N|no|NO) return 1 ;;
    *) return 1 ;;
  esac
}

prompt_default() {
  local prompt=$1
  local default=$2
  local answer=""
  read -r -p "${prompt} [${default}]: " answer || true
  if [[ -z "$answer" ]]; then
    answer="$default"
  fi
  printf '%s' "$answer"
}

prompt_secret() {
  local prompt=$1
  local answer=""
  read -r -s -p "${prompt}: " answer || true
  echo
  printf '%s' "$answer"
}

generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return 0
  fi
  python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
}

generate_password() {
  local length=$((24 + RANDOM % 9))
  local password=""
  while true; do
    if command -v openssl >/dev/null 2>&1; then
      password=$(openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c "${length}")
    else
      password=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${length}")
    fi
    if [[ ${#password} -ge ${length} && "$password" =~ [A-Z] && "$password" =~ [a-z] && "$password" =~ [0-9] ]]; then
      break
    fi
  done
  printf '%s' "${password:0:length}"
}

escape_env_value() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '%s' "$value"
}

write_env_line() {
  local key=$1
  local value=$2
  printf '%s="%s"\n' "$key" "$(escape_env_value "$value")"
}

detect_os_id() {
  if [[ -f /etc/os-release ]]; then
    ( . /etc/os-release && printf '%s' "${ID:-}" )
  fi
}

maybe_add_snap_path() {
  if [[ -d /snap/bin && ":${PATH}:" != *":/snap/bin:"* ]]; then
    export PATH="/snap/bin:${PATH}"
  fi
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
    return 0
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "yum"
    return 0
  fi
  return 1
}

install_packages() {
  local manager=$1
  shift
  local packages=("$@")
  if [[ ${#packages[@]} -eq 0 ]]; then
    return 0
  fi
  if [[ "$manager" == "apt" ]]; then
    apt-get update -y
    local rc=0
    set +e
    apt-get install -y "${packages[@]}"
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      fail "apt-get install failed. Try 'apt-get -y --fix-broken install' and re-run."
    fi
  elif [[ "$manager" == "dnf" ]]; then
    local rc=0
    set +e
    dnf -y install "${packages[@]}"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      log "dnf install failed; retrying with --nobest."
      dnf -y --nobest install "${packages[@]}"
      rc=$?
    fi
    if [[ $rc -ne 0 ]]; then
      log "dnf install failed; retrying with --skip-broken."
      dnf -y --skip-broken install "${packages[@]}"
      rc=$?
    fi
    set -e
    return $rc
  else
    local rc=0
    set +e
    yum -y install "${packages[@]}"
    rc=$?
    if [[ $rc -ne 0 ]]; then
      log "yum install failed; retrying with --nobest."
      yum -y --nobest install "${packages[@]}"
      rc=$?
    fi
    if [[ $rc -ne 0 ]]; then
      log "yum install failed; retrying with --skip-broken."
      yum -y --skip-broken install "${packages[@]}"
      rc=$?
    fi
    set -e
    return $rc
  fi
}

package_installed() {
  local manager=$1
  local package=$2
  if [[ "$manager" == "apt" ]]; then
    dpkg -s "$package" >/dev/null 2>&1
  else
    rpm -q "$package" >/dev/null 2>&1
  fi
}

ensure_packages_installed() {
  local manager=$1
  shift
  local packages=("$@")
  local missing=()
  local package=""
  for package in "${packages[@]}"; do
    if ! package_installed "$manager" "$package"; then
      missing+=("$package")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log "Installing missing packages: ${missing[*]}"
    install_packages "$manager" "${missing[@]}"
    local still_missing=()
    for package in "${missing[@]}"; do
      if ! package_installed "$manager" "$package"; then
        still_missing+=("$package")
      fi
    done
    if [[ ${#still_missing[@]} -gt 0 ]]; then
      fail "Unable to install required packages: ${still_missing[*]}"
    fi
  fi
}

ensure_epel_release() {
  local manager=$1
  if [[ "$manager" != "dnf" && "$manager" != "yum" ]]; then
    return 0
  fi
  if rpm -q epel-release >/dev/null 2>&1; then
    return 0
  fi
  log "Installing EPEL repository."
  install_packages "$manager" epel-release
}

ensure_snapd() {
  local manager=$1
  if command -v snap >/dev/null 2>&1; then
    maybe_add_snap_path
    return 0
  fi
  ensure_epel_release "$manager"
  log "Installing snapd for LXD."
  ensure_packages_installed "$manager" snapd
  systemctl enable --now snapd.socket
  if [[ ! -e /snap ]]; then
    ln -s /var/lib/snapd/snap /snap
  fi
  maybe_add_snap_path
}

ensure_snap_lxd() {
  if command -v lxc >/dev/null 2>&1 && command -v lxd >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v snap >/dev/null 2>&1; then
    fail "snap is not available; cannot install LXD via snap."
  fi
  if snap list lxd >/dev/null 2>&1; then
    maybe_add_snap_path
    return 0
  fi
  log "Installing LXD via snap."
  snap install lxd
  maybe_add_snap_path
  if ! command -v lxc >/dev/null 2>&1; then
    log "Warning: lxc not found in PATH; log out and back in to refresh snap paths."
  fi
}

ensure_root() {
  if [[ $(id -u) -eq 0 ]]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  fail "Run as root or install sudo."
}

ensure_dirs() {
  mkdir -p "${SSL_DIR}" "${STATE_DIR}" "${STATE_DIR}/backups" "${STATE_DIR}/shares" "${ACME_DIR}"
  touch "${LOG_FILE}" "${API_LOG}" "${UI_LOG}"
}

ensure_tls() {
  if [[ -f "${SSL_DIR}/key.pem" && -f "${SSL_DIR}/cert.pem" ]]; then
    return 0
  fi
  log "Generating self-signed TLS certificate under ${SSL_DIR}."
  openssl req -x509 -nodes -newkey rsa:2048 -days 365 -subj "/CN=fortress" \
    -keyout "${SSL_DIR}/key.pem" -out "${SSL_DIR}/cert.pem"
  touch "${SELF_SIGNED_MARKER}"
}

ensure_python_venv_support() {
  local manager=$1
  if python3 - <<'PY' >/dev/null 2>&1
import venv
PY
  then
    return 0
  fi
  if [[ "$manager" == "apt" ]]; then
    ensure_packages_installed "$manager" python3-venv
  else
    ensure_packages_installed "$manager" python3-virtualenv
  fi
  if ! python3 - <<'PY' >/dev/null 2>&1
import venv
PY
  then
    fail "python3 venv module is unavailable; install python3-venv or python3-virtualenv."
  fi
}

ensure_python_env() {
  if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip
  "${VENV_DIR}/bin/pip" install -r "${ROOT_DIR}/requirements.txt"
}

ensure_node_deps() {
  if [[ ! -d "${UI_DIR}" ]]; then
    return 0
  fi
  (cd "${UI_DIR}" && npm install)
}

ensure_certbot() {
  local manager=$1
  if command -v certbot >/dev/null 2>&1; then
    return 0
  fi
  log "Attempting to install certbot for Let's Encrypt."
  set +e
  if [[ "$manager" == "apt" ]]; then
    apt-get update -y
    apt-get install -y certbot
  elif [[ "$manager" == "dnf" ]]; then
    dnf -y install epel-release
    dnf -y install certbot
  else
    yum -y install epel-release
    yum -y install certbot
  fi
  set -e
  if ! command -v certbot >/dev/null 2>&1; then
    log "Warning: certbot install failed. Install certbot manually to enable Let's Encrypt."
  fi
}

ensure_lxd_initialized() {
  local lxc_bin=""
  local lxd_bin=""
  lxc_bin=$(command -v lxc || true)
  lxd_bin=$(command -v lxd || true)
  if [[ -z "${lxc_bin}" && -x /snap/bin/lxc ]]; then
    lxc_bin="/snap/bin/lxc"
  fi
  if [[ -z "${lxd_bin}" && -x /snap/bin/lxd ]]; then
    lxd_bin="/snap/bin/lxd"
  fi
  if [[ -z "${lxc_bin}" ]]; then
    log "lxc not found; container features will be unavailable."
    return 0
  fi
  if "${lxc_bin}" info >/dev/null 2>&1; then
    return 0
  fi
  log "LXD is installed but not initialized."
  if [[ -z "${lxd_bin}" ]]; then
    log "lxd command not found; cannot run lxd init."
    return 0
  fi
  if prompt_yes_no "Run 'lxd init --auto' now?" "N"; then
    "${lxd_bin}" init --auto
  else
    log "Skipping LXD init. Container APIs will fail until LXD is initialized."
  fi
}

is_loopback_host() {
  local host=$1
  case "${host}" in
    127.0.0.1|localhost|::1) return 0 ;;
    *) return 1 ;;
  esac
}

ensure_firewalld_port_open() {
  local port=$1
  local zone=$2
  if firewall-cmd --zone="${zone}" --query-port="${port}/tcp" >/dev/null 2>&1; then
    return 0
  fi
  if ! prompt_yes_no "Open firewall port ${port}/tcp in firewalld zone ${zone}?" "Y"; then
    log "Skipping firewalld port ${port}/tcp."
    return 0
  fi
  set +e
  firewall-cmd --zone="${zone}" --add-port="${port}/tcp"
  firewall-cmd --zone="${zone}" --permanent --add-port="${port}/tcp"
  firewall-cmd --reload
  set -e
}

maybe_open_ui_firewall() {
  local ui_host=$1
  local ui_port=$2
  if ! command -v firewall-cmd >/dev/null 2>&1; then
    return 0
  fi
  if ! firewall-cmd --state >/dev/null 2>&1; then
    return 0
  fi
  if is_loopback_host "${ui_host}"; then
    return 0
  fi
  local zone
  zone=$(firewall-cmd --get-default-zone 2>/dev/null || true)
  if [[ -z "${zone}" ]]; then
    zone="public"
  fi
  ensure_firewalld_port_open "${ui_port}" "${zone}"
}

ensure_sshd_setting() {
  local key=$1
  local value=$2
  local config="/etc/ssh/sshd_config"
  if [[ ! -f "${config}" ]]; then
    fail "Missing ${config}; cannot update SSH settings."
  fi
  if grep -qE "^[#[:space:]]*${key}\\b" "${config}"; then
    sed -i -E "s|^[#[:space:]]*${key}\\b.*|${key} ${value}|" "${config}"
  else
    printf '\n%s %s\n' "${key}" "${value}" >> "${config}"
  fi
}

create_admin_user() {
  local username=$1
  local password=$2
  if id -u "${username}" >/dev/null 2>&1; then
    log "User ${username} already exists; ensuring sudo access."
  else
    if command -v adduser >/dev/null 2>&1; then
      adduser "${username}"
    else
      useradd -m "${username}"
    fi
  fi
  usermod -aG wheel "${username}"
  if [[ -n "${password}" ]]; then
    printf '%s:%s\n' "${username}" "${password}" | chpasswd
  fi
}

maybe_harden_ssh() {
  local username=""
  local password=""
  local user_exists="0"
  local ssh_changed="0"
  if ! prompt_yes_no "Apply AlmaLinux SSH hardening (create sudo user + optional root login disable)?" "N"; then
    return 0
  fi
  username=$(prompt_default "SSH admin username" "adminuser")
  if [[ "${username}" == "root" ]]; then
    fail "Refusing to use root as the SSH admin user."
  fi
  if id -u "${username}" >/dev/null 2>&1; then
    user_exists="1"
  fi
  if [[ "${user_exists}" == "1" ]]; then
    log "User ${username} already exists."
    if prompt_yes_no "Reset password for ${username}?" "N"; then
      password=$(prompt_secret "Password for ${username} (leave blank to auto-generate)")
      if [[ -z "${password}" ]]; then
        password=$(generate_password)
        log "Generated password for ${username}: ${password}"
      fi
    fi
  else
    password=$(prompt_secret "Password for ${username} (leave blank to auto-generate)")
    if [[ -z "${password}" ]]; then
      password=$(generate_password)
      log "Generated password for ${username}: ${password}"
    fi
  fi
  create_admin_user "${username}" "${password}"
  if getent group lxd >/dev/null 2>&1; then
    if prompt_yes_no "Add ${username} to the lxd group?" "Y"; then
      usermod -aG lxd "${username}"
    fi
  fi
  if prompt_yes_no "Disable root SSH login now?" "Y"; then
    ensure_sshd_setting "PermitRootLogin" "no"
    ssh_changed="1"
  fi
  if prompt_yes_no "Disable SSH password authentication (requires SSH keys)?" "N"; then
    ensure_sshd_setting "PasswordAuthentication" "no"
    ssh_changed="1"
  fi
  if [[ "${ssh_changed}" == "1" ]]; then
    systemctl restart sshd
    log "SSH configuration updated. Test login as ${username} before ending this session."
  fi
}

start_ui_nohup() {
  if [[ ! -d "${UI_DIR}" ]]; then
    log "UI directory not found; skipping admin UI."
    return 0
  fi
  local node_bin
  node_bin=$(command -v node || true)
  if [[ -z "$node_bin" ]]; then
    fail "node not found; install Node.js or disable the UI."
  fi
  log "Starting admin UI in background (logs: ${UI_LOG})."
  nohup "${node_bin}" "${UI_DIR}/server.js" >> "${UI_LOG}" 2>&1 &
}

start_api_foreground() {
  log "Starting Fortress API server in foreground."
  exec "${VENV_DIR}/bin/python" "${ROOT_DIR}/py/server.py"
}

start_screen_sessions() {
  if ! command -v screen >/dev/null 2>&1; then
    fail "screen not installed; rerun with --mode foreground or install screen."
  fi
  local path_prefix=""
  if [[ -d /snap/bin ]]; then
    path_prefix="export PATH=\"/snap/bin:\\$PATH\"; "
  fi
  local node_bin=""
  if [[ "${FORTRESS_UI_ENABLED:-}" == "1" ]]; then
    node_bin=$(command -v node || true)
    if [[ -z "$node_bin" ]]; then
      fail "node not found; install Node.js or disable the UI."
    fi
  fi
  if screen -list | grep -q "fortress-api"; then
    log "Screen session fortress-api already running; skipping."
  else
    screen -dmS fortress-api bash -lc "${path_prefix}cd \"${ROOT_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && exec \"${VENV_DIR}/bin/python\" \"${ROOT_DIR}/py/server.py\""
  fi
  if [[ "${FORTRESS_UI_ENABLED:-}" == "1" ]]; then
    if screen -list | grep -q "fortress-ui"; then
      log "Screen session fortress-ui already running; skipping."
    else
      screen -dmS fortress-ui bash -lc "${path_prefix}cd \"${UI_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && exec \"${node_bin}\" \"${UI_DIR}/server.js\""
    fi
  fi
}

write_systemd_service() {
  local node_bin=$1
  local api_service="/etc/systemd/system/fortress.service"
  local ui_service="/etc/systemd/system/fortress-ui.service"
  local path_line=""
  if [[ -d /snap/bin ]]; then
    path_line="Environment=PATH=/snap/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  fi

  cat > "${api_service}" <<EOF
[Unit]
Description=Linus Fortress API
After=network.target

[Service]
Type=simple
WorkingDirectory=${ROOT_DIR}
EnvironmentFile=${ENV_FILE}
${path_line}
ExecStart=${VENV_DIR}/bin/python ${ROOT_DIR}/py/server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  if [[ "${FORTRESS_UI_ENABLED:-}" == "1" ]]; then
    cat > "${ui_service}" <<EOF
[Unit]
Description=Linus Fortress Admin UI
After=network.target

[Service]
Type=simple
WorkingDirectory=${UI_DIR}
EnvironmentFile=${ENV_FILE}
${path_line}
ExecStart=${node_bin} ${UI_DIR}/server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  else
    rm -f "${ui_service}"
    systemctl disable --now fortress-ui.service >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl enable --now fortress.service
  if [[ "${FORTRESS_UI_ENABLED:-}" == "1" ]]; then
    systemctl enable --now fortress-ui.service
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        RUN_MODE_ARG=${2:-}
        shift 2
        ;;
      --foreground)
        RUN_MODE_ARG="foreground"
        shift
        ;;
      --screen)
        RUN_MODE_ARG="screen"
        shift
        ;;
      --service)
        RUN_MODE_ARG="service"
        shift
        ;;
      --skip-ui)
        UI_ENABLED_ARG="0"
        shift
        ;;
      --enable-ui)
        UI_ENABLED_ARG="1"
        shift
        ;;
      --configure)
        FORCE_SETUP="1"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "Unknown argument: $1"
        ;;
    esac
  done
}

main() {
  parse_args "$@"
  ensure_root "$@"
  maybe_add_snap_path

  local first_run="0"
  if [[ -n "${FORCE_SETUP}" || ! -f "${ENV_FILE}" ]]; then
    first_run="1"
  fi

  local manager
  manager=$(detect_package_manager) || fail "Unsupported OS (requires apt-get, dnf, or yum)."
  local os_id=""
  os_id=$(detect_os_id)
  local is_almalinux="0"
  if [[ "${os_id}" == "almalinux" ]]; then
    is_almalinux="1"
  fi

  if [[ "${is_almalinux}" == "1" ]]; then
    ensure_epel_release "$manager"
  fi

  local base_packages=()
  if [[ "$manager" == "apt" ]]; then
    base_packages=(python3 python3-pip openssl git curl nginx ufw nodejs npm lxd lxc)
  else
    base_packages=(python3 python3-pip openssl git curl nginx firewalld nodejs npm)
    if [[ "${is_almalinux}" != "1" ]]; then
      base_packages+=(lxd lxc)
    fi
  fi
  ensure_packages_installed "$manager" "${base_packages[@]}"
  ensure_python_venv_support "$manager"
  if [[ "${is_almalinux}" == "1" ]]; then
    if ! command -v lxc >/dev/null 2>&1 || ! command -v lxd >/dev/null 2>&1; then
      ensure_snapd "$manager"
      ensure_snap_lxd
    fi
  fi

  if [[ "${first_run}" == "1" ]]; then
    log "First run detected; preparing Fortress configuration."
    ensure_dirs
    ensure_tls
    ensure_python_env
    ensure_node_deps
    ensure_certbot "$manager"
    ensure_lxd_initialized
    if [[ "${is_almalinux}" == "1" ]]; then
      maybe_harden_ssh
    fi

    log "Collecting first-run configuration."
    local host_interface
    host_interface=$(prompt_default "Fortress API host interface" "0.0.0.0")
    local host_port=""
    while true; do
      host_port=$(prompt_default "Fortress API port" "8443")
      if [[ "$host_port" =~ ^[0-9]+$ ]] && ((host_port >= 1 && host_port <= 65535)); then
        break
      fi
      log "Port must be a number between 1 and 65535."
    done
    local enable_master="1"
    if ! prompt_yes_no "Enable master API key for bootstrap?" "Y"; then
      enable_master="0"
    fi
    local api_key=""
    if [[ "${enable_master}" == "1" ]]; then
      api_key=$(prompt_secret "Master API key (leave blank to auto-generate)")
      if [[ -z "$api_key" ]]; then
        api_key=$(generate_secret)
        log "Generated master API key: ${api_key}"
      fi
    fi
    local backup_password
    backup_password=$(prompt_secret "Backup encryption password (leave blank to auto-generate)")
    if [[ -z "$backup_password" ]]; then
      backup_password=$(generate_secret)
      log "Generated backup password: ${backup_password}"
    fi

    local ui_enabled="1"
    if ! prompt_yes_no "Enable admin UI server?" "Y"; then
      ui_enabled="0"
    fi

    local ui_host=""
    local ui_port=""
    local api_url=""
    local ui_api_key=""
    local ui_user_token=""
    local ui_insecure_tls="0"
    if [[ "${ui_enabled}" == "1" ]]; then
      ui_host=$(prompt_default "Admin UI host" "127.0.0.1")
      while true; do
        ui_port=$(prompt_default "Admin UI port" "8090")
        if [[ "$ui_port" =~ ^[0-9]+$ ]] && ((ui_port >= 1 && ui_port <= 65535)); then
          break
        fi
        log "Port must be a number between 1 and 65535."
      done
      api_url=$(prompt_default "Admin UI API URL" "https://127.0.0.1:${host_port}")
      if [[ -n "${api_key}" ]]; then
        if prompt_yes_no "Use master API key for UI auth?" "Y"; then
          ui_api_key="${api_key}"
        else
          ui_user_token=$(prompt_secret "Delegated user token for UI")
        fi
      else
        ui_user_token=$(prompt_secret "Delegated user token for UI (required when master key disabled)")
      fi
      if [[ -f "${SELF_SIGNED_MARKER}" ]]; then
        if prompt_yes_no "Allow UI to trust self-signed TLS from API?" "Y"; then
          ui_insecure_tls="1"
        fi
      fi
      if [[ -z "${ui_api_key}" && -z "${ui_user_token}" ]]; then
        log "Warning: UI has no API credentials; it will not be able to call the Fortress API."
      fi
    fi

    local run_mode="foreground"
    while true; do
      run_mode=$(prompt_default "Run mode (foreground/screen/service)" "foreground")
      if [[ "$run_mode" == "foreground" || "$run_mode" == "screen" || "$run_mode" == "service" ]]; then
        break
      fi
      log "Run mode must be foreground, screen, or service."
    done

    mkdir -p "$(dirname "${ENV_FILE}")"
    local tmp_env
    tmp_env=$(mktemp)
    {
      write_env_line "FORTRESS_HOST_INTERFACE" "${host_interface}"
      write_env_line "FORTRESS_HOST_PORT" "${host_port}"
      write_env_line "FORTRESS_BACKUP_PASSWORD" "${backup_password}"
      write_env_line "FORTRESS_ACME_CHALLENGE_DIR" "${ACME_DIR}"
      if [[ -n "${api_key}" ]]; then
        write_env_line "FORTRESS_API_KEY" "${api_key}"
      fi
      write_env_line "FORTRESS_RUN_MODE" "${run_mode}"
      write_env_line "FORTRESS_UI_ENABLED" "${ui_enabled}"
      if [[ "${ui_enabled}" == "1" ]]; then
        write_env_line "FORTRESS_UI_HOST" "${ui_host}"
        write_env_line "FORTRESS_UI_PORT" "${ui_port}"
        write_env_line "FORTRESS_API_URL" "${api_url}"
        if [[ -n "${ui_api_key}" ]]; then
          write_env_line "FORTRESS_UI_API_KEY" "${ui_api_key}"
        fi
        if [[ -n "${ui_user_token}" ]]; then
          write_env_line "FORTRESS_UI_USER_TOKEN" "${ui_user_token}"
        fi
        write_env_line "FORTRESS_UI_INSECURE_TLS" "${ui_insecure_tls}"
      fi
    } > "${tmp_env}"

    chmod 640 "${tmp_env}"
    mv "${tmp_env}" "${ENV_FILE}"
    log "Saved configuration to ${ENV_FILE}."
  fi

  ensure_dirs

  if [[ ! -f "${ENV_FILE}" ]]; then
    fail "Missing ${ENV_FILE}; run with --configure to create it."
  fi

  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a

  local run_mode="${RUN_MODE_ARG:-${FORTRESS_RUN_MODE:-foreground}}"
  if [[ "$run_mode" != "foreground" && "$run_mode" != "screen" && "$run_mode" != "service" ]]; then
    fail "Invalid run mode: ${run_mode}"
  fi

  local ui_enabled="${UI_ENABLED_ARG:-${FORTRESS_UI_ENABLED:-1}}"
  export FORTRESS_UI_ENABLED="${ui_enabled}"
  if [[ "${ui_enabled}" == "1" ]]; then
    local ui_host_value="${FORTRESS_UI_HOST:-127.0.0.1}"
    local ui_port_value="${FORTRESS_UI_PORT:-8090}"
    maybe_open_ui_firewall "${ui_host_value}" "${ui_port_value}"
  fi

  if [[ "${run_mode}" == "screen" ]]; then
    if ! command -v screen >/dev/null 2>&1; then
      ensure_packages_installed "$manager" screen
    fi
  fi

  if [[ ! -d "${VENV_DIR}" ]]; then
    ensure_python_env
  fi

  if [[ "${ui_enabled}" == "1" && -d "${UI_DIR}" && ! -d "${UI_DIR}/node_modules" ]]; then
    ensure_node_deps
  fi

  if [[ "${run_mode}" == "service" ]]; then
    if ! command -v systemctl >/dev/null 2>&1; then
      fail "systemctl not found; cannot install service."
    fi
    local node_bin
    node_bin=$(command -v node || true)
    if [[ -z "$node_bin" && "${ui_enabled}" == "1" ]]; then
      fail "node not found; install Node.js or disable the UI."
    fi
    write_systemd_service "${node_bin:-/usr/bin/node}"
    log "Service mode enabled. Use 'systemctl status fortress' to inspect."
    exit 0
  fi

  if [[ "${run_mode}" == "screen" ]]; then
    start_screen_sessions
    log "Screen sessions started. Attach with 'screen -r fortress-api' or 'screen -r fortress-ui'."
    exit 0
  fi

  if [[ "${ui_enabled}" == "1" ]]; then
    start_ui_nohup
  fi

  start_api_foreground
}

main "$@"
