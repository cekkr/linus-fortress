#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="${ROOT_DIR}/ui"
PYTHON_BIN="${FORTRESS_PYTHON_BIN:-python3}"
NODE_BIN="${FORTRESS_NODE_BIN:-node}"
NPM_BIN="${FORTRESS_NPM_BIN:-npm}"

MODE="cli"
SERVER_URL=""
API_KEY=""
USER_TOKEN=""
TOKEN_INPUT=""
VERIFY_TLS="auto"
UI_HOST="127.0.0.1"
UI_PORT="8090"
RESET_KEYS="0"
ISSUE_TOKEN="0"
TOKEN_LABEL=""
TOKEN_PERMS=""
PASS_PHRASE="${FORTRESS_PASSPHRASE:-}"
BOOTSTRAP_UI_ADMIN="auto"
FORTRESS_HOME="${FORTRESS_HOME:-${HOME}/.fortress-cli}"
CA_BUNDLE_PATH="${FORTRESS_CA_BUNDLE:-${FORTRESS_HOME}/api-ca.pem}"
PIN_CERT_MODE="auto"
PINNED_CA_BUNDLE=""
ACTIVE_CA_BUNDLE=""

usage() {
  cat <<'EOF'
Usage: ./run-client.sh [--webui] [options]

Default flow configures the CLI connection (fortress-cli setup).

Options:
  --webui            Guide setup for running the WebUI locally.
  --server ADDR      Fortress API address or URL (e.g. 203.0.113.10 or https://host:8443).
  --api-key KEY      Master API key (optional).
  --user-token TOKEN Delegated API user token (optional).
  --token TOKEN      Typed token (api-key:... or user-token:...).
  --reset-keys       Regenerate CLI RSA keypair during setup.
  --issue-token      Create a delegated token after CLI setup.
  --token-label NAME Label for the delegated token (default: client).
  --token-perms LIST Comma-separated permissions for the token.
  --passphrase PASS  CLI key passphrase (or set FORTRESS_PASSPHRASE).
  --pin-cert         Fetch and pin the API TLS certificate for verification (useful for self-signed).
  --ca-bundle PATH   Use an existing CA bundle for API verification (implies --secure).
  --no-pin-cert      Disable automatic pin prompt (default is auto-prompt for public hosts).
  --bootstrap-admin  Prompt to bootstrap the local UI admin (default in --webui).
  --no-bootstrap-admin Skip UI admin bootstrap prompt.
  --insecure         Disable TLS verification (self-signed certs).
  --secure           Force TLS verification.
  --ui-host HOST     WebUI bind host (default 127.0.0.1).
  --ui-port PORT     WebUI bind port (default 8090).
  -h, --help         Show this help.
EOF
}

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

prompt_default() {
  local text=$1
  local default=$2
  local value=""
  if [[ -t 0 ]]; then
    read -r -p "${text} [${default}]: " value || true
  fi
  if [[ -z "${value}" ]]; then
    value="${default}"
  fi
  printf '%s' "${value}"
}

prompt_secret() {
  local text=$1
  local value=""
  if [[ -t 0 ]]; then
    read -r -s -p "${text}: " value || true
    printf '\n' >&2
  fi
  printf '%s' "${value}"
}

prompt_yes_no() {
  local text=$1
  local default=$2
  local value=""
  if [[ -t 0 ]]; then
    read -r -p "${text} [${default}]: " value || true
  fi
  if [[ -z "${value}" ]]; then
    value="${default}"
  fi
  case "${value}" in
    Y|y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
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

parse_host_port() {
  local url=$1
  python - "$url" <<'PY'
import sys
import urllib.parse

raw = sys.argv[1]
if "://" not in raw:
    raw = "https://" + raw
parsed = urllib.parse.urlparse(raw)
host = parsed.hostname or ""
port = parsed.port or (443 if parsed.scheme == "https" else 80)
print(host)
print(port)
PY
}

is_public_host() {
  local host=$1
  python - "$host" <<'PY'
import ipaddress
import sys

host = sys.argv[1]
try:
    ip = ipaddress.ip_address(host)
    print("1" if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast) else "0")
except ValueError:
    # Assume DNS names are public unless they end with .local or lack a dot
    if host.endswith(".local") or "." not in host:
        print("0")
    else:
        print("1")
PY
}

ensure_ca_dir() {
  local path=$1
  local dir
  dir="$(dirname "${path}")"
  mkdir -p "${dir}"
}

fetch_server_cert_bundle() {
  local host=$1
  local port=$2
  local dest=$3
  if command -v openssl >/dev/null 2>&1; then
    if ! openssl s_client -showcerts -servername "${host}" -connect "${host}:${port}" </dev/null 2>/dev/null \
      | awk '/BEGIN CERTIFICATE/{flag=1}flag{print}/END CERTIFICATE/{if(flag){print;flag=0}}' > "${dest}"; then
      return 1
    fi
    if [[ ! -s "${dest}" ]]; then
      return 1
    fi
    return 0
  fi
  # Python fallback: grabs leaf cert only
  python - "$host" "$port" "$dest" <<'PY'
import ssl
import socket
import sys

host, port, dest = sys.argv[1], int(sys.argv[2]), sys.argv[3]
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with socket.create_connection((host, port), timeout=10) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        der = ssock.getpeercert(True)
        pem = ssl.DER_cert_to_PEM_cert(der)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(pem)
PY
}

maybe_pin_server_cert() {
  local url=$1
  if [[ "${PIN_CERT_MODE}" == "off" ]]; then
    return 0
  fi
  read -r host port < <(parse_host_port "${url}")
  if [[ -z "${host}" ]]; then
    return 0
  fi
  local public="0"
  public=$(is_public_host "${host}" || echo "0")
  local should_pin="0"
  if [[ "${PIN_CERT_MODE}" == "on" ]]; then
    should_pin="1"
  elif [[ "${PIN_CERT_MODE}" == "auto" && "${public}" == "1" && -t 0 ]]; then
    if prompt_yes_no "Pin TLS cert from ${host}:${port} for verification?" "Y"; then
      should_pin="1"
    fi
  fi
  if [[ "${should_pin}" != "1" ]]; then
    return 0
  fi
  ensure_ca_dir "${CA_BUNDLE_PATH}"
  log "Fetching TLS certificate from ${host}:${port}..."
  if ! fetch_server_cert_bundle "${host}" "${port}" "${CA_BUNDLE_PATH}"; then
    log "Failed to fetch certificate; continuing without pinning."
    return 0
  fi
  PINNED_CA_BUNDLE="${CA_BUNDLE_PATH}"
  ACTIVE_CA_BUNDLE="${CA_BUNDLE_PATH}"
  VERIFY_TLS="secure"
  log "Pinned certificate to ${PINNED_CA_BUNDLE} (set REQUESTS_CA_BUNDLE to reuse)."
}

TOKEN_TYPE=""
TOKEN_VALUE=""

parse_typed_token() {
  local raw=$1
  TOKEN_TYPE=""
  TOKEN_VALUE="${raw}"
  if [[ -z "${raw}" || "${raw}" != *:* ]]; then
    return 0
  fi
  local prefix="${raw%%:*}"
  local token="${raw#*:}"
  local normalized="${prefix,,}"
  case "${normalized}" in
    api-key|api_key|master|master-key|master_key|api)
      TOKEN_TYPE="api-key"
      TOKEN_VALUE="${token}"
      ;;
    user-token|user_token|user|delegated|token)
      TOKEN_TYPE="user-token"
      TOKEN_VALUE="${token}"
      ;;
    *)
      TOKEN_TYPE=""
      TOKEN_VALUE="${raw}"
      ;;
  esac
}

apply_token_input() {
  local raw=$1
  if [[ -z "${raw}" ]]; then
    return 0
  fi
  parse_typed_token "${raw}"
  if [[ "${TOKEN_TYPE}" == "api-key" ]]; then
    API_KEY="${TOKEN_VALUE}"
    USER_TOKEN=""
    return 0
  fi
  if [[ -z "${TOKEN_TYPE}" ]]; then
    log "Token type not specified; assuming user-token."
  fi
  USER_TOKEN="${TOKEN_VALUE}"
  API_KEY=""
}

normalize_server_url() {
  local input=$1
  local default_port=${2:-8443}
  if [[ -z "${input}" ]]; then
    printf 'https://127.0.0.1:%s' "${default_port}"
    return 0
  fi
  if [[ "${input}" == *"://"* ]]; then
    printf '%s' "${input}"
    return 0
  fi
  if [[ "${input}" == *:*:* ]]; then
    if [[ "${input}" =~ ^\\[.*\\](:[0-9]+)?$ ]]; then
      if [[ "${input}" =~ :[0-9]+$ ]]; then
        printf 'https://%s' "${input}"
      else
        printf 'https://%s:%s' "${input}" "${default_port}"
      fi
    else
      printf 'https://[%s]:%s' "${input}" "${default_port}"
    fi
    return 0
  fi
  if [[ "${input}" =~ ^[^/]+:[0-9]+$ ]]; then
    printf 'https://%s' "${input}"
    return 0
  fi
  printf 'https://%s:%s' "${input}" "${default_port}"
}

ui_base_url() {
  local host=$1
  local port=$2
  if [[ "${host}" == "0.0.0.0" ]]; then
    host="127.0.0.1"
  fi
  printf 'http://%s:%s' "${host}" "${port}"
}

bootstrap_ui_admin() {
  local force=${1:-0}
  local base_url
  base_url=$(ui_base_url "${UI_HOST}" "${UI_PORT}")
  local username
  username=$(prompt_default "UI admin username" "admin")
  local password=""
  if prompt_yes_no "Auto-generate a strong admin password?" "Y"; then
    password=$(generate_password)
    log "Generated UI admin password: ${password}"
  else
    password=$(prompt_secret "UI admin password")
    local confirm
    confirm=$(prompt_secret "Confirm admin password")
    if [[ "${password}" != "${confirm}" ]]; then
      fail "Passwords do not match."
    fi
  fi
  if ! command -v curl >/dev/null 2>&1; then
    if [[ "${force}" == "1" ]]; then
      log "curl not found; run the bootstrap request manually once the UI is running:"
      log "  curl -s -X POST ${base_url}/api/admin/bootstrap -H 'Content-Type: application/json' -d '{\"username\":\"${username}\",\"password\":\"${password}\"}'"
    else
      log "curl not found; skipping bootstrap. Start the UI, then run: ./run-client.sh --webui --bootstrap-admin"
    fi
    return 0
  fi
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${base_url}/api/admin/session" || true)
  if [[ "${status}" != "200" ]]; then
    if [[ "${force}" == "1" ]]; then
      log "UI not reachable at ${base_url}. Start the UI, then run:"
      log "  curl -s -X POST ${base_url}/api/admin/bootstrap -H 'Content-Type: application/json' -d '{\"username\":\"${username}\",\"password\":\"${password}\"}'"
    else
      log "UI not reachable at ${base_url}. Start the UI first, then run: ./run-client.sh --webui --bootstrap-admin"
    fi
    return 0
  fi
  local payload
  payload=$(UI_BOOTSTRAP_USER="${username}" UI_BOOTSTRAP_PASS="${password}" "${PYTHON_BIN}" - <<'PY'
import json
import os

print(json.dumps({"username": os.environ["UI_BOOTSTRAP_USER"], "password": os.environ["UI_BOOTSTRAP_PASS"]}))
PY
)
  local response
  response=$(curl -s -w "\n%{http_code}" -X POST "${base_url}/api/admin/bootstrap" \
    -H "Content-Type: application/json" \
    -d "${payload}")
  local body="${response%$'\n'*}"
  local code="${response##*$'\n'}"
  if [[ "${code}" == "200" ]]; then
    log "UI admin bootstrap complete."
    return 0
  fi
  if [[ "${code}" == "409" ]]; then
    log "UI admin already initialized."
    return 0
  fi
  log "UI admin bootstrap failed (${code}). Response: ${body}"
  return 1
}

quote_env() {
  printf '%q' "$1"
}

write_ui_env_file() {
  local env_path=$1
  {
    printf 'FORTRESS_API_URL=%s\n' "$(quote_env "${SERVER_URL}")"
    printf 'FORTRESS_UI_HOST=%s\n' "$(quote_env "${UI_HOST}")"
    printf 'FORTRESS_UI_PORT=%s\n' "$(quote_env "${UI_PORT}")"
    if [[ -n "${API_KEY}" ]]; then
      printf 'FORTRESS_UI_API_KEY=%s\n' "$(quote_env "${API_KEY}")"
    fi
    if [[ -n "${USER_TOKEN}" ]]; then
      printf 'FORTRESS_UI_USER_TOKEN=%s\n' "$(quote_env "${USER_TOKEN}")"
    fi
    if [[ "${VERIFY_TLS}" == "insecure" ]]; then
      printf 'FORTRESS_UI_INSECURE_TLS=1\n'
    fi
    if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
      printf 'NODE_EXTRA_CA_CERTS=%s\n' "$(quote_env "${ACTIVE_CA_BUNDLE}")"
    fi
  } > "${env_path}"
  chmod 600 "${env_path}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --webui)
        MODE="webui"
        shift
        ;;
      --server|--api-url)
        SERVER_URL="${2:-}"
        shift 2
        ;;
      --api-key)
        API_KEY="${2:-}"
        shift 2
        ;;
      --user-token)
        USER_TOKEN="${2:-}"
        shift 2
        ;;
      --token)
        TOKEN_INPUT="${2:-}"
        shift 2
        ;;
      --reset-keys)
        RESET_KEYS="1"
        shift
        ;;
      --issue-token)
        ISSUE_TOKEN="1"
        shift
        ;;
      --token-label)
        TOKEN_LABEL="${2:-}"
        shift 2
        ;;
      --token-perms)
        TOKEN_PERMS="${2:-}"
        shift 2
        ;;
      --passphrase)
        PASS_PHRASE="${2:-}"
        shift 2
        ;;
      --pin-cert)
        PIN_CERT_MODE="on"
        shift
        ;;
      --no-pin-cert)
        PIN_CERT_MODE="off"
        shift
        ;;
      --ca-bundle)
        CA_BUNDLE_PATH="${2:-}"
        ACTIVE_CA_BUNDLE="${CA_BUNDLE_PATH}"
        VERIFY_TLS="secure"
        if [[ -n "${CA_BUNDLE_PATH}" && ! -f "${CA_BUNDLE_PATH}" ]]; then
          log "Warning: CA bundle not found at ${CA_BUNDLE_PATH}; requests may fail until it exists."
        fi
        shift 2
        ;;
      --bootstrap-admin)
        BOOTSTRAP_UI_ADMIN="1"
        shift
        ;;
      --no-bootstrap-admin)
        BOOTSTRAP_UI_ADMIN="0"
        shift
        ;;
      --insecure)
        VERIFY_TLS="insecure"
        shift
        ;;
      --secure)
        VERIFY_TLS="secure"
        shift
        ;;
      --ui-host)
        UI_HOST="${2:-}"
        shift 2
        ;;
      --ui-port)
        UI_PORT="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "Unknown argument: $1 (use --help for usage)"
        ;;
    esac
  done
}

ensure_python_deps() {
  if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    fail "python3 not found; install Python 3 and try again."
  fi
  if ! "${PYTHON_BIN}" - <<'PY' >/dev/null 2>&1; then
import requests  # noqa: F401
import cryptography  # noqa: F401
PY
    log "Python deps missing; run: pip install -r requirements.txt"
  fi
}

split_perms() {
  local raw=$1
  raw=${raw//,/ }
  raw=${raw//;/ }
  printf '%s' "${raw}"
}

create_delegated_token_cli() {
  local label=$1
  local perms_raw=$2
  local default_perms="*"
  if [[ -z "${label}" ]]; then
    label="client"
  fi
  if [[ -z "${perms_raw}" ]]; then
    perms_raw="${default_perms}"
  fi
  local perms
  perms=$(split_perms "${perms_raw}")
  local perm_args=()
  if [[ "${perms}" == "*" ]]; then
    perm_args=("*")
  else
    read -r -a perm_args <<< "${perms}"
  fi
  log "Creating delegated token '${label}'..."
  local output
  local cli_args=("${PYTHON_BIN}" "${ROOT_DIR}/fortress-cli.py")
  if [[ -n "${PASS_PHRASE}" ]]; then
    cli_args+=("--passphrase" "${PASS_PHRASE}")
  fi
  cli_args+=("api-users" "create" "${label}" "--permissions" "${perm_args[@]}")
  if ! output=$("${cli_args[@]}" 2>&1); then
    log "${output}"
    fail "Failed to create delegated token. Ensure the stored auth has api_user_admin permission."
  fi
  local token
  token=$(TOKEN_PAYLOAD="${output}" "${PYTHON_BIN}" - <<'PY'
import json
import os

raw = os.environ.get("TOKEN_PAYLOAD", "")
try:
    payload = json.loads(raw)
except Exception:
    payload = {}
print(payload.get("token", ""))
PY
)
  log "Delegated token created:"
  local typed_token="user-token:${token}"
  log "  ${token}"
  log "  ${typed_token}"
  log "Copy/paste helpers:"
  log "  FORTRESS_UI_USER_TOKEN=${token}"
  log "  ./run-client.sh --server ${SERVER_URL} --token ${typed_token}"
  log "  ./fortress-cli.py setup --server ${SERVER_URL} --user-token ${token}"
}

run_cli_setup() {
  ensure_python_deps
  if [[ -z "${SERVER_URL}" ]]; then
    local server_input
    server_input=$(prompt_default "Fortress API address or URL" "127.0.0.1")
    SERVER_URL=$(normalize_server_url "${server_input}")
  else
    SERVER_URL=$(normalize_server_url "${SERVER_URL}")
  fi
  local host port public_host
  read -r host port < <(parse_host_port "${SERVER_URL}")
  public_host=$(is_public_host "${host}" || echo "0")
  if [[ "${VERIFY_TLS}" == "auto" && "${public_host}" == "1" ]]; then
    VERIFY_TLS="secure"
  fi
  if [[ "${VERIFY_TLS}" == "auto" && -t 0 ]]; then
    if prompt_yes_no "Allow self-signed TLS for the API?" "N"; then
      VERIFY_TLS="insecure"
    else
      VERIFY_TLS="secure"
    fi
  fi
  if [[ "${VERIFY_TLS}" != "insecure" || "${PIN_CERT_MODE}" == "on" ]]; then
    maybe_pin_server_cert "${SERVER_URL}"
  fi
  if [[ -z "${API_KEY}" && -z "${USER_TOKEN}" && -t 0 ]]; then
    local token_input
    token_input=$(prompt_secret "Access token (api-key:... or user-token:..., leave blank to skip)")
    if [[ -n "${token_input}" ]]; then
      apply_token_input "${token_input}"
    fi
  fi
  local setup_args=("${PYTHON_BIN}" "${ROOT_DIR}/fortress-cli.py" "setup" "--server" "${SERVER_URL}")
  if [[ "${RESET_KEYS}" == "1" ]]; then
    setup_args+=("--force-keys")
    if [[ -n "${PASS_PHRASE}" ]]; then
      setup_args+=("--key-passphrase" "${PASS_PHRASE}")
    fi
  fi
  if [[ "${VERIFY_TLS}" == "insecure" ]]; then
    setup_args+=("--insecure")
  elif [[ "${VERIFY_TLS}" == "secure" ]]; then
    setup_args+=("--secure")
  fi
  if [[ -n "${API_KEY}" ]]; then
    setup_args+=("--api-key" "${API_KEY}")
  fi
  if [[ -n "${USER_TOKEN}" ]]; then
    setup_args+=("--user-token" "${USER_TOKEN}")
  fi
  if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
    setup_args+=("--ca-bundle" "${ACTIVE_CA_BUNDLE}")
  fi
  local setup_env=()
  if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
    setup_env+=("REQUESTS_CA_BUNDLE=${ACTIVE_CA_BUNDLE}")
  fi
  log "Running fortress-cli setup..."
  if [[ ${#setup_env[@]} -gt 0 ]]; then
    env "${setup_env[@]}" "${setup_args[@]}"
  else
    "${setup_args[@]}"
  fi
  log "CLI ready. Example: ./fortress-cli.py status"
  if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
    log "TLS: using CA bundle at ${ACTIVE_CA_BUNDLE} (stored in fortress-cli config)"
  fi
  if [[ "${ISSUE_TOKEN}" == "1" ]]; then
    if [[ -z "${PASS_PHRASE}" && -t 0 ]]; then
      PASS_PHRASE=$(prompt_secret "CLI key passphrase (leave blank to prompt later)")
    fi
    create_delegated_token_cli "${TOKEN_LABEL}" "${TOKEN_PERMS}"
  elif [[ -t 0 ]]; then
    if prompt_yes_no "Create a delegated token now?" "N"; then
      local label
      label=$(prompt_default "Delegated token label" "${TOKEN_LABEL:-client}")
      local perms
      perms=$(prompt_default "Delegated token permissions (comma-separated or *)" "${TOKEN_PERMS:-*}")
      if [[ -z "${PASS_PHRASE}" ]]; then
        PASS_PHRASE=$(prompt_secret "CLI key passphrase (leave blank to prompt later)")
      fi
      create_delegated_token_cli "${label}" "${perms}"
    fi
  fi
}

guide_webui_setup() {
  if [[ ! -d "${UI_DIR}" ]]; then
    fail "UI directory not found at ${UI_DIR}"
  fi
  ensure_python_deps
  if ! command -v "${NODE_BIN}" >/dev/null 2>&1; then
    log "Warning: node not found; install Node.js before running the WebUI."
  fi
  if ! command -v "${NPM_BIN}" >/dev/null 2>&1; then
    log "Warning: npm not found; install Node.js (npm) before running the WebUI."
  fi

  if [[ -z "${SERVER_URL}" ]]; then
    local server_input
    server_input=$(prompt_default "Fortress API address or URL" "127.0.0.1")
    SERVER_URL=$(normalize_server_url "${server_input}")
  else
    SERVER_URL=$(normalize_server_url "${SERVER_URL}")
  fi

  local host port public_host
  read -r host port < <(parse_host_port "${SERVER_URL}")
  public_host=$(is_public_host "${host}" || echo "0")
  if [[ "${VERIFY_TLS}" == "auto" && "${public_host}" == "1" ]]; then
    VERIFY_TLS="secure"
  fi

  if [[ "${VERIFY_TLS}" == "auto" ]]; then
    if prompt_yes_no "Allow self-signed TLS for the API?" "N"; then
      VERIFY_TLS="insecure"
    else
      VERIFY_TLS="secure"
    fi
  fi

  if [[ "${VERIFY_TLS}" != "insecure" || "${PIN_CERT_MODE}" == "on" ]]; then
    maybe_pin_server_cert "${SERVER_URL}"
  fi

  if [[ -z "${API_KEY}" && -z "${USER_TOKEN}" ]]; then
    local token_input
    token_input=$(prompt_secret "WebUI access token (api-key:... or user-token:..., leave blank to skip)")
    if [[ -n "${token_input}" ]]; then
      apply_token_input "${token_input}"
    fi
  fi

  local env_path="${UI_DIR}/.env.local"
  local wrote_env="0"
  if prompt_yes_no "Write WebUI env file to ${env_path}?" "Y"; then
    write_ui_env_file "${env_path}"
    wrote_env="1"
    log "Wrote ${env_path} (chmod 600)."
    if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
      log "WebUI will trust TLS using NODE_EXTRA_CA_CERTS=${ACTIVE_CA_BUNDLE}"
    fi
  else
    log "Skipping env file write."
  fi

  log ""
  log "Next steps (run WebUI locally):"
  log "1) cd ui"
  log "2) ${NPM_BIN} install"
  if [[ "${wrote_env}" == "1" ]]; then
    log "3) set -a; source .env.local; set +a"
    log "4) ${NPM_BIN} start"
  else
    log "3) Export FORTRESS_API_URL and any FORTRESS_UI_* vars"
    if [[ -n "${ACTIVE_CA_BUNDLE}" ]]; then
      log "   Also export NODE_EXTRA_CA_CERTS=${ACTIVE_CA_BUNDLE} for self-signed/pinned TLS"
    fi
    log "4) ${NPM_BIN} start"
  fi
  log "5) Open http://${UI_HOST}:${UI_PORT} in your browser"
  log ""
  if [[ "${wrote_env}" != "1" ]]; then
    log "If you skipped the env file, export FORTRESS_API_URL and FORTRESS_UI_* vars before starting."
  fi

  if [[ "${BOOTSTRAP_UI_ADMIN}" == "auto" && -t 0 ]]; then
    if prompt_yes_no "Bootstrap a local UI admin now? (UI must be running)" "Y"; then
      bootstrap_ui_admin 0
    fi
  elif [[ "${BOOTSTRAP_UI_ADMIN}" == "1" ]]; then
    bootstrap_ui_admin 1
  fi
}

main() {
  parse_args "$@"
  if [[ -n "${TOKEN_INPUT}" && -z "${API_KEY}" && -z "${USER_TOKEN}" ]]; then
    apply_token_input "${TOKEN_INPUT}"
  fi
  if [[ "${MODE}" == "webui" ]]; then
    guide_webui_setup
  else
    run_cli_setup
  fi
}

main "$@"
