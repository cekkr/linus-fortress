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
VERIFY_TLS="auto"
UI_HOST="127.0.0.1"
UI_PORT="8090"
RESET_KEYS="0"
ISSUE_TOKEN="0"
TOKEN_LABEL=""
TOKEN_PERMS=""

usage() {
  cat <<'EOF'
Usage: ./run-client.sh [--webui] [options]

Default flow configures the CLI connection (fortress-cli setup).

Options:
  --webui            Guide setup for running the WebUI locally.
  --server URL       Fortress API base URL (e.g. https://host:8443).
  --api-key KEY      Master API key (optional).
  --user-token TOKEN Delegated API user token (optional).
  --reset-keys       Regenerate CLI RSA keypair during setup.
  --issue-token      Create a delegated token after CLI setup.
  --token-label NAME Label for the delegated token (default: client).
  --token-perms LIST Comma-separated permissions for the token.
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
  local default_perms="read_status manage_containers access_control manage_backups package_manage recipes_manage recipes_apply manage_routing api_user_admin"
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
  if ! output=$("${PYTHON_BIN}" "${ROOT_DIR}/fortress-cli.py" api-users create "${label}" --permissions "${perm_args[@]}"); then
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
  log "  ${token}"
  log "Copy/paste helpers:"
  log "  FORTRESS_UI_USER_TOKEN=${token}"
  log "  ./fortress-cli.py setup --server ${SERVER_URL} --user-token ${token}"
}

run_cli_setup() {
  ensure_python_deps
  if [[ -z "${SERVER_URL}" ]]; then
    SERVER_URL=$(prompt_default "Fortress API base URL" "https://127.0.0.1:8443")
  fi
  if [[ "${VERIFY_TLS}" == "auto" && -t 0 ]]; then
    if prompt_yes_no "Allow self-signed TLS for the API?" "N"; then
      VERIFY_TLS="insecure"
    else
      VERIFY_TLS="secure"
    fi
  fi
  local setup_args=("${PYTHON_BIN}" "${ROOT_DIR}/fortress-cli.py" "setup" "--server" "${SERVER_URL}")
  if [[ "${RESET_KEYS}" == "1" ]]; then
    setup_args+=("--force-keys")
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
  log "Running fortress-cli setup..."
  "${setup_args[@]}"
  log "CLI ready. Example: ./fortress-cli.py status"
  if [[ "${ISSUE_TOKEN}" == "1" ]]; then
    create_delegated_token_cli "${TOKEN_LABEL}" "${TOKEN_PERMS}"
  elif [[ -t 0 ]]; then
    if prompt_yes_no "Create a delegated token now?" "N"; then
      local label
      label=$(prompt_default "Delegated token label" "${TOKEN_LABEL:-client}")
      local perms
      perms=$(prompt_default "Delegated token permissions (comma-separated or *)" "${TOKEN_PERMS:-read_status,manage_containers,access_control,manage_backups,package_manage,recipes_manage,recipes_apply,manage_routing,api_user_admin}")
      create_delegated_token_cli "${label}" "${perms}"
    fi
  fi
}

guide_webui_setup() {
  if [[ ! -d "${UI_DIR}" ]]; then
    fail "UI directory not found at ${UI_DIR}"
  fi
  if ! command -v "${NODE_BIN}" >/dev/null 2>&1; then
    log "Warning: node not found; install Node.js before running the WebUI."
  fi
  if ! command -v "${NPM_BIN}" >/dev/null 2>&1; then
    log "Warning: npm not found; install Node.js (npm) before running the WebUI."
  fi

  if [[ -z "${SERVER_URL}" ]]; then
    SERVER_URL=$(prompt_default "Fortress API base URL" "https://127.0.0.1:8443")
  fi

  if [[ "${VERIFY_TLS}" == "auto" ]]; then
    if prompt_yes_no "Allow self-signed TLS for the API?" "N"; then
      VERIFY_TLS="insecure"
    else
      VERIFY_TLS="secure"
    fi
  fi

  if [[ -z "${API_KEY}" && -z "${USER_TOKEN}" ]]; then
    local auth_choice
    auth_choice=$(prompt_default "Auth for WebUI (api-key/user-token/skip)" "user-token")
    case "${auth_choice}" in
      api-key)
        API_KEY=$(prompt_secret "API master key")
        ;;
      user-token)
        USER_TOKEN=$(prompt_secret "Delegated user token")
        ;;
      skip)
        ;;
      *)
        log "Unknown choice; continuing without stored credentials."
        ;;
    esac
  fi

  local env_path="${UI_DIR}/.env.local"
  local wrote_env="0"
  if prompt_yes_no "Write WebUI env file to ${env_path}?" "Y"; then
    write_ui_env_file "${env_path}"
    wrote_env="1"
    log "Wrote ${env_path} (chmod 600)."
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
    log "4) ${NPM_BIN} start"
  fi
  log "5) Open http://${UI_HOST}:${UI_PORT} in your browser"
  log ""
  if [[ "${wrote_env}" != "1" ]]; then
    log "If you skipped the env file, export FORTRESS_API_URL and FORTRESS_UI_* vars before starting."
  fi
}

main() {
  parse_args "$@"
  if [[ "${MODE}" == "webui" ]]; then
    guide_webui_setup
  else
    run_cli_setup
  fi
}

main "$@"
