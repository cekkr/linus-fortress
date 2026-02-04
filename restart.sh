#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE_DEFAULT="/etc/fortress/fortress.env"
ENV_FILE="${FORTRESS_ENV_FILE:-${ENV_FILE_DEFAULT}}"
VENV_DIR="${ROOT_DIR}/.venv"
UI_DIR="${ROOT_DIR}/ui"
API_LOG="${ROOT_DIR}/.restart-api.log"
UI_LOG="${ROOT_DIR}/.restart-ui.log"

MODE="auto"
DO_PULL="1"
DRY_RUN="0"

usage() {
  cat <<'USAGE'
Usage: ./restart.sh [options]

Options:
  --no-pull, --skip-pull  Skip git pull update step.
  --mode auto|service|screen|process
                          Restart strategy (default: auto).
  --env /path/to/env      Override env file (default: /etc/fortress/fortress.env).
  --dry-run               Print actions without executing.
  -h, --help              Show this help.
USAGE
}

log() {
  echo "[restart] $*"
}

warn() {
  echo "[restart] Warning: $*" >&2
}

fail() {
  echo "[restart] Error: $*" >&2
  exit 1
}

run_cmd() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    log "dry-run: $*"
    return 0
  fi
  "$@"
}

pull_changes() {
  if [[ "${DO_PULL}" != "1" ]]; then
    return 0
  fi
  if ! command -v git >/dev/null 2>&1; then
    warn "git not found; skipping update."
    return 0
  fi
  if [[ ! -d "${ROOT_DIR}/.git" ]]; then
    warn "${ROOT_DIR} is not a git repo; skipping update."
    return 0
  fi
  if ! git -C "${ROOT_DIR}" diff --quiet || ! git -C "${ROOT_DIR}" diff --cached --quiet; then
    warn "Working tree has uncommitted changes; skipping git pull."
    return 0
  fi
  log "Updating source with git pull --ff-only."
  if ! run_cmd git -C "${ROOT_DIR}" pull --ff-only; then
    warn "git pull failed; continuing with restart."
  fi
}

load_env() {
  if [[ -r "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "${ENV_FILE}"
    set +a
  else
    warn "Env file not readable: ${ENV_FILE}. Continuing with current environment."
  fi
}

kill_pids() {
  local pids=$1
  if [[ -z "${pids}" ]]; then
    return 0
  fi
  if [[ "${DRY_RUN}" == "1" ]]; then
    log "dry-run: kill -TERM ${pids}"
    return 0
  fi
  kill -TERM ${pids} >/dev/null 2>&1 || true
  for _ in {1..10}; do
    if ! kill -0 ${pids} >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  kill -KILL ${pids} >/dev/null 2>&1 || true
}

resolve_python_bin() {
  local python_bin="${VENV_DIR}/bin/python"
  if [[ -x "${python_bin}" ]]; then
    echo "${python_bin}"
    return 0
  fi
  python_bin=$(command -v python3 || true)
  if [[ -n "${python_bin}" ]]; then
    echo "${python_bin}"
    return 0
  fi
  python_bin=$(command -v python || true)
  if [[ -n "${python_bin}" ]]; then
    echo "${python_bin}"
    return 0
  fi
  echo ""
}

resolve_node_bin() {
  local node_bin="${FORTRESS_NODE_BIN:-}"
  if [[ -n "${node_bin}" && -x "${node_bin}" ]]; then
    echo "${node_bin}"
    return 0
  fi
  node_bin=$(command -v node || true)
  if [[ -n "${node_bin}" ]]; then
    echo "${node_bin}"
    return 0
  fi
  echo ""
}

restart_systemd() {
  local api_active=$1
  local ui_active=$2
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found; cannot restart services."
    return 1
  fi
  if [[ $EUID -ne 0 && "${DRY_RUN}" != "1" ]]; then
    warn "Not running as root; systemd restart may fail without sudo."
  fi
  if [[ "${api_active}" == "1" || "${MODE}" == "service" ]]; then
    log "Restarting fortress.service"
    run_cmd systemctl restart fortress.service || warn "Failed to restart fortress.service"
  fi
  if [[ "${ui_active}" == "1" ]]; then
    log "Restarting fortress-ui.service"
    run_cmd systemctl restart fortress-ui.service || warn "Failed to restart fortress-ui.service"
  else
    if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^fortress-ui.service"; then
      if systemctl is-active --quiet fortress-ui.service; then
        log "Restarting fortress-ui.service"
        run_cmd systemctl restart fortress-ui.service || warn "Failed to restart fortress-ui.service"
      fi
    fi
  fi
}

restart_screen() {
  local api_was_running=$1
  local ui_was_running=$2
  if ! command -v screen >/dev/null 2>&1; then
    warn "screen not found; cannot restart screen sessions."
    return 1
  fi

  if [[ "${api_was_running}" == "1" || "${MODE}" == "screen" ]]; then
    log "Stopping screen session fortress-api"
    run_cmd screen -S fortress-api -X quit >/dev/null 2>&1 || true
  fi
  if [[ "${ui_was_running}" == "1" ]]; then
    log "Stopping screen session fortress-ui"
    run_cmd screen -S fortress-ui -X quit >/dev/null 2>&1 || true
  fi

  local python_bin
  python_bin=$(resolve_python_bin)
  if [[ -z "${python_bin}" ]]; then
    warn "Python not found; skipping API restart."
    return 1
  fi

  local path_prefix=""
  if [[ -d /snap/bin ]]; then
    path_prefix="export PATH=\"/snap/bin:\$PATH\"; "
  fi

  if [[ "${api_was_running}" == "1" || "${MODE}" == "screen" ]]; then
    log "Starting screen session fortress-api"
    run_cmd screen -dmS fortress-api bash -lc "${path_prefix}cd \"${ROOT_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && exec \"${python_bin}\" \"${ROOT_DIR}/py/server.py\""
  fi

  local ui_enabled="${FORTRESS_UI_ENABLED:-}"
  local should_start_ui="0"
  if [[ "${ui_was_running}" == "1" ]]; then
    should_start_ui="1"
  elif [[ "${MODE}" == "screen" && "${ui_enabled}" == "1" ]]; then
    should_start_ui="1"
  fi

  if [[ "${should_start_ui}" == "1" && -d "${UI_DIR}" ]]; then
    local node_bin
    node_bin=$(resolve_node_bin)
    if [[ -z "${node_bin}" ]]; then
      warn "node not found; skipping UI restart."
      return 1
    fi
    log "Starting screen session fortress-ui"
    run_cmd screen -dmS fortress-ui bash -lc "${path_prefix}cd \"${UI_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && exec \"${node_bin}\" \"${UI_DIR}/server.js\""
  fi
}

start_process() {
  local start_api=$1
  local start_ui=$2

  local python_bin
  python_bin=$(resolve_python_bin)
  if [[ "${start_api}" == "1" ]]; then
    if [[ -z "${python_bin}" ]]; then
      warn "Python not found; skipping API restart."
    else
      log "Starting API process (log: ${API_LOG})"
      if [[ "${DRY_RUN}" == "1" ]]; then
        log "dry-run: cd \"${ROOT_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && nohup \"${python_bin}\" \"${ROOT_DIR}/py/server.py\" >> \"${API_LOG}\" 2>&1 &"
      else
        (
          cd "${ROOT_DIR}"
          # shellcheck disable=SC1090
          set -a
          [[ -r "${ENV_FILE}" ]] && source "${ENV_FILE}"
          set +a
          nohup "${python_bin}" "${ROOT_DIR}/py/server.py" >> "${API_LOG}" 2>&1 &
        )
      fi
    fi
  fi

  if [[ "${start_ui}" == "1" && -d "${UI_DIR}" ]]; then
    local node_bin
    node_bin=$(resolve_node_bin)
    if [[ -z "${node_bin}" ]]; then
      warn "node not found; skipping UI restart."
      return 0
    fi
    log "Starting UI process (log: ${UI_LOG})"
    if [[ "${DRY_RUN}" == "1" ]]; then
      log "dry-run: cd \"${UI_DIR}\" && set -a && source \"${ENV_FILE}\" && set +a && nohup \"${node_bin}\" \"${UI_DIR}/server.js\" >> \"${UI_LOG}\" 2>&1 &"
    else
      (
        cd "${UI_DIR}"
        # shellcheck disable=SC1090
        set -a
        [[ -r "${ENV_FILE}" ]] && source "${ENV_FILE}"
        set +a
        nohup "${node_bin}" "${UI_DIR}/server.js" >> "${UI_LOG}" 2>&1 &
      )
    fi
  fi
}

restart_processes() {
  local api_pids=$1
  local ui_pids=$2
  local api_was_running="0"
  local ui_was_running="0"

  if [[ -n "${api_pids}" ]]; then
    api_was_running="1"
    log "Stopping API process: ${api_pids}"
    kill_pids "${api_pids}"
  fi
  if [[ -n "${ui_pids}" ]]; then
    ui_was_running="1"
    log "Stopping UI process: ${ui_pids}"
    kill_pids "${ui_pids}"
  fi

  local ui_enabled="${FORTRESS_UI_ENABLED:-}"
  local start_api="${api_was_running}"
  if [[ "${MODE}" == "process" ]]; then
    start_api="1"
  fi
  local start_ui="0"
  if [[ "${ui_was_running}" == "1" ]]; then
    start_ui="1"
  elif [[ "${MODE}" == "process" && "${ui_enabled}" == "1" ]]; then
    start_ui="1"
  fi

  start_process "${start_api}" "${start_ui}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-pull|--skip-pull)
        DO_PULL="0"
        shift
        ;;
      --mode)
        MODE="${2:-}"
        shift 2
        ;;
      --env)
        ENV_FILE="${2:-}"
        shift 2
        ;;
      --dry-run)
        DRY_RUN="1"
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
  case "${MODE}" in
    auto|service|screen|process) ;;
    *) fail "Invalid --mode ${MODE}. Use auto, service, screen, or process." ;;
  esac

  pull_changes
  load_env

  local systemd_api_active="0"
  local systemd_ui_active="0"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet fortress.service; then
      systemd_api_active="1"
    fi
    if systemctl is-active --quiet fortress-ui.service; then
      systemd_ui_active="1"
    fi
  fi

  local screen_api_active="0"
  local screen_ui_active="0"
  if command -v screen >/dev/null 2>&1; then
    if screen -list | grep -q "fortress-api"; then
      screen_api_active="1"
    fi
    if screen -list | grep -q "fortress-ui"; then
      screen_ui_active="1"
    fi
  fi

  local api_pids=""
  local ui_pids=""
  api_pids=$(pgrep -f "${ROOT_DIR}/py/server.py" || true)
  ui_pids=$(pgrep -f "${UI_DIR}/server.js" || true)

  local process_api_active="0"
  local process_ui_active="0"
  if [[ -n "${api_pids}" ]]; then
    process_api_active="1"
  fi
  if [[ -n "${ui_pids}" ]]; then
    process_ui_active="1"
  fi

  if [[ "${MODE}" == "auto" ]]; then
    if [[ "${systemd_api_active}" == "1" || "${systemd_ui_active}" == "1" ]]; then
      MODE="service"
    elif [[ "${screen_api_active}" == "1" || "${screen_ui_active}" == "1" ]]; then
      MODE="screen"
    elif [[ "${process_api_active}" == "1" || "${process_ui_active}" == "1" ]]; then
      MODE="process"
    else
      log "No running Fortress instances detected; nothing to restart."
      exit 0
    fi
  fi

  if [[ "${systemd_api_active}" == "1" && ("${screen_api_active}" == "1" || "${process_api_active}" == "1") ]]; then
    warn "Multiple run modes detected; defaulting to systemd."
  elif [[ "${screen_api_active}" == "1" && "${process_api_active}" == "1" ]]; then
    warn "Multiple run modes detected; defaulting to screen."
  fi

  case "${MODE}" in
    service)
      restart_systemd "${systemd_api_active}" "${systemd_ui_active}"
      ;;
    screen)
      restart_screen "${screen_api_active}" "${screen_ui_active}"
      ;;
    process)
      restart_processes "${api_pids}" "${ui_pids}"
      ;;
  esac
}

main "$@"
