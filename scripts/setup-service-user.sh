#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
USER_NAME="fortress"
GROUP_NAME="fortress"
SUDOERS_PATH="/etc/sudoers.d/fortress"

usage() {
  cat <<'EOF'
Usage: ./scripts/setup-service-user.sh [options]

Options:
  --user NAME        Service user name (default: fortress)
  --group NAME       Service group name (default: fortress)
  --repo PATH        Fortress repo root (default: parent of this script)
  --sudoers PATH     sudoers file path (default: /etc/sudoers.d/fortress)
  -h, --help         Show this help.
EOF
}

fail() {
  echo "[fortress] Error: $*" >&2
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        USER_NAME=${2:-}
        shift 2
        ;;
      --group)
        GROUP_NAME=${2:-}
        shift 2
        ;;
      --repo)
        REPO_ROOT=${2:-}
        shift 2
        ;;
      --sudoers)
        SUDOERS_PATH=${2:-}
        shift 2
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

ensure_group() {
  if getent group "${GROUP_NAME}" >/dev/null 2>&1; then
    return 0
  fi
  if command -v groupadd >/dev/null 2>&1; then
    groupadd --system "${GROUP_NAME}"
  else
    fail "groupadd not found; create group ${GROUP_NAME} manually."
  fi
}

ensure_user() {
  if id -u "${USER_NAME}" >/dev/null 2>&1; then
    return 0
  fi
  local shell="/usr/sbin/nologin"
  if [[ ! -x "${shell}" ]]; then
    shell="/bin/false"
  fi
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --create-home --shell "${shell}" --gid "${GROUP_NAME}" "${USER_NAME}"
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --home "/home/${USER_NAME}" --shell "${shell}" --ingroup "${GROUP_NAME}" "${USER_NAME}"
  else
    fail "useradd/adduser not found; create user ${USER_NAME} manually."
  fi
}

warn_if_repo_writable() {
  if ! command -v stat >/dev/null 2>&1; then
    return 0
  fi
  local target="${REPO_ROOT}/run-server.sh"
  if [[ ! -f "${target}" ]]; then
    return 0
  fi
  local mode=""
  mode=$(stat -c "%a" "${target}" 2>/dev/null || true)
  if [[ -n "${mode}" ]]; then
    local group_bits=$(( (mode / 10) % 10 ))
    local other_bits=$(( mode % 10 ))
    if (( group_bits & 2 )) || (( other_bits & 2 )); then
      echo "[fortress] Warning: ${target} is group/other writable. Make it root-owned and non-writable."
    fi
  fi
}

install_sudoers() {
  local template="${SCRIPT_DIR}/fortress-sudoers.template"
  [[ -f "${template}" ]] || fail "Missing ${template}."
  local systemctl_bin
  systemctl_bin=$(command -v systemctl || true)
  if [[ -z "${systemctl_bin}" ]]; then
    systemctl_bin="/bin/systemctl"
  fi
  local tmp_file
  tmp_file=$(mktemp)
  sed \
    -e "s|__FORTRESS_USER__|${USER_NAME}|g" \
    -e "s|__FORTRESS_ROOT__|${REPO_ROOT}|g" \
    -e "s|__SYSTEMCTL_BIN__|${systemctl_bin}|g" \
    "${template}" > "${tmp_file}"
  chmod 440 "${tmp_file}"
  mv "${tmp_file}" "${SUDOERS_PATH}"
  if command -v visudo >/dev/null 2>&1; then
    if ! visudo -cf "${SUDOERS_PATH}"; then
      rm -f "${SUDOERS_PATH}"
      fail "sudoers validation failed; removed ${SUDOERS_PATH}."
    fi
  fi
}

main() {
  parse_args "$@"
  [[ -n "${USER_NAME}" ]] || fail "Missing --user value."
  [[ -n "${GROUP_NAME}" ]] || fail "Missing --group value."
  [[ -d "${REPO_ROOT}" ]] || fail "Repo root ${REPO_ROOT} not found."
  [[ -f "${REPO_ROOT}/run-server.sh" ]] || fail "run-server.sh not found under ${REPO_ROOT}."

  ensure_group
  ensure_user
  install_sudoers
  warn_if_repo_writable

  echo "[fortress] Created ${USER_NAME}:${GROUP_NAME} and installed ${SUDOERS_PATH}."
  echo "[fortress] Use: sudo -u ${USER_NAME} ${REPO_ROOT}/run-server.sh --mode service"
}

main "$@"
