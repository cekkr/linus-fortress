#!/usr/bin/env bash
# Run from a trusted operator shell with restic repository credentials configured.
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'EOF'
Usage: bash scripts/host-recovery.sh backup [additional absolute paths ...]
       bash scripts/host-recovery.sh snapshots
       bash scripts/host-recovery.sh verify
       bash scripts/host-recovery.sh restore SNAPSHOT_ID TRUSTED_STAGING_PARENT
EOF
  exit 2
}

action=${1:-}
[[ -n "${action}" ]] || usage
shift
tag=fortress-host-v1

record_result() {
  local result=$?
  if command -v logger >/dev/null; then
    logger -t fortress-recovery -- "action=${action} exit_code=${result}" || true
  fi
}

case "${action}" in
  backup)
    paths=(/etc/fortress /var/lib/fortress)
    for path in /etc/nginx /etc/letsencrypt /etc/firewalld /etc/ufw \
        /etc/systemd/system/fortress.service /etc/systemd/system/fortress-ui.service; do
      if [[ -e "${path}" ]]; then
        paths+=("${path}")
      fi
    done
    for path in "$@"; do
      [[ "${path}" == /* ]] || usage
      paths+=("${path}")
    done
    trap record_result EXIT
    restic backup --tag "${tag}" \
      --exclude '/var/lib/fortress/backups/.export-*' \
      --exclude '/var/lib/fortress/backups/.backup-*' \
      --exclude '/var/lib/fortress/backups/.restore-*' \
      --exclude '/var/lib/fortress/site_backups/.site-backup-*' \
      -- "${paths[@]}"
    ;;
  snapshots)
    [[ "$#" == 0 ]] || usage
    restic snapshots --tag "${tag}"
    ;;
  verify)
    [[ "$#" == 0 ]] || usage
    trap record_result EXIT
    restic check --read-data
    ;;
  restore)
    [[ "$#" == 2 && "$1" =~ ^[0-9a-f]{8,64}$ && -d "$2" ]] || usage
    trap record_result EXIT
    parent=$(cd -- "$2" && pwd -P)
    staging=$(mktemp -d "${parent%/}/fortress-recovery.XXXXXXXX")
    printf 'Recovery staging directory: %s\n' "${staging}"
    restic restore "$1" --target "${staging}" --verify
    ;;
  *) usage ;;
esac
