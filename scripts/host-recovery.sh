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
       bash scripts/host-recovery.sh restore-ssh SNAPSHOT_ID LOCAL_STAGING_PARENT SSH_HOST REMOTE_STAGING_PARENT
       bash scripts/host-recovery.sh stage-ssh LOCAL_DIRECTORY SSH_HOST REMOTE_STAGING_PARENT
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

restore_snapshot() {
  local snapshot=$1 parent=$2
  shift 2
  [[ "$snapshot" =~ ^[0-9a-f]{8,64}$ && -d "$parent" ]] || usage
  parent=$(cd -- "$parent" && pwd -P)
  recovery_staging=$(mktemp -d "${parent%/}/fortress-recovery.XXXXXXXX")
  printf 'Recovery staging directory: %s\n' "$recovery_staging"
  restic restore "$snapshot" --target "$recovery_staging" --verify "$@"
}

validate_ssh_destination() {
  [[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_.:@%-]*$ && "$2" == /* && "$2" != *[[:cntrl:]]* ]] || usage
}

shell_quote() {
  local escaped=${1//\'/\'\\\'\'}
  printf "'%s'" "$escaped"
}

stage_over_ssh() {
  local source=$1 destination=$2 parent=$3 archiver=tar tar_version special remote_script staged
  local -a archive_options=(--format=pax)
  [[ -d "$source" ]] || usage
  source=$(cd -- "$source" && pwd -P)
  if command -v gtar >/dev/null; then archiver=gtar; fi
  tar_version=$("$archiver" --version)
  case "$tar_version" in
    *'GNU tar'*) archive_options+=(--sparse) ;;
    *bsdtar*) archive_options+=(--no-xattrs --no-acls --no-fflags) ;;
    *) printf 'SSH staging requires GNU tar or bsdtar on the client.\n' >&2; return 1 ;;
  esac
  special=$(find "$source" ! -type d ! -type f ! -type l -print -quit)
  if [[ -n "$special" ]]; then
    printf 'SSH staging accepts only directories, regular files and symbolic links.\n' >&2
    return 1
  fi
  remote_script='
set -euo pipefail
umask 077
unset TAR_OPTIONS
parent=$(cd -- "$1" && pwd -P)
staging=$(mktemp -d "${parent%/}/fortress-recovery.XXXXXXXX")
trap '\''rm -rf -- "$staging"'\'' EXIT
mkdir -- "$staging/files"
tar --extract --file=- --directory="$staging/files" --no-same-owner --no-same-permissions
trap - EXIT
printf "%s\n" "$staging/files"
'
  if staged=$(TAR_OPTIONS= COPYFILE_DISABLE=1 "$archiver" "${archive_options[@]}" --create --file=- -C "$source" . |
      ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15 -- "$destination" \
        "bash -c $(shell_quote "$remote_script") fortress-recovery $(shell_quote "$parent")"); then
    printf 'Remote recovery staging directory: %s\n' "$staged"
  else
    if [[ -n "$staged" ]]; then printf 'Incomplete SSH staging directory: %s\n' "$staged" >&2; fi
    return 1
  fi
}

case "${action}" in
  backup)
    paths=(/etc/fortress /var/lib/fortress)
    schema_dir=${FORTRESS_SCHEMA_DIR:-"$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../schemas" && pwd -P)"}
    [[ "$schema_dir" == /* && -d "$schema_dir" ]] || usage
    schema_dir=$(cd -- "$schema_dir" && pwd -P)
    paths+=("$schema_dir")
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
    [[ "$#" == 2 ]] || usage
    trap record_result EXIT
    restore_snapshot "$1" "$2"
    ;;
  restore-ssh)
    [[ "$#" == 4 ]] || usage
    validate_ssh_destination "$3" "$4"
    trap record_result EXIT
    restore_snapshot "$1" "$2" --sparse
    stage_over_ssh "$recovery_staging" "$3" "$4"
    ;;
  stage-ssh)
    [[ "$#" == 3 ]] || usage
    validate_ssh_destination "$2" "$3"
    trap record_result EXIT
    stage_over_ssh "$1" "$2" "$3"
    ;;
  *) usage ;;
esac
