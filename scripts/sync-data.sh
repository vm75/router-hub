#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$WORKSPACE_DIR/data"

HOST="dwar"
DRY_RUN=0

usage() {
    cat <<USAGE
Usage:
  $0 [-t] [-s server] get <local-dir|all>
  $0 [-t] [-s server] put <local-dir|all>
  $0 zip
  $0 -h

Options:
  -t          Test mode; pass --dry-run to rsync
  -s <server>   Remote SSH server (default: dwar)
  -h          Show this help

Configured local directories:
  opt/etc/AdGuardHome
  opt/etc/init.d
  opt/etc/mosquitto
  opt/etc/nginx
  opt/etc/router-hub
  opt/etc/logrotate.d
  jffs/addons
  jffs/configs
  jffs/scripts
  jffs/www
  opt/var/log
  vaultwarden
  opt/home/shasak/.certs

A directory may also be specified by its final component:

  $0 get nginx
  $0 put scripts
USAGE
}

die() {
    echo "Error: $*" >&2
    echo >&2
    usage >&2
    exit 1
}

while getopts ":ts:h" opt; do
    case "$opt" in
        t)
            DRY_RUN=1
            ;;
        s)
            HOST="$OPTARG"
            ;;
        h)
            usage
            exit 0
            ;;
        :)
            die "Option -$OPTARG requires an argument"
            ;;
        \?)
            die "Unknown option: -$OPTARG"
            ;;
    esac
done

shift $((OPTIND - 1))

COMMAND="${1:-}"
SELECTION="${2:-}"

# Parallel arrays containing:
#   local path
#   remote path
#   item type
LOCAL_PATHS=(
    "opt/etc/AdGuardHome"
    "opt/etc/init.d"
    "opt/etc/mosquitto"
    "opt/etc/nginx"
    "opt/etc/router-hub"
    "opt/etc/logrotate.d"
    "jffs/addons"
    "jffs/configs"
    "jffs/scripts"
    "jffs/www"
    "opt/var/log"
    "vaultwarden"
    "opt/home/shasak/.certs"
)

REMOTE_PATHS=(
    "/opt/etc/AdGuardHome"
    "/opt/etc/init.d"
    "/opt/etc/mosquitto"
    "/opt/etc/nginx"
    "/opt/etc/router-hub"
    "/opt/etc/logrotate.d"
    "/jffs/addons"
    "/jffs/configs"
    "/jffs/scripts"
    "/jffs/www"
    "/opt/var/log"
    "/opt/home/shasak/.local/share/vaultwarden/.env"
    "/opt/home/shasak/.certs"
)

ITEM_TYPES=(
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "dir"
    "file"
    "dir"
)

DIR_RSYNC_ARGS=(-av --delete)
FILE_RSYNC_ARGS=(-av)

if ((DRY_RUN)); then
    DIR_RSYNC_ARGS+=(--dry-run)
    FILE_RSYNC_ARGS+=(--dry-run)
fi

normalize_path() {
    local path="$1"

    path="${path#./}"

    while [[ "$path" == */ ]]; do
        path="${path%/}"
    done

    printf '%s\n' "$path"
}

RESOLVED_INDEX=""

resolve_index() {
    local requested
    local local_path
    local base
    local found=""
    local i

    requested="$(normalize_path "$1")"

    for i in "${!LOCAL_PATHS[@]}"; do
        local_path="${LOCAL_PATHS[$i]}"
        base="${local_path##*/}"

        if [[ "$requested" == "$local_path" ||
              "$requested" == "$base" ]]; then
            if [[ -n "$found" ]]; then
                die "Ambiguous directory name: $1"
            fi

            found="$i"
        fi
    done

    [[ -n "$found" ]] || die "Unknown local directory: $1"

    RESOLVED_INDEX="$found"
}

sync_one() {
    local direction="$1"
    local index="$2"
    local local_path="${LOCAL_PATHS[$index]}"
    local remote_path="${REMOTE_PATHS[$index]}"
    local item_type="${ITEM_TYPES[$index]}"
    local target_path="$DATA_DIR/$local_path"

    case "$direction:$item_type" in
        get:dir)
            mkdir -p "$target_path"

            rsync "${DIR_RSYNC_ARGS[@]}" \
                "$HOST:$remote_path/" \
                "$target_path/"
            ;;

        put:dir)
            [[ -d "$target_path" ]] ||
                die "Local directory does not exist: $target_path"

            rsync "${DIR_RSYNC_ARGS[@]}" \
                "$target_path/" \
                "$HOST:$remote_path/"
            ;;

        get:file)
            mkdir -p "$target_path"

            rsync "${FILE_RSYNC_ARGS[@]}" \
                "$HOST:$remote_path" \
                "$target_path/"
            ;;

        put:file)
            local local_file="$target_path/${remote_path##*/}"

            [[ -f "$local_file" ]] ||
                die "Local file does not exist: $local_file"

            rsync "${FILE_RSYNC_ARGS[@]}" \
                "$local_file" \
                "$HOST:$remote_path"
            ;;

        *)
            die "Unsupported sync operation: $direction:$item_type"
            ;;
    esac
}

sync_selection() {
    local direction="$1"
    local selection="$2"
    local i

    if [[ "$selection" == "all" ]]; then
        for i in "${!LOCAL_PATHS[@]}"; do
            sync_one "$direction" "$i"
        done
    else
        resolve_index "$selection"
        sync_one "$direction" "$RESOLVED_INDEX"
    fi
}

case "$COMMAND" in
    get|put)
        [[ $# -eq 2 ]] ||
            die "$COMMAND requires exactly one argument: <local-dir|all>"

        sync_selection "$COMMAND" "$SELECTION"
        ;;

    zip)
        [[ $# -eq 1 ]] || die "zip does not accept arguments"

        tar zcf "$DATA_DIR/router.tgz" -C "$DATA_DIR" \
            opt/var/log/*.log \
            opt/var/log/nginx \
            vaultwarden/ \
            opt/etc/AdGuardHome/AdGuardHome.yaml \
            opt/etc/nginx \
            opt/etc/init.d/ \
            opt/etc/router-hub \
            opt/etc/logrotate.d \
            jffs/scripts/
        ;;

    "")
        die "Missing command"
        ;;

    *)
        die "Unknown command: $COMMAND"
        ;;
esac
