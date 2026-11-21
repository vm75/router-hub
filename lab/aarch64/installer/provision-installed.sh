#!/bin/sh
# Provision the newly installed disk from the live ISO, without starting daemons.
set -eu

ROOT_DEVICE=${1:-/dev/vda3}
TARGET=${2:-/mnt/router-lab}
REPOSITORY=${3:-/mnt/router-hub}
MOUNTS=""

cleanup() {
    status=$?
    trap - EXIT
    failed=0
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        umount "$path" || failed=1
    done <<EOF
$MOUNTS
EOF
    [ "$status" -ne 0 ] || status=$failed
    exit "$status"
}
trap cleanup EXIT

mount_into() {
    destination=$1
    shift
    mount "$@" "$destination"
    MOUNTS="$destination
$MOUNTS"
}

mkdir -p "$TARGET"
mount_into "$TARGET" "$ROOT_DEVICE"
[ -f "$TARGET/etc/alpine-release" ] || { echo 'Error: Target is not an installed Alpine system.' >&2; exit 1; }
mkdir -p "$TARGET/proc" "$TARGET/sys" "$TARGET/dev" "$TARGET/run" "$TARGET/tmp" "$TARGET/mnt/router-hub"
mount_into "$TARGET/run" -t tmpfs tmpfs
mount_into "$TARGET/tmp" -t tmpfs tmpfs
mount_into "$TARGET/proc" -t proc proc
mount_into "$TARGET/sys" --bind /sys
mount_into "$TARGET/dev" --bind /dev
mount_into "$TARGET/mnt/router-hub" --bind "$REPOSITORY"

# The live ISO has working DHCP/DNS; the installed guest has not booted yet.
rm -f "$TARGET/etc/resolv.conf"
cp /etc/resolv.conf "$TARGET/etc/resolv.conf"
chroot "$TARGET" /usr/bin/env LAB_OFFLINE=1 MAESTRO_DEFER_START=1 \
    /bin/sh /mnt/router-hub/lab/aarch64/provision.sh
