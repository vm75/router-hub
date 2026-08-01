#!/usr/bin/env bash
set -euo pipefail

host=${1:?Usage: $0 <user@host>}
bin="dist/router-hub-aarch64-unknown-linux-musl"
remote="/opt/bin/router-hub"
service="/opt/etc/init.d/S99router-hub"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=5)

ssh "${ssh_opts[@]}" "$host" "test -f '$remote'" ||
    { echo "Cannot reach $host or $remote does not exist" >&2; exit 1; }

make release
test -f "$bin" || { echo "Missing build: $bin" >&2; exit 1; }

tmp="${remote}.new.$$"
scp -O "${ssh_opts[@]}" "$bin" "$host:$tmp"

ssh "${ssh_opts[@]}" "$host" "
    chmod +x '$tmp' &&
    '$service' stop &&
    mv '$tmp' '$remote' &&
    '$service' start
"