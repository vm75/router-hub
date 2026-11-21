#!/usr/bin/env bash
set -euo pipefail
REPO_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"
TMP=$(mktemp -d)
VERSION=$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)
NAME="maestro_${VERSION}-1_aarch64-3.10.ipk"
trap 'rm -rf "$TMP"; rm -f "dist/$NAME" "dist/$NAME.sha256"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$TMP/maestro"
chmod +x "$TMP/maestro"
bash scripts/package-ipk.sh "v${VERSION}" aarch64-unknown-linux-musl "$TMP/maestro"
(
  cd dist
  sha256sum -c "$NAME.sha256"
)
test "$(tar -tzf "dist/$NAME" | tr '\n' ' ')" = "./debian-binary ./control.tar.gz ./data.tar.gz "
tar -xzOf "dist/$NAME" ./control.tar.gz > "$TMP/control.tar.gz"
tar -xzOf "dist/$NAME" ./data.tar.gz > "$TMP/data.tar.gz"
tar -xOzf "$TMP/control.tar.gz" ./control | grep -Fx 'Architecture: aarch64-3.10'
tar -xOzf "$TMP/control.tar.gz" ./control | grep -Fx 'Conflicts: router-hub'
tar -tzf "$TMP/control.tar.gz" | grep -Fx './postinst'
tar -tzf "$TMP/control.tar.gz" | grep -Fx './prerm'
# Migration runs during every IPK post-install, before service restart.
tar -xzOf "$TMP/control.tar.gz" ./postinst | grep -F 'setup-merlin.sh'
setup=scripts/setup-merlin.sh
migration_line=$(grep -nF 'migrate-nginx-inputs' "$setup" | tail -1 | cut -d: -f1)
start_line=$(grep -nF '/opt/etc/init.d/S99maestro restart' "$setup" | tail -1 | cut -d: -f1)
legacy_line=$(grep -nF 'LEGACY_CONFIG=/opt/etc/router-hub/router-hub.toml' "$setup" | head -1 | cut -d: -f1)
test -n "$legacy_line" && test "$legacy_line" -lt "$migration_line"
test -n "$migration_line" && test -n "$start_line" && test "$migration_line" -lt "$start_line"
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/bin/maestro'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/bin/router-hub'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/etc/init.d/S99maestro'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/libexec/maestro/setup-merlin.sh'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/share/maestro/dehydrated-dns01-hook.sh'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/var/lib/maestro/dehydrated/dehydrated-dns01-hook.sh'
tar -tzf "$TMP/data.tar.gz" | grep -Fx './opt/share/maestro/maestro.example.toml'
# Exercise the packaged init script without touching host services or /opt.
mkdir -p "$TMP/bin"
tar -xzOf "$TMP/data.tar.gz" ./opt/etc/init.d/S99maestro | \
    sed -e 's|^PATH=.*|PATH="$INIT_TEST_BIN:/usr/bin:/bin"|' \
        -e 's|^\. /opt/etc/init.d/rc.func$|. "$INIT_TEST_RC"|' > "$TMP/init"
cat > "$TMP/bin/pidof" <<'EOF'
#!/bin/sh
exit "${INIT_TEST_PID_STATUS:-1}"
EOF
chmod +x "$TMP/bin/pidof"
# Model rc.func's stop behavior: dead returns 1, successful stop returns 0.
cat > "$TMP/rc.func" <<'EOF'
printf '%s\n' "$1" >> "$INIT_TEST_CALLS"
return "${INIT_TEST_RC_STATUS:-1}"
EOF
export INIT_TEST_BIN="$TMP/bin" INIT_TEST_RC="$TMP/rc.func" INIT_TEST_CALLS="$TMP/calls"
sh "$TMP/init" stop
test ! -e "$TMP/calls"
INIT_TEST_PID_STATUS=0 INIT_TEST_RC_STATUS=0 sh "$TMP/init" stop
test "$(cat "$TMP/calls")" = stop
# A real stop failure and a dead service check must still report failure.
if INIT_TEST_PID_STATUS=0 sh "$TMP/init" stop; then
    echo "Init script hid a stop failure" >&2
    exit 1
fi
if sh "$TMP/init" check; then
    echo "Init script reported a stopped service as running" >&2
    exit 1
fi
echo "IPK package structure and checksum passed"
