#!/usr/bin/env bash
# Unit and integration test for AArch64 lab scripts and fixtures.
set -euo pipefail

REPO_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"

echo "=== 1. Validating shell script syntax ==="
bash -n lab/aarch64/run.sh
bash -n lab/aarch64/init.sh
sh -n lab/aarch64/setup-alpine.answers
sh -n lab/aarch64/installer/install.sh
sh -n lab/aarch64/installer/provision-installed.sh
sh -n scripts/setup-merlin.sh
sh -n lab/aarch64/provision.sh
sh -n lab/aarch64/configure-share.sh
sh -n lab/aarch64/configure-shell.sh
sh -n lab/aarch64/files/login-banner.sh
sh -n lab/aarch64/files/nvram
sh -n lab/aarch64/files/service
sh -n lab/aarch64/files/logread
sh -n lab/aarch64/files/entware.initd
sh -n lab/aarch64/files/httpd.initd
sh -n lab/aarch64/files/httpds.initd
echo "Script syntax validation passed."

echo "=== 2. Testing CLI help flags ==="
lab/aarch64/run.sh --help >/dev/null
echo "CLI help checks passed."

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "=== 3. Testing NVRAM mock ==="
cp lab/aarch64/files/nvram.initial "$TMP/nvram"
NVRAM="lab/aarch64/files/nvram"

export NVRAM_FILE="$TMP/nvram"
test "$("$NVRAM" get lan_ipaddr)" = "10.0.2.15"
test "$("$NVRAM" get productid)" = "QEMU-AARCH64-LAB"
test "$("$NVRAM" get odmpid)" = "router-lab"
test "$("$NVRAM" get firmver)" = "lab"
test "$("$NVRAM" get buildno)" = "1"
test "$("$NVRAM" get extendno)" = "qemu"
test "$("$NVRAM" get nonexistent)" = ""

# Test argument validation
set +e
"$NVRAM" get >/dev/null 2>&1
status=$?
set -euo pipefail
test "$status" -eq 2

set +e
"$NVRAM" set foo bar >/dev/null 2>&1
status=$?
set -euo pipefail
test "$status" -eq 2
echo "NVRAM mock passed."

echo "=== 4. Testing mock service handler ==="
SERVICE="lab/aarch64/files/service"
mkdir "$TMP/bin"
cat > "$TMP/bin/logger" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$LOGGER_ARGS"
EOF
chmod +x "$TMP/bin/logger"
LOGGER_ARGS="$TMP/logger-args" PATH="$TMP/bin:$PATH" "$SERVICE" dnsmasq restart
printf '%s\n' '-t' 'router-lab' 'mock: dnsmasq restart requested' > "$TMP/expected-logger-args"
cmp "$TMP/expected-logger-args" "$TMP/logger-args"

set +e
"$SERVICE" unsupported action >/dev/null 2>&1
status=$?
set -euo pipefail
test "$status" -eq 2
echo "Mock service handler passed."

echo "=== 5. Testing mock logread ==="
LOGREAD="lab/aarch64/files/logread"
# Must exit 0 even if /var/log/messages does not exist
"$LOGREAD" >/dev/null
echo "Mock logread passed."

echo "=== 6. Testing firewall-policy.json fixture ==="
jq -e '.enabled == false and .rules == []' lab/aarch64/files/firewall-policy.json >/dev/null
echo "Firewall policy JSON fixture passed."

echo "=== 7. Testing QEMU project share ==="
cat > "$TMP/bin/qemu-system-aarch64" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$QEMU_ARGS"
for arg do
    case "$arg" in
        file=fat:ro:*,format=raw,if=virtio,readonly=on)
            seed=${arg#file=fat:ro:}
            seed=${seed%,format=raw,if=virtio,readonly=on}
            cp "$seed/router-lab.apkovl.tar.gz" "$SEED_CAPTURE"
            ;;
    esac
done
EOF
printf '#!/bin/sh\nexit 0\n' > "$TMP/bin/qemu-img"
chmod +x "$TMP/bin/qemu-system-aarch64" "$TMP/bin/qemu-img"
touch "$TMP/disk.qcow2" "$TMP/uefi.fd" "$TMP/installer.iso"
QEMU_ARGS="$TMP/qemu-args" PATH="$TMP/bin:$PATH" lab/aarch64/run.sh \
    --disk "$TMP/disk.qcow2" --uefi "$TMP/uefi.fd" >/dev/null
grep -Fx -- '-virtfs' "$TMP/qemu-args" >/dev/null
grep -Fx "local,path=$REPO_DIR,mount_tag=router-hub,security_model=none,readonly=on" "$TMP/qemu-args" >/dev/null
grep -Fx 'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:8080-:8080,hostfwd=tcp:127.0.0.1:8443-:8443,hostfwd=tcp:127.0.0.1:3030-:3030' "$TMP/qemu-args" >/dev/null
# The simulated firmware must not occupy NGINX's HTTP/HTTPS ports.
(
    . lab/aarch64/files/httpd.initd
    test "$command_args" = 'httpd -f -p 8080 -h /www -c /etc/router-lab/httpd.conf'
    . lab/aarch64/files/httpds.initd
    test "$command" = /usr/bin/stunnel
    test "$command_args" = /etc/router-lab/httpds.conf
)
grep -Fx 'accept = 0.0.0.0:8443' lab/aarch64/files/httpds.conf >/dev/null
grep -Fx 'connect = 127.0.0.1:8080' lab/aarch64/files/httpds.conf >/dev/null
QEMU_ARGS="$TMP/qemu-args" PATH="$TMP/bin:$PATH" lab/aarch64/run.sh \
    --disk "$TMP/disk.qcow2" --uefi "$TMP/uefi.fd" --iso "$TMP/installer.iso" >/dev/null
grep -Fx -- '-virtfs' "$TMP/qemu-args" >/dev/null
echo "QEMU project share checks passed."

echo "=== Testing lab initialization and media caching ==="
# Use a private checkout and package so initialization never changes real artifacts.
INIT_REPO="$TMP/init-repo"
mkdir -p "$INIT_REPO/lab/aarch64" "$INIT_REPO/dist" "$TMP/ipk-data/opt/libexec/maestro"
cp lab/aarch64/init.sh lab/aarch64/run.sh "$INIT_REPO/lab/aarch64/"
cp -R lab/aarch64/installer "$INIT_REPO/lab/aarch64/"
cp scripts/setup-merlin.sh "$TMP/ipk-data/opt/libexec/maestro/"
tar -czf "$TMP/data.tar.gz" -C "$TMP/ipk-data" .
TEST_PACKAGE="$INIT_REPO/dist/maestro_0.0.1-1_aarch64-3.10.ipk"
tar -czf "$TEST_PACKAGE" -C "$TMP" ./data.tar.gz
(cd "$(dirname "$TEST_PACKAGE")" && sha256sum "$(basename "$TEST_PACKAGE")" > "$(basename "$TEST_PACKAGE").sha256")
INIT_SCRIPT="$INIT_REPO/lab/aarch64/init.sh"
cat > "$TMP/bin/qemu-img" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" >> "$DISK_CALLS"
touch "$4"
EOF
cat > "$TMP/bin/curl" <<'EOF'
#!/bin/sh
printf '%s\n' "$2" >> "$CURL_CALLS"
case "$2" in
    */latest-releases.yaml) cp "$MEDIA_FIXTURES/releases.yaml" "$4" ;;
    *.sha256) cp "$MEDIA_FIXTURES/installer.sha256" "$4" ;;
    *.iso) cp "$MEDIA_FIXTURES/installer.iso" "$4" ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$TMP/bin/qemu-img" "$TMP/bin/curl"
export MEDIA_FIXTURES="$TMP/media" CURL_CALLS="$TMP/curl-calls"
export DISK_CALLS="$TMP/disk-calls" QEMU_ARGS="$TMP/qemu-args"
export SEED_CAPTURE="$TMP/installer.apkovl.tar.gz"
mkdir "$MEDIA_FIXTURES"
printf 'mock installer\n' > "$MEDIA_FIXTURES/installer.iso"
iso_name=alpine-standard-3.99.1-aarch64.iso
printf '%s\n' '---' '-' '  file: alpine-virt-3.99.1-aarch64.iso' \
    '-' "  file: $iso_name" > "$MEDIA_FIXTURES/releases.yaml"
iso_hash=$(sha256sum "$MEDIA_FIXTURES/installer.iso")
printf '%s  %s\n' "${iso_hash%% *}" "$iso_name" > "$MEDIA_FIXTURES/installer.sha256"
(
    export PATH="$TMP/bin:$PATH" LAB_DIR="$TMP/lab media" AARCH64_UEFI="$TMP/uefi.fd"
    unset LAB_DISK ALPINE_ISO
    "$INIT_SCRIPT" >/dev/null
    test -f "$LAB_DIR/$iso_name"
    test -f "$LAB_DIR/router-lab.qcow2"
    mkdir "$TMP/overlay-check"
    tar -xzf "$SEED_CAPTURE" -C "$TMP/overlay-check"
    test -f "$TMP/overlay-check/etc/.default_boot_services"
    cmp lab/aarch64/installer/inittab "$TMP/overlay-check/etc/inittab"
    cmp lab/aarch64/installer/install.sh "$TMP/overlay-check/etc/router-lab/install.sh"
    grep -Fx "file=$LAB_DIR/router-lab.qcow2,format=qcow2,if=virtio" "$QEMU_ARGS" >/dev/null
    grep -Fx "if=none,id=cd,media=cdrom,readonly=on,file=$LAB_DIR/$iso_name" "$QEMU_ARGS" >/dev/null
    test "$(wc -l < "$CURL_CALLS")" -eq 3
    cp "$DISK_CALLS" "$TMP/first-disk-calls"
    printf 'keep existing disk\n' > "$LAB_DIR/router-lab.qcow2"
    rm "$QEMU_ARGS" "$SEED_CAPTURE"
    "$INIT_SCRIPT" >/dev/null
    test ! -f "$QEMU_ARGS"
    test ! -f "$SEED_CAPTURE"
    cmp "$DISK_CALLS" "$TMP/first-disk-calls"
    grep -Fx 'keep existing disk' "$LAB_DIR/router-lab.qcow2" >/dev/null
    test "$(wc -l < "$CURL_CALLS")" -eq 3
    # An existing custom disk must exit before even creating the media directory.
    LAB_DISK="$LAB_DIR/router-lab.qcow2" LAB_DIR="$TMP/unused-media" "$INIT_SCRIPT" >/dev/null
    test ! -e "$TMP/unused-media"
    test ! -f "$QEMU_ARGS"
    lab/aarch64/run.sh >/dev/null
    grep -Fx "file=$LAB_DIR/router-lab.qcow2,format=qcow2,if=virtio" "$QEMU_ARGS" >/dev/null
    if grep -F 'file=fat:ro:' "$QEMU_ARGS" >/dev/null; then
        echo 'Normal disk boot unexpectedly attaches the installer overlay' >&2
        exit 1
    fi
    if lab/aarch64/run.sh --installer-seed "$TMP/overlay-check" >"$TMP/init-error" 2>&1; then
        echo 'Installer seed unexpectedly accepted without an ISO' >&2
        exit 1
    fi
    # Corrupted cached media must never boot QEMU or recreate the disk.
    printf 'corrupt\n' >> "$LAB_DIR/$iso_name"
    rm "$QEMU_ARGS" "$LAB_DIR/router-lab.qcow2"
    if "$INIT_SCRIPT" >"$TMP/init-error" 2>&1; then
        echo 'Corrupted ISO unexpectedly accepted' >&2
        exit 1
    fi
    test ! -f "$QEMU_ARGS"
    cmp "$DISK_CALLS" "$TMP/first-disk-calls"
    # A failed fresh download must not become cached media or create a disk.
    export LAB_DIR="$TMP/bad-download"
    printf 'wrong checksum content\n' > "$MEDIA_FIXTURES/installer.iso"
    if "$INIT_SCRIPT" >"$TMP/init-error" 2>&1; then
        echo 'Corrupted download unexpectedly accepted' >&2
        exit 1
    fi
    test ! -f "$LAB_DIR/$iso_name"
    test ! -f "$LAB_DIR/router-lab.qcow2"
    # Missing packages fail before creating a disk or downloading any media.
    mv "$TEST_PACKAGE" "$TMP/saved.ipk"
    cp "$CURL_CALLS" "$TMP/previous-curl-calls"
    if "$INIT_SCRIPT" >"$TMP/init-error" 2>&1; then
        echo 'Initialization unexpectedly accepted a missing Maestro package' >&2
        exit 1
    fi
    cmp "$CURL_CALLS" "$TMP/previous-curl-calls"
    cmp "$DISK_CALLS" "$TMP/first-disk-calls"
    # Existing disks still exit even when packages are absent.
    touch "$LAB_DIR/router-lab.qcow2"
    "$INIT_SCRIPT" >/dev/null
    # Old package hooks must be rebuilt before automatic chroot provisioning.
    mv "$TMP/saved.ipk" "$TEST_PACKAGE"
    printf '#!/bin/sh\nexit 0\n' > "$TMP/ipk-data/opt/libexec/maestro/setup-merlin.sh"
    tar -czf "$TMP/data.tar.gz" -C "$TMP/ipk-data" .
    tar -czf "$TEST_PACKAGE" -C "$TMP" ./data.tar.gz
    (cd "$(dirname "$TEST_PACKAGE")" && sha256sum "$(basename "$TEST_PACKAGE")" > "$(basename "$TEST_PACKAGE").sha256")
    if LAB_DIR="$TMP/stale-package-media" "$INIT_SCRIPT" >"$TMP/init-error" 2>&1; then
        echo 'Initialization unexpectedly accepted a package that starts services in the chroot' >&2
        exit 1
    fi
    test ! -e "$TMP/stale-package-media"
    cmp "$CURL_CALLS" "$TMP/previous-curl-calls"
    cmp "$DISK_CALLS" "$TMP/first-disk-calls"
)
echo "Lab initialization checks passed."
bash tests/test_lab_provisioning.sh

echo "=== 8. Testing TOML template substitution and validation ==="
AUTH_TOKEN="0123456789abcdef0123456789abcdef"
sed -e "s|__AUTH_TOKEN__|$AUTH_TOKEN|" \
    -e "s|__OPENSSL_BIN__|/usr/bin/openssl|" \
    -e "s|__IP_BIN__|/sbin/ip|" \
    lab/aarch64/files/maestro.toml.template > "$TMP/maestro.toml"

# Run check-config subcommand using target/release/maestro or target/debug/maestro
MAESTRO=""
for candidate in target/debug/maestro target/release/maestro; do
    if [[ -x "$candidate" ]]; then
        MAESTRO="$candidate"
        break
    fi
done

if [[ -n "$MAESTRO" ]]; then
    # Create test directories needed for validation
    mkdir -p "$TMP/certs" "$TMP/nginx" "$TMP/www" "$TMP/var/wwwext"
    cp lab/aarch64/files/menuTree.js "$TMP/www/menuTree.js"
    sed -i "s|/www/require/modules/menuTree.js|$TMP/www/menuTree.js|" "$TMP/maestro.toml"
    sed -i "s|/tmp/var/wwwext/user20.asp|$TMP/var/wwwext/user20.asp|" "$TMP/maestro.toml"

    "$MAESTRO" --config "$TMP/maestro.toml" check-config >/dev/null
    echo "Configuration template check-config passed."

    echo "=== 9. Testing ASUS UI mounting and rendering with lab fixtures ==="
    "$MAESTRO" --config "$TMP/maestro.toml" mount-ui >/dev/null
    test -f "$TMP/var/wwwext/user20.asp"
    grep -F "user20.asp" "$TMP/www/menuTree.js" >/dev/null
    grep -F "$AUTH_TOKEN" "$TMP/var/wwwext/user20.asp" >/dev/null
    echo "ASUS UI mount-ui and ASP rendering passed."
fi

echo "=== All AArch64 lab checks passed successfully ==="
