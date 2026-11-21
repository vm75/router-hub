#!/bin/sh
# Guest provisioning script for AArch64 Maestro lab on Alpine Linux.
set -eu

[ "$(id -u)" = "0" ] || { echo "Error: Must run as root inside the Alpine VM." >&2; exit 1; }
LAB_OFFLINE="${LAB_OFFLINE:-0}"
case "$LAB_OFFLINE" in
    0|1) ;;
    *) echo 'Error: LAB_OFFLINE must be 0 or 1.' >&2; exit 1 ;;
esac
if [ "$LAB_OFFLINE" = 1 ]; then
    export MAESTRO_DEFER_START=1
fi

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")
FILES_DIR="${FILES_DIR:-}"

if [ -z "$FILES_DIR" ]; then
    for candidate in \
        "$SCRIPT_DIR/files" \
        "$PWD/files" \
        "/root/router-lab/files" \
        "/tmp/router-lab/files"; do
        if [ -d "$candidate" ]; then
            FILES_DIR="$candidate"
            break
        fi
    done
fi

if [ -z "$FILES_DIR" ] || [ ! -d "$FILES_DIR" ]; then
    echo "Error: files directory not found. Set FILES_DIR=/path/to/files." >&2
    exit 1
fi

echo "=== Step 1: Install Alpine packages and create directories ==="
apk update
apk add --no-cache ca-certificates curl openssl iproute2 busybox-extras
# stunnel is in Alpine community; use the guest's matching repository branch.
COMMUNITY_REPO=$(sed -n 's|^\(https\{0,1\}://.*/\)main/*$|\1community|p' /etc/apk/repositories | head -n1)
[ -n "$COMMUNITY_REPO" ] || { echo "Error: No Alpine main repository found for stunnel." >&2; exit 1; }
apk add --no-cache --repository "$COMMUNITY_REPO" stunnel

# The installer or guest console mounted the repository. Retain it across reboots.
if [ "$LAB_OFFLINE" = 1 ] || mountpoint -q /mnt/router-hub; then
    sh "$SCRIPT_DIR/configure-share.sh"
fi

mkdir -p \
    /opt \
    /jffs/configs \
    /jffs/scripts \
    /www/require/modules \
    /etc/router-lab \
    /usr/local/libexec/router-lab \
    /opt/etc/wireguard \
    /opt/etc/maestro \
    /opt/var/lib/maestro \
    /tmp/var/wwwext

echo "=== Step 2: Bootstrap Entware ==="
if [ ! -x /opt/bin/opkg ]; then
    echo "Downloading and running Entware generic installer..."
    curl -fLo /tmp/entware.sh https://bin.entware.net/aarch64-k3.10/installer/generic.sh
    /bin/sh /tmp/entware.sh
fi

if ! /opt/bin/opkg print-architecture | grep -q "aarch64-3.10"; then
    echo "Warning: /opt/bin/opkg print-architecture did not report aarch64-3.10" >&2
fi

# Ensure Entware tools are on PATH
cat > /etc/profile.d/entware.sh <<'EOF'
export PATH="/opt/bin:/opt/sbin:$PATH"
EOF
chmod 0644 /etc/profile.d/entware.sh
export PATH="/opt/bin:/opt/sbin:$PATH"

sh "$SCRIPT_DIR/configure-shell.sh"

echo "=== Step 3: Configure Entware OpenRC service ==="
cp "$FILES_DIR/entware.initd" /etc/init.d/entware
chmod 0755 /etc/init.d/entware
rc-update add entware default

echo "=== Step 4: Supply simulated firmware calls ==="
cp "$FILES_DIR/nvram" /bin/nvram
chmod 0755 /bin/nvram

if [ ! -f /etc/router-lab/nvram ]; then
    GUEST_IP=$(ip -4 addr show scope global 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1 || echo "")
    GUEST_IP="${GUEST_IP:-10.0.2.15}"
    cp "$FILES_DIR/nvram.initial" /etc/router-lab/nvram
    sed -i "s/^lan_ipaddr=.*/lan_ipaddr=$GUEST_IP/" /etc/router-lab/nvram
    chmod 0644 /etc/router-lab/nvram
    echo "Initialized /etc/router-lab/nvram (lan_ipaddr=$GUEST_IP)"
fi

cp "$FILES_DIR/service" /usr/local/libexec/router-lab/service
chmod 0755 /usr/local/libexec/router-lab/service

cp "$FILES_DIR/logread" /usr/local/libexec/router-lab/logread
chmod 0755 /usr/local/libexec/router-lab/logread

echo "=== Step 5: Configure real WireGuard and web root ==="
/opt/bin/opkg update
/opt/bin/opkg install wireguard-tools wg-quick dnsmasq nginx

# Check the running guest kernel only when provisioning a booted system.
if [ "$LAB_OFFLINE" = 1 ]; then
    mkdir -p /etc/modules-load.d
    printf '%s\n' wireguard > /etc/modules-load.d/router-lab-wireguard.conf
else
    modprobe wireguard 2>/dev/null || true
    if ip link add wgprobe type wireguard 2>/dev/null; then
        ip link del wgprobe
        echo "Kernel WireGuard support verified."
    else
        echo "Notice: WireGuard interface probe not available; check guest kernel modules."
    fi
fi

# WireGuard interface configuration
if [ ! -f /opt/etc/wireguard/wgs1.conf ]; then
    (
        umask 077
        WG_KEY=$(/opt/bin/wg genkey)
        cat > /opt/etc/wireguard/wgs1.conf <<EOF
[Interface]
PrivateKey = $WG_KEY
Address = 10.77.0.1/24
EOF
    )
    chmod 0600 /opt/etc/wireguard/wgs1.conf
    echo "Generated /opt/etc/wireguard/wgs1.conf"
fi

# Ensure wg-quick short name resolution finds the configuration
mkdir -p /etc/wireguard
ln -sf /opt/etc/wireguard/wgs1.conf /etc/wireguard/wgs1.conf

# Setup httpd
if [ ! -f /etc/router-lab/httpd.conf ]; then
    HTTPD_PASS=$(openssl rand -hex 12)
    printf '.asp:text/html\n/:lab:%s\n' "$HTTPD_PASS" > /etc/router-lab/httpd.conf
    chmod 0600 /etc/router-lab/httpd.conf
    printf 'user=lab\npassword=%s\n' "$HTTPD_PASS" > /etc/router-lab/httpd-credentials.txt
    chmod 0600 /etc/router-lab/httpd-credentials.txt
    echo "Generated /etc/router-lab/httpd.conf (credentials in /etc/router-lab/httpd-credentials.txt)"
fi

cp "$FILES_DIR/httpd.initd" /etc/init.d/router-lab-httpd
chmod 0755 /etc/init.d/router-lab-httpd
rc-update add router-lab-httpd default
if [ "$LAB_OFFLINE" = 0 ]; then
    rc-service router-lab-httpd restart 2>/dev/null || rc-service router-lab-httpd start
fi

# Terminate HTTPS independently of Entware NGINX, leaving ports 80/443 free.
if [ ! -f /etc/router-lab/httpds.crt ] || [ ! -f /etc/router-lab/httpds.key ]; then
    (
        umask 077
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -subj '/CN=router-lab' \
            -addext 'subjectAltName=DNS:router-lab,DNS:localhost,IP:127.0.0.1' \
            -keyout /etc/router-lab/httpds.key -out /etc/router-lab/httpds.crt
    )
fi
chmod 0600 /etc/router-lab/httpds.key
cp "$FILES_DIR/httpds.conf" /etc/router-lab/httpds.conf
cp "$FILES_DIR/httpds.initd" /etc/init.d/router-lab-httpds
chmod 0755 /etc/init.d/router-lab-httpds
rc-update add router-lab-httpds default
if [ "$LAB_OFFLINE" = 0 ]; then
    rc-service router-lab-httpds restart 2>/dev/null || rc-service router-lab-httpds start
fi

# Web root fixtures
cp "$FILES_DIR/menuTree.js" /www/require/modules/menuTree.js
chmod 0644 /www/require/modules/menuTree.js

cp "$FILES_DIR/state.js" /www/state.js
chmod 0644 /www/state.js

ln -sf /tmp/var/wwwext/user20.asp /www/user20.asp

echo "=== Step 6: Configure Maestro settings ==="
# Seed disabled firewall policy
for dir in /opt/etc/maestro /opt/var/lib/maestro; do
    if [ ! -f "$dir/firewall-policy.json" ]; then
        cp "$FILES_DIR/firewall-policy.json" "$dir/firewall-policy.json"
        chmod 0600 "$dir/firewall-policy.json"
    fi
done

if [ ! -f /opt/etc/maestro/maestro.toml ]; then
    OPENSSL_BIN=$(command -v openssl || echo "/usr/bin/openssl")
    IP_BIN=$(command -v ip || echo "/sbin/ip")
    AUTH_TOKEN=$(openssl rand -hex 24)

    sed -e "s|__AUTH_TOKEN__|$AUTH_TOKEN|" \
        -e "s|__OPENSSL_BIN__|$OPENSSL_BIN|" \
        -e "s|__IP_BIN__|$IP_BIN|" \
        "$FILES_DIR/maestro.toml.template" > /opt/etc/maestro/maestro.toml
    chmod 0600 /opt/etc/maestro/maestro.toml
    printf 'auth_token=%s\n' "$AUTH_TOKEN" > /opt/etc/maestro/auth-token.txt
    chmod 0600 /opt/etc/maestro/auth-token.txt
    echo "Generated /opt/etc/maestro/maestro.toml"
fi

echo "=== Step 7: Install Maestro IPK ==="
IPK_FILE="${PACKAGE:-}"
if [ -z "$IPK_FILE" ]; then
    for candidate in "$SCRIPT_DIR"/../../dist/maestro_*_aarch64-3.10.ipk; do
        if [ -f "$candidate" ] && { [ -z "$IPK_FILE" ] || [ "$candidate" -nt "$IPK_FILE" ]; }; then
            IPK_FILE="$candidate"
        fi
    done
fi

if [ -n "$IPK_FILE" ] && [ -f "$IPK_FILE" ]; then
    echo "Found package: $IPK_FILE"
    if [ ! -f "${IPK_FILE}.sha256" ]; then
        echo "Error: Missing package checksum: ${IPK_FILE}.sha256" >&2
        exit 1
    fi
    echo "Verifying SHA-256 checksum..."
    (cd "$(dirname "$IPK_FILE")" && sha256sum -c "$(basename "$IPK_FILE").sha256")
    echo "Installing IPK..."
    /opt/bin/opkg install "$IPK_FILE"
    echo "Maestro package installation complete."
    echo "Upgrading nginx..."
    /opt/bin/maestro upgrade-nginx
else
    if [ "$LAB_OFFLINE" = 1 ]; then
        echo 'Error: No Maestro IPK found; build it with make ipk before initializing the lab.' >&2
        exit 1
    fi
    echo "Notice: No IPK file found to install yet."
    echo "To install manually later, run: /opt/bin/opkg install <maestro_*.ipk>"
fi

echo ""
echo "============================================================"
echo "Guest Provisioning Complete!"
if [ "$LAB_OFFLINE" = 1 ]; then
    echo 'Services will start when the installed guest boots.'
fi
echo 'Log in as root to see credentials and browser links in the shell banner.'
echo "============================================================"
