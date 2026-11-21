#!/bin/sh
# Shared first-install/upgrade configuration for tarball and Entware IPK installs.
set -eu

EXAMPLES_DIR="${1:?Usage: setup-merlin.sh EXAMPLES_DIR}"
CONFIG_DIR="/opt/etc/maestro"
DATA_DIR="/opt/var/lib/maestro"
MOSQUITTO_USER="${MOSQUITTO_USER:-}"
MOSQUITTO_PASS="${MOSQUITTO_PASS:-${MOSQUITTO_PASSWD:-}}"

# The lab installer configures the installed disk in a chroot before first boot.
# In that mode, complete setup while leaving all service lifecycle calls to boot.
[ "$(id -u)" = "0" ] || { echo "Run as root on the router." >&2; exit 1; }
[ -x /opt/bin/maestro ] || { echo "/opt/bin/maestro not installed" >&2; exit 1; }
mkdir -p /opt/etc/init.d "$CONFIG_DIR" "$DATA_DIR" "$DATA_DIR/dehydrated" /opt/var/log/nginx /opt/var/run/maestro
if [ "${MAESTRO_DEFER_START:-0}" != 1 ] && [ -x /opt/etc/init.d/S99maestro ]; then
    /opt/etc/init.d/S99maestro stop
fi

# Keep all state/NGINX paths in legacy user config; never relocate data implicitly.
# Copy rather than move to preserve rollback to Router Hub.
LEGACY_CONFIG=/opt/etc/router-hub/router-hub.toml
LEGACY_DATA=/opt/var/lib/router-hub
if [ ! -e "$CONFIG_DIR/maestro.toml" ] && [ -f "$LEGACY_CONFIG" ]; then
    cp -p "$LEGACY_CONFIG" "$CONFIG_DIR/maestro.toml"
    chmod 0600 "$CONFIG_DIR/maestro.toml"
    # The old IPK owned its DNS hook and may remove it on uninstall.
    # Move only packaged dehydrated executable/hook references into Maestro's tree.
    sed -i 's|/opt/var/lib/router-hub/dehydrated|/opt/var/lib/maestro/dehydrated|g' "$CONFIG_DIR/maestro.toml"
    echo "Adopted Router Hub configuration; existing state and NGINX inputs stay at their configured paths."
fi
if [ ! -f "$DATA_DIR/dehydrated/dehydrated" ] && [ -s "$LEGACY_DATA/dehydrated/dehydrated" ]; then
    cp -p "$LEGACY_DATA/dehydrated/dehydrated" "$DATA_DIR/dehydrated/dehydrated"
fi
if [ ! -f "$CONFIG_DIR/maestro.toml" ]; then
    cp "$EXAMPLES_DIR/maestro.example.toml" "$CONFIG_DIR/maestro.toml"
    chmod 0600 "$CONFIG_DIR/maestro.toml"
    TOKEN="$(openssl rand -hex 24)"
    sed -i "s/REPLACE-WITH-AT-LEAST-24-RANDOM-CHARACTERS/$TOKEN/" "$CONFIG_DIR/maestro.toml"
    echo "Created $CONFIG_DIR/maestro.toml. Review rendered_page and menu_tree before starting."
fi

# Relocate current-format inputs while Maestro is stopped.
/opt/bin/maestro --config "$CONFIG_DIR/maestro.toml" migrate-nginx-inputs

# Install the embedded main configuration, backing up a different nginx.conf.
# Saved inputs, existing shared fragments, and configured nginx paths are retained.
/opt/bin/maestro --config "$CONFIG_DIR/maestro.toml" init-nginx

# Install default dehydrated DNS-01 challenge hook if not already installed.
if [ ! -f "$DATA_DIR/dehydrated/dehydrated-dns01-hook.sh" ]; then
    if [ -f "$EXAMPLES_DIR/dehydrated-dns01-hook.sh" ]; then
        cp "$EXAMPLES_DIR/dehydrated-dns01-hook.sh" "$DATA_DIR/dehydrated/dehydrated-dns01-hook.sh"
    elif [ -f "$EXAMPLES_DIR/../scripts/dehydrated-dns01-hook.sh" ]; then
        cp "$EXAMPLES_DIR/../scripts/dehydrated-dns01-hook.sh" "$DATA_DIR/dehydrated/dehydrated-dns01-hook.sh"
    fi
fi
if [ -f "$DATA_DIR/dehydrated/dehydrated-dns01-hook.sh" ]; then
    chmod 0755 "$DATA_DIR/dehydrated/dehydrated-dns01-hook.sh"
fi

# Download the latest dehydrated executable on install.
mkdir -p "$DATA_DIR/dehydrated"
DEHYDRATED_BIN="$DATA_DIR/dehydrated/dehydrated"
DEHYDRATED_URL="https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated"

if ! /opt/bin/maestro --config "$CONFIG_DIR/maestro.toml" update-dehydrated 2>/dev/null || [ ! -s "$DEHYDRATED_BIN" ]; then
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DEHYDRATED_URL" -o "$DEHYDRATED_BIN" 2>/dev/null || \
            curl -fsSL -k "$DEHYDRATED_URL" -o "$DEHYDRATED_BIN" 2>/dev/null || true
    fi
    if [ ! -s "$DEHYDRATED_BIN" ] && command -v wget >/dev/null 2>&1; then
        wget -q -O "$DEHYDRATED_BIN" "$DEHYDRATED_URL" 2>/dev/null || \
            wget -q --no-check-certificate -O "$DEHYDRATED_BIN" "$DEHYDRATED_URL" 2>/dev/null || true
    fi
fi

if [ -s "$DEHYDRATED_BIN" ]; then
    chmod 0700 "$DEHYDRATED_BIN"
    echo "Dehydrated executable installed at $DEHYDRATED_BIN."
else
    echo "Warning: Could not download latest dehydrated during install; use Certificates > Update dehydrated once connected." >&2
fi

if [ -n "$MOSQUITTO_USER" ] && [ -n "$MOSQUITTO_PASS" ]; then
    mkdir -p /opt/etc/mosquitto
    HASH=$(openssl passwd -6 "$MOSQUITTO_PASS")
    printf '%s:%s\n' "$MOSQUITTO_USER" "$HASH" > /opt/etc/mosquitto/passwd
    chmod 0644 /opt/etc/mosquitto/passwd
    echo "Configured Mosquitto password for user '$MOSQUITTO_USER' in /opt/etc/mosquitto/passwd."
elif [ -n "$MOSQUITTO_USER" ] || [ -n "$MOSQUITTO_PASS" ]; then
    echo "Warning: Both --mosquitto-user and --mosquitto-pass (or MOSQUITTO_USER and MOSQUITTO_PASS env vars) are required." >&2
fi
# Repair permissions on existing installations as well as new ones.
chmod 0600 "$CONFIG_DIR/maestro.toml"
if [ -d /opt/etc/nginx/certs ]; then
    find /opt/etc/nginx/certs -type f -name 'privkey*.pem' -exec chmod 0644 {} \; # read access needed for nobody
fi
if [ ! -f "$CONFIG_DIR/firewall-policy.json" ] && [ -f "$EXAMPLES_DIR/firewall-policy.example.json" ]; then
    cp "$EXAMPLES_DIR/firewall-policy.example.json" "$CONFIG_DIR/firewall-policy.json"
fi
if [ ! -f "$DATA_DIR/firewall-policy.json" ] && [ -f "$EXAMPLES_DIR/firewall-policy.example.json" ]; then
    cp "$EXAMPLES_DIR/firewall-policy.example.json" "$DATA_DIR/firewall-policy.json"
fi
chmod 0600 "$CONFIG_DIR/firewall-policy.json" "$DATA_DIR/firewall-policy.json" 2>/dev/null || true

POST_MOUNT=/jffs/scripts/post-mount
if [ ! -f "$POST_MOUNT" ]; then
    printf '#!/bin/sh\n' >"$POST_MOUNT"
    chmod 0755 "$POST_MOUNT"
fi
if grep -qF 'router-hub firewall reconciliation' "$POST_MOUNT"; then
    sed -i 's|router-hub firewall reconciliation|maestro firewall reconciliation|g; s|S99router-hub reconcile|S99maestro reconcile|g' "$POST_MOUNT"
fi
if ! grep -qF 'maestro firewall reconciliation' "$POST_MOUNT"; then
    cat >> "$POST_MOUNT" <<'EOF'

# Maestro: firewall reconciliation
/opt/etc/init.d/S99maestro reconcile
EOF
fi

FIREWALL_START=/jffs/scripts/firewall-start
if [ ! -f "$FIREWALL_START" ]; then
    printf '#!/bin/sh\n' >"$FIREWALL_START"
    chmod 0755 "$FIREWALL_START"
fi
if grep -qF 'Router Hub: restore firewall hooks after Asuswrt rebuilds its firewall' "$FIREWALL_START"; then
    sed -i 's|Router Hub: restore firewall hooks after Asuswrt rebuilds its firewall|Maestro: restore firewall hooks after Asuswrt rebuilds its firewall|g; s|S99router-hub reconcile|S99maestro reconcile|g; s|logger -t router-hub|logger -t maestro|g' "$FIREWALL_START"
fi
if ! grep -qF 'Maestro: restore firewall hooks after Asuswrt rebuilds its firewall' "$FIREWALL_START"; then
    cat >> "$FIREWALL_START" <<'EOF'

# Maestro: restore firewall hooks after Asuswrt rebuilds its firewall
(
    attempt=0

    while [ "$attempt" -lt 30 ]; do
        if /opt/etc/init.d/S99maestro reconcile; then
            logger -t maestro \
                "firewall-start reconciliation completed"
            exit 0
        fi

        attempt=$((attempt + 1))
        sleep 1
    done

    logger -t maestro \
        "firewall-start reconciliation failed after 30 attempts"
) &
EOF
fi

/opt/bin/maestro --config "$CONFIG_DIR/maestro.toml" check-config
if [ "${MAESTRO_DEFER_START:-0}" != 1 ]; then
    /opt/etc/init.d/S99maestro restart
fi
printf '\nMaestro installed. Use the ASUS menu entry, or open http://<router-ip>:3030/#token=<auth-token>.\n'
