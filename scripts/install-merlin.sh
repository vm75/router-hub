#!/bin/sh
set -eu

SCRIPT_DIR=$(dirname "$0")
REPO_DIR=$(dirname "$SCRIPT_DIR")

BINARY="${1:-./router-hub}"
CONFIG_DIR="/opt/etc/router-hub"
DATA_DIR="/opt/var/lib/router-hub"

[ "$(id -u)" = "0" ] || { echo "Run as root on the router." >&2; exit 1; }
[ -f "$BINARY" ] || { echo "Binary not found: $BINARY" >&2; exit 1; }

mkdir -p /opt/bin /opt/etc/init.d "$CONFIG_DIR" "$DATA_DIR" /opt/var/log/nginx /opt/var/run/router-hub
cp "$BINARY" /opt/bin/router-hub
chmod 0755 /opt/bin/router-hub
cp "$SCRIPT_DIR/S99router-hub" /opt/etc/init.d/S99router-hub
chmod 0755 /opt/etc/init.d/S99router-hub
if [ ! -f "$CONFIG_DIR/router-hub.toml" ]; then
    cp "$REPO_DIR/config/router-hub.example.toml" "$CONFIG_DIR/router-hub.toml"
    chmod 0600 "$CONFIG_DIR/router-hub.toml"
    TOKEN="$(openssl rand -hex 24)"
    sed -i "s/REPLACE-WITH-AT-LEAST-24-RANDOM-CHARACTERS/$TOKEN/" "$CONFIG_DIR/router-hub.toml"
    echo "Created $CONFIG_DIR/router-hub.toml. Review rendered_page and menu_tree before starting."
fi
if [ ! -f "$CONFIG_DIR/firewall-policy.json" ] && [ -f "$REPO_DIR/config/firewall-policy.example.json" ]; then
    cp "$REPO_DIR/config/firewall-policy.example.json" "$CONFIG_DIR/firewall-policy.json"
fi
if [ ! -f "$DATA_DIR/firewall-policy.json" ] && [ -f "$REPO_DIR/config/firewall-policy.example.json" ]; then
    cp "$REPO_DIR/config/firewall-policy.example.json" "$DATA_DIR/firewall-policy.json"
fi

FIREWALL_START=/jffs/scripts/firewall-start
if [ ! -f "$FIREWALL_START" ]; then
    printf '#!/bin/sh\n' >"$FIREWALL_START"
    chmod 0755 "$FIREWALL_START"
fi
if ! grep -Fq '# router-hub firewall reconciliation' "$FIREWALL_START"; then
    if tail -n 1 "$FIREWALL_START" | grep -Eq '^[[:space:]]*exit([[:space:]]|$)'; then
        sed -i '$i\
# router-hub firewall reconciliation\
/opt/etc/init.d/S99router-hub reconcile\
' "$FIREWALL_START"
    else
        printf '\n# router-hub firewall reconciliation\n/opt/etc/init.d/S99router-hub reconcile\n' >>"$FIREWALL_START"
    fi
fi

/opt/bin/router-hub --config "$CONFIG_DIR/router-hub.toml" check-config
/opt/etc/init.d/S99router-hub restart
printf '\nRouter Hub installed. Use the ASUS menu entry, or open http://<router-ip>:3030/?token=<auth-token>.\n'
