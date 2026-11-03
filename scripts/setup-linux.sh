#!/usr/bin/env bash
set -euo pipefail

# Prepare a persistent, unprivileged Linux lab; never replace existing files.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
lab="$repo_root/data/linux"
missing=0
for tool in cargo nginx openssl curl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Missing required command: %s\n' "$tool" >&2
        missing=1
    fi
done
if (( missing )); then
    echo 'Install the missing commands with your system package manager, then rerun this script.' >&2
    exit 2
fi
nginx_bin=$(command -v nginx)
dehydrated_bin=$(command -v dehydrated || true)
if [[ -z "$dehydrated_bin" ]]; then
    dehydrated_bin="$lab/certs/dehydrated"
    echo "Dehydrated is not installed. Use Certificates > Update dehydrated after setup."
fi
api_port=3030
nginx_port=8080
umask 077
mkdir -p "$lab"/{state,run,logs/nginx,nginx/conf.d,nginx/domains-available,nginx/domains-enabled,nginx/templates,nginx/snippets,init.d,wireguard,certs}
mkdir -p "$lab/nginx"/{client-body,proxy,fastcgi,uwsgi,scgi,logs}

# Install the shared, portable nginx templates while preserving local edits.
cp -an "$repo_root/config/nginx/templates/." "$lab/nginx/templates/"
cp -an "$repo_root/config/nginx/snippets/." "$lab/nginx/snippets/"
cp -an "$repo_root/config/nginx/conf.d/." "$lab/nginx/conf.d/"
if [[ ! -e "$lab/nginx/composer.toml" && ! -L "$lab/nginx/composer.toml" ]]; then
    cp "$repo_root/config/nginx/composer.toml" "$lab/nginx/composer.toml"
fi
if [[ ! -e "$lab/nginx/mime.types" && ! -L "$lab/nginx/mime.types" ]]; then
    install -m 644 "$repo_root/config/nginx/mime.types" "$lab/nginx/mime.types"
fi

if [[ ! -e "$lab/state/firewall-policy.json" && ! -L "$lab/state/firewall-policy.json" ]]; then
    printf '%s\n' '{"enabled":false,"observe_only":false,"rules":[],"allowlist":[]}' > "$lab/state/firewall-policy.json"
fi

if [[ ! -e "$lab/nginx/nginx.conf" && ! -L "$lab/nginx/nginx.conf" ]]; then
    python3 "$repo_root/scripts/render-nginx-config.py" \
        "$repo_root/config/nginx/nginx.conf.template" \
        "$lab/nginx/nginx.conf" "$lab/run/nginx.pid" "$lab/logs/nginx/error.log"
    cat > "$lab/nginx/conf.d/00-linux-default.conf" <<EOF
server {
    listen $nginx_port;
    location ^~ /.well-known/acme-challenge/ {
        alias $lab/certs/acme-challenge/;
        default_type text/plain;
    }
    location / { return 200 'router-hub linux nginx'; }
}
EOF
fi

if [[ ! -e "$lab/router-hub.toml" && ! -L "$lab/router-hub.toml" ]]; then
    token=$(openssl rand -hex 24)
cat > "$lab/router-hub.toml" <<EOF
platform = "linux"
test_mode = false

[server]
bind = "127.0.0.1"
port = $api_port
auth_token = "$token"
allowed_origins = ["http://127.0.0.1:$api_port"]
daemonize = false

[paths]
data_dir = "$lab/state"
runtime_dir = "$lab/run"
log_file = "$lab/logs/router-hub.log"
hosts_add = "$lab/hosts.add"
dnsmasq_conf_add = "$lab/dnsmasq.conf.add"
wireguard_conf = "$lab/wireguard/wglab.conf"
proc_stat = "/proc/stat"
proc_meminfo = "/proc/meminfo"
proc_net_dev = "/proc/net/dev"
proc_uptime = "/proc/uptime"
proc_loadavg = "/proc/loadavg"

[commands]
nginx = "$nginx_bin"
dehydrated = "$dehydrated_bin"
openssl = "$(command -v openssl)"
ip = "/usr/sbin/ip"
ping = "/bin/ping"

[asus_ui]
enabled = false
rendered_page = "$lab/router-hub.asp"

[services]
init_dir = "$repo_root/data/linux/init.d"
log_dirs = ["$lab/logs"]

[nginx]
root_dir = "$lab/nginx"
config_path = "$lab/nginx/nginx.conf"
prefix_path = "$lab/nginx"
pid_path = "$lab/run/nginx.pid"
domains_available_dir = "$lab/nginx/domains-available"
domains_enabled_dir = "$lab/nginx/domains-enabled"
templates_dir = "$lab/nginx/templates"
composer_path = "$lab/nginx/composer.toml"
domain_upstream_map_path = "$lab/nginx/conf.d/02_domain_upstream_map.conf"
subdomain_upstream_map_path = "$lab/nginx/conf.d/03_subdomain_upstream_map.conf"
subfolder_upstream_map_path = "$lab/nginx/conf.d/04_subfolder_upstream_map.conf"
http_forwarder_path = "$lab/nginx/conf.d/05-http-to-https.conf"
log_dir = "$lab/logs/nginx"

[certificates]
certs_dir = "$lab/certs"

[firewall]
log_dirs = ["$lab/logs/nginx"]

[adguard]
enabled = false
lan_ip = "127.0.0.1"

[system]
wan_interface = "lo"
EOF

fi

mkdir -p "$repo_root/data/linux/init.d"
for name in S80nginx S99router-hub; do
    if [[ ! -e "$repo_root/data/linux/init.d/$name" && ! -e "$repo_root/data/linux/init.d/.disabled.$name" ]]; then
        install -m 700 "$repo_root/scripts/linux-init.py" "$repo_root/data/linux/init.d/$name"
    fi
done

printf 'Linux lab ready: %s\n' "$lab"
printf 'Auth token is stored in %s/router-hub.toml\n' "$lab"
printf 'Start from the repository root:\n  cargo run -- --config data/linux/router-hub.toml --linux-mode serve\n'
echo 'New configs use http://127.0.0.1:3030 and nginx port 8080. Existing files are preserved.'
echo 'Optional feature tools: ip, ping, wg, wg-quick, dehydrated, ipset, iptables, ip6tables.'
echo 'Configure their paths before testing those features; firewall enforcement requires an isolated VM or network namespace.'
