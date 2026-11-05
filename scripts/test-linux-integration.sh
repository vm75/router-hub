#!/usr/bin/env bash
set -euo pipefail

# Real, unprivileged Linux integration smoke test. No mocks, host service
# configuration changes, DNS provider calls, or firewall rule modifications.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for tool in cargo nginx openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Missing required command: $tool" >&2
        exit 2
    }
done

python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"; import jinja2' || {
    echo 'Activate a Python 3.11+ environment with requirements.txt installed.' >&2
    exit 2
}
nginx_bin=$(command -v nginx)
lab=$(mktemp -d "${TMPDIR:-/tmp}/router-hub-linux.XXXXXX")
hub_pid=
keep_lab=${ROUTER_HUB_KEEP_LINUX_LAB:-0}

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n "$hub_pid" ]]; then
        kill "$hub_pid" 2>/dev/null || true
        wait "$hub_pid" 2>/dev/null || true
    fi
    if [[ -s "$lab/run/nginx.pid" ]]; then
        "$nginx_bin" -p "$lab/nginx/" -c "$lab/nginx/nginx.conf" -s quit >/dev/null 2>&1 || true
    fi
    if [[ "$keep_lab" == "1" ]]; then
        echo "Linux integration lab retained: $lab"
    else
        rm -rf -- "$lab"
    fi
    exit "$result"
}
trap cleanup EXIT

port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}
api_port=$(port)
nginx_port=$(port)
while [[ "$nginx_port" == "$api_port" ]]; do nginx_port=$(port); done
nginx_tls_port=$(port)
while [[ "$nginx_tls_port" == "$api_port" || "$nginx_tls_port" == "$nginx_port" ]]; do nginx_tls_port=$(port); done
token=$(openssl rand -hex 24)
mkdir -p "$lab"/{data,run,logs/nginx,nginx/conf.d,nginx/domains-available,nginx/domains-enabled,nginx/snippets,init.d,wireguard}
mkdir -p "$lab/tmp" "$lab/nginx/logs"

# No automatic bans or external firewall writes in this unprivileged suite.
printf '%s\n' '{"enabled":false,"observe_only":false,"rules":[],"allowlist":[]}' > "$lab/data/firewall-policy.json"

python3 "$repo_root/scripts/render-nginx-config.py" \
    "$repo_root/config/nginx" "$lab/nginx" \
    --var-dir "$lab/var" --pid-path "$lab/run/nginx.pid" \
    --error-log-path "$lab/var/log/nginx/error.log" \
    --acme-directory "$lab/certs/acme-challenge" \
    --http-port "$nginx_port" --https-port "$nginx_tls_port"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
    -keyout "$lab/nginx/certs/default/privkey.pem" \
    -out "$lab/nginx/certs/default/fullchain.pem" >/dev/null 2>&1
mkdir -p "$lab/tmp"
cat > "$lab/nginx/conf.d/00-linux-default.conf" <<EOF
server {
    server_name 127.0.0.1;
    listen 127.0.0.1:$nginx_port;
    location / { return 200 'router-hub linux nginx'; }
}
EOF

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
data_dir = "$lab/data"
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
openssl = "$(command -v openssl)"
ip = "/usr/sbin/ip"
ping = "/bin/ping"

[asus_ui]
enabled = false
rendered_page = "$lab/router-hub.asp"

[services]
init_dir = "$lab/init.d"
log_dirs = ["$lab/logs"]

[nginx]
root_dir = "$lab/nginx"
config_path = "$lab/nginx/nginx.conf"
prefix_path = "$lab/nginx"
pid_path = "$lab/run/nginx.pid"
domains_available_dir = "$lab/nginx/domains-available"
domains_enabled_dir = "$lab/nginx/domains-enabled"
domain_upstream_map_path = "$lab/nginx/conf.d/02_domain_upstream_map.conf"
subdomain_upstream_map_path = "$lab/nginx/conf.d/03_subdomain_upstream_map.conf"
subfolder_upstream_map_path = "$lab/nginx/conf.d/04_subfolder_upstream_map.conf"
http_forwarder_path = "$lab/nginx/conf.d/05-http-to-https.conf"
log_dir = "$lab/var/log/nginx"

[certificates]
certs_dir = "$lab/certs"

[firewall]
log_dirs = ["$lab/var/log/nginx"]

[adguard]
enabled = false
lan_ip = "127.0.0.1"

[system]
wan_interface = "lo"
EOF

cd "$repo_root"
cargo build --quiet --locked
bin="$repo_root/target/debug/router-hub"
"$bin" --config "$lab/router-hub.toml" --linux-mode check-config
"$bin" --config "$lab/router-hub.toml" --linux-mode serve >"$lab/logs/router-hub.stdout" 2>&1 &
hub_pid=$!

api="http://127.0.0.1:$api_port"
ready=false
for _ in $(seq 1 80); do
    if curl --silent --fail "$api/healthz" >/dev/null; then
        ready=true
        break
    fi
    if ! kill -0 "$hub_pid" 2>/dev/null; then
        cat "$lab/logs/router-hub.stdout" >&2
        echo "Router Hub exited before becoming ready" >&2
        exit 1
    fi
    sleep 0.25
done
if [[ "$ready" != true ]]; then
    cat "$lab/logs/router-hub.stdout" >&2
    echo "Router Hub did not become ready" >&2
    exit 1
fi

get() {
    curl --silent --show-error --fail-with-body -H "Authorization: Bearer $token" "$api$1"
}
post() {
    curl --silent --show-error --fail-with-body -X POST -H "Authorization: Bearer $token" "$api$1"
}
real_result() {
    python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["success"] is True and x["simulated"] is False, x'
}

unauth=$(curl --silent --output /dev/null --write-out '%{http_code}' "$api/api/runtime")
[[ "$unauth" == 401 ]] || { echo "Expected HTTP 401, got $unauth" >&2; exit 1; }

get /api/runtime | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["test_mode"] is False and x["platform"] == "linux", x'
get /api/system/usage | python3 -c 'import json,sys; x=json.load(sys.stdin); assert "cpu" in x and "memory" in x, x'
get /api/firewall | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["policy"]["enabled"] is False, x'

post /api/nginx/test | real_result
post /api/nginx/start | real_result
get /api/nginx/status | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["running"] is True, x'
[[ $(curl --silent --fail "http://127.0.0.1:$nginx_port/") == "router-hub linux nginx" ]]

# Regeneration must retain the lab's non-root runtime options and listener ports.
get /api/nginx/settings > "$lab/nginx-settings.json"
python3 - "$lab/nginx-settings.json" "$lab/nginx" <<'PYSETTINGS'
import json, sys
settings = json.load(open(sys.argv[1]))
assert settings['shared']['temp_dir'] == str(__import__('pathlib').Path(sys.argv[2]).parent / 'tmp'), settings
assert settings['shared']['nginx_user'] == '', settings
assert settings['shared']['nginx_daemon'] is True, settings
PYSETTINGS
curl --silent --show-error --fail-with-body -X PUT \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    --data-binary "@$lab/nginx-settings.json" "$api/api/nginx/settings" >/dev/null
post /api/nginx/test | real_result
[[ $(curl --silent --fail "http://127.0.0.1:$nginx_port/") == "router-hub linux nginx" ]]

# Exercise the settings-only managed-site workflow against real nginx.
# Managed hosts use their own certificate folder; keep this entirely self-signed.
mkdir -p "$lab/nginx/certs/linux_test"
cp "$lab/nginx/certs/default/fullchain.pem" "$lab/nginx/certs/default/privkey.pem" "$lab/nginx/certs/linux_test/"
curl --silent --show-error --fail-with-body -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    --data '{"domain":"linux.test","name":"linux.test","enabled":true,"settings":{"disable_root":true,"enable_lanonly":false,"client_max_body_size":"2M"}}' \
    "$api/api/nginx/objects/domain" >/dev/null
[[ -f "$lab/nginx/domains-available/linux.test/root.conf" ]]
get /api/nginx/objects/domain/linux.test/linux.test | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["settings"]["client_max_body_size"] == "2M", x'
python3 - "$lab/nginx/settings/sites.toml" <<'PYSITES'
import sys, tomllib
with open(sys.argv[1], 'rb') as stream:
    sites = tomllib.load(stream)['sites']
site, = sites.values()
assert site['domain'] == 'linux.test' and site['enabled'] is True, site
assert site['client_max_body_size'] == '2M', site
PYSITES
curl --silent --show-error --fail-with-body -X PUT \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    --data '{"settings":{"disable_root":true,"enable_lanonly":false,"client_max_body_size":"3M"}}' \
    "$api/api/nginx/objects/domain/linux.test/linux.test" >/dev/null
# Shared-settings regeneration must preserve the saved site override.
curl --silent --show-error --fail-with-body -X PUT \
    -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
    --data-binary "@$lab/nginx-settings.json" "$api/api/nginx/settings" >/dev/null
get /api/nginx/objects/domain/linux.test/linux.test | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["settings"]["client_max_body_size"] == "3M" and x["settings"]["enable_lanonly"] is False and "include snippets/restrict.conf;" not in x["content"], x'
# The bundle intentionally drops scanner user agents, including curl's default.
code=$(curl --silent --show-error --insecure --noproxy '*' \
    --user-agent 'RouterHub-Linux-Smoke/1.0' \
    --resolve "linux.test:$nginx_tls_port:127.0.0.1" \
    --output /dev/null --write-out '%{http_code}' "https://linux.test:$nginx_tls_port/")
[[ "$code" == 404 ]] || { echo "Expected managed site HTTP 404, got $code" >&2; exit 1; }
curl --silent --show-error --fail-with-body -X DELETE \
    -H "Authorization: Bearer $token" "$api/api/nginx/objects/domain/linux.test/linux.test" >/dev/null
[[ ! -e "$lab/nginx/domains-available/linux.test/root.conf" ]]
post /api/nginx/test | real_result
post /api/nginx/reload | real_result
post /api/nginx/stop | real_result

echo "PASS: native Linux router-hub uses real nginx, filesystem, auth, metrics and API"
