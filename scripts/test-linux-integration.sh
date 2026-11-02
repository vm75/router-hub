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
token=$(openssl rand -hex 24)
mkdir -p "$lab"/{data,run,logs/nginx,nginx/conf.d,nginx/domains-available,nginx/domains-enabled,nginx/templates,init.d,wireguard}

# No automatic bans or external firewall writes in this unprivileged suite.
printf '%s\n' '{"enabled":false,"observe_only":false,"rules":[],"allowlist":[]}' > "$lab/data/firewall-policy.json"

cat > "$lab/nginx/nginx.conf" <<EOF
worker_processes 1;
pid $lab/run/nginx.pid;
error_log $lab/logs/nginx/error.log;
events { worker_connections 128; }
http {
    access_log $lab/logs/nginx/access.log;
    include $lab/nginx/conf.d/*.conf;
    include $lab/nginx/domains-enabled/*/root.conf;
    server {
        listen 127.0.0.1:$nginx_port;
        location / { return 200 'router-hub linux nginx'; }
    }
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
templates_dir = "$lab/nginx/templates"
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

cd "$repo_root"
cargo build --quiet
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

get /api/runtime | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["test_mode"] is False, x'
get /api/system/usage | python3 -c 'import json,sys; x=json.load(sys.stdin); assert "cpu" in x and "memory" in x, x'
get /api/firewall | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["policy"]["enabled"] is False, x'

post /api/nginx/test | real_result
post /api/nginx/start | real_result
get /api/nginx/status | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["running"] is True, x'
[[ $(curl --silent --fail "http://127.0.0.1:$nginx_port/") == "router-hub linux nginx" ]]

# Exercise a real file mutation through the API, then validate real nginx again.
curl --silent --show-error --fail-with-body -X POST \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    --data '{"domain":"linux.test","name":"linux.test","enabled":false,"content":"server { server_name linux.test; return 200; }"}' \
    "$api/api/nginx/objects/domain" >/dev/null
[[ -f "$lab/nginx/domains-available/linux.test/root.conf" ]]
post /api/nginx/test | real_result
post /api/nginx/reload | real_result
post /api/nginx/stop | real_result

echo "PASS: native Linux router-hub uses real nginx, filesystem, auth, metrics and API"
