#!/bin/sh
#
# collect-router-hub-diagnostics.sh
#
# Read-only diagnostics collector for Router Hub on Asuswrt-Merlin.
# It collects firewall/ban state, enforcement counters, bounded relevant logs,
# Router Hub API status (when locally reachable), and minimal router context.
#
# Defaults:
#   OUTPUT_DIR=/tmp
#   MAX_LOG_BYTES=1048576      # 1 MiB per configured log
#   SAMPLE_SECONDS=0           # set e.g. 600 to get a 10-minute counter delta
#   ROUTER_HUB_CONFIG=/opt/etc/router-hub/router-hub.toml
#
# Example:
#   chmod 700 collect-router-hub-diagnostics.sh
#   SAMPLE_SECONDS=600 ./collect-router-hub-diagnostics.sh
#
# The resulting archive can contain public attacker IPs, URLs, internal
# subnets/allowlists, and selected log content. Review before sharing.

umask 077

PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

OUTPUT_DIR="${OUTPUT_DIR:-/tmp}"
MAX_LOG_BYTES="${MAX_LOG_BYTES:-1048576}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-0}"
CONFIG="${ROUTER_HUB_CONFIG:-/opt/etc/router-hub/router-hub.toml}"

STAMP="$(date '+%Y%m%d-%H%M%S' 2>/dev/null || echo unknown-time)"
HOST="$(hostname 2>/dev/null || echo router)"
WORK="${OUTPUT_DIR}/router-hub-diagnostics-${HOST}-${STAMP}.$$"
BASE="router-hub-diagnostics-${HOST}-${STAMP}"
ARCHIVE="${OUTPUT_DIR}/${BASE}.tar.gz"

mkdir -p "$WORK" 2>/dev/null || {
    echo "ERROR: cannot create $WORK" >&2
    exit 1
}
for d in system router-hub firewall logs nginx; do
    mkdir -p "$WORK/$d" 2>/dev/null || {
        echo "ERROR: cannot create $WORK/$d" >&2
        exit 1
    }
done

cleanup() {
    rm -rf "$WORK" 2>/dev/null
}
trap cleanup EXIT HUP INT TERM

note() {
    printf '%s\n' "$*" >&2
}

have() {
    command -v "$1" >/dev/null 2>&1
}

toml_get() {
    # Usage: toml_get section key file
    section="$1"
    key="$2"
    file="$3"
    [ -r "$file" ] || return 0
    awk -v want_section="$section" -v want_key="$key" '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            s=$0
            gsub(/^[[:space:]]*\[/, "", s)
            gsub(/\][[:space:]]*$/, "", s)
            inside=(s == want_section)
            next
        }
        inside {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            if (line ~ "^[[:space:]]*" want_key "[[:space:]]*=") {
                sub("^[[:space:]]*" want_key "[[:space:]]*=[[:space:]]*", "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (line ~ /^".*"$/) {
                    sub(/^"/, "", line)
                    sub(/"$/, "", line)
                }
                print line
                exit
            }
        }
    ' "$file"
}

sanitize_toml() {
    src="$1"
    dst="$2"
    awk '
        {
            low=tolower($0)
            if (low ~ /^[[:space:]]*[a-z0-9_.-]*(auth_token|password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token)[a-z0-9_.-]*[[:space:]]*=/) {
                eq=index($0, "=")
                if (eq > 0) {
                    print substr($0, 1, eq) " \"<redacted>\""
                    next
                }
            }
            print
        }
    ' "$src" > "$dst"
}

run_to_file() {
    out="$1"
    shift
    {
        printf '$'
        for arg in "$@"; do printf ' %s' "$arg"; done
        printf '\n'
        "$@"
    } >"$out" 2>&1
}

resolve_cmd() {
    # Usage: resolve_cmd configured_path fallback_name
    configured="$1"
    fallback="$2"
    if [ -n "$configured" ] && [ -x "$configured" ]; then
        printf '%s\n' "$configured"
    elif have "$fallback"; then
        command -v "$fallback"
    fi
}

api_get() {
    # Usage: api_get path output_file auth(0|1)
    path="$1"
    outfile="$2"
    need_auth="$3"
    url="${API_BASE}${path}"

    if [ "$need_auth" = "1" ] && [ -z "$AUTH_TOKEN" ]; then
        printf 'skipped: auth token unavailable\n' >"$outfile"
        return 0
    fi

    CURL_BIN=""
    WGET_BIN=""
    for candidate in /opt/bin/curl /usr/bin/curl /bin/curl; do
        if [ -x "$candidate" ]; then CURL_BIN="$candidate"; break; fi
    done
    [ -n "$CURL_BIN" ] || { have curl && CURL_BIN="$(command -v curl)"; }

    for candidate in /usr/sbin/wget /usr/bin/wget /opt/bin/wget /bin/wget; do
        if [ -x "$candidate" ]; then WGET_BIN="$candidate"; break; fi
    done
    [ -n "$WGET_BIN" ] || { have wget && WGET_BIN="$(command -v wget)"; }

    if [ -n "$CURL_BIN" ]; then
        if [ "$need_auth" = "1" ]; then
            "$CURL_BIN" -fsS --connect-timeout 3 --max-time 10 \
                -H "Authorization: Bearer ${AUTH_TOKEN}" \
                "$url" >"$outfile" 2>"${outfile}.error" || true
        else
            "$CURL_BIN" -fsS --connect-timeout 3 --max-time 10 \
                "$url" >"$outfile" 2>"${outfile}.error" || true
        fi
    elif [ -n "$WGET_BIN" ]; then
        if [ "$need_auth" = "1" ]; then
            "$WGET_BIN" -q -T 10 -O "$outfile" \
                --header="Authorization: Bearer ${AUTH_TOKEN}" \
                "$url" 2>"${outfile}.error" || true
        else
            "$WGET_BIN" -q -T 10 -O "$outfile" \
                "$url" 2>"${outfile}.error" || true
        fi
    else
        printf 'skipped: curl/wget not found in known ASUS/Entware paths or PATH\n' >"$outfile"
    fi

    [ -s "${outfile}.error" ] || rm -f "${outfile}.error" 2>/dev/null
}

firewall_snapshot() {
    label="$1"
    dest="$WORK/firewall/$label"
    mkdir -p "$dest"

    if [ -n "$IPSET" ]; then
        run_to_file "$dest/ipset-v4.txt" "$IPSET" list "$SET4"
        run_to_file "$dest/ipset-v6.txt" "$IPSET" list "$SET6"
    fi

    if [ -n "$IPTABLES" ]; then
        run_to_file "$dest/iptables-input-parent.txt" "$IPTABLES" -nvxL INPUT --line-numbers
        run_to_file "$dest/iptables-forward-parent.txt" "$IPTABLES" -nvxL FORWARD --line-numbers
        run_to_file "$dest/iptables-router-hub-input.txt" "$IPTABLES" -nvxL ROUTER_HUB_INPUT --line-numbers
        run_to_file "$dest/iptables-router-hub-forward.txt" "$IPTABLES" -nvxL ROUTER_HUB_FORWARD --line-numbers
    fi

    if [ -n "$IP6TABLES" ]; then
        run_to_file "$dest/ip6tables-input-parent.txt" "$IP6TABLES" -nvxL INPUT --line-numbers
        run_to_file "$dest/ip6tables-forward-parent.txt" "$IP6TABLES" -nvxL FORWARD --line-numbers
        run_to_file "$dest/ip6tables-router-hub-input.txt" "$IP6TABLES" -nvxL ROUTER_HUB_INPUT --line-numbers
        run_to_file "$dest/ip6tables-router-hub-forward.txt" "$IP6TABLES" -nvxL ROUTER_HUB_FORWARD --line-numbers
    fi

    date -u '+%Y-%m-%dT%H:%M:%SZ' >"$dest/captured-at-utc.txt" 2>/dev/null || true
}

copy_bounded_log() {
    src="$1"
    [ -r "$src" ] || return 0

    safe="$(printf '%s' "$src" | sed 's#^/##; s#[^A-Za-z0-9._-]#_#g')"
    dst="$WORK/logs/${safe}.tail"

    {
        printf 'source=%s\n' "$src"
        if have wc; then
            wc -c "$src" 2>/dev/null | awk '{print "source_bytes=" $1}'
        fi
        printf 'max_collected_bytes=%s\n' "$MAX_LOG_BYTES"
        printf '%s\n' '---'
    } >"$dst"

    # For access-style logs, prefer failures/suspicious responses to reduce
    # irrelevant browsing history. Other security logs are tailed directly.
    case "$src" in
        *access.log|*access_log*)
            if tail -c "$MAX_LOG_BYTES" "$src" >/dev/null 2>&1; then
                tail -c "$MAX_LOG_BYTES" "$src" 2>/dev/null \
                    | grep -E '" [45][0-9][0-9] ' >>"$dst" 2>/dev/null || true
            else
                tail -n 5000 "$src" 2>/dev/null \
                    | grep -E '" [45][0-9][0-9] ' >>"$dst" 2>/dev/null || true
            fi
            ;;
        *)
            if tail -c "$MAX_LOG_BYTES" "$src" >>"$dst" 2>/dev/null; then
                :
            else
                tail -n 5000 "$src" >>"$dst" 2>/dev/null || true
            fi
            ;;
    esac

    printf '%s\n' "$src" >>"$WORK/logs/collected-paths.txt"
}

note "Collecting Router Hub diagnostics into $WORK"

# ---- Router Hub configuration and state ------------------------------------

DATA_DIR="/opt/etc/router-hub"
BIND=""
PORT="3030"
AUTH_TOKEN=""
IPSET_CFG=""
IPTABLES_CFG=""
IP6TABLES_CFG=""
NGINX_CFG=""
SET4="router_hub_bans4"
SET6="router_hub_bans6"

if [ -r "$CONFIG" ]; then
    sanitize_toml "$CONFIG" "$WORK/router-hub/router-hub.sanitized.toml"

    v="$(toml_get paths data_dir "$CONFIG")"; [ -n "$v" ] && DATA_DIR="$v"
    v="$(toml_get server bind "$CONFIG")"; [ -n "$v" ] && BIND="$v"
    v="$(toml_get server port "$CONFIG")"; [ -n "$v" ] && PORT="$v"
    AUTH_TOKEN="$(toml_get server auth_token "$CONFIG")"

    IPSET_CFG="$(toml_get commands ipset "$CONFIG")"
    IPTABLES_CFG="$(toml_get commands iptables "$CONFIG")"
    IP6TABLES_CFG="$(toml_get commands ip6tables "$CONFIG")"
    NGINX_CFG="$(toml_get commands nginx "$CONFIG")"

    v="$(toml_get firewall set_name_v4 "$CONFIG")"; [ -n "$v" ] && SET4="$v"
    v="$(toml_get firewall set_name_v6 "$CONFIG")"; [ -n "$v" ] && SET6="$v"
else
    printf 'config not readable: %s\n' "$CONFIG" >"$WORK/router-hub/config-missing.txt"
fi

POLICY="${DATA_DIR}/firewall-policy.json"
STATE="${DATA_DIR}/ban-attack-state.json"

if [ -r "$POLICY" ]; then
    cp "$POLICY" "$WORK/router-hub/firewall-policy.json"
fi
if [ -r "$STATE" ]; then
    cp "$STATE" "$WORK/router-hub/ban-attack-state.json"
fi

if [ -x /opt/bin/router-hub ] && have sha256sum; then
    sha256sum /opt/bin/router-hub >"$WORK/router-hub/router-hub-binary.sha256" 2>/dev/null || true
fi

# ---- Local API -------------------------------------------------------------

case "$BIND" in
    ""|0.0.0.0)
        API_HOST="127.0.0.1"
        ;;
    "::"|"[::]")
        API_HOST="[::1]"
        ;;
    *:*)
        API_HOST="[$BIND]"
        ;;
    *)
        API_HOST="$BIND"
        ;;
esac
API_BASE="http://${API_HOST}:${PORT}"

printf '%s\n' "$API_BASE" >"$WORK/router-hub/api-base-used.txt"
api_get "/healthz" "$WORK/router-hub/api-healthz.txt" 0
api_get "/api/version" "$WORK/router-hub/api-version.json" 0
api_get "/api/dashboard" "$WORK/router-hub/api-dashboard.json" 1
api_get "/api/system/usage" "$WORK/router-hub/api-system-usage.json" 1
api_get "/api/firewall?include_bans=true" "$WORK/router-hub/api-firewall.json" 1

# Pretty-print useful JSON if jq exists, while retaining originals.
if have jq; then
    for f in \
        "$WORK/router-hub/api-version.json" \
        "$WORK/router-hub/api-dashboard.json" \
        "$WORK/router-hub/api-system-usage.json" \
        "$WORK/router-hub/api-firewall.json" \
        "$WORK/router-hub/firewall-policy.json" \
        "$WORK/router-hub/ban-attack-state.json"
    do
        [ -s "$f" ] || continue
        jq . "$f" >"${f}.pretty" 2>/dev/null || rm -f "${f}.pretty"
    done

    if [ -s "$WORK/router-hub/ban-attack-state.json" ]; then
        jq '{
          schema_version,
          saved_at,
          active_bans: (.active_bans | length),
          scores: (.scores | length),
          reputation_entries: (.reputation | length),
          subnet_offenders: (.subnet_offenders | length),
          rule_stats
        }' "$WORK/router-hub/ban-attack-state.json" \
            >"$WORK/router-hub/state-summary.json" 2>/dev/null || true
    fi
fi

# ---- System/router context -------------------------------------------------

{
    echo "captured_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
    echo "hostname=$HOST"
    echo "uid=$(id -u 2>/dev/null || echo unknown)"
    echo "config=$CONFIG"
    echo "data_dir=$DATA_DIR"
    echo "sample_seconds=$SAMPLE_SECONDS"
    echo "max_log_bytes=$MAX_LOG_BYTES"
} >"$WORK/system/collector-settings.txt"

run_to_file "$WORK/system/uname.txt" uname -a
[ -r /proc/version ] && cp /proc/version "$WORK/system/proc-version.txt"
[ -r /proc/uptime ] && cp /proc/uptime "$WORK/system/proc-uptime.txt"
[ -r /proc/loadavg ] && cp /proc/loadavg "$WORK/system/proc-loadavg.txt"
[ -r /proc/meminfo ] && grep -E '^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree):' /proc/meminfo \
    >"$WORK/system/memory-summary.txt" 2>/dev/null || true
[ -r /proc/sys/net/ipv4/ip_forward ] && cp /proc/sys/net/ipv4/ip_forward "$WORK/system/ipv4-forwarding.txt"
[ -r /proc/sys/net/ipv6/conf/all/forwarding ] && cp /proc/sys/net/ipv6/conf/all/forwarding "$WORK/system/ipv6-forwarding.txt"

if have df; then
    df -h /tmp /jffs /opt >"$WORK/system/disk.txt" 2>&1 || df -h >"$WORK/system/disk.txt" 2>&1 || true
fi

if have ps; then
    ps 2>&1 | grep -E '[r]outer-hub|[n]ginx' >"$WORK/system/processes-router-hub-nginx.txt" 2>/dev/null || true
fi

NVRAM="$(resolve_cmd "/bin/nvram" nvram)"
if [ -n "$NVRAM" ]; then
    {
        for k in productid odmpid firmver buildno extendno; do
            val="$("$NVRAM" get "$k" 2>/dev/null || true)"
            [ -n "$val" ] && printf '%s=%s\n' "$k" "$val"
        done
    } >"$WORK/system/asus-model-firmware.txt"
fi

# ---- Firewall/ipset enforcement snapshots ---------------------------------

IPSET="$(resolve_cmd "$IPSET_CFG" ipset)"
IPTABLES="$(resolve_cmd "$IPTABLES_CFG" iptables)"
IP6TABLES="$(resolve_cmd "$IP6TABLES_CFG" ip6tables)"

firewall_snapshot "t0"

case "$SAMPLE_SECONDS" in
    ''|*[!0-9]*)
        printf 'invalid SAMPLE_SECONDS=%s; no delayed sample taken\n' "$SAMPLE_SECONDS" \
            >"$WORK/firewall/sample-warning.txt"
        ;;
    0)
        ;;
    *)
        note "Sleeping $SAMPLE_SECONDS seconds for a second firewall-counter sample..."
        sleep "$SAMPLE_SECONDS"
        firewall_snapshot "t1"
        ;;
esac

# ---- Router/syslog evidence ------------------------------------------------

LOGREAD=""
for candidate in /opt/sbin/logread /sbin/logread /usr/sbin/logread; do
    if [ -x "$candidate" ]; then LOGREAD="$candidate"; break; fi
done
[ -n "$LOGREAD" ] || { have logread && LOGREAD="$(command -v logread)"; }

if [ -n "$LOGREAD" ]; then
    "$LOGREAD" 2>/dev/null \
        | grep -Ei 'router-hub|ban-attack|ROUTER_HUB_|ipset|iptables|ip6tables|nginx' \
        | tail -n 5000 >"$WORK/logs/router-syslog-security.tail" 2>/dev/null || true
fi

# Common Router Hub/Entware logs if present.
for f in \
    /opt/var/log/router-hub.log \
    /opt/var/log/router-hub/current \
    /tmp/router-hub.log
do
    [ -r "$f" ] && copy_bounded_log "$f"
done

# Extract absolute log paths from the firewall policy. This intentionally only
# accepts /opt/var/log and /tmp to avoid copying arbitrary policy-referenced files.
if [ -r "$POLICY" ]; then
    if grep -oE '"/(opt/var/log|tmp)/[^"]+"' "$POLICY" >/dev/null 2>&1; then
        grep -oE '"/(opt/var/log|tmp)/[^"]+"' "$POLICY" \
            | tr -d '"' \
            | sort -u >"$WORK/logs/policy-log-paths.txt" 2>/dev/null || true
    else
        # BusyBox grep fallback if -oE is unavailable.
        awk '
          {
            line=$0
            while (match(line, /"\/(opt\/var\/log|tmp)\/[^"]+"/)) {
              p=substr(line, RSTART+1, RLENGTH-2)
              print p
              line=substr(line, RSTART+RLENGTH)
            }
          }
        ' "$POLICY" | sort -u >"$WORK/logs/policy-log-paths.txt" 2>/dev/null || true
    fi

    if [ -s "$WORK/logs/policy-log-paths.txt" ]; then
        while IFS= read -r log_path; do
            copy_bounded_log "$log_path"
        done <"$WORK/logs/policy-log-paths.txt"
    fi
fi

# ---- Nginx version and only ban/log-related configuration lines ------------

NGINX="$(resolve_cmd "$NGINX_CFG" nginx)"
if [ -n "$NGINX" ]; then
    "$NGINX" -V >"$WORK/nginx/nginx-version.txt" 2>&1 || true
    "$NGINX" -T 2>&1 \
        | grep -Ei 'log_format|access_log|error_log|limit_req|limit_conn|trap|badbot|unknown-host' \
        >"$WORK/nginx/security-log-config.filtered.txt" 2>/dev/null || true
fi

# ---- Sharing/analysis notes ------------------------------------------------

cat >"$WORK/README-SHARE.txt" <<EOF
Router Hub diagnostics collected: ${STAMP}

Purpose
-------
Measure Router Hub ban-engine effectiveness and improve detection/ban rules.

Useful files
------------
router-hub/api-firewall.json
  Live policy, bounded score snapshot, active bans, engine health, and tuning.

router-hub/ban-attack-state.json
  Persistent active bans, IP scores, subnet reputation/promotion history,
  and per-rule match/ban statistics.

firewall/t0/ and firewall/t1/
  ipset membership plus INPUT/FORWARD Router Hub chain counters.
  If SAMPLE_SECONDS > 0, compare packet/byte counters between t0 and t1.

logs/
  Bounded tails of log files referenced by the firewall policy.
  access.log-style files are filtered to HTTP 4xx/5xx lines.

nginx/security-log-config.filtered.txt
  Only log/protection-related nginx -T lines, useful for interpreting fields.

Privacy / review before sharing
-------------------------------
The main TOML is sanitized and obvious token/password/secret/API-key assignments
are redacted. Certificate definitions, AdGuard data, hosts files, Wi-Fi config,
full NVRAM, routing tables, and full nginx configuration are NOT collected.

The archive can still contain:
  * public attacker/source IP addresses,
  * internal allowlist subnets,
  * requested URLs/paths and query strings,
  * usernames or application messages present in security logs,
  * router hostname/model/firmware.

Review logs and JSON before posting the archive publicly.

Suggested analysis
------------------
1. Verify engine health:
   - last_poll_at / last_match_at / last_reconcile_at / last_persist_at
   - error_count / command_timeout_count / dropped_line_count
   - eviction_count and tracked counts versus configured caps

2. Verify enforcement:
   - active bans in Router Hub state vs ipset members
   - ROUTER_HUB_INPUT / ROUTER_HUB_FORWARD hooks exist
   - packet/byte counters increase after bans (especially with t0/t1 sampling)

3. Tune rules:
   - rule_stats match_count and ban_count
   - triggering_rule and offense_count on active bans
   - subnet promotions and repeat reputation
   - suspicious 4xx/5xx log lines that do not correspond to useful rule matches
   - rules with many matches but poor ban value / obvious false-positive patterns

Collector settings:
  CONFIG=${CONFIG}
  DATA_DIR=${DATA_DIR}
  MAX_LOG_BYTES=${MAX_LOG_BYTES}
  SAMPLE_SECONDS=${SAMPLE_SECONDS}
EOF

# File manifest/checksums before archiving.
if have find; then
    (
        cd "$WORK" || exit 0
        find . -type f -print | sort >MANIFEST.txt
        if have sha256sum; then
            find . -type f ! -name SHA256SUMS -exec sha256sum '{}' \; 2>/dev/null \
                | sort >SHA256SUMS || true
        fi
    )
fi

# Archive.
if tar -czf "$ARCHIVE" -C "$OUTPUT_DIR" "$(basename "$WORK")" 2>/dev/null; then
    :
else
    ARCHIVE="${OUTPUT_DIR}/${BASE}.tar"
    tar -cf "$ARCHIVE" -C "$OUTPUT_DIR" "$(basename "$WORK")" || {
        echo "ERROR: failed to create archive" >&2
        exit 1
    }
fi

if have sha256sum; then
    sha256sum "$ARCHIVE" >"${ARCHIVE}.sha256" 2>/dev/null || true
fi

echo
echo "Created: $ARCHIVE"
[ -f "${ARCHIVE}.sha256" ] && echo "SHA256:  ${ARCHIVE}.sha256"
echo
echo "Review README-SHARE.txt and the collected logs/JSON before sharing."
