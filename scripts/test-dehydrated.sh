#!/usr/bin/env bash
set -euo pipefail

# Exercise dehydrated and a Router Hub-compatible hook against the Let's Encrypt
# staging CA.  This deliberately uses a temporary data directory and never
# changes Router Hub's configured certificate files.

usage() {
    cat <<'EOF'
Usage:
  test-dehydrated.sh [options] <domain> [domain ...]

Issue a staging certificate using the same dehydrated config and command line
that Router Hub uses. The first domain is the certificate name unless --name
is supplied. Domains may include a leading '*.' for wildcard DNS challenges.

Options:
  --name NAME       Certificate name (default: derived from the first domain)
  --method METHOD   http or dns (default: dns)
  --hook PATH       Hook path (default: scripts/dehydrated-dns01-hook.sh)
  --env KEY=VALUE   Export a hook environment value; may be repeated
  --force           Pass --force, like Router Hub's renew operation
  --keep            Keep the temporary dehydrated directory after completion
  -h, --help        Show this help

Examples:
  DNS_PROVIDER=duckdns DUCKDNS_TOKEN=... \
    scripts/test-dehydrated.sh '*.example.duckdns.org'

  scripts/test-dehydrated.sh --env DNS_PROVIDER=cloudflare \
    --env CLOUDFLARE_API_TOKEN=... '*.example.com'
EOF
}

die() {
    echo "test-dehydrated.sh: $*" >&2
    exit 2
}

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dehydrated=${DEHYDRATED:-}
method=dns
name=
hook="${script_dir}/dehydrated-dns01-hook.sh"
force=false
keep=false
domains=()
hook_env=()

while (($#)); do
    case "$1" in
        --name)
            (($# >= 2)) || die "--name requires a value"
            name=$2
            shift 2
            ;;
        --method)
            (($# >= 2)) || die "--method requires a value"
            method=$2
            shift 2
            ;;
        --hook)
            (($# >= 2)) || die "--hook requires a path"
            hook=$2
            shift 2
            ;;
        --env)
            (($# >= 2)) || die "--env requires KEY=VALUE"
            hook_env+=("$2")
            shift 2
            ;;
        --force)
            force=true
            shift
            ;;
        --keep)
            keep=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            domains+=("$@")
            break
            ;;
        -* )
            die "unknown option: $1"
            ;;
        *)
            domains+=("$1")
            shift
            ;;
    esac
done

((${#domains[@]} > 0)) || { usage >&2; exit 2; }
[[ "$method" == http || "$method" == dns ]] || die "--method must be http or dns"
[[ -x "$hook" || "$method" == http ]] || die "hook is not executable: $hook"

if [[ -z "$dehydrated" ]]; then
    if command -v dehydrated >/dev/null 2>&1; then
        dehydrated=$(command -v dehydrated)
    else
        die "set DEHYDRATED or put dehydrated on PATH"
    fi
fi
[[ -x "$dehydrated" ]] || die "dehydrated is not executable: $dehydrated"

if [[ -z "$name" ]]; then
    name=${domains[0]#\*.}
    name=${name//\*/wildcard}
    name=${name//[^A-Za-z0-9_.-]/_}
fi
[[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || die "invalid certificate name: $name"

quote_shell() {
    local value=$1
    printf "'%s'" "${value//\'/\'\\\'\'}"
}

for assignment in "${hook_env[@]}"; do
    [[ "$assignment" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]] ||
        die "--env must use a valid shell variable name: KEY=VALUE"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/router-hub-dehydrated-test.XXXXXX")
cleanup() {
    if "$keep"; then
        echo "Temporary dehydrated data kept at: $work_dir"
    else
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT

cfg="$work_dir/${name}.cfg"
domains_file="$work_dir/${name}.txt"

{
    printf "CA='letsencrypt-test'\n"
    printf "AUTO_CLEANUP='yes'\n"
    printf 'DOMAINS_TXT=%s\n' "$(quote_shell "$domains_file")"
    printf "CHALLENGETYPE=%s\n" "$(quote_shell "${method}-01")"
    if [[ "$method" == http ]]; then
        printf 'WELLKNOWN=%s\n' "$(quote_shell "$work_dir/acme-challenge")"
    else
        printf 'HOOK=%s\n' "$(quote_shell "$hook")"
    fi
    for assignment in "${hook_env[@]}"; do
        key=${assignment%%=*}
        value=${assignment#*=}
        printf 'export %s=%s\n' "$key" "$(quote_shell "$value")"
    done
} >"$cfg"

marker=${domains[0]#\*.}
{
    printf '\n# %s-start\n' "$marker"
    printf '%s > %s\n' "${domains[*]}" "$name"
    printf '# %s-end\n' "$marker"
} >"$domains_file"

args=(--cron --accept-terms --config "$cfg")
if "$force"; then
    args+=(--force)
fi

echo "Running dehydrated against Let's Encrypt staging: $name"
echo "  method: $method"
echo "  domains: ${domains[*]}"
echo "  hook: $hook"
echo "  data: $work_dir"
echo -n "  command: $dehydrated --cron --accept-terms --config $cfg"
if "$force"; then
    echo -n " --force"
fi
echo
"$dehydrated" "${args[@]}"
