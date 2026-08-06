#!/usr/bin/env bash

# dehydrated DNS-01 hook for DuckDNS, Namesilo, or Cloudflare.
#
# Required environment by provider:
#   DNS_PROVIDER=duckdns     DUCKDNS_TOKEN=...
#   DNS_PROVIDER=namesilo    NAMESILO_API_KEY=...
#   DNS_PROVIDER=cloudflare  CLOUDFLARE_API_TOKEN=...
#
# CLOUDFLARE_API_TOKEN must have Zone:Read and DNS:Edit for the zone.

set -euo pipefail

: "${DNS_PROVIDER:?DNS_PROVIDER is not set (duckdns, namesilo, or cloudflare)}"

deploy_challenge() {
  local domain="${1}" token_filename="${2}" token_value="${3}"

  case "${DNS_PROVIDER}" in
    duckdns)
      : "${DUCKDNS_TOKEN:?DUCKDNS_TOKEN is not set}"
      curl --fail --silent --show-error --get 'https://www.duckdns.org/update' \
        --data-urlencode "domains=${domain}" --data-urlencode "token=${DUCKDNS_TOKEN}" \
        --data-urlencode "txt=${token_value}"
      echo
      sleep "${DUCKDNS_PROPAGATION_SECONDS:-30}"
      ;;
    namesilo)
      : "${NAMESILO_API_KEY:?NAMESILO_API_KEY is not set}"
      local host='_acme-challenge' zone="${domain}"
      if [[ "${zone}" == *.*.* ]]; then
        host="_acme-challenge.${zone%.*.*}"
        zone="${zone#*.}"
      fi
      curl --fail --silent --show-error --get 'https://www.namesilo.com/api/dnsAddRecord' \
        --data-urlencode 'version=1' --data-urlencode 'type=json' \
        --data-urlencode "key=${NAMESILO_API_KEY}" --data-urlencode "domain=${zone}" \
        --data-urlencode 'rrtype=TXT' --data-urlencode "rrhost=${host}" \
        --data-urlencode "rrvalue=${token_value}"
      echo
      sleep "${NAMESILO_PROPAGATION_SECONDS:-600}"
      ;;
    cloudflare)
      cloudflare_deploy_challenge "${domain}" "${token_value}"
      ;;
    *)
      echo "Unsupported DNS_PROVIDER: ${DNS_PROVIDER}" >&2
      return 1
      ;;
  esac
}

clean_challenge() {
  local domain="${1}" token_filename="${2}" token_value="${3}"

  case "${DNS_PROVIDER}" in
    duckdns)
      : "${DUCKDNS_TOKEN:?DUCKDNS_TOKEN is not set}"
      curl --fail --silent --show-error --get 'https://www.duckdns.org/update' \
        --data-urlencode "domains=${domain}" --data-urlencode "token=${DUCKDNS_TOKEN}" \
        --data-urlencode 'txt=removed' --data-urlencode 'clear=true'
      echo
      ;;
    namesilo)
      : "${NAMESILO_API_KEY:?NAMESILO_API_KEY is not set}"
      local host='_acme-challenge' zone="${domain}"
      if [[ "${zone}" == *.*.* ]]; then
        host="_acme-challenge.${zone%.*.*}"
        zone="${zone#*.}"
      fi
      local record_ids
      record_ids="$(curl --fail --silent --show-error --get 'https://www.namesilo.com/api/dnsListRecords' \
        --data-urlencode 'version=1' --data-urlencode 'type=json' \
        --data-urlencode "key=${NAMESILO_API_KEY}" --data-urlencode "domain=${zone}" | \
        jq -r --arg host "${host}.${zone}" \
          '.reply.resource_record[]? | select(.type == "TXT" and .host == $host) | .record_id')"
      local record_id
      for record_id in ${record_ids}; do
        curl --fail --silent --show-error --get 'https://www.namesilo.com/api/dnsDeleteRecord' \
          --data-urlencode 'version=1' --data-urlencode 'type=json' \
          --data-urlencode "key=${NAMESILO_API_KEY}" --data-urlencode "domain=${zone}" \
          --data-urlencode "rrid=${record_id}"
        echo
      done
      ;;
    cloudflare)
      cloudflare_clean_challenge "${domain}" "${token_value}"
      ;;
    *)
      echo "Unsupported DNS_PROVIDER: ${DNS_PROVIDER}" >&2
      return 1
      ;;
  esac
}

cloudflare_api() {
  curl --fail-with-body --silent --show-error --retry 3 \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H 'Content-Type: application/json' "$@"
}

cloudflare_zone_id_for() {
  local domain="${1}" response zone_id
  domain="${domain#\*.}"
  while [[ "${domain}" == *.* ]]; do
    response="$(cloudflare_api "https://api.cloudflare.com/client/v4/zones?name=${domain}&per_page=1")"
    zone_id="$(jq -r '.result[0].id // empty' <<<"${response}")"
    [[ -n "${zone_id}" ]] && { printf '%s\n' "${zone_id}"; return; }
    domain="${domain#*.}"
  done
  echo "Unable to find a Cloudflare zone for ${1}" >&2
  return 1
}

cloudflare_record_name_for() {
  local domain="${1#\*.}"
  printf '_acme-challenge.%s\n' "${domain}"
}

cloudflare_deploy_challenge() {
  local domain="${1}" token_value="${2}" zone_id record_name
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is not set}"
  zone_id="$(cloudflare_zone_id_for "${domain}")"
  record_name="$(cloudflare_record_name_for "${domain}")"
  cloudflare_api -X POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
    --data "$(jq -cn --arg name "${record_name}" --arg content "${token_value}" \
      '{type:"TXT", name:$name, content:$content, ttl:120}')" >/dev/null
  echo " - Created Cloudflare TXT record ${record_name}"
  sleep "${CLOUDFLARE_PROPAGATION_SECONDS:-30}"
}

cloudflare_clean_challenge() {
  local domain="${1}" token_value="${2}" zone_id record_name response record_id
  : "${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN is not set}"
  zone_id="$(cloudflare_zone_id_for "${domain}")"
  record_name="$(cloudflare_record_name_for "${domain}")"
  response="$(cloudflare_api "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=TXT&name=${record_name}&per_page=100")"
  while IFS= read -r record_id; do
    [[ -n "${record_id}" ]] || continue
    cloudflare_api -X DELETE "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" >/dev/null
    echo " - Deleted Cloudflare TXT record ${record_name}"
  done < <(jq -r --arg content "${token_value}" '.result[]? | select(.content == $content) | .id' <<<"${response}")
}

deploy_cert() {
  local domain="${1}" keyfile="${2}" certfile="${3}" fullchainfile="${4}" chainfile="${5}"
  local mode="${CERT_MODE:-600}"
  # Keep the private key restrictive; set permissions on certificate files based on mode.
  chmod "${mode}" "${certfile}" "${fullchainfile}" "${chainfile}"
  echo " - Set public certificate permissions for ${domain} (${mode})"
}

unchanged_cert() {
  echo "The ${1} certificate is still valid and therefore was not reissued."
}

handler="${1:-}"
shift || true
case "${handler}" in
  deploy_challenge|clean_challenge|deploy_cert|unchanged_cert) "${handler}" "$@" ;;
esac
