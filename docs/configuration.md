# Configuration and operation

[← Back to README](../README.md)

Use [`config/router-hub.example.toml`](../config/router-hub.example.toml) as the
reference. The main sections are:

- `[server]` — bind address, port, bearer token, CORS origins, and request
  limits;
- `[paths]` — persistent data, runtime, and configurable `hosts.add` path;
- `[commands]` — absolute paths to nginx, Entware utilities, firewall tools,
  dehydrated, OpenSSL, NVRAM, and network commands;
- `[asus_ui]` — extension-page rendering and ASUS menu integration;
- `[services]` — Entware init directory, log roots, and timeouts;
- `[nginx]` — nginx root/configuration, managed object trees, generated
  includes, and log limits;
- `[certificates]` — dehydrated certificate directory and renewal policy;
- `[firewall]` — matching, scoring, retention, subnet promotion, resource
  bounds, and command limits.

The Ban Shield tab can edit the attack thresholds, score/promotion/reputation
retention, reputation-aware re-promotion threshold, and ban durations. Those
edits are stored as an optional `tuning` override in `firewall-policy.json` and
are applied to the running ban engine immediately. When no override exists,
`router-hub.toml` remains the source of those values. Prefix sizes, command
paths, and resource caps stay TOML-only because changing them live has broader
runtime consequences.

The shipped defaults retain scores and subnet promotion history for 14 days,
longer than the 7-day minimum subnet ban. A subnet with retained reputation can
be promoted again as soon as one address reaches the IP threshold; by default
that fast re-promotion starts after the subnet's first prior promotion.

For an Internet-facing installation where false positives are less costly than
letting repeated hostile networks retry, the UI's **Load strict preset** uses:

```text
ip_failures = 3
subnet_failures = 6
promote_after_banned_ips = 2
reputation_repromote_after_offenses = 1
score_retention_days = 60
subnet_promotion_window_days = 60
reputation_retention_days = 365
subnet_ban_days = 30
first_ban_days = 1
second_ban_days = 7
third_ban_days = 30
max_ban_days = 180
```

This profile deliberately remembers activity for two months, makes the minimum
subnet ban 30 days, and keeps repeat-offender reputation for a year. Use a
less aggressive profile when legitimate users commonly share public source
subnets (carrier NAT, corporate egress, large hosting networks, or similar).

Persistent JSON is stored below `paths.data_dir` and written atomically. It
contains certificate definitions, Wake-on-LAN machines, firewall policy and
state, and AdGuard overrides. Nginx objects remain represented by nginx files
and relative symlinks rather than a second database. Existing dehydrated
definitions and deployed nginx certificates can be imported at startup.

## Security and operational notes

- Management routes require `Authorization: Bearer <token>`. The standalone
  page is opened with a URL fragment such as `/#token=<token>`; fragments are
  not sent to the server or written to HTTP access logs. The Asuswrt page
  embeds the configured token because the ASUS page and Axum listener are
  separate request contexts.
- Production configuration rejects placeholder or short tokens. Protect the
  TOML and JSON files because certificate DNS hook settings may contain
  credentials.
- The built-in listener is HTTP-only. If the UI is loaded through HTTPS, set
  `asus_ui.api_base_url` to an HTTPS reverse proxy to avoid mixed-content
  blocking.
- External programs are invoked with configured executable paths and separate
  arguments. Router Hub does not accept arbitrary shell command strings from
  the API.
- Nginx edits validate paths, reject unsafe symlink/traversal cases, write
  atomically, and restore the previous state when `nginx -t` fails.
- Firewall and certificate background work is bounded and recoverable. A
  dehydrated `lock` pauses certificate issue/renew operations until it is
  cleared from the Certificates view.
- Set Wake-on-LAN machines to the directed LAN broadcast (for example
  `192.168.1.255`) when `255.255.255.255` is not routed to the LAN.

## Nginx settings


Port existing nginx configuration manually to the current
[`config/nginx` bundle](../config/nginx/README.md) **before deploying Router Hub**.
The service contains no legacy template renderer or old map migration.
The installer runs `init-nginx` to bootstrap only a missing configuration,
including an empty site tree and a self-signed fallback certificate. Existing
configuration is preserved. For an existing installation, port the shared tree, `mime.types`,
`dhparams.pem`, certificates, required modules, and writable runtime directories.
Use the configured nginx prefix and paths for your installation.

Nginx → Setup quick reference provides offline profiles for PWAs, WordPress, and
media servers, plus upload guidance and route examples for SPA/API exclusions,
login protection, and SSE. The same guide opens from each site editor while
keeping unsaved settings in place.

In Nginx → Global settings, configure listeners, workers, DNS, PWA headers,
client IP/CIDR allowlists, shared domain suffixes, and site defaults. Settings are
stored atomically in `<nginx.root_dir>/settings/nginx.toml`. Saving renders
the shared runtime files and all managed sites, tests the combined tree with
`nginx -t`, and reloads a running nginx. Failure restores the previous files.
An empty LAN allowlist denies all clients for LAN-only locations.
`settings/nginx.toml` is the single source of global inputs: `[global]` contains
shared nginx options, `[site_defaults]` contains inherited site policies, and
root-level `allowed_ips` and `free_subdomains` arrays contain the allowlists.
Text allowlist fragments are generated from TOML. Relative fallback
certificate directories resolve beneath the configured nginx root; traversal
is rejected. Global settings also save `nginx_daemon`, `nginx_user`, and
`temp_dir`. When Router Hub runs as non-root, generated nginx configuration omits
`user`. When it runs as root, nginx uses `nginx_user`, falling back to `nobody`
when blank or unset. Only the temporary parent folder is configurable: nginx
uses `client-body`, `proxy`, `fastcgi`, `uwsgi`, and `scgi` beneath it. Linux mode
defaults to a `tmp` folder alongside the nginx root (for example, `data/linux/tmp`).
The temporary parent is created before validation; it must be writable by the
account running nginx. Set `nginx_daemon = false` when nginx runs under a foreground supervisor.
These settings survive regeneration; listener ports remain administrator choices.

Managed sites select the domain, subdomain, or subfolder policy automatically.
Site editors show domain-only controls only for domains. Proxy controls appear
when a domain root proxies traffic; upload, timeout, transport, and cache controls
follow the effective settings, including inherited defaults. Values are retained
when temporarily hidden, and child-route defaults remain editable. Each setting
has a **?** button; its explanation stays hidden until opened.

Per-site controls inherit global defaults; explicit No and a size of `0` remain
overrides. Clearing an override restores inheritance. Route policies accept JSON
using the documented settings in the bundle guide. Managed inputs, aliases,
upstreams, and enablement are saved atomically in
`<nginx.root_dir>/settings/sites.toml`. Saving a site regenerates its nginx
configuration and upstream maps, validates enabled configuration, and reloads a
running nginx. Failed validation or reload restores the previous inputs and output.
The UI exposes settings for managed sites; generated nginx text is disposable.
Generated comments are output metadata; only entries in `sites.toml` identify
managed sites. Output paths are derived from site identity; remove obsolete
`output` fields before loading deployment inputs.

Custom server configurations remain authored nginx text and are never treated
as Jinja or regenerated by a global-default change. They must use the current
runtime includes and data layout. Policy templates are embedded in the binary;
template editing and root-file editing are unavailable in both UI and API.
Upstreams live in `settings/domains.conf`, `settings/subdomains.conf`, and
`settings/subfolders.conf`; unrelated entries in these fragments are retained.
Listener and filesystem choices must match the nginx paths configured in TOML.
Python is needed only for lab setup and bundle tests, not by Router Hub at runtime.
