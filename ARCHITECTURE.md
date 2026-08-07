# Architecture

## Purpose and scope

Router Hub is one Rust executable. This document records the current module
boundaries, request and background flows, persistence model, and safety
invariants that are easy to violate during maintenance. It is not a deployment
guide or an aspirational redesign.

## System context

An administrator uses either the standalone page served by Axum or the same UI
rendered into a writable Asuswrt `user<n>.asp` extension page. At startup,
Router Hub replaces a configured ASUS menu while retaining its index for the
firmware-provided icon. The service talks to
configured
router programs and files: Entware init scripts, nginx, dehydrated/OpenSSL,
ipset/iptables, NVRAM, and optionally an AdGuard Home HTTP API.

## Components

| Component | Responsibility | Important dependencies |
| --- | --- | --- |
| `src/main.rs` | CLI, configuration loading, startup, shutdown, listener, background task startup, and init-script signal handling | `config`, `state`, `api` |
| `src/config.rs` | TOML schema, defaults, validation, test-mode path overrides | filesystem paths and command paths |
| `src/api/` | Axum routes, authentication layer, request validation, JSON responses | `AppState` and domain modules |
| `src/state.rs` | Shared runtime state, dehydrated configuration, renewal loop, and tool updater | `storage`, `firewall`, dehydrated/OpenSSL through `CommandRunner`, GitHub HTTPS download |
| `src/storage.rs` | Load/save JSON stores with atomic replacement, dehydrated certificate discovery, and policy fallback | configured data paths |
| `src/command.rs` | External command boundary, timeout handling, test-mode simulation | configured executable paths |
| `src/nginx.rs` | Nginx object tree, templates, upstream maps, HTTP forwarder, root files, logs, symlinks, atomic writes | configured nginx filesystem |
| `src/firewall.rs`, `src/ban_attack/` | Rule compilation, log tailing, aggregation, persistence, firewall backend | configured logs and ipset/iptables |
| `src/asus_ui.rs` | Standalone UI rendering, ASP extraction, extension-page and menu-tree updates | `web/index.html`, ASUS template, configured ASUS paths |
| `src/adguard.rs` | AdGuard Home HTTP client and LAN-IP discovery | configured endpoint or router NVRAM |

## Dependency direction

API handlers operate on `AppState` and call domain modules. Domain modules own
validation and filesystem/runtime semantics; they do not receive arbitrary
shell command strings from handlers. External programs are invoked through
`CommandRunner` where the domain module uses that adapter. The ban-attack
backend is a separate, narrow argument-vector executor for `ipset` and
`iptables`/`ip6tables`; it does not accept shell command strings. Dehydrated
configuration is deliberately emitted in its shell-sourceable format, with
shell-quoted paths and validated hook variable names; installed hooks remain
administrator-trusted programs.

The UI is a client of the API and contains no server-side state. Nginx object
state is represented by its configured files and symlinks, not a duplicate JSON
database.

Nginx site changes also maintain the configured auxiliary includes. Subdomain
aliases are entries in the hostname upstream map; subfolder names are entries
in both the request-URI selector and the subfolder upstream map. The HTTP
forwarder is regenerated from enabled domain and subdomain `server_name`
values, so it provides a default HTTP-to-HTTPS redirect for every active site.
The shipped domain roots and templates do not declare a second port-80 server.
The former known-subdomains include is migrated on regeneration to avoid
duplicate HTTP server blocks. Existing map entries not owned by the edited
site are retained.

## Data and control flow

At startup, `main` loads and validates TOML, applies test-mode overrides when
requested, loads JSON stores and imports matching dehydrated `.cfg`/`.txt`
certificate pairs plus otherwise-unmanaged certificates deployed below the
nginx root, initializes the firewall manager, renders the UI, starts
background loops, and serves the Axum router. Authenticated API calls
then validate input, update the relevant filesystem/store, and invoke external
commands through the command boundary when needed.
Startup also reconciles existing site upstream-map entries and regenerates the
HTTP-to-HTTPS forwarder include before nginx is managed.

The firewall loop securely opens exact regular files below configured roots,
detects rotation using device/inode and byte anchors, applies bounded
backpressure, runs the hybrid matcher, aggregates bounded IP and subnet state,
updates owned ipset/iptables chains, and persists active bans, scores,
promotion history, and reputation. The ban-attack pipeline is described below.
Periodic and `SIGUSR1`-triggered reconciliation reconstructs the desired
firewall state. The certificate loop
periodically inspects the nginx-deployed `certs/<name>/cert.pem` file, falling
back to the deployed full chain and then dehydrated's working copy, and issues
or renews definitions marked for automatic renewal.
When certs_dir/lock exists, the loop and certificate API skip issue/renew
operations until an authenticated clear action removes the lock. Issuance writes the matching
`<name>.cfg` and `<name>.txt` files first, then invokes dehydrated's `--cron`
command; Router Hub's loop replaces a separate cron installation. An explicit
management action can atomically replace the dehydrated executable with the
official GitHub raw script; hook files are left untouched.

## Ban-attack engine

`FirewallManager` is the application boundary around `BanEngine`. It loads the
`FirewallPolicy` from `firewall-policy.json`, skips disabled rules, groups rules
by exact log path, and starts an engine only when the policy is enabled and has
at least one configured file. The manager always gives those files
`start_at = end`; direct engine users and tests may choose beginning or end.
Policy updates compile and validate the candidate's enabled log/rule
configuration, apply it to the running engine, and then save the policy. A save
failure restores the previous in-memory policy and attempts to restore the
previous engine configuration. `FirewallPolicy` may also contain a persisted
`tuning` override for thresholds, retention, reputation-aware re-promotion, and
ban durations. The Firewall tab writes that override through the same atomic
policy-update path; when it is absent, the application `[firewall]` TOML values
remain authoritative. Prefixes, backend commands, and bounded capacities stay
TOML-only.
The `BanRule.attempts` field remains accepted for API compatibility but is not
used by the engine; `weight` is the effective rule contribution.

The engine owns a dedicated worker thread and a bounded synchronous command
queue (128 entries in the application manager). Commands cover status,
configuration changes, manual bans, count resets, reconciliation, flushing,
disablement, and shutdown. The worker uses an absolute poll deadline so a
continuous stream of API commands cannot starve log polling. Rule matching uses
a hybrid lazy-DFA prefilter followed by a capture regex. Named IP captures and
optional named-group value filters are validated at compile time; non-IP
captures are ignored at match time, and only the first matching rule for a line
contributes.

Log paths must be absolute, exact, and free of traversal or glob characters.
Their nearest existing parent must resolve below a configured
`firewall.log_dirs` root. A configured file must be regular and not a symlink;
the open uses `O_NOFOLLOW` and rechecks file identity after opening. The tailer
tracks device/inode identity, detects rotation and truncation using a byte
anchor, drains a retired inode briefly, and preserves partial-line backlog.
Each file gets independent per-poll limits: by default 262,144 bytes, 1,000
lines, and 16,384 bytes per line. Overlong lines are discarded through their
next newline and counted; invalid UTF-8 lines are also counted and reported.

Aggregation adds each rule's weight to both an IP score and its configured
IPv4 `/24` or IPv6 `/64` bucket. With the application defaults, an IP reaches
the automatic-ban threshold at 4 points, a subnet score threshold is 8, and
two contributing addresses are required for a first-time promotion. Promotion
can happen when two distinct addresses cross the IP threshold within the
14-day promotion window, or when distributed activity reaches the subnet
threshold with the same minimum number of contributing addresses. Scores also
retain activity for 14 days after last sighting, so both score and promotion
memory outlive the default 7-day subnet ban.

Subnet reputation adds a separate repeat-offender path. When a subnet has at
least `reputation_repromote_after_offenses` retained prior subnet offenses
(default 1), any address in that subnet at or above the IP threshold can
re-promote the subnet without waiting for a second distinct offender. This
allows a newly observed IP to restore subnet-wide blocking quickly after a
previous subnet ban expires. Reputation is retained for 180 days by default, longer than the 90-day maximum ban.
Automatic ban durations escalate by retained offense count from 1 day to 7
days, 30 days, and a 90-day maximum. Subnet promotions have at least the
configured 7-day subnet duration.

Active bans are timed records with source, reason, creation and expiry times,
hit count, and offense count. Expiry cleanup runs every 60 seconds, removes
the backend entry, and retains non-expired reputation for later escalation.
Scores, subnet offender records, subnet buckets, reputation, and active bans
have explicit capacities (default 10,000 IPs, 2,048 subnets, 4,096 reputation
entries, and 8,192 active bans). Old score/offender/subnet/reputation entries
are evicted when their bounded tracking capacity is reached; active-ban
capacity rejects new runtime bans (restore truncates excess entries and records
an eviction). Counts continue after an IP is banned so subnet
promotion and escalation still have the required history. A promoted or
manually banned subnet is authoritative over contained IP bans, and redundant
exact-IP ban records are removed from backend/state.

The firewall API exposes policy/rule and allowlist mutation, bounded status,
manual bans, unban, and count-reset operations. Manual bans accept an IP or
subnet for 60 seconds through the configured maximum duration. The
`DELETE /firewall/bans/{network}` route and the backwards-compatible `/reset`
variant both add a durable allowlist exception and clear the target's active
ban, score, promotion history, and reputation.
`POST /firewall/reset-counts/{network}` is
different: it clears retained counters and reputation but does not remove an
active ban or create an allowlist entry.

The status response separates the policy, a snapshot, ban records, legacy
summary settings, the effective security `tuning`, and `EngineHealth`. Snapshot
lists are capped by `max_status_entries` (100 by default), while health reports
disabled, observe, running, degraded, or stopped state; lifecycle timestamps;
last error; error and timeout counts; dropped-line count; set capacity; and
current set entries.

## Ban-attack firewall backend and recovery

The production backend manages IPv4 and IPv6 `hash:net` ipsets and owned
`ROUTER_HUB_INPUT`/`ROUTER_HUB_FORWARD` chains. Owned rules carry the
`router-hub:ban-attack` comment, and disabling the policy removes only Router
Hub's parent hooks; administrator or other-tool rules are not removed. The
application path currently supplies a 65,536-entry ipset capacity; the lower
level engine type accepts a configurable capacity, but there is not yet an
application `[firewall]` setting for it.

Reconciliation verifies or creates compatible sets and owned chains, updates
`nomatch` allowlist exceptions, and restores the desired entries by building
bounded staging sets with `ipset restore`, swapping them into place, and
destroying the staging sets. It is used at startup, every 60 seconds while
enabled, on an explicit worker request, and after `SIGUSR1`. The installer
appends a token-free `S99router-hub reconcile` action to
`/jffs/scripts/post-mount` and a background retry loop to
`/jffs/scripts/firewall-start` to re-apply hooks when Asuswrt rebuilds its
firewall; `S99router-hub` sends `SIGUSR1` to the running process. A bounded 2 MiB
stdin limit and five-second default command deadline apply to backend commands;
timed-out children are killed and reaped.

`observe_only` prevents backend set, rule, and hook changes and removes owned
hooks during reconciliation, but the current worker still aggregates matches
and can persist `active_bans` in its engine state. It is therefore an
observe/no-enforcement backend mode, not yet a separate hypothetical-ban store.
The engine's memory backend is used by unit and integration tests; test mode
simulates production command success and redirects paths to fixture roots.

## Persistent state

The configured data directory contains pretty JSON for certificates, WOL
machines, firewall policy, versioned `ban-attack-state.json`, and optional
AdGuard overrides. Stores load
defaults when optional files are absent. Matching dehydrated certificate
definitions are imported into `certificates.json`; deployed nginx certificates
without a definition are inferred from their DNS subject names and imported
with automatic renewal disabled. Existing JSON definitions with the same name
retain their Router Hub settings. The colocated domain file is preferred, with
`DOMAINS_TXT` as a fallback. Firewall policy can fall back to the
configured router policy location. Writes use a temporary sibling file and
rename, so readers see either the previous or complete new document.

`ban-attack-state.json` is the only authoritative engine state file. Version 1
contains `active_bans`, weighted `scores`, retained `reputation`, and
time-bounded `subnet_offenders`, plus `schema_version` and `saved_at`. Expired
bans, scores outside retention, reputation outside retention, and stale subnet
offenders are not restored. Restored subnets are processed before contained IP
bans, and all restored targets are reconciled into the backend before
allowlist exceptions are applied.

The engine prefers a valid version-1 state file. If it is absent, it imports
either the historical `Vec<BanRecord>` shape or the historical
`{banned_ips,banned_subnets}` shape from `bans.json`; records without expiry
receive a one-hour migration expiry. After a successful write it archives the
legacy file as `bans.json.migrated-v1`. A malformed state file, unsupported
schema, or failed migration is logged and leaves the worker running in
`degraded` state rather than silently discarding state. New engine writes never
share the old `Stores` ban collection or serialize the legacy mirror fields.
Engine writes are dirty-state writes: ordinary matches wait for the configured
30-second interval, while transitions, manual operations, configuration
changes, cleanup, and shutdown force a save. Each save creates a unique mode
0600 sibling temporary file, writes and syncs it, renames it over the target,
and syncs the parent directory; failed writes remove only the temporary file.

## AdGuard integration

Nginx site reconciliation creates only dot-delimited AdGuard rewrites. Domains
containing an underscore are rejected before an add, and existing underscore
entries are excluded from startup deduplication, the rewrite editor, and nginx
disable cleanup; Router Hub does not remove those legacy entries.

The authenticated AdGuard hosts API reads and atomically replaces the
configured `paths.hosts_add` file (default `/jffs/configs/hosts.add`). Each
entry contains one IP address and one or more hostnames. A successful save
restarts dnsmasq through the configured service command and arguments.

## Invariants

- Production configuration rejects short or shipped placeholder API tokens.
- Management routes require constant-time bearer-token matching; only health,
  version, and the public standalone UI shell are outside the management layer.
- API-originated values never become shell-interpolated commands.
- Firewall commands have separate argument boundaries, bounded stdin and
  execution deadlines, and reconciliation swaps fully prepared staging sets
  into service.
- Ban aggregation, status output, command queues, and each log polling turn
  have explicit resource limits.
- User-selected paths remain below configured roots; traversal, symlink
  ancestors, and nginx managed trees are rejected where applicable.
- Nginx enablement is represented by the expected relative symlink hierarchy.
  Failed validation or lifecycle actions restore the prior enabled state.
- Template-backed nginx objects store their template identity in a reserved
  comment; rendered `server_name` values are the per-object override and may
  contain multiple aliases for one shared configuration.
- Nginx root-file writes and JSON writes are atomic; invalid nginx changes are
  rolled back after `nginx -t` failure.
- Site upstream-map edits validate nginx map tokens and URL targets, update
  aliases together, and keep unrelated map entries intact.
- The generated HTTP forwarder contains only enabled domain/subdomain names and
  uses the configured `listen-http` and ACME challenge snippets.
- Test mode redirects router paths, skips ASUS menu updates, simulates external
  commands, and prevents WOL transmission while retaining filesystem and API
  behavior.
- The WOL view polls `/api/wol/status` only while that tab is active. The
  endpoint matches configured MAC addresses against `ip neigh` output and
  checks each resolved IP with a bounded ping.
- The UI remains a single self-contained HTML/ASP asset and must work without
  a frontend package manager or third-party CDN.
- Router Hub service (`S99router-hub`) cannot be disabled via API request, init
  script, or UI action to ensure management engine availability.

## Security and trust boundaries

Router Hub is administrator-only; it has no users or RBAC. The API token is
embedded in the extension page and therefore must be treated as a credential by
anyone who can read that page. Raw nginx configuration, dehydrated hook paths,
hook environment values, and configured credentials are trusted administrator
input, but paths, shell-variable names, shell quoting, and command argument
boundaries are still validated by the service.

The built-in listener does not terminate TLS. Put it behind a trusted HTTPS
reverse proxy for encrypted browser access and restrict the listener with the
router's LAN/VPN firewall policy.

## Failure and recovery

Missing external commands and command timeouts are explicit errors; timed-out
children are killed. Ban-engine startup, backend, parser, and persistence
errors are surfaced through `EngineHealth` and move the worker to `degraded`
state while it can continue polling where possible. Nginx validation failures
roll back the affected file or symlink state. Firewall bans are persisted and
restored on engine startup, and the backend periodically re-verifies sets and
owned chains to recover from router firewall flushes. ASUS extension-page
rendering and menu updates are skipped only when the ASUS UI is disabled or
test mode is active.

## Extension points

Add API behavior in the matching `src/api/<area>.rs` module, domain semantics
in its owning module, and configuration in `src/config.rs` with a conservative
default, example TOML entry, and test-mode override for router paths. Add
integration coverage in `tests/` when behavior crosses the HTTP or command
boundaries.

## Verification

Use the commands in [`AGENTS.md`](AGENTS.md). Firewall-focused coverage
includes the shipped high-confidence XML-RPC trap producing one immediate ban,
weighted matching, persistence and restart restoration, graceful flushing of
subthreshold scores, path and symlink validation, rotation/truncation,
per-poll line bounds, subnet promotion, exception cleanup, capacity eviction,
and backend reconciliation. The broader integration suite covers
authentication, dashboard, services, nginx, WOL, firewall, and AdGuard API
flows; unit tests cover path safety, storage atomicity, command simulation,
UI rendering, matching, aggregation, and log rotation.
