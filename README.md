# Router Hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Asuswrt--Merlin-red.svg)](https://www.asuswrt-merlin.net/)
[![Target](https://img.shields.io/badge/Target-aarch64--musl-informational.svg)](#requirements-and-support)

Router Hub is a lightweight management hub for Asuswrt-Merlin routers. Its
purpose is to bring a useful set of self-hosted network services together on
the router—without adding a database, a frontend build system, or a large
management stack.

From one administrator-only UI, Router Hub can manage nginx sites and
certificates, operate Entware services, integrate with AdGuard Home, wake LAN
devices, and provide bounded log-based attack protection with IP and subnet
bans. The UI can run as a standalone page or be installed into the Asuswrt
menu as a custom `user<n>.asp` page.

The service is written in Rust and exposes a protected Axum JSON API behind
the same UI. Router-sensitive paths, commands, limits, and integrations are
configured in TOML so an installation can match the router’s filesystem.
Router Hub coordinates the Entware-installed programs; it does not bundle a
second nginx, DNS server, or certificate authority.

> Router Hub performs privileged router operations. Keep it on a trusted LAN
> or VPN, use a long random token, and do not expose its HTTP listener directly
> to the public internet.

## What it manages

### Nginx and HTTPS

- Create, edit, enable, disable, validate, and reload nginx domains,
  subdomains, and subfolders.
- Create composable sites from version-controlled TOML options (access, routing, uploads, timeouts, streaming, WebSocket/PWA), while retaining legacy templates and custom Nginx. See [Nginx composition](docs/NGINX_COMPOSITION.md).
- Manage templates, upstream maps, aliases, root files, symlinks, and bounded
  log views while keeping nginx’s filesystem configuration authoritative.
- Generate the configured HTTP-to-HTTPS forwarder for enabled sites.
- Issue and renew certificates through dehydrated using HTTP-01 or DNS-01
  configuration, inspect deployed certificate status, and recover from a
  dehydrated lock when an operation needs intervention.

### Lightweight attack protection

- Match configured nginx or other log files with bounded reads and compiled
  rules.
- Track weighted activity per address and IPv4 `/24` or IPv6 `/64` subnet.
- Escalate ban durations, promote distributed attacks to subnet bans, and
  enforce bans through owned ipset and iptables/ip6tables chains.
- Maintain allowlists, persistent state, post-mount and firewall-start
  reconciliation, and an `observe_only` mode for evaluating rules without
  enforcement.

The engine is deliberately bounded: log reads, line sizes, tracked addresses,
subnets, reputation, active bans, command input, and command deadlines all have
limits. Its defaults are intended for a small router, not for replacing a
dedicated IDS or high-volume firewall appliance.

### Router and LAN administration

- Discover executable Entware init scripts, show bounded logs, and start,
  stop, restart, reconfigure, enable, or disable services (disabling Router Hub
  itself is restricted).
- Manage AdGuard Home connection settings, protection state, and DNS rewrites.
  Router Hub can hide nginx-managed domains and aliases from the rewrite editor
  so the two systems do not compete over the same names.
- Save LAN machines and send Wake-on-LAN magic packets, with optional neighbor
  and reachability status checks.
- Show a dashboard with service, nginx, certificate, firewall, and runtime
  status.

### Asuswrt integration

When enabled, startup renders the self-contained UI into a configured
Asuswrt-Merlin extension page and replaces an existing ASUS menu entry while
retaining that menu’s index and icon. This keeps the experience inside the
router UI. The same HTML can also be served standalone on the configured
listener.

The UI is offline-capable: it is one HTML asset with no npm build step and no
third-party CDN dependency.

## Requirements and support

For development and local builds:

- Rust 1.85 or newer.
- A Unix-like environment with the standard Rust tooling.

For a router installation:

- Asuswrt-Merlin with JFFS custom scripts/configuration enabled.
- Entware mounted at `/opt`.
- A binary built for the router CPU and libc/ABI.
- nginx, dehydrated, OpenSSL, ipset, iptables, and related utilities only for
  the features that use them.

AArch64 musl is the primary tested release target. Legacy MIPS compatibility is
not promised; a target is supported only after testing it on the matching
router CPU and firmware.

## Try it locally

The repository includes a fixture-backed test mode. It redirects router paths
to `test-fixtures/`, simulates external commands, skips Asuswrt menu changes,
and does not transmit Wake-on-LAN packets.

```sh
cargo run -- --config ./test-fixtures/etc/router-hub/router-hub.toml --test-mode serve
```

Open <http://127.0.0.1:3030>. The test token is `router-hub-test-token` when
using the repository test configuration. The equivalent shortcut is:

```sh
make run
```

The test configuration is safe for exercising the UI and API, but it is not a
router deployment configuration.

## Native Linux integration (real services)

For testing the production execution path on a development Linux machine,
use `platform = "linux"` and `test_mode = false` in a **separate**
configuration. Alternatively, pass `--linux-mode` to select the Linux
platform from the CLI. Do **not** pass `--test-mode`: that flag simulates
external commands. Simulated test mode and the Linux platform cannot be
combined.

The native Linux platform runs the normal command runner and HTTP API,
reads real Linux `/proc` metrics, and uses the configured service paths. It
skips ASUS menu installation, standalone startup does not emit an ASUS ASP
page, and AdGuard LAN IP discovery does not call router NVRAM. Set a real
`[adguard].lan_ip` if AdGuard Home is enabled. All native Linux paths and
executables must be configured for the development host. Use
`[server].daemonize = false` for local interactive runs.

To prepare a persistent local setup, run:

```sh
./scripts/setup-linux.sh
cargo run -- --config data/linux/router-hub.toml --linux-mode serve
```

The setup script checks for required tools and creates `data/linux/router-hub.toml`,
`data/linux/nginx/nginx.conf`, and isolated state, log, and runtime directories.
It preserves existing files on subsequent runs. New configs bind the API to
`127.0.0.1:3030`, use nginx port `8080`, generate a random API token in the TOML
file, and disable firewall enforcement and AdGuard integration. Nginx uses local
temporary directories so it can run without root. Start nginx through the UI;
the setup script does not start services or install packages.

The built-in **unprivileged** smoke test requires `cargo`, `nginx`,
`openssl`, `curl`, and `python3`. It creates an isolated temporary
configuration and nginx prefix under `data/linux/lab`, runs the real router-hub binary, verifies
authentication and system metrics, and exercises real nginx validation,
startup, reload, shutdown, and a managed file edit:

```sh
make test-linux
# Or retain the temporary directory and logs after execution:
ROUTER_HUB_KEEP_LINUX_LAB=1 make test-linux
```

The smoke test neither uses mocks nor touches the host's nginx configuration.
It deliberately leaves the Ban Shield firewall policy **disabled**, does
not send WOL packets, and does not issue public certificates or change DNS.
It is a real local integration smoke test, not exhaustive feature coverage.

To test additional features against actual services, point the Linux
configuration to a dedicated nginx tree, real `dehydrated`, `openssl`,
`ip`, `ping`, `wg`/`wg-quick`, and a dedicated AdGuard Home API endpoint.
Use `[nginx].prefix_path` when nginx's relative includes must resolve below
a separate `-p` prefix. Certificate DNS-01 tests require a real DNS
provider and a domain you control; `scripts/test-dehydrated.sh` exercises
the dehydrated command against Let's Encrypt staging without changing Router
Hub's certificate store. HTTP-01 additionally requires a publicly reachable
ACME challenge. Run real ipset/iptables Ban Shield enforcement only inside an
isolated Linux network namespace or a disposable VM: even
`observe_only = true` can remove Router Hub-owned firewall hooks during
reconciliation. A local systemd unit does not automatically satisfy the
Entware-style init script interface; use real compatible init scripts in a
separate `[services].init_dir`.

The Linux platform does **not** emulate firmware behaviors such as NVRAM,
ASUS menu injection, JFFS startup hooks, or router-specific service actions.
Those still need router validation. Linux keeps its firewall policy within
`[paths].data_dir` instead of reading or mirroring the router's
`/opt/etc/router-hub/firewall-policy.json`.

## Versioned releases and installation packages

Router Hub follows [Semantic Versioning](https://semver.org/). Set the version
in `Cargo.toml` and commit the matching `Cargo.lock`; Git tags use the
`vMAJOR.MINOR.PATCH` convention (or a prerelease such as `v0.8.0-rc.1`).
The [GitHub Releases page](https://github.com/vm75/router-hub/releases) offers
versioned AArch64 musl installation archives and SHA-256 checksums.

Automatic CI runs **only after a pull request is merged into `main`**.
Ordinary branch pushes, direct pushes to `main`, and PR updates do not trigger
CI. To check an **open PR manually**, after this workflow has been merged into
`main`, select **Actions → CI → Run workflow**, select `main`, and enter
the PR number. It checks GitHub's proposed merge result against `main`.
Alternatively, run `gh workflow run ci.yml --ref main -f pr_number=123`.
The manual check is not a required pre-merge check; enable a separate
pre-merge workflow if your branch protection needs one.

Pushing a version tag starts a separate full release: version and ancestry
validation, Rust formatting, tests, Clippy, stable toolchain compatibility,
AArch64 musl cross-compilation, packaging, checksum verification, and GitHub
Release publication. Tags must match Cargo's version and point to commits
already merged into `main`. A prerelease tag publishes a GitHub prerelease.
No release workflow installs anything onto a router automatically.

### Install a published version

On the router, ensure `curl`, `tar`, and `sha256sum` are available. You can
instead download and verify on another Linux machine, then transfer the
extracted directory to the router. For example, **after** `v0.7.2` has been
published:

```sh
VERSION=v0.7.2
TARGET=aarch64-unknown-linux-musl
PACKAGE="router-hub-${VERSION}-${TARGET}"
URL="https://github.com/vm75/router-hub/releases/download/${VERSION}"

curl -fLO "${URL}/${PACKAGE}.tar.gz"
curl -fLO "${URL}/${PACKAGE}.tar.gz.sha256"
sha256sum -c "${PACKAGE}.tar.gz.sha256"
tar -xzf "${PACKAGE}.tar.gz"
cd "${PACKAGE}"
# Run as root on the router:
./scripts/install-merlin.sh ./router-hub
```

The package includes the executable, `config/`, `scripts/`, and release
documentation. Back up the router's configuration and persistent data before
upgrading; the installer preserves existing `router-hub.toml` and should be
reviewed for your environment. AArch64 musl compatibility requires validation
on your router CPU and firmware.

### Publish the next release

1. Update `Cargo.toml` using Semantic Versioning, refresh `Cargo.lock`,
   and update `CHANGELOG.md`. Run local checks and the release build.
2. Merge the version changes into `main` by PR and verify the merged-PR CI.
3. From the updated `main`, create and push an annotated tag:

```sh
git switch main
git pull --ff-only
git tag -a v0.7.2 -m "Router Hub v0.7.2"
git push origin v0.7.2
```

Replace `v0.7.2` with the actual new version. Never reuse or move a published
tag; issue a new patch version for corrections. GitHub Actions performs the
release build when the tag is pushed.

## Build and install on a router

Build the release artifact for the target CPU. The helper also writes a SHA-256
file under `dist/`:

```sh
./scripts/build-release.sh aarch64-unknown-linux-musl
```

Alternatively, build and deploy to a remote target in one step using:

```sh
./scripts/build-and-deploy.sh user@router-host
```

To exercise the dehydrated command and DNS hook against Let's Encrypt staging,
use the temporary test harness. It uses the same `--cron --accept-terms
--config` invocation as Router Hub and leaves router certificate data untouched:

```sh
DEHYDRATED=/path/to/dehydrated \
  DNS_PROVIDER=duckdns DUCKDNS_TOKEN=... \
  ./scripts/test-dehydrated.sh '*.example.duckdns.org'
```

Use repeated `--env KEY=VALUE` options when you want the hook settings written
into the temporary dehydrated config, as they are by Router Hub. The harness
uses the staging CA by default and supports `--method http`, `--hook`,
`--force`, and `--keep`.

Or copy the resulting binary, `config/`, and `scripts/` to the router, then run
the installer as root from that copied repository:

```sh
./scripts/install-merlin.sh ./router-hub-aarch64-unknown-linux-musl --mosquitto-user admin --mosquitto-pass mysecretpassword
```

The installer:

1. installs the binary as `/opt/bin/router-hub` and the Entware init script as
   `/opt/etc/init.d/S99router-hub`;
2. creates `/opt/etc/router-hub/router-hub.toml` and a random authentication
   token on first install;
3. installs missing shared nginx templates and snippets under `/opt/etc/nginx`
   without replacing existing router-local files, then creates runtime/data
   directories and installs the example firewall policy when needed;
4. configures Mosquitto credentials in `/opt/etc/mosquitto/passwd` if `--mosquitto-user` and `--mosquitto-pass` (or `MOSQUITTO_USER` / `MOSQUITTO_PASS` env vars) are supplied;
5. adds token-free reconciliation calls to `/jffs/scripts/post-mount` and
   `/jffs/scripts/firewall-start` (with a background retry loop);
6. validates the configuration and restarts Router Hub.

Review the generated TOML before starting. In particular, set the correct
Asuswrt extension page (`user1.asp` through `user20.asp`), `menu_tree`,
`menu_index`, nginx paths, certificate paths, bind address, and allowed
origins. The installer’s default paths are examples for a typical Entware
layout, not proof that every firmware image uses the same layout.

The service supports the usual Entware init actions:

```sh
/opt/etc/init.d/S99router-hub start
/opt/etc/init.d/S99router-hub stop
/opt/etc/init.d/S99router-hub restart
/opt/etc/init.d/S99router-hub status
```

`reconcile` requests an immediate firewall reconciliation from the running
process and is used by the installed `post-mount` and `firewall-start` hooks.

## Configuration

Use [`config/router-hub.example.toml`](config/router-hub.example.toml) as the
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

## Development checks

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Shortcuts are available through `make check`, `make test`, `make fmt`,
`make clippy`, `make run`, and `make release`.

## API overview

The API is primarily consumed by the bundled UI. Unauthenticated endpoints are
`GET /healthz` and `GET /api/version`; the standalone page is token-gated.
Management endpoints require the bearer token and are grouped as follows:

- `/api/services` — Entware service discovery, actions, and logs;
- `/api/nginx` — nginx status, lifecycle, objects, files, templates, and logs;
- `/api/certificates` — certificate definitions, issue/renew operations,
  dehydrated lock handling, and script update;
- `/api/wol` — machine management, wake, and status;
- `/api/firewall` — policy, rules, allowlists, bans, counters, and status;
- `/api/adguard` — AdGuard configuration, protection, staged rewrites, and
  `hosts.add` management (saving hosts restarts dnsmasq);
- `/api/dashboard`, `/api/runtime`, and `/api/auth/check` — authenticated
  status views.

The authoritative route map is [`src/api/mod.rs`](src/api/mod.rs).

## Project documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — module boundaries, flows, persistence,
  firewall behavior, and invariants;
- [`AGENTS.md`](AGENTS.md) — repository workflow and engineering constraints;
- [`CHANGELOG.md`](CHANGELOG.md) — user-visible release history;
- [`config/router-hub.example.toml`](config/router-hub.example.toml) — complete
  configuration example;
- [`config/firewall-policy.example.json`](config/firewall-policy.example.json)
  — example attack-protection policy.

## License

MIT; see [`LICENSE`](LICENSE).

Linux setup installs executable `S80nginx` and `S99router-hub` adapters in
`data/linux/init.d`. These use the normal Services discovery and actions. They require
Python 3.11 or newer and default to `data/linux/router-hub.toml`; set
`ROUTER_HUB_CONFIG` to select another configuration. For an existing setup, set
`[services].init_dir` to the absolute path of `data/linux/init.d` and rerun
`./scripts/setup-linux.sh`. Existing adapters are preserved.

Build Router Hub before starting it through `data/linux/init.d/S99router-hub start`.
The adapter prefers the release binary, falling back to the debug binary, and
requires `server.daemonize = false`. It also recognizes a foreground server
started with an explicit `--config` argument for the same configuration.
Nginx actions use the configured executable, prefix, configuration, and PID file.

Linux setup selects dehydrated from `PATH` and writes its absolute path to
`[commands].dehydrated`. If unavailable, it selects a local executable path
under `data/linux/certs`; use the Certificates page’s dehydrated update action
to download it before issuing certificates. For existing configurations, add
an explicit `[commands].dehydrated` path and restart Router Hub.

Linux setup seeds domain and subdomain `proxy` templates and a subfolder
`location` template in `data/linux/nginx/templates`. Rerunning setup adds missing
templates and preserves existing files. These starter templates proxy to
`127.0.0.1:3030` and use HTTP port 8080 for virtual hosts; edit their listen ports
and upstreams in Nginx → Templates for your deployment before creating sites.
TLS listeners and certificate paths must be configured separately.

The generated Linux nginx HTTP server listens on all IPv4 interfaces and serves
`/.well-known/acme-challenge/` from `data/linux/certs/acme-challenge`. For HTTP-01,
forward WAN TCP port 80 to the Linux host’s nginx HTTP port and allow that port
through its firewall. Existing nginx configurations are preserved by setup.
When changing a loopback listener to all interfaces on the same port, stop and
start the configured nginx instance if a reload reports an address conflict.

Router Hub's portable nginx templates live in `config/nginx/templates`. Test
mode points directly to this shared template set. Linux setup copies it into
`data/linux/nginx/templates`, preserving local template edits, and the Linux
nginx smoke test uses the same source templates. The extracted templates omit
router addresses and filesystem paths; deployment-specific listeners, paths,
and upstreams remain in the active nginx configuration or site content.

The shared nginx source tree also provides the generic `nginx.conf.template`,
`mime.types`, `conf.d/01-global.conf`, and portable proxy/security snippets.
Linux setup and the real Linux integration test install these shared assets into
their nginx prefixes while preserving local files. The template keeps PID and
error log paths as render-time settings; listeners, certificate paths, LAN
allowlists, and challenge storage remain deployment-specific.

The router installer bootstraps `/opt/etc/nginx/nginx.conf` from the shared
`config/nginx/nginx.conf.template` only when no nginx config exists. If nginx is
already configured, Router Hub keeps using that config. In both cases, the
installer copies missing portable templates and snippets from `config/nginx/`
without replacing existing router-local files. Listener addresses, access
rules, certificate paths, and local templates remain deployment-specific.
Router Hub adds HTTP-01 certificate domains to its managed HTTP forwarder and
serves the challenge path from the certificate store configured in TOML.

The portable `restrict.conf` starts with `deny all` so LAN-only templates do not
expose a site when no local subnet has been configured. Add the router or host
LAN CIDR as an `allow` directive before `deny all` in the deployed snippet.
