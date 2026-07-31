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
- Maintain allowlists, persistent state, firewall-start reconciliation, and an
  `observe_only` mode for evaluating rules without enforcement.

The engine is deliberately bounded: log reads, line sizes, tracked addresses,
subnets, reputation, active bans, command input, and command deadlines all have
limits. Its defaults are intended for a small router, not for replacing a
dedicated IDS or high-volume firewall appliance.

### Router and LAN administration

- Discover executable Entware init scripts, show bounded logs, and start,
  stop, restart, reconfigure, enable, or disable services.
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
cargo run -- --config ./config/router-hub.test.toml --test-mode serve
```

Open <http://127.0.0.1:3030>. The test token is `router-hub-test-token` when
using the repository test configuration. The equivalent shortcut is:

```sh
make run
```

The test configuration is safe for exercising the UI and API, but it is not a
router deployment configuration.

## Build and install on a router

Build the release artifact for the target CPU. The helper also writes a SHA-256
file under `dist/`:

```sh
./scripts/build-release.sh aarch64-unknown-linux-musl
```

Copy the resulting binary, `config/`, and `scripts/` to the router, then run
the installer as root from that copied repository:

```sh
./scripts/install-merlin.sh ./router-hub-aarch64-unknown-linux-musl
```

The installer:

1. installs the binary as `/opt/bin/router-hub` and the Entware init script as
   `/opt/etc/init.d/S99router-hub`;
2. creates `/opt/etc/router-hub/router-hub.toml` and a random authentication
   token on first install;
3. creates the runtime/data directories and installs the example firewall
   policy when needed;
4. adds a token-free reconciliation call to `/jffs/scripts/firewall-start`;
5. validates the configuration and restarts Router Hub.

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
process and is used by the installed `firewall-start` hook.

## Configuration

Use [`config/router-hub.example.toml`](config/router-hub.example.toml) as the
reference. The main sections are:

- `[server]` — bind address, port, bearer token, CORS origins, and request
  limits;
- `[paths]` — persistent data and runtime directories;
- `[commands]` — absolute paths to nginx, Entware utilities, firewall tools,
  dehydrated, OpenSSL, NVRAM, and network commands;
- `[asus_ui]` — extension-page rendering and ASUS menu integration;
- `[services]` — Entware init directory, log roots, and timeouts;
- `[nginx]` — nginx root/configuration, managed object trees, generated
  includes, and log limits;
- `[certificates]` — dehydrated certificate directory and renewal policy;
- `[firewall]` — matching, scoring, retention, subnet promotion, resource
  bounds, and command limits.

Persistent JSON is stored below `paths.data_dir` and written atomically. It
contains certificate definitions, Wake-on-LAN machines, firewall policy and
state, and AdGuard overrides. Nginx objects remain represented by nginx files
and relative symlinks rather than a second database. Existing dehydrated
definitions and deployed nginx certificates can be imported at startup.

## Security and operational notes

- Management routes require `Authorization: Bearer <token>`. The standalone
  page receives its token through its initial query string; the Asuswrt page
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
- `/api/adguard` — AdGuard configuration, protection, and staged rewrites;
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
