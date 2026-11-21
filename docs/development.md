# Development

[← Back to README](../README.md)

## Prerequisites

- Rust 1.85 or newer.
- A Unix-like environment with the standard Rust tooling.
- Python 3.11 or newer (for Linux lab setup scripts and nginx template validation). You can use `uv` to set up a virtual environment and install dependencies:

  ```sh
  uv venv
  source .venv/bin/activate
  uv pip install -r requirements.txt
  ```

## Run locally

```sh
make run
```

Open <http://127.0.0.1:3030> with the fixture test token `router-hub-test-token`.
Fixture-backed test mode simulates external commands, skips ASUS menu changes,
and does not send Wake-on-LAN packets.

For real services, see the [Linux integration guide](linux.md).
For validating AArch64 packaging, Entware service startup, ASUS UI integration, and kernel WireGuard in an emulated guest, see the [AArch64 Router Lab guide](../lab/aarch64/README.md).

## Sync router data

Copy `.env.example` to `.env` and set `SYNC_DATA_HOST` to your SSH host or
alias. Set `SYNC_DATA_ROUTER_HOME` to the remote user's home directory if it
differs from `/opt/home/admin`; this also sets the certificate mirror path.
The script sources `.env` as trusted Bash assignments. `.env` and its local
variants are ignored by Git.

```sh
./scripts/sync-data.sh -t get nginx
./scripts/sync-data.sh -s user@router-host get nginx
```

`-s` overrides the configured host. `get` and `put` require a host; help and
`zip` work without one. Mirrored files and archives stay in ignored `data/` and
can contain credentials, certificates, and private logs.

## Checks

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Shortcuts are available through `make check`, `make test`, `make fmt`,
`make clippy`, `make run`, and `make release`.

Run `make ipk` to build the AArch64 musl release binary and package the Entware
IPK using the version in `Cargo.toml`. The package and its SHA-256 checksum are
written to `dist/maestro_<version>-1_aarch64-3.10.ipk` and `.ipk.sha256`.
This uses the same cross-compilation toolchain as `make release`.

With the Python environment active, run `make test-nginx` for the bundled
nginx policy and loopback tests. `make test-linux` exercises the API with real
nginx, including managed-site persistence, regeneration, and HTTPS.

The emulated nginx examples are managed inputs in
`test-fixtures/etc/router-hub/nginx/sites.toml`. Test mode still writes fixture
files when you save settings; the ASUS page is generated at startup and ignored
by Git.

## Build cache size

Development and test builds use limited debug information (`debug = 1`) to
reduce `target/` disk usage. Backtraces retain file and line information, but
debugger type and variable inspection is limited. Incremental compilation stays
enabled for faster rebuilds after source changes.

For a debugging session that needs full debug information, run
`CARGO_PROFILE_DEV_DEBUG=2 cargo build`.

Cargo can retain artifacts from old compiler, dependency, and feature settings.
With no builds running, remove `target/debug/incremental/` to clear just the
development and test incremental cache. Run `cargo clean --profile dev` to
remove development and test artifacts, or `cargo clean` to remove all build
artifacts. The next build recreates what it needs.

## Ingress and offline UI regression checks

`cargo test --test nginx_ingress_test` exercises managed ingress, temporary
HTTP-01 sessions, concurrency, failure recovery and real loopback nginx. The
certificate WAN unit tests use `test-fixtures/bin/netfilter-mock.py`; they never
execute host firewall tools. These tests do not certify firmware behavior.

For the optional browser workflow check, install Node 22+ and Chromium, build
with `cargo build`, then run:

```sh
node scripts/test-nginx-ui.mjs target/debug/maestro /usr/sbin/chromium
```

The script starts a temporary test-mode server and checks normal form controls,
source previews, advanced-route preservation, draft retention, narrow layout,
keyboard access and offline failures. It uses built-in Node APIs and Chromium's
debugging protocol without npm packages. Pass `--keep` to retain the lab and its
mobile screenshot. Browser and live-nginx checks require loopback socket access.

## Certificate staging tests

To exercise the dehydrated command and DNS hook against Let's Encrypt staging,
use the temporary test harness. It uses the same `--cron --accept-terms
--config` invocation as Maestro and leaves router certificate data untouched:

```sh
DEHYDRATED=/path/to/dehydrated \
  DNS_PROVIDER=duckdns DUCKDNS_TOKEN=... \
  ./scripts/test-dehydrated.sh '*.example.duckdns.org'
```

Use repeated `--env KEY=VALUE` options when you want the hook settings written
into the temporary dehydrated config, as they are by Maestro. The harness
uses the staging CA by default and supports `--method http`, `--hook`,
`--force`, and `--keep`.

## API overview

The API is primarily consumed by the bundled UI. Unauthenticated endpoints are
`GET /healthz` and `GET /api/version`; the standalone page is token-gated.
Management endpoints require the bearer token and are grouped as follows:

- `/api/services` — Entware service discovery, actions, and logs;
- `/api/nginx` — nginx status, lifecycle, global settings, site objects, and logs;
- `/api/certificates` — certificate definitions, issue/renew operations,
  dehydrated lock handling, and script update;
- `/api/wol` — machine management, wake, and status;
- `/api/firewall` — policy, rules, allowlists, bans, counters, and status;
- `/api/adguard` — AdGuard configuration, protection, staged rewrites, and
  `hosts.add` management (saving hosts restarts dnsmasq);
- `/api/dashboard`, `/api/runtime`, and `/api/auth/check` — authenticated
  status views.

The authoritative route map is [`src/api/mod.rs`](../src/api/mod.rs).

See [architecture](architecture.md) for boundaries and invariants, and
[CI and releases](releases.md) for publishing.
