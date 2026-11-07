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

Open <http://127.0.0.1:3030> with the test token `router-hub-test-token`.
Fixture-backed test mode simulates external commands, skips ASUS menu changes,
and does not send Wake-on-LAN packets.

For real services, see the [Linux integration guide](linux.md).

## Checks

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Shortcuts are available through `make check`, `make test`, `make fmt`,
`make clippy`, `make run`, and `make release`.

With the Python environment active, run `make test-nginx` for the bundled
nginx policy and loopback tests. `make test-linux` exercises the API with real
nginx, including managed-site persistence, regeneration, and HTTPS.

The emulated nginx examples are managed inputs in
`test-fixtures/etc/router-hub/nginx/sites.toml`. Test mode still writes fixture
files when you save settings; the ASUS page is generated at startup and ignored
by Git.

## Certificate staging tests

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
