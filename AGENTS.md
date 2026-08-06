# Router Hub agent guide

## Project overview

Router Hub is a Rust service for administrators of Asuswrt-Merlin routers. It
serves a standalone or mounted web UI and a protected Axum API for Entware
services, nginx configuration, certificates, Wake-on-LAN, firewall bans, and
optional AdGuard Home integration. Router-sensitive state is kept in TOML and
atomic JSON files; nginx configuration remains authoritative for nginx objects.

## Repository map

- `src/main.rs`, `src/config.rs`, `src/state.rs` — startup, configuration, and shared runtime state.
- `src/api/` — authenticated HTTP API handlers and route map.
- `src/nginx.rs`, `src/firewall.rs`, `src/ban_attack/` — nginx filesystem workflows and log-driven bans.
- `src/command.rs`, `src/asus_ui.rs`, `src/storage.rs` — privilege boundary, ASUS page integration, and persistence.
- `web/index.html`, `config/`, `scripts/`, `test-fixtures/` — UI/template, configuration, router install, and test-mode support.
- `tests/` — API and firewall integration coverage.
- [`README.md`](README.md) — operator setup and usage.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — current boundaries, flows, and invariants.

## Working commands

Rust 1.85 or newer is required.

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Useful repository shortcuts are `make check`, `make test`, `make run`,
`make fmt`, `make clippy`, and `make release`. `make run` starts x64 test mode
with `test-fixtures/etc/router-hub/router-hub.toml`; it does not execute router commands or send
Wake-on-LAN packets.

For a release artifact, use `./scripts/build-release.sh <rust-target>`.
The repository contains a helper default for `aarch64-unknown-linux-musl`,
but a target is supported only after testing it on the matching router CPU and
firmware. Legacy MIPS support is not promised.

## Engineering constraints

- Follow KISS and YAGNI. Make the smallest change that satisfies the concrete request.
- Keep context lean: search first and read only task-relevant files; do not scan generated, vendored, or build-output trees by default.
- Do not read, search, or modify the `data/` directory unless explicitly requested by the user. It contains configuration and logs mirrored from the deployment router.
- Preserve existing behavior and user changes. Do not reset or overwrite unrelated work.
- Build the release binary (`./scripts/build-release.sh` or `cargo build --release`) before committing whenever the version is bumped.
- Run privileged programs through `CommandRunner` as a program plus separate arguments. Never use `sh -c`, interpolation, `eval`, or arbitrary API-supplied command strings.
- Keep router paths configurable and provide a test-mode override for every new router-specific path.
- Preserve atomic JSON and nginx writes, path/symlink protections, token authentication, and bounded log reads.
- Do not claim router compatibility without an actual matching architecture and firmware test.
- Keep the self-contained UI offline-capable; do not add a frontend build chain or CDN dependency without a concrete need.

## Documentation routing

- Update `README.md` for user-facing setup, configuration, capabilities, or limitations.
- Update `AGENTS.md` for agent workflow, commands, navigation, or safety constraints.
- Update `ARCHITECTURE.md` when component boundaries, data flow, or invariants change.
- Update `CHANGELOG.md` for user-visible release history when the project’s release policy requires it.
- Do not create design, decision, container, or CI documentation without repository evidence or a concrete requirement.

## Definition of done

- Relevant tests, formatting, Clippy, and builds pass when available.
- Release binary build (`./scripts/build-release.sh` or `cargo build --release`) is completed prior to committing version bumps.
- New behavior has focused tests when practical.
- Documentation describes the repository after the change and contains no placeholders or machine-local links.
- No unrelated files, dependencies, generated artifacts, or claims were added.
