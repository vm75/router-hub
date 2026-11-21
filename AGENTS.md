# Maestro agent guide

## Project overview

Maestro is a Rust service for administrators of Asuswrt-Merlin routers. It
serves a standalone or mounted web UI and a protected Axum API for Entware
services, nginx configuration, certificates, Wake-on-LAN, firewall bans, and
optional AdGuard Home integration. Router-sensitive state is kept in TOML and
atomic JSON files. Managed nginx site inputs live in `<nginx.inputs_dir>/sites.toml`;
custom nginx objects remain authored configuration files.

## Repository map

- `src/main.rs`, `src/config.rs`, `src/state.rs`, `src/platforms/{upgrade,nginx_upgrade}.rs` — startup, configuration, runtime state, and router-only upgrade commands.
- `src/api/` — authenticated HTTP API handlers and route map.
- `src/modules/{nginx,nginx_sites}.rs`, `src/nginx_render.rs` — nginx filesystem workflows, Jinja rendering, and settings.
- `src/modules/firewall.rs`, `src/ban_attack/` — firewall management and log-driven bans.
- `src/command.rs`, `src/platforms/asus_ui.rs`, `src/storage.rs` — privilege boundary, ASUS page integration, and persistence.
- `src/core/modules.rs`, `src/core/system_usage.rs`, `src/modules/`, `src/platforms/` — capabilities, feature code and platform-specific adapters.
- `web/src/`, `scripts/build-web-ui.py`, `web/index.html` — modular UI sources, deterministic offline composer, and the embedded generated artifact.
- `config/`, `scripts/`, `test-fixtures/` — configuration, router installation, and test-mode support.
- `tests/` — API and firewall integration coverage.
- [`README.md`](README.md) — operator setup and usage.
- [`docs/architecture.md`](docs/architecture.md) — current boundaries, flows, and invariants.

## Working commands

Rust 1.85 or newer is required.

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 scripts/build-web-ui.py --check
node scripts/test-web-ui.mjs
```

Useful repository shortcuts are `make check`, `make test`, `make run`,
`make fmt`, `make clippy`, `make test-nginx`, `make test-lab`, and `make release`.
`make test-nginx` needs Python 3.11+, Jinja2, nginx, and OpenSSL and uses temporary
files and loopback servers. `make run` starts x64 test mode
with `test-fixtures/etc/router-hub/router-hub.toml`; it does not execute router commands or send
Wake-on-LAN packets.

For **real Linux integration** use `platform = "linux"` (or
`--linux-mode`) with `test_mode = false`. `make test-linux` runs a
temporary unprivileged real-nginx smoke test; it does not exercise live
firewall enforcement, DNS providers, or router firmware. Keep real firewall
tests in isolated network namespaces/VMs and always use lab-only paths.

For a release artifact, use `./scripts/build-release.sh <rust-target>`.
Use `make ipk` to build and package the AArch64 musl Entware IPK and checksum
in `dist/`, deriving the package version from `Cargo.toml`.
The `scripts/package-ipk.sh` helper and `scripts/test-package-ipk.sh` smoke test
build and validate a static-musl AArch64 IPK without an Entware toolchain.
The repository contains a helper default for `aarch64-unknown-linux-musl`,
but a target is supported only after testing it on the matching router CPU and
firmware. Legacy MIPS support is not promised.

## Release workflow

CI runs on every push to main and opt-in `ci/**` branches. Other PRs are
manual: workflow_dispatch accepts an open PR number to check its proposed merge,
or no number to check the selected branch. Successful push CI on current main
automatically tags a new stable version matching `Cargo.toml` and `Cargo.lock`.
Tagging requires the release GitHub App credentials documented in `docs/releases.md`.
Annotated version tags trigger the separate full release checks and publication
of AArch64 musl archives/IPKs with SHA-256 checksums. Manual tags remain supported.
Do not commit `dist/` output or retag published versions; never deploy to
production routers automatically.

The standalone Entware NGINX builder has a **manual-only** GitHub Actions
workflow (`.github/workflows/build-nginx.yml`). Its uniquely tagged
`nginx-v*` GitHub Releases must always be created with `--latest=false`;
stable Maestro releases remain Latest for the router-only upgrade command.
Do not introduce automatic NGINX build triggers or router deployment.

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
- Keep the self-contained UI offline-capable; do not add a frontend package manager or CDN dependency. Edit `web/src/`, then regenerate `web/index.html` with `python3 scripts/build-web-ui.py`.
- Phase 1 was merged as v0.10.5. Phase 1.5 rebrands the application to Maestro on `refactor/rebrand-maestro`. Preserve legacy installed configuration, state, NGINX inputs and firewall identities. Keep the existing Go `vm75/server-man` as a Phase 2 reference; do not port its features in Phase 1.5.

## Documentation routing

- Update `README.md` for the user-facing overview and quick start; keep detailed installation, configuration, development, Linux integration, and release guidance in the linked `docs/` guides.
- Update `AGENTS.md` for agent workflow, commands, navigation, or safety constraints.
- Update `docs/architecture.md` when component boundaries, data flow, or invariants change.
- Update `CHANGELOG.md` for user-visible release history when the project’s release policy requires it.
- Do not create design, decision, container, or CI documentation without repository evidence or a concrete requirement.

## Definition of done

- Relevant tests, formatting, Clippy, and builds pass when available.
- Release binary build (`./scripts/build-release.sh` or `cargo build --release`) is completed prior to committing version bumps.
- New behavior has focused tests when practical.
- Documentation describes the repository after the change and contains no placeholders or machine-local links.
- No unrelated files, dependencies, generated artifacts, or claims were added.
