# Changelog

## 0.11.0

### Changed

- Rebrand the Rust application as **Maestro** (binary, CLI, UI, IPK, service, release assets, new-install configuration and documentation).
- Keep existing API paths and legacy firewall identifiers stable while adding Maestro static asset endpoints.
- Provide a one-time, non-destructive Router Hub configuration adoption path. The new Entware package conflicts with the old package and requires a controlled migration; no automatic cross-package upgrade is attempted.
- Preserve the existing SVG/PNG artwork under renamed filenames for replacement separately.

Router Hub follows [Semantic Versioning](https://semver.org/).

## 0.10.5

### Added

- Install `dehydrated-dns01-hook.sh` along with Router Hub at
  `/opt/var/lib/router-hub/dehydrated/dehydrated-dns01-hook.sh`, default DNS-01
  challenge configuration to that hook, and support user overrides in
  configuration (`[certificates].dns01_hook` or `[commands].dehydrated_dns01_hook`)
  or per-certificate.
- Download the latest dehydrated executable to
  `/opt/var/lib/router-hub/dehydrated/dehydrated` during installation, and add
  the `update-dehydrated` CLI command.
- Add `make ipk` to build and package the AArch64 musl Entware IPK and checksum
  using the version in `Cargo.toml`.
- Add an AArch64 QEMU lab with Entware, simulated ASUS firmware interfaces and
  WireGuard support. The mock ASUS UI uses HTTP 8080 and HTTPS 8443, leaving
  ports 80 and 443 available for NGINX. `make init-lab` caches a checksum-verified
  Alpine installer and creates a missing disk in `data/lab/`; `make run-lab`
  reuses that disk. `init-lab` exits immediately for an existing disk; for a new
  disk it automatically mounts the project share, runs the Alpine answer file,
  confirms erasure of that new disk, and provisions the installed system in a
  chroot before powering off. Services start on the installed guest's first boot.
  Root's interactive shell displays saved credentials and browser links. Alpine
  installs into a separate mount directory so cleanup preserves the project share.

### Fixed

- Take over the main nginx configuration during installation and `init-nginx`,
  saving a different existing file as a unique backup while preserving saved
  inputs and other existing shared/custom files.
- Allow IPK installation and removal when Router Hub is already stopped.
- Allow NGINX upgrades with an empty PID file created by `nginx -t` when
  process inspection confirms NGINX is stopped; retain checks for malformed
  PID files and unverified running processes.

## 0.10.4

### Added

- Add router-only `upgrade-nginx` with stable/mainline/exact release selection,
  HTTPS downloads, SHA-256 verification of matching Entware IPKs, and
  explicit opt-in downgrades.
- Preserve pre-install NGINX binaries, modules, module directives and init script
  for emergency recovery. Activate new NGINX masters with SIGUSR2 and gracefully
  retire the old master with SIGQUIT, rather than an abrupt init.d restart.

### Fixed

- Detect custom NGINX release rebuilds by executable/module checksums rather
  than version alone, paginate release discovery, and reject ambiguous release
  tags, unsafe filenames, and invalid package asset sizes.
- Serialize upgrades, isolate downloaded packages in non-overwriting private
  directories, check temporary disk space, and report opkg/activation failures
  instead of reporting success. Restore prior files on pre-activation failures
  and document limits of package-manager rollback.

## 0.10.3

### Added

- Run CI on main updates and opt-in `ci/**` branches, retain manual PR checks,
  and automatically tag new stable versions after successful main CI using a
  repository-scoped GitHub App token to start the existing release workflow.

- Add `router-hub restore <archive>` with an optional `--root` inspection tree,
  archive validation before destination writes, and atomic file replacement.
  Recovery works with missing or invalid configuration; `--test-mode` validates
  without restoring files.
- Add `router-hub backup` to archive configuration, persistent state, nginx,
  certificates, the installed executable and router hooks. Router backups go to
  `/tmp`; Linux backups go alongside the selected configuration file.
- Create a backup before upgrading to a newer release, including download-only
  upgrades. `--no-backup` skips the backup; a backup failure otherwise aborts
  installation.

### Fixed

- Use HTTP/1.1 for nginx-builder downloads of release metadata, source archives,
  signatures and signing keys from nginx.org.

## 0.10.2

### Added

- Publish a verified Entware `aarch64-3.10` IPK alongside stable AArch64
  tarball releases, with package-managed service lifecycle hooks and shared
  installation initialization that migrates nginx inputs when required and
  preserves existing configuration and state.
- Add router-only `router-hub upgrade` to find the newest stable GitHub
  release, verify its IPK checksum, stage it under `/tmp`, and run Entware
  `opkg install` when possible. `--download-only` prints the manual command.
- Test IPK archive structure in CI and verify checksums during release.

## 0.10.1

### Fixed

- Install supported nginx.org stable packages in CI and release jobs before
  integration tests. The runner's distribution nginx rejects the bundled
  `http2 on` directive, which requires nginx 1.25.1+ with HTTP/2 support.
- Resolve nginx and OpenSSL from PATH in the live ingress test instead of
  assuming the development host's executable locations.
- Build nginx listener directives and retained map rows without intermediate
  formatted strings to satisfy the Rust 1.85 Clippy release checks.
- Wait for a complete mock issuer log record before asserting on concurrent
  certificate renewal, avoiding a race with creation of the empty log file.

## 0.10.0

### Changed

- Default nginx daemon mode to enabled across platforms and test mode, and warn
  when disabling it because foreground nginx blocks `init.d` startup scripts.

- Deploy standard renewed certificate output into nginx with validation and
  rollback, and disable shared TLS session caching to prevent handshake failures
  after reloads with dynamic certificates.

- Add reusable nginx listener profiles, source access rules, blocked paths and
  effective-access previews in the offline UI. Retain legacy configuration and
  transactional rollback across managed inputs and generated output. Reject
  authored HTTP listener conflicts before adopting renewal-only validation.
- Add optional HTTP-01 renewal windows shared by scheduled/manual certificate
  work, with startup recovery and cleanup status. The scoped IPv4 WAN adapter
  requires target-firmware verification; abrupt process death still requires
  startup/manual closure of local HTTP listeners.
- Scope managed upstream lookup to active listener assignments, preserve shared
  upstreams and split-DNS rewrites during staged site moves, and keep older
  hostname conflicts editable. Validate generated restricted-session routes,
  retain unknown-host logging, and recover HTTP access past stale ACME locks.

## 0.9.0

### Changed

- Separate persistent nginx inputs from runtime configuration. Global settings,
  managed sites, and administrator-owned render fragments now live under
  `/opt/etc/router-hub/nginx` by default, configurable with `nginx.inputs_dir`.
  nginx's tree contains final configuration and runtime includes; Jinja policies
  remain embedded in the binary.
- Add `migrate-nginx-inputs` for current-format installations. It rejects
  conflicting destinations, validates copied settings, rolls back failures,
  and preserves active runtime includes and custom nginx configuration. The
  router installer stops Router Hub and runs this migration before initialization.

## 0.8.2

### Added

- Add named nginx request-rate and concurrent-request policies with persistent
  site defaults, nested route overrides, and independent per-IP budgets.
  Expose policy editing through the API and UI, retain existing default and
  supplemental limits, and document a bounded static-asset policy example.

### Tests

- Cover policy validation, inheritance, persistence, and regeneration. Validate
  rendered nginx configurations and isolated asset bursts, independent budgets,
  delayed processing, excess traffic, and LAN/security guards.

## 0.8.1

### Fixed

- Compact the nginx site editors with a responsive settings grid, a separate route policy modal with examples, and setting help popups.

- Align WireGuard interface and peer panes with the shared card, form, and status styles.

- Preserve managed subdomain and subfolder identities when toggling enablement
  for entries without explicit names. Keep distinct site types from overwriting
  each other's settings when they share a hostname, and reject conflicting keys.

## 0.8.0

### Changed

- Update emulated nginx fixtures to use managed site inputs, remove obsolete
  templates and the generated ASUS page, and expand Linux smoke coverage to
  managed-site persistence, regeneration, and HTTPS. Add `make test-nginx` and
  check Linux Python dependencies before creating lab files.

- Simplify the root README and move detailed guides into `docs/`, including
  `docs/architecture.md`. Include the guides in release archives.

- Remove automatic legacy ban-state imports and nginx compatibility settings;
  older installations must follow the migration guide. Consolidate cache settings
  under `cache_policy`, remove unused helpers and dependency features, and avoid
  allocating unused firewall match-event captures. Existing unban route aliases
  retain their behavior.

- Show nginx site settings only for the applicable object type and active features,
  preserving temporarily hidden values and defaults used by child routes. Add
  on-demand help beside each nginx setting.

- Add an offline nginx setup quick reference for PWA, WordPress, and media sites,
  available from the Nginx page and site editors.

- Use `settings/nginx.toml` as the sole persisted source for shared nginx settings,
  site defaults, and allowlists; remove the separate global JSON state file.

- Rename nginx deployment inputs to `settings/nginx.toml` with a `[global]` table.

- Omit nginx's worker-user directive for non-root execution; root execution uses
  the configured user or `nobody`. Configure one temporary parent with fixed
  nginx subfolders, defaulting to `tmp` alongside the Linux nginx root.

- Preserve nginx worker user, daemon mode, and Linux temporary paths during
  regeneration and normalize relative fallback certificate paths.

- Save managed nginx site inputs in `settings/sites.toml`, read deployment entries,
  and regenerate configuration from settings-only managed editors.

- Render nginx using bundled Jinja policies with global settings and inherited
  per-site controls, preserving explicit false/zero values and custom server text.
- Remove nginx template/root-file editors and legacy configuration conversion;
  existing configurations must be manually ported before deployment. The router
  installer bootstraps a missing nginx configuration from the current empty bundle.

## 0.7.2

### Changed

- Adopted SemVer Git tags, tag-triggered verified AArch64 musl release packages and GitHub Releases.
- Restricted automatic CI to merged pull requests into main, with optional manual CI for open pull requests.


### Fixed

- Distinguish active dehydrated certificate renewals from leftover lock files in the Certificates UI, and prevent clearing a lock while the renewal or a known DNS hook is running.
- Serialize certificate issue/renewal requests, retain completed/failed operation status, and log failures to remove dehydrated locks.
- Terminate dehydrated's entire process group on command timeout so DNS hook subprocesses do not outlive a timed-out renewal.
- Set the example certificate timeout to one hour so it exceeds the NameSilo hook's ten-minute DNS propagation wait.
- Confined native Linux firewall-policy persistence to the configured data directory instead of consulting router-specific `/opt` paths.
- Avoided Asuswrt NVRAM discovery for AdGuard LAN IP in native Linux mode.

### Added

- Added native Linux integration platform with real external commands, no ASUS menu changes, and an isolated nginx prefix option.
- Added `make test-linux` for an unprivileged real-nginx, API, authentication, and metrics smoke test.

## 0.7.1

### Fixed

- Fixed an issue where resuming AdGuard Home protection would fail because it sent an incorrect payload (`protection_enabled` instead of `enabled`).
- Improved mobile responsiveness for AdGuard Home pause controls.

## 0.7.0

### Added

- Reimplemented WireGuard management to natively integrate with live kernel interfaces using the `wg showconf` and `wg syncconf` commands.
- Updated WireGuard parser to gracefully handle lowercase properties and common formatting discrepancies.

## 0.6.2

### Added

- Added live-editable firewall security tuning overrides stored in `firewall-policy.json`.
- Added reputation-aware fast subnet re-promotion for repeat-offender networks.
- Added strict security tuning preset and health validation warnings in the Ban Shield UI.

## 0.6.1

### Fixed

- Fixed nginx object editing for aliased domains and subdomains, including subfolder parent/name detection and upstream map editing.

## 0.6.0

### Added

- Added site launch action button for Nginx domain, subdomain, and subfolder objects.
- Added dehydrated certificate renewal lock status query, UI notice, action blocking, and lock clearing endpoint (`DELETE /api/certificates/dehydrated/lock`).
- Added data sync script (`scripts/sync-data.sh`) supporting get/put for Mosquitto config/passwords, nginx objects/templates, dehydrated certs, scripts, and logs.
- Added DNS-01 hook script for dehydrated (`scripts/dehydrated-dns01-hook.sh`) and test helper (`scripts/test-dehydrated.sh`).

### Fixed

- Fixed the Services tab nginx log action to read the configured nginx log directory.

## 0.5.4

### Added

- Added support for 1, 10, 30, and 60 minute pause options for AdGuard filtering and protection.
- Added separate API Endpoint and Web UI Launch Alias configuration for AdGuard Home integration.
- Added standalone mode hero banner, centered layout container, and embedded SVG logo support (`router-hub.svg`).

### Fixed

- Fixed AdGuard Home filtering status query endpoint to use `GET /control/filtering/status` and corrected auto-resume timer execution.

## 0.5.1

### Added

- Support for prompting and storing authentication tokens automatically when used outside of the Asus UI.

## 0.5.0

### Added

- Added firewall health and capacity reporting to the dashboard.
- Added sortable columns to nginx, firewall, DNS, and DHCP tables.
- Added nginx template duplication and renaming support.
- Added upstream port display for nginx objects.

## 0.4.0

### Added

- Added authenticated management of dnsmasq DHCP reservations while preserving
  unmanaged directives and comments.
- Added favicon serving and navigation support for direct links to UI tabs.

### Changed

- Added domain upstream-map support alongside existing subdomain and subfolder
  upstream maps.
- Added the DNS reservation controls to the web UI.

## 0.3.0

### Added

- Added authenticated `hosts.add` management for AdGuard-compatible local DNS
  entries, with atomic writes and dnsmasq restart after saves.

### Changed

- Excluded underscore-containing AdGuard rewrite domains from Router Hub's
  managed rewrite workflows.

## 0.2.0

### Changed

- Simplified firewall retention and ban duration configuration parameters to use days instead of seconds.
- Added strict validation for firewall ban escalation tiers and retention durations.

### Added

- Added separate counters for active IP bans and active subnet bans to the dashboard overview.

### Fixed & Improved

- Hardened post-mount reconciliation, firewall hooks execution scripts, and token authentication.
- Disabled ANSI color formatting in standard tracing output for clean router syslog logging.

## 0.1.0 — Initial release

The first release provides a resource-conscious management hub for
Asuswrt-Merlin routers. It combines a self-contained web UI, a protected Axum
API, and configurable router integrations in one Rust executable.

### Included

- Asuswrt-Merlin integration through a rendered `user<n>.asp` extension page,
  menu integration, and standalone UI mode.
- Entware service discovery and lifecycle controls, including bounded service
  log viewing.
- Filesystem-backed nginx management for domains, subdomains, subfolders,
  templates, aliases, upstream maps, validation, reloads, and safe root-file
  editing.
- Dehydrated certificate management with HTTP-01 and DNS-01 definitions,
  automatic renewal, deployed-certificate discovery, lock handling, and
  authenticated script updates.
- AdGuard Home configuration, protection controls, and staged DNS rewrite
  management.
- Wake-on-LAN machine management and bounded neighbor/reachability status.
- Log-driven attack protection with compiled matching, weighted IP scoring,
  IPv4 `/24` and IPv6 `/64` subnet promotion, escalating bans, allowlists, and
  ipset/iptables enforcement.
- Persistent JSON state with atomic writes, configurable paths and commands,
  bounded resource usage, timeout handling, and post-mount and firewall-start
  reconciliation.
- Fixture-backed test mode that redirects router paths, simulates privileged
  commands, skips Asuswrt menu changes, and prevents Wake-on-LAN transmission.
- Router installation and release helpers for cross-compiled artifacts,
  including SHA-256 output and an Entware init script.

### Compatibility and security baseline

- Rust 1.85 or newer is required to build the project.
- AArch64 musl is the primary tested router target; other architectures require
  validation on matching hardware and firmware.
- Management routes require a bearer token, production configurations reject
  placeholder or short tokens, and router-sensitive paths are configurable.
- Nginx and JSON changes use path validation and atomic or rollback-safe
  workflows where applicable.
- The built-in listener is HTTP-only and should be kept on a trusted LAN or
  VPN, or placed behind an HTTPS reverse proxy.
