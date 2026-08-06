# Changelog

Router Hub follows [Semantic Versioning](https://semver.org/).

## 0.6.0

### Added

- Added site launch action button for Nginx domain, subdomain, and subfolder objects.
- Added dehydrated certificate renewal lock status query, UI notice, action blocking, and lock clearing endpoint (`DELETE /api/certificates/dehydrated/lock`).
- Added data sync script (`scripts/sync-data.sh`) supporting get/put for Mosquitto config/passwords, nginx objects/templates, dehydrated certs, scripts, and logs.
- Added DNS-01 hook script for dehydrated (`scripts/dehydrated-dns01-hook.sh`) and test helper (`scripts/test-dehydrated.sh`).

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
