# Changelog

Router Hub follows [Semantic Versioning](https://semver.org/).

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
