# Router Hub

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Asuswrt--Merlin-red.svg)](https://www.asuswrt-merlin.net/)

**One administrator UI for your Asuswrt-Merlin router’s services, sites, and security.**

Manage your router from a standalone page or inside the ASUS menu. Written in
Rust, with an offline-capable UI, no database, and no frontend build step.
Router Hub coordinates your installed Entware tools.

[Install](#install-on-your-router) · [Try locally](#try-it-locally) · [Documentation](#documentation) · [Releases](https://github.com/vm75/router-hub/releases)

## Features

| | What you can do |
| --- | --- |
| **Nginx sites** | Manage domains, subdomains, reverse proxies, and subfolders with inherited settings, validation, and rollback. |
| **HTTPS certificates** | Issue and renew through dehydrated using HTTP-01 or DNS-01; inspect certificates and clear stuck locks. |
| **Ban Shield** | Detect log-based attacks, score IPs and subnets, and enforce escalating bans with allowlists and observe-only mode. |
| **Entware services** | Start, stop, restart, enable, and disable services; inspect status and logs. |
| **AdGuard Home** | Toggle protection and manage DNS rewrites without conflicting with nginx-managed names. |
| **Wake-on-LAN** | Save LAN devices, check reachability, and send magic packets. |
| **Dashboard & ASUS menu** | View service and runtime status, standalone or in an Asuswrt extension page. |

> Keep management access on a trusted LAN or VPN and use a long random token.
> The built-in listener is HTTP-only; use an HTTPS reverse proxy when needed.
> Do not expose the listener directly to the public internet.

## Install on your router

You need **Asuswrt-Merlin**, JFFS custom scripts enabled, **Entware at `/opt`**,
and a binary matching your router CPU and ABI. Install nginx, dehydrated,
OpenSSL, and firewall utilities as required by the features you use.
Releases provide **AArch64 musl** packages; compatibility still needs testing
on your matching CPU and firmware. Legacy MIPS support is not promised.

1. Back up your configuration and persistent state. For an existing installation,
   read the [migration guide](docs/migration.md) first; existing nginx configuration
   must be ported to the current bundle before deployment.
2. Download the matching archive and checksum from
   [GitHub Releases](https://github.com/vm75/router-hub/releases).
   Verify with `sha256sum -c <archive>.tar.gz.sha256`, then extract the archive.
3. From the extracted package, run as root on the router:

   ```sh
   ./scripts/install-merlin.sh ./router-hub
   ```

   The installer creates a token and configuration on first install, preserves
   existing configuration, installs startup hooks, and restarts Router Hub.
4. Review `/opt/etc/router-hub/router-hub.toml`: set your bind address,
   allowed origins, ASUS page/menu, API URL, and service paths. The shipped
   values are examples. Restart after changes:

   ```sh
   /opt/etc/init.d/S99router-hub restart
   ```

5. Open the configured ASUS menu entry, or
   `http://<router-ip>:3030/#token=<auth-token>` using the token from your TOML.

See [installation](docs/installation.md) for download commands, source builds,
installer options, and service control.

## Try it locally

With **Rust 1.85+**, from a checkout:

```sh
make run
```

Open <http://127.0.0.1:3030> and use the test token `router-hub-test-token`.
This uses fixture data, simulates external commands, skips ASUS menu changes,
and does not send Wake-on-LAN packets.

For testing against real services, follow the [Linux integration guide](docs/linux.md).

## Configure and use

Start with the [example TOML](config/router-hub.example.toml) for paths,
authentication, commands, and integration settings. Then use the UI to manage
services, sites, certificates, saved devices, and firewall policy.

- **Nginx:** set listeners and defaults in **Global settings**, then add sites.
  **Setup quick reference** has offline profiles and route examples.
- **Ban Shield:** evaluate rules with `observe_only` before enabling enforcement;
  tune thresholds and ban durations to suit your network.
- **AdGuard Home:** configure its endpoint and credentials to enable integration.

See [configuration and operation](docs/configuration.md) for persistence,
security, nginx settings, and firewall tuning.

## Documentation

| Guide | Contents |
| --- | --- |
| [Installation](docs/installation.md) | Packages, source builds, installer options, service commands |
| [Configuration](docs/configuration.md) | TOML sections, nginx settings, Ban Shield tuning, operational notes |
| [Upgrading](docs/migration.md) | Migration steps and nginx compatibility |
| [Development](docs/development.md) | Prerequisites, local checks, certificate tests, API overview |
| [Linux integration](docs/linux.md) | Real-service lab setup and smoke tests |
| [Architecture](docs/architecture.md) | Components, data flows, persistence, invariants |
| [CI and releases](docs/releases.md) | Manual PR checks, versioning, publishing |
| [Nginx bundle](config/nginx/README.md) | Site options, route policies, templates, validation |
| [Changelog](CHANGELOG.md) | Release history |

Coding agents: see [AGENTS.md](AGENTS.md) for repository workflow and constraints.

## License

[MIT](LICENSE)
