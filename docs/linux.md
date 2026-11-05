# Native Linux integration

[← Back to README](../README.md)

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
`openssl`, `curl`, and `python3` (with Jinja2 available in `PATH` or the activated `uv` virtual environment). It creates an isolated temporary
configuration and nginx prefix under `/tmp`, runs the real router-hub binary, verifies
authentication and system metrics, and exercises real nginx validation,
startup, reload, shutdown, and managed-site creation, updates, regeneration,
HTTPS requests with self-signed certificates, and deletion:

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

## Service adapters and nginx setup

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

Linux setup requires Python Jinja2 (available via `requirements.txt` in the virtual environment), nginx, and openssl. For a new lab it renders
only the current Jinja bundle, generates a temporary fallback TLS certificate,
and records its loopback listeners and runtime paths in
`nginx/settings/nginx.toml`. HTTP uses port 8080 and HTTPS uses port 8443.
Existing lab configurations are preserved; setup performs no conversion.
The smoke test uses a separate temporary directory under `/tmp`.
