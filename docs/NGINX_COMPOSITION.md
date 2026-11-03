# Composable Nginx sites (schema v1)

Router Hub supports three Nginx site modes:

* **Composed:** an adjacent `.toml` file is the source of truth. Router Hub generates the matching `.conf`.
* **Template:** the existing named template expands to a `.conf`, as before.
* **Custom:** a hand-written `.conf` remains authoritative; Router Hub does not rewrite it.

Existing sites are **not migrated automatically**. This is intentional: some deployed template-backed files contain manual modifications. Convert one site at a time using the editor's **Composed (TOML)** mode, checking the rendered configuration before saving. Custom files remain supported indefinitely.

## Site definitions and generated files

Definitions live beside the corresponding Nginx site, within the existing `domains-available` tree:

| Site type | Authoritative definition | Generated configuration |
|---|---|---|
| Domain | `domains-available/example.test/root.toml` | `root.conf` |
| Subdomain | `domains-available/example.test/subdomains-available/media.toml` | `media.conf` |
| Subfolder | `domains-available/example.test/subfolders-available/app.toml` | `app.conf` |

The normal `domains-enabled` and `subdomains-enabled`/`subfolders-enabled` symlinks continue to control enablement. Upstream maps, aliases, certificate configuration, HTTP redirects, and the Nginx test/reload lifecycle remain managed by Router Hub. **Do not edit generated `.conf` files directly.**

### Example: LAN-only streaming subdomain with large uploads

```toml
schema_version = 1
kind = "subdomain"
domain = "example.test"
name = "media"
server_names = ["media.example.test", "video.example.test"]
upstream = "http://127.0.0.1:8096"

[options]
access = "lan"
streaming = true
long_lived = true
large_upload = true
body_size = "5G"
read_timeout = "3600s"
send_timeout = "3600s"
```

`access = "lan"` uses the deployed `snippets/restrict.conf`; configure trusted `allow` networks there. The repository's default file is deny-all until it is customized. It does **not** automatically discover LAN CIDRs.

### Example: root domain that hosts subfolders

```toml
schema_version = 1
kind = "domain"
domain = "example.test"
name = "example.test"
server_names = ["example.test"]

[options]
root = "subfolders"
body_size = "100M"
```

`root` choices are `subfolders` (root returns 404), `proxy`, or `proxy_and_subfolders`. Proxy roots require an `upstream` URL; these use the **domain upstream map**.

### Example: standard or PWA subfolder

```toml
schema_version = 1
kind = "subfolder"
domain = "example.test"
name = "app"
server_names = ["example.test"]
upstream = "http://127.0.0.1:3000"

[options]
access = "lan"
subfolder = "pwa"
```

`subfolder` choices are `standard` and `pwa`. Additional subfolder rewrites, overlapping regex locations, SSE routes, or application-specific authorization should continue to use custom Nginx.

## Supported options (v1)

Only options from the existing templates/deployment are implemented. Unsupported fields cause validation errors rather than being ignored.

| Option | Applies to | Behavior |
|---|---|---|
| `access = "public" / "lan"` | all | Include `restrict.conf` for LAN/restricted mode |
| `root = "subfolders" / "proxy" / "proxy_and_subfolders"` | domain | Choose domain root routing |
| `subfolder = "standard" / "pwa"` | subfolder | Choose mounted proxy behavior |
| `large_upload = true` | subdomain, proxying domain | Request streaming and default max body 5G |
| `long_lived = true` | subdomain, proxying domain | Default read/send timeouts of 3600s |
| `streaming = true` | subdomain | Turn off response buffering |
| `websocket = true` | subdomain | Default read/send timeouts of 60s (the common proxy snippet already handles upgrades) |
| `pwa = true` | LAN-only subdomain | Include the existing PWA static-asset locations |
| `sessions_lan_only = true` | streaming subdomain | Restrict and bypass logging for `/Sessions` |
| `strip_origin = true` | subdomain | Suppress the request Origin header upstream |
| `body_size = "5G"` | domain or subdomain | Override request body size |
| `read_timeout = "3600s"`, `send_timeout = "3600s"` | domain proxy or subdomain | Override proxy timeouts |

Timeouts accept positive integer `s`, `m`, `h`, or `d` units. Body sizes accept positive integer `k`, `m`, or `g` units. Features are merged **before** rendering to avoid duplicate Nginx directives. See the unit tests in `src/nginx_compose.rs`.

A composed proxy site requires an upstream URL. Subfolder definitions currently permit only access policy and standard/PWA behavior; more complex applications remain custom. The schema is intentionally strict and small.

## Version control and applying external changes

You can commit the `.toml` definitions to Git alongside custom site files. **The source-of-truth for a composed site is its TOML**, not the generated Nginx file. If TOML is edited outside the UI, run:

```sh
router-hub --config /opt/etc/router-hub/router-hub.toml render-sites
```

This command reads the adjacent TOML definitions, regenerates their `.conf` files, synchronizes all site upstream maps/aliases and the HTTP forwarder, runs `nginx -t`, and restores the previous files and maps on a failure. **It does not reload Nginx**; use Router Hub's Nginx reload action after checking the result.

UI edits of composed sites write both the generated configuration and the TOML definition. The normal existing validation and rollback behavior applies to enabled-site changes. Non-composed sites follow the unchanged template/custom logic.

The CLI processes definitions only for sites that already have a `.conf` file. For a brand-new site, use the UI/API to create it before editing its TOML directly. Enablement remains a symlink operation, not a TOML field.

## Conversion notes and limitations

1. First compare the existing `.conf` with its deployed template; template markers alone do not prove that the file is unchanged. The deployment used for this work contains hand-edited template instances.
2. Select **Composed (TOML)** in the site editor, set the appropriate capabilities, and explicitly review the generated `.conf` before enabling/reloading. Existing custom sites should not be converted automatically.
3. Validate on the target Nginx build. File inclusion, HTTP header inheritance, URI rewriting, and overlapping locations can be application-specific.
4. Treat `snippets/restrict.conf`, TLS/certificate assets, and any custom include files as deployment-owned. Installers intentionally preserve local modifications to these files.
5. Avoid placing secrets in version-controlled TOML. Use appropriate access controls and a private repository where needed.

The composer deliberately does **not** implement arbitrary additional locations, WordPress rules, request authentication, unusual aliases/fallbacks, custom SSE rules, or arbitrary Nginx directives. Those configurations continue to use **Custom**.
