# Nginx composition: version-controlled TOML catalog (schema v1)

Nginx Compose is **data-driven**. The supported options, allowed site kinds, defaults, dependencies, parameters, and Nginx directives are read at runtime from [`config/nginx/composer.toml`](../config/nginx/composer.toml). There are no per-feature Rust enums or JavaScript conditionals. Add or change a supported option by editing this catalog and deploying it; no change to `src/nginx_compose.rs` or `web/index.html` is needed.

Router Hub keeps three site modes:

- **Composed**: an adjacent TOML site file is authoritative; a `.conf` file is generated.
- **Template**: the existing named template continues to work.
- **Custom**: a hand-written Nginx `.conf` remains authoritative. Complex WordPress rules, token endpoints, authentication, and custom rewrites stay in this mode.

No existing site is converted automatically. Switching a legacy site to composed mode replaces its rendered Nginx content; **preview and compare before converting**.

## Files and schema versions

There are two versioned TOML file types:

| File | Schema | Purpose |
|---|---|---|
| `/opt/etc/nginx/composer.toml` | `schema_version = 1` | Reusable option catalog, edited and tracked in Git |
| `domains-available/.../*.toml` | `schema_version = 1` | Site identity, upstream and selected option values |

You can override the deployment catalog location using `[nginx].composer_path` in `router-hub.toml`. The router installer and Linux setup seed the default catalog without replacing an existing local copy. Git remains the owner of its committed source file; Router Hub reads it but does **not** rewrite it.

For example:

```toml
schema_version = 1
kind = "subdomain"
domain = "example.test"
name = "media"
server_names = ["media.example.test"]
upstream = "http://127.0.0.1:8096"

[options]
access = "lan"
streaming = true
large_upload = true
long_lived = true
body_size = "5G"
read_timeout = "1200s"
```

Site paths are unchanged: `domains-available/example.test/root.toml` for domain roots, `subdomains-available/media.toml` for subdomains, and `subfolders-available/app.toml` for subfolders, each next to its generated `.conf`. Enabled symlinks continue to govern activation.

## Catalog option types

Each `[[options]]` entry has an `id`, `type`, `label`, `kinds`, and zero or more directive `effects`. Types are:

### 1. Optional (Boolean)

```toml
[[options]]
id = "streaming"
type = "optional"
label = "Media streaming"
kinds = ["subdomain"]
priority = 20
[[options.effects]]
slot = "location"
directive = "proxy_buffering"
value = "off"
```

A site selects it with `streaming = true`. Omitted optional options are false unless the catalog has `default = "true"`.

### 2. Choice (A, B, or C)

```toml
[[options]]
id = "access"
type = "choice"
label = "Access policy"
kinds = ["domain", "subdomain", "subfolder"]
default = "public"
priority = 10

[[options.choices]]
value = "public"
label = "Public"

[[options.choices]]
value = "lan"
label = "LAN / restricted"
[[options.choices.effects]]
slot = "site"
directive = "include"
value = "snippets/restrict.conf"
```

Site setting: `access = "lan"`. The root routing choice (`subfolders`, `proxy`, or `proxy_and_subfolders`) and subfolder choice (`standard` or `pwa`) work the same way. Their structural effects are catalog entries rather than code branches.

### 3. Parameterized (value with validation)

```toml
[[options]]
id = "read_timeout"
type = "parameterized"
label = "Read timeout"
kinds = ["domain", "subdomain"]
pattern = "[1-9][0-9]*[smhd]"
priority = 100
[[options.effects]]
slot = "location"
directive = "proxy_read_timeout"
value = "{{value}}"
```

Site setting: `read_timeout = "3600s"`. Values must pass the catalog's **full-match regex** and cannot contain Nginx syntax delimiters. All parameters are strings.

## Directive slots and conflicts

Supported `slot` values:

| Slot | Rendered location |
|---|---|
| `server` | Nginx server block (domain/subdomain) |
| `location` | Root proxy location; for subfolders, their mounted location |
| `site` | Server for domain/subdomain; mounted location for subfolder |
| `location:/Sessions` | Additional named location in the server block |

The composer generates only the surrounding `server`/`location` structure, `server_name`, and subfolder mount path. Shared defaults (`[[base]]`), feature effects and options live in the catalog.

Effects use `directive = "proxy_read_timeout"` and `value = "3600s"` rather than arbitrary config text. The engine validates slot names, directive tokens, placeholders and values. Supported placeholders: `{{domain}}`, `{{name}}`, `{{regex_name}}`, `{{server_name}}`, and `{{value}}`.

**Conflict resolution:** within a slot, single-valued directives are merged by name, with higher `priority` taking precedence. Repeated `include` directives are preserved if they refer to different files; repeated `proxy_set_header` or `add_header` directives are keyed by header name. Conflicting equal-priority values fail validation. As a result, enabling both `websocket` and `long_lived` produces a single effective timeout. Explicit parameters in the shipped catalog have priority 100 and override feature defaults.

For dependencies, add `requires = ["streaming"]` or `requires = ["access=lan"]`. To constrain a particular site kind, add:

```toml
[[options.requirements]]
kind = "domain"
condition = "root!=subfolders"
```

Unknown option names, disallowed site kinds, invalid parameters, unmet dependencies, malformed catalog entries or unsupported schema versions are rejected.

### Extending the catalog

To add a feature, append another `[[options]]` block with its type, kinds and effects; then add the corresponding Boolean, string choice or parameter value under a site's `[options]` table. The UI fetches the catalog through `GET /api/nginx/compose/catalog` and automatically renders the appropriate checkbox, select, or text field.

The only capability intentionally fixed in Rust is *structural* Nginx syntax and safe composition mechanics. A new directive inside an existing supported slot requires no Rust changes. Adding a new kind of structural construct (a custom `map`, `upstream` block, or unusual nested `location` scheme) is not supported by the catalog's v1 schema; use Custom Nginx until the schema is extended.

## Applying Git-managed changes

The catalog is loaded when previewing, creating, editing or rendering composed sites. A malformed catalog causes these operations to fail rather than silently use stale definitions. Ordinary legacy and custom sites are unaffected.

For site TOML files edited through Git, explicitly regenerate and validate:

```sh
router-hub --config /opt/etc/router-hub/router-hub.toml render-sites
```

The command renders the existing composed site files, updates managed upstream mappings and the generated HTTP forwarder, runs `nginx -t` and restores the previous configuration on failure. It **does not reload Nginx**; reload through Router Hub after reviewing the result. For a brand-new site, use the UI/API to create its hierarchy before editing its TOML directly.

The site editor's **Composed (TOML)** mode uses the same catalog for its control labels, choices and options. The **Preview generated Nginx** button renders without modifying files.

## Migration and operational precautions

The initial deployment has template-backed sites with manual changes. Compare each current `.conf` with its preview before switching to composed mode; the earlier template comment does not guarantee equivalence. Custom sites are never converted automatically.

Older composed TOML files written by the first feature-branch prototype contained default values for unrelated site kinds. The new loader discards only inapplicable *default-valued* fields; it rejects inapplicable non-default values. Saving a composed site writes the normalized definition.

The installed `snippets/restrict.conf` defaults to `deny all;`, so configure deployment-specific allow-lists before enabling LAN-only sites. Keep the catalogue, deployed snippets and certificates versioned or managed appropriately; do not commit secrets. Nginx source-file syntax validation does not guarantee correct application rewrites or HTTP behavior, so test important routes on the target Nginx build.
