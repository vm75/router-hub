# nginx configuration templates

`templates/` has one Jinja2 template each for a domain, subdomain, and subfolder.
The variant table below documents how the previous templates map to feature
switches; the previous template and candidate folders have been removed.

`settings/` is version-controlled and contains empty deployment-data defaults plus
reusable Jinja policy modules. Actual site names, upstreams, network allowlists,
log suppression rules and exceptions belong in the ignored
`nginx.deploy/settings/` directory. Synthetic examples live in `examples/`.
The deployment copy is not read by tests or changed by template validation.

Load Jinja2 templates relative to this directory with autoescaping disabled and
`StrictUndefined` enabled. Render before installing nginx configuration. This
requires a Jinja2-capable renderer; literal placeholder substitution cannot
process these files. nginx itself does not interpret Jinja2.

```python
from jinja2 import Environment, FileSystemLoader, StrictUndefined

env = Environment(loader=FileSystemLoader('.'), undefined=StrictUndefined,
                  autoescape=False, trim_blocks=True, lstrip_blocks=True)
site = env.get_template('templates/subdomain.conf.jinja').render(
    server_name='app.example.com', enable_lanonly=False,
    enable_large_upload=True, enable_streaming=True,
)
```

Install rendered domain files as `domains-enabled/<domain>/root.conf`, subdomains
as `domains-enabled/<domain>/subdomains-enabled/<name>.conf`, and subfolders as
`domains-enabled/<domain>/subfolders-enabled/<name>.conf`. A domain render requires
`server_name` and, when subfolders are enabled, `domain` (the directory name).
A subdomain requires `server_name`; a subfolder requires `subfolder`, a single
literal path segment safe for both an nginx location and a regular expression
(for example `app` or `media-center`). Subfolders strip that segment before
proxying, preserve query strings, and use the original `$request_uri` to select
the upstream. Configure upstreams in `settings/domains.conf`,
`settings/subdomains.conf`, and `settings/subfolders.conf` as appropriate.

## Site options

[settings/proxy.jinja](settings/proxy.jinja) owns proxy defaults. Templates import
it with the current site context, then expand `snippets/proxy-location.conf.jinja` via
Jinja2 includes. Pass real booleans and nginx size/time values, not boolean strings.
`default(...)` applies only to undefined values, so `false` and a size of `0`
remain meaningful overrides.

| Parameter | Default | Effect |
| --- | --- | --- |
| `enable_lanonly` | `true` | Apply `settings/allowed_ips.txt`, then deny other clients |
| `enable_subfolders` | `true` | Domain only: load enabled subfolders |
| `disable_root` | `true` | Domain only: return 404 at root; `false` enables the domain upstream |
| `enable_large_upload` | `false` | Stream request bodies, increase body limit, enable long timeouts |
| `enable_longlived` | `false` | Extend upstream and downstream idle timeouts |
| `enable_streaming` | `false` | Disable response buffering |
| `enable_byte_ranges` | `false` | Force byte-range support and forward Range/If-Range |
| `enable_restricted_sessions` | `false` | Add a LAN-restricted `/Sessions` prefix route with access logging disabled |
| `clear_origin` | `false` | Remove the upstream Origin header for applications that require this |
| `client_max_body_size` | `100M` | Normal proxy body limit |
| `large_upload_max_body_size` | `5G` | Body limit when large uploads are enabled; `0` means unlimited |
| `proxy_connect_timeout` | `10s` | Upstream connection timeout |
| `proxy_session_timeout` | `3600s` | Read, write, and downstream idle timeout for long sessions/uploads |
| `client_upload_timeout` | `3600s` | Idle timeout between upload body reads for large uploads |

WebSockets are the default proxy transport through the shared HTTP upgrade map;
individual SSE routes select their own transport.
Long-lived idle WebSockets should enable `enable_longlived` or send heartbeat
traffic. Large uploads automatically use the long-session snippet once, even
when both switches are enabled. Streaming and byte ranges can be combined with
either. No-cache mode repeats security headers at location scope to preserve
them on nginx versions where local `add_header` replaces inherited headers.

LAN restrictions inherit from a containing domain server: setting a subfolder's
`enable_lanonly=false` does not remove its parent's restrictions. To mix public
and LAN-only subfolders, make the domain public and enable restrictions on the
private subfolders. A LAN-only server also restricts its HTTPS ACME location;
HTTP-01 uses the separate HTTP listener.

All three layouts support these features independently. A domain needs
`disable_root=false` for root proxy features to apply. Restricted sessions use
`/Sessions` for domains/subdomains and `/<subfolder>/Sessions` for mounted apps;
that nested route shares the selected proxy features and always applies the LAN
allowlist. WebSockets remain available with PWA caching enabled.

PWA caching uses HTTP-context maps in `conf.d/00-pwa-cache-map.conf.jinja`, configurable
header values in `settings/pwa.jinja`, and location directives in
`snippets/proxy-location.conf.jinja`. `pwa_shell_cache_control` defaults to
`no-cache, no-store, must-revalidate`; `pwa_asset_cache_control` defaults to
`public, max-age=31536000, immutable`. These are shared render parameters.
Shell files are `sw.js`, `index.html`, and `manifest.webmanifest` at the app root.
Shell detection also covers `service-worker.js` and `manifest.json` before
immutable JavaScript matching. Static assets use the extensions from the previous
PWA snippet. Classification
uses the rewritten URI, so a mounted app follows the same policy. Other resources
receive no extra cache headers. Use `cache_policy="no_cache"` for applications
that should never cache any response.

Every previous template variant has a replacement below. Unlisted options
use the defaults above. Comma-separated entries are separate render parameters.

| Previous template | Parameters |
| --- | --- |
| `domain/basic` | `enable_lanonly=false` |
| `domain/lan-only` | `enable_lanonly=true` |
| `domain/reverse-proxy` | `enable_lanonly=false`, `disable_root=false`, `enable_subfolders=false`, `enable_longlived=true` |
| `subdomain/proxy` | `enable_lanonly=false` |
| `subdomain/websocket` | `enable_lanonly=false`, `enable_longlived=true` |
| `subdomain/lan-only` | `enable_lanonly=true`, `cache_policy="pwa"` |
| `subdomain/lan-only-long-lived` | `enable_lanonly=true`, `enable_longlived=true` |
| `subdomain/lan-only-large-upload` | `enable_lanonly=true`, `enable_large_upload=true`, `clear_origin=true` |
| `subdomain/lan-only-media-streaming` | `enable_lanonly=true`, `enable_streaming=true`, `enable_longlived=true` |
| `subdomain/media-streaming` | `enable_lanonly=false`, `enable_streaming=true`, `enable_longlived=true` |
| `subdomain/media-streaming-upload` | `enable_lanonly=false`, `enable_streaming=true`, `enable_large_upload=true` |
| `subdomain/media-streaming-sessions` | `enable_lanonly=false`, `enable_streaming=true`, `enable_longlived=true`, `enable_restricted_sessions=true` |
| `subfolder/standard` | `enable_lanonly=false`, `enable_streaming=true`, `enable_longlived=true`, `proxy_session_timeout='86400s'` |
| `subfolder/lan-only` | `enable_lanonly=true`, `enable_streaming=true`, `enable_longlived=true`, `proxy_session_timeout='86400s'` |
| `subfolder/pwa-app` | `enable_lanonly=false`, `enable_streaming=true`, `enable_byte_ranges=true`, `cache_policy="no_cache"` |

The reverse-proxy domain uses the dedicated domain upstream map. All variants
now have WebSocket support and preserve forwarding/security headers when caching
policies are enabled. CORS is opt-in per route.

## Settings data and loops

`settings/allowed_ips.txt` contains one IP or CIDR per line, without nginx
keywords or semicolons. Blank lines and comments (including inline comments) are
allowed:

```text
192.0.2.0/24
198.51.100.0/24 # Example VPN
2001:db8::/32
```

`snippets/restrict.conf.jinja` captures that file with a Jinja include and loops over
its entries to produce `allow <IP/CIDR>;`, followed by `deny all;`. An empty list
renders only `deny all;`. Re-render that snippet after changes; nginx includes the
rendered snippet at configuration load time. The settings input is no longer
included directly by nginx. Router Hub writes this format directly and renders the access snippet after changes.

`settings/free_subdomains.txt` likewise contains one shared/free domain suffix
per line, such as `shared.example.test` or `ddns.example.test`. Blank lines and comments are
allowed. A loop in `conf.d/03_subdomain_upstream_map.conf.jinja` generates the
certificate-folder regex entries before the general domain/TLD fallback:
`app.tenant.shared.example.test` selects `tenant_shared_example_test`. Dots in each suffix are
matched literally. Keep more specific suffixes first when suffixes overlap.
Re-render that map after edits; the suffix list is a render input, not an nginx
include file.

The subfolder URI map in `conf.d/04_subfolder_upstream_map.conf.jinja` is generated
from the first column of `settings/subfolders.conf`; there is no separate regex
settings file to maintain. Every listed name matches itself and its `-dev` suffix,
with a path, query, or end-of-URI boundary. Names must be single literal path
segments using letters, digits, underscores, or hyphens. Blank lines and comments
are ignored; an empty list emits no regex rule. Re-render the map after adding or
removing names. The captured name retains `-dev`, so dev mounts use their own upstream entry
and a subfolder template rendered with that full name. Dev targets are explicit;
they never silently fall back to production. The shipped upstream maps are empty; populate the base and `-dev` targets in
deployment settings independently.

## Generic route policies

Pass a `routes` list to any of the three templates. Paths are relative to the
application mount; `/admin` becomes `/app/admin` for that mounted app.
Each entry supports `children`; omitted settings inherit the effective parent
policy, and explicit `false` remains an override. Nested route paths are still
relative to the application root, not the parent route. The root subfolder
location permits regex children; private prefix routes use `^~` so cache regexes
cannot bypass their access restrictions.

```python
routes = [
    {"path": "/admin", "enable_lanonly": True, "spa_fallback": ""},
    {"path": "/identity/connect/token", "match": "exact",
     "rate_limit": {"zone": "vaultwarden_login", "burst": 5}},
    {"path": "/api/updates", "proxy_transport": "sse", "spa_fallback": ""},
    {"path": "/control", "access_log": False},
]
```

Route match modes are `prefix` (default), `exact`, `regex` and `regex_i`. Regex
paths are expressions relative to the mount, including their initial `/`; the
renderer prepends the anchor and mount. Keep regex routes in the intended match
order. Paths and directive values are trusted administrator configuration, not
unvalidated request data. The API validates enums, paths, rate-limit zone names and directive values before rendering.

Routes accept the existing upload, timeout, streaming, range and Origin settings,
plus these options (also usable as site defaults unless noted):

| Setting | Default | Behavior |
| --- | --- | --- |
| `access_log` | `true` | Ordinary access records; security/error logs remain enabled |
| `proxy_transport` | `websocket` | `websocket`, `http`, or `sse` |
| `cache_policy` | Inherit current policy | `inherit`, `no_cache`, `immutable`, or `pwa` |
| `backend_auth` | `false` | Delegate auth/challenges to the backend explicitly |
| `forwarded_for` | `replace` | `replace` client forwarding chain or deliberately `append` it |
| `hide_etag` | `false` | Hide the backend ETag response header |
| `disable_proxy_redirect` | `false` | Emit `proxy_redirect off` |
| `spa_fallback` | Empty | Retry upstream 404s at this application URI, e.g. `/index.html` |
| `rewrite_to` | Empty | Rewrite this route to a fixed application URI |
| `cors_origin` | Empty | Opt-in CORS response headers; never enabled merely by SSE |
| `rate_limit` | None | Route-only `{zone, burst}`; retain the global limit too |

SSE disables upgrade headers, response buffering, caching and chunked transfer;
its connection/session idle defaults are 300 seconds. WebSockets remain available
on the other routes. Each location has one owner for timeout, buffering and
connection-header directives. Locations with response-header policies repeat
security headers for nginx versions with replacement inheritance.

SPA fallbacks are named uniquely per mount and route and preserve the originating
route's access policy, headers and log setting. The fallback response uses
no-cache headers and cannot recurse. Set `spa_fallback=""` on API/admin routes
that must return their actual upstream 404s. An exact `/` route can use
`rewrite_to="/index.html"` and `hide_etag=true` for the app shell.

`settings/sites.toml` defaults to an empty `[sites]` table. `examples/sites.toml`
contains nine synthetic examples covering the reviewed custom-policy shapes:
a fallback server, backend authentication, quiet control paths, private admin and
rate-limited login routes, and production/development SPA/PWA mounts.
`kind` selects the template; `upstream` records the corresponding map target.
The remaining fields are render context. Actual per-site values belong in
`<nginx.root_dir>/settings/sites.toml`. Router Hub reads this file as the source
of managed site inputs and saves API/UI changes there atomically. Each entry has
`kind`, `domain`, `server_name`, `upstream`, `enabled`, and policy overrides;
`name` identifies subdomains and `subfolder` identifies mounts. Deployment keys
such as `app.example.test` and `example.test/app` can supply the name instead.
Output paths are derived from site identity; an `output` field is not accepted.
Managed editors expose settings, and saving regenerates the configuration.
Generated settings comments are output metadata; managed inputs must be in TOML.
Shared settings and defaults live only in `settings/nginx.toml`. The `[global]`
table holds shared nginx options, `[site_defaults]` holds inherited site policy,
and root-level `allowed_ips` and `free_subdomains` arrays hold the allowlists.
API/UI saves update this file atomically with generated runtime output; failed
validation or reload restores the previous TOML. Allowlist fragments are
generated from TOML. Relative fallback certificate directories resolve below the nginx root.
Runtime options `nginx_daemon`, `nginx_user`,
and `temp_dir` are validated and rendered by the same policy as listener settings.
The effective UID determines whether `user` is emitted: non-root omits it; root
uses the configured worker user, falling back to `nobody` for an empty or missing
value. This runtime decision is not a configurable privilege override.
`temp_dir` supplies the parent for fixed subfolders `client-body`, `proxy`,
`fastcgi`, `uwsgi`, and `scgi`. Linux defaults to `tmp` alongside the nginx root;
only this parent is configurable. It is created before nginx validation and
symlink traversal is rejected.
The examples use explicit limits and timeouts instead of changed defaults.
`rewrite_to` and `rate_limit` apply only where configured, rather than being
copied implicitly into child policies.

## Access logging and Home Assistant checks

`settings/access_log_suppress.conf` is an administrator-owned native nginx map
fragment and defaults to no rules. Put the actual request signature in
`nginx.deploy/settings/access_log_suppress.conf`; a synthetic example is:

```nginx
"video.example.test|GET|/Sessions|Home-Assistant/example|192.0.2.10" 1;
```

The fields are hostname, method, original path without query, User-Agent, and
nginx-observed client IP. Exact map keys are case-insensitive in nginx. The
original path remains stable across subfolder rewrites and SPA fallbacks. This
rule suppresses only matching **2xx** records in the normal access log. Failed
checks, other hosts/paths/methods/clients and security traps remain logged. Update
the entry when Home Assistant's versioned User-Agent changes. Remove/comment all
entries to disable filtering. No source IP is inferred from forwarding headers.
Native map regex entries are available for deliberate administrator-authored
rules; exact literal entries are the default example. Keep map values `0` or `1`.

For dedicated noisy endpoints, `access_log=false` suppresses ordinary records for
that route, including failures; this is separate from the successful-healthcheck
filter. Children inherit it, explicit `true` restores normal filtered logging,
and SPA fallbacks retain it. Trap and error logs stay enabled. Server-phase trap
rejections can still appear in the normal log even for a quiet endpoint. Legacy
raw custom configurations retain control of their own `access_log off` directives.

The shared `ban-shield/access-logging.conf.jinja` owns both managed log destinations. The
HTTP maps in `conf.d/00-access-log-map.conf` match the settings; Ban Shield
log-selection maps preserve trap records. The trap classifier combines security, allowlist and bot flags with the
same separators used by its rules. `settings/security_trap_allow.conf` defaults to
no exceptions; place any required, narrowly scoped host/path exceptions in its
deployment override. Allowlisted paths still do not bypass scanner-agent rules.

## Ban Shield integration

[ban-shield/README.md](ban-shield/README.md) describes the intentionally retained
nginx integration for Router Hub Ban Config. Its log formats, classifiers, gates,
rate-limit zones and unknown-host server live together under `ban-shield/`.
`conf.d/00-ban-shield.conf` loads the HTTP declarations once; generated servers
include its server guard. General HTTP performance settings stay in
`conf.d/01-global.conf.jinja`. Custom server configurations use the current runtime paths directly; no legacy
include aliases are shipped.

The reorganization preserves log paths, field formats, classifications and
limits. Deployment exceptions remain data in the ignored settings override,
not hardcoded hostnames inside this module.

## Custom configurations and shared runtime files

Keep full custom `.conf` objects as authored files. Do not regenerate them from
managed site defaults or implicitly treat them as Jinja. The custom API mode remains separate from managed settings. Router Hub preserves
custom text, atomic writes, combined-tree `nginx -t` validation and rollback.
Only the new Jinja-based configuration is supported. Custom configurations use
current runtime includes or their own explicit nginx directives; obsolete proxy,
PWA, SSE and upstream-pass helper names are not supported. Legacy configuration
conversion is a separate one-time operation, not part of normal rendering.

File extensions distinguish render inputs from nginx-ready files:

| Extension | Purpose | Example |
| --- | --- | --- |
| `.conf.jinja` | nginx source requiring Jinja rendering | `templates/subdomain.conf.jinja` |
| `.conf` | Static nginx configuration or directive fragments | `snippets/proxy-upgrade.conf` |
| `.jinja` | Jinja defaults modules | `settings/location.jinja` |
| `.txt` | Plain lists consumed during rendering | `settings/allowed_ips.txt` |
| `.toml` | Structured per-site render inputs | `settings/sites.toml` |

Render `nginx.conf.jinja`, `resolver.conf.jinja`, and `conf.d/*.conf.jinja` before
installation. Render the `ssl`, `acme-challenge` and `restrict` runtime snippet
templates (each named `<name>.conf.jinja`) and copy `security-headers.conf`. Other
source snippets are expanded by Jinja and must not be installed as runtime files.
Also render `ban-shield/*.conf.jinja` to their corresponding `.conf` files.
Copy the static Ban Shield module files and its two `conf.d` entry includes.
Strip only the final `.jinja` from each output filename. Copy referenced static `.conf` files unchanged. Jinja includes/imports reference
source filenames; nginx includes reference rendered `.conf` filenames.

All other snippet templates are expanded into each managed site; they are not
independent runtime files. The route renderer uses Jinja macros: MiniJinja users
must enable `builtins`, `multi_template`, **`macros`**, and `serde`. Router Hub
implements only the four Python string methods used by this bundle, avoiding
the general Python compatibility extension.
Keep the upstream map settings, `mime.types` and `dhparams.pem` available to nginx.
`allowed_ips.txt`, `free_subdomains.txt`, `servers.conf`, `sites.toml` and
`settings/*.jinja` are render inputs, not standalone nginx includes.
`servers.conf` defaults to the empty-name fragment `"";` and retains its final
semicolon for `server_name`.

A renderer should select deployment overrides for data files (`.conf`, `.txt`,
`.toml`) and otherwise use the shipped defaults. Always load the versioned Jinja
policy modules from this bundle; stale copies of `.jinja` modules in a deployment
directory must not shadow current renderer logic. Runtime map includes receive
the selected data files when assembling the output tree. Empty network defaults
fail closed for LAN-only routes, empty suppression rules log normally, and empty
upstream/site defaults do not enable any application.

Shared render parameters retain their defaults: `router_ip=127.0.0.1`,
`http_port=80`, `https_port=443`, `var_dir=/opt/var`, `worker_processes=2`,
`worker_connections=64`, `resolver_addr=127.0.0.1`, `resolver_validity=30s`, and
`acme_challenge_dir=/opt/acme-challenge`. Both ACME listeners use that directory.
The fallback server's `default_certificate_dir` defaults to `certs/default` via
`settings/tls.jinja`; pass the actual certificate directory in deployment context.
Re-render the HTTP redirect when its server list changes. Supply certificates,
modules and writable runtime/log paths appropriate to the installation.
The bundle tests never install or reload configuration on a deployment router.
Saving settings through Router Hub renders the shared runtime files, regenerates
managed sites, validates the tree, and reloads nginx when running. Template and
root-file editing and legacy conversions are not available.

## Validation

With Python, Jinja2, nginx and openssl installed, run from this directory:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The tests cover defaults, false/zero values, all 192 base combinations, additional
feature combinations, every historical variant and all nine synthetic custom-policy examples.
Loopback checks exercise LAN restrictions, route-specific rate limits, SSE,
WebSockets, caching, authentication headers, -dev routing and SPA fallbacks.
Logging checks close connections and stop nginx before inspecting logs: matching
successful checks are absent, failed checks and other clients remain, quiet
children/fallbacks stay quiet, explicit opt-in restores logging, and trap/error
records remain. An empty filter and an unchanged raw custom server are covered.
All paths, certificates and services used by these tests are temporary/local.
