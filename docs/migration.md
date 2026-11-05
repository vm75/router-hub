# Upgrading older Router Hub installations

Current releases read versioned ban state and current nginx settings only. They do
not convert older documents. Back up the installed binary, Router Hub configuration
and state directory, and the nginx configuration tree before upgrading. Use the
paths configured on your installation; router and native Linux paths can differ.

## Versions older than 0.7.2

First install and run 0.7.2 using the same configuration and state directory.
Installing the binary alone does not migrate bans: the firewall policy must be
enabled and have configured log files so the ban engine starts.

Check the logs for migration or persistence failures. Confirm that
`ban-attack-state.json` in the configured data directory contains
`"schema_version": 1`. When importing `bans.json`, 0.7.2 normally archives it as
`bans.json.migrated-v1` after writing the new document. If versioned state already
exists, it takes precedence over `bans.json`; resolve any unexpected stale state
before continuing. Do not manufacture an empty state file to bypass migration.

0.7.2 imports unexpired records from the old ban-record array. Records without
expiration and the older IP/subnet-list format receive a one-hour lifetime.
Expired bans are not preserved. Inspect active bans in the UI before proceeding.
Stop 0.7.2 cleanly and retain its versioned state when installing the new release.
If the firewall is intentionally disabled, either complete migration before
disabling it again or explicitly accept discarding the old transient bans.

## Nginx configuration

The 0.7.2 bridge handles ban state; it does not port old nginx configuration to
the current Jinja bundle. Prepare and validate nginx separately before switching
Router Hub versions.

- Remove the obsolete `nginx.templates_dir` option from `router-hub.toml`.
- Use `settings/nginx.toml` for shared settings under `[global]`, site defaults
  under `[site_defaults]`, and top-level `allowed_ips` and `free_subdomains` lists.
  Copy any entries from `allowed_ips.txt` and `free_subdomains.txt` into these
  lists; strip comments. The fragments are generated outputs after saving.
  Copy any separately stored global JSON settings manually into the TOML schema.
- Put managed site inputs in `settings/sites.toml` using the
  [current examples](../config/nginx/examples/sites.toml). Remove `output` fields;
  output paths are derived from site identity. Preserve upstreams, hostnames,
  enablement and per-site settings. Copy settings from generated `router-hub-settings` comments when needed,
  but review and save them in TOML; saving shared settings no longer adopts
  generated files automatically or treats their comments as managed inputs.
- Replace `enable_no_cache` and `enable_pwa` with `cache_policy` in site defaults,
  sites, routes and nested children. An existing explicit `cache_policy` wins;
  otherwise true `enable_no_cache` becomes `"no_cache"`, then true `enable_pwa`
  becomes `"pwa"`. If both are false, omit the policy to preserve inheritance
  (the site default is `"inherit"`). Remove both old keys after conversion.
  Account for effective site defaults when converting site overrides.
- Preserve custom authored server configuration. Port its old include paths to
  the [current runtime files](../config/nginx/README.md), and review any custom
  maps or routing rules against the new bundle. The old template/file editors
  and automatic nginx conversions are unavailable.

Prepare the replacement tree in a lab or staging location with suitable paths.
Validate with `router-hub --config <config-path> check-config` and nginx's `-t`
using the intended configuration. Check HTTP redirects, ACME challenge routing,
TLS, upstreams, access restrictions, cache headers, and custom routes before
activating it. `init-nginx` only bootstraps a missing configuration; it does not
upgrade an existing tree.

## After upgrading

Confirm that firewall policy, allowlists, active unexpired bans, certificates,
and nginx sites have the expected behavior. Keep the backup until verification
is complete. To roll back, stop the new service and restore the matching old
binary, configuration and state backup together.
