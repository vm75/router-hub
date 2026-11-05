# Router Hub Ban Config integration

This folder holds the nginx side of Router Hub's Ban Shield/Ban Config feature.
It is an intentional product integration and remains in version control. It
contains reusable enforcement and logging policy, not deployed site data.

## Include boundaries

- `conf.d/00-ban-shield.conf` loads `ban-shield/http.conf` once inside `http {}`.
- `http.conf` declares the rate/connection zones, stable log formats, classifiers,
  default access/trap logging, log-selection maps and request timeouts.
- Generated HTTPS servers and the HTTP redirect include `server-guard.conf`.
  Its return-only gate runs before location selection and subfolder rewrites.
- `conf.d/02-default-drop.conf` includes `default-drop.conf` for unknown hosts.

Render `access-logging.conf.jinja` and `default-drop.conf.jinja` into this same
runtime folder, dropping only the final `.jinja`. Copy the static `.conf` files
unchanged. Do not load `http.conf` or its component declarations twice. Custom
servers use these current paths directly; no legacy include aliases are shipped.
The server-phase classifier replaces the obsolete explicit trap-location snippet.

## Log contract

The default destinations remain `<var_dir>/log/nginx/access.log`, `traps.log`
and `unknown-host.log`, with `var_dir=/opt/var` unless overridden. `f2b_access`
and `f2b_trap` retain their names and layouts: client IP is first, and trap
records contain the quoted `trap="0|1"` and `badbot="0|1"` fields. Existing
Ban Config rules select their log paths and regular expressions independently;
this folder does not rewrite the saved rules or enable firewall enforcement.
The engine regression test covers a trap record producing one immediate ban.

The gate returns 444 for classified traps and blocked scanner agents. Narrow
exceptions in `settings/security_trap_allow.conf` can permit a particular host
and path but do not exempt blocked agents. Actual exceptions belong in the
ignored deployment-settings override. The shipped exception file is empty.

Healthcheck matching in `conf.d/00-access-log-map.conf` and the Ban Shield
`log-conditions.conf` maps affect ordinary
successful records only. Trap logs remain independent, and traps remain visible
even on routes configured to suppress routine access records. nginx filtering
and request limits remain active as configured; the Ban Shield firewall policy
has its own enabled state.

The companion HTTP policy defines `wplogin`, `vaultwarden_login`, `global_rate`
and `per_client_conn` zones for the generated route and server guards. The ban
engine itself consumes logs and enforces its saved firewall policy. Their nginx shared-memory sizes/rates are visible in
`zones.conf`, separate from general HTTP tuning.
