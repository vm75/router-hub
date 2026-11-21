# Migrating Router Hub 0.10.5 to Maestro 0.11.0

Maestro is the Phase 1.5 Rust rebrand. It has the same API/features as the validated Phase 1 Router Hub release; Linux Applications, systemd provider port and the Svelte shell remain Phase 2 work. The GitHub repository still lives at [vm75/router-hub](https://github.com/vm75/router-hub) until the owner separately renames it. The existing Go [vm75/server-man](https://github.com/vm75/server-man) is unrelated and untouched.

## Names after rebranding

| Item | Router Hub | Maestro |
|---|---|---|
| Entware IPK | `router-hub` | `maestro` (conflicts with `router-hub`) |
| Executable | `/opt/bin/router-hub` | `/opt/bin/maestro` |
| Entware init script | `S99router-hub` | `S99maestro` |
| Current configuration | `/opt/etc/router-hub/router-hub.toml` | `/opt/etc/maestro/maestro.toml` |
| New-install persistent data | `/opt/etc/router-hub` and `/opt/var/lib/router-hub` | `/opt/etc/maestro` and `/opt/var/lib/maestro` |
| Release asset | `router-hub_<version>-1_aarch64-3.10.ipk` | `maestro_<version>-1_aarch64-3.10.ipk` |

The new IPK ships a `/opt/bin/router-hub` **CLI-only compatibility symlink**, but not a duplicate init script. Existing REST endpoints and page selectors remain available; the old `/router-hub.svg` and `/router-hub.png` URLs also remain aliases. The icon artwork has not been redesigned.

## Safe one-time IPK upgrade (router)

1. Make a Router Hub backup before removing the old IPK, and **copy it off the router** because `/tmp` is volatile:
   ```sh
   /opt/bin/router-hub backup
   /opt/bin/opkg list-installed | grep -E '^(router-hub|maestro) '
   ```
   Also copy `/opt/etc/router-hub`, `/opt/var/lib/router-hub`, the nginx tree and your `/jffs/scripts` hooks if used. Verify your saved backup.
2. Stop the old service. During the package switch the management UI is offline:
   ```sh
   /opt/etc/init.d/S99router-hub stop
   /opt/bin/opkg remove router-hub
   ```
   Do this only when you have console/SSH access and a known rollback IPK. **Do not use `opkg --force-overwrite` or install both packages together.** Existing user-created data is not packaged and should remain, but the legacy package owns some installed hook files, which is why this process takes a backup.
3. Download the published Maestro IPK and corresponding checksum, verify SHA-256, then install:
   ```sh
   VERSION=0.11.0
   FILE="maestro_${VERSION}-1_aarch64-3.10.ipk"
   BASE="https://github.com/vm75/router-hub/releases/download/v${VERSION}"
   cd /tmp
   curl -fLO "${BASE}/${FILE}"
   curl -fLO "${BASE}/${FILE}.sha256"
   sha256sum -c "${FILE}.sha256"
   /opt/bin/opkg install "/tmp/${FILE}"
   ```
   These commands require that the release has actually been published; the rebrand branch itself does not publish a release.
4. The post-install helper copies the old TOML into `/opt/etc/maestro/maestro.toml` **only if no Maestro TOML exists**. It leaves existing NGINX inputs, tokens, policy files, ban state, certificates and configured state paths where the old TOML points. It copies the old dehydrated executable when present and redirects packaged dehydrated hook paths in the new TOML to `/opt/var/lib/maestro/dehydrated`. It updates only Router Hub-owned reconciliation hook lines in JFFS. Review the copied TOML before using the service.
5. Validate:
   ```sh
   /opt/bin/maestro --config /opt/etc/maestro/maestro.toml check-config
   /opt/etc/init.d/S99maestro check
   /opt/bin/maestro backup
   ```
   Check ASUS ASP integration, service actions, DNS rewrites, WireGuard, WOL, nginx site CRUD/reload, certificate scheduling and observe-only firewall status. Verify old `S99router-hub` does not run on boot, then check reboot persistence.

The old configuration and data directories are **not deleted or renamed automatically**. This is intentional: existing nginx input paths, ban states and firewall ownership identifiers can be bound to those locations. Do not remove legacy directories merely because the service now says Maestro. Fresh installations use Maestro defaults; adopted installations use the explicit paths from their old TOML. A preexisting Maestro config wins: if both configurations exist, compare manually.

For an old *tarball-only* install, stop and back up the old service, install the new binary/scripts, then disable the old unowned `S99router-hub` init script after verifying the new service. For native Linux, copy the old TOML to a new config path manually, keep its explicitly configured paths, and launch `maestro --config <path> --linux-mode serve`; do not use Entware migration commands.

## Rollback

Stop `S99maestro`, uninstall its IPK, and reinstall the previously verified Router Hub 0.10.5 IPK. Reuse the **untouched** original `/opt/etc/router-hub/router-hub.toml` and directories, and restore your offline backup if necessary. Recheck `S99router-hub`, nginx and the JFFS reconciliation scripts because the new installer may have updated those hook command lines. The backup/restore CLI does not roll back `opkg` package records or external firewall state. Never downgrade while both management daemons are running.

## Phase 1.5 validation gate

Before merging/releasing, run `cargo fmt --all -- --check`, `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo build --release --locked`, `make test-ui`, `make test-ipk`, `make test-linux` and router hardware verification. Test clean install, legacy IPK migration, reboot, backup/restore and rollback on a disposable router/lab. Phase 2 begins only after the M1.5 gate is accepted.
