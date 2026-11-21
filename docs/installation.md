# Router installation

[← Back to README](../README.md)

## Requirements and support

For a router installation:

- Asuswrt-Merlin with JFFS custom scripts/configuration enabled.
- Entware mounted at `/opt`.
- A binary built for the router CPU and libc/ABI.
- nginx, dehydrated, OpenSSL, ipset, iptables, and related utilities only for
  the features that use them.

Release tarballs target AArch64 musl and the Entware IPK has architecture
`aarch64-3.10`. Verify `opkg print-architecture` on the target router. Legacy
MIPS compatibility is
not promised; a target is supported only after testing it on the matching
router CPU and firmware.

For Router Hub 0.10.5 installations, follow the [Maestro migration guide](maestro-migration.md) before uninstalling anything. Historical schema migrations are in [legacy upgrading](migration.md).

## Install a published version

### Entware IPK (recommended for the router)

Stable GitHub releases include a `.ipk` and `.ipk.sha256` pair. For example,
after `v0.11.0` is published, download both assets from
[GitHub Releases](https://github.com/vm75/router-hub/releases) and verify:

```sh
VERSION=0.11.0
PACKAGE="maestro_${VERSION}-1_aarch64-3.10.ipk"
BASE="https://github.com/vm75/router-hub/releases/download/v${VERSION}"
cd /tmp
curl -fLO "${BASE}/${PACKAGE}"
curl -fLO "${BASE}/${PACKAGE}.sha256"
sha256sum -c "${PACKAGE}.sha256"
/opt/bin/opkg install "/tmp/${PACKAGE}"
```

Use a root shell. The package owns the Maestro binary, Entware init script,
example configuration, and shared setup helper, but **not** runtime settings or
state. The `postinst` hook initializes first-install configuration, migrates
current-format nginx inputs where needed, installs JFFS reconciliation hooks,
validates configuration and starts the service. `prerm` stops the service
before an upgrade or removal; it does not delete persistent data.

**Migrating from a Router Hub package or tarball:** Make a backup and follow the
[Maestro migration guide](maestro-migration.md) first. The Maestro IPK declares a conflict with the old Router Hub package. Remove the
old package only after backing up and follow the documented data adoption steps.
The new package does not delete legacy administrator-created state. Removing the IPK also intentionally
leaves administrator-created configuration, data and JFFS hooks in place.

### Backups

Create a backup from the installed binary:

```sh
/opt/bin/maestro backup
```

On routers this writes `/tmp/maestro-backup-YYYYMMDD-HHMMSS.tar.gz` using
local time. Copy it off the router before rebooting, since `/tmp` is temporary.
On native Linux (`platform = "linux"` or `--linux-mode`), the archive is saved
alongside the configuration file selected by `--config`:

```sh
maestro --config /etc/maestro/maestro.toml --linux-mode backup
# Optional existing destination directory on either platform:
maestro --config /etc/maestro/maestro.toml --linux-mode backup --output-dir /srv/backups
```

The archive includes the configuration directory, running executable, configured
persistent state, nginx root and separately configured nginx inputs/includes,
certificate store, dehydrated executable, and existing `S99maestro` init script.
Router backups also include `paths.jffs_scripts_dir` (default `/jffs/scripts`),
`paths.hosts_add` and `paths.dnsmasq_conf_add`. Missing optional inputs are skipped;
an existing configuration file is required. Configured root symlink targets are
included, while symlinks inside archived directories are preserved without following
them. Archives use paths relative to `/` for manual extraction and restore.

The command uses `commands.tar` (default `/bin/tar`) with gzip support and a
five-minute timeout. Archives have mode `0600` because they contain tokens and
private keys. Failed archives are removed, existing archives are never overwritten,
and prior `maestro-backup-*.tar.gz` archives are excluded to prevent recursive
backups. A second backup in the same second fails rather than replacing the first.
Test mode only prints the planned destination and does not create an archive.

Backups read files without stopping services or freezing writes. Avoid editing
settings or renewing certificates during a backup; stop Maestro before a manual
backup when a consistent cross-file snapshot is required. Review and restore the
needed files from an extracted archive or use the restore command below while
services are stopped.

### Restore a backup

Use a trusted backup from the same installation. Stop Maestro and any other
services whose configuration or certificates will be restored. On a router:

```sh
/opt/etc/init.d/S99maestro stop
/opt/bin/maestro restore /tmp/maestro-backup-YYYYMMDD-HHMMSS.tar.gz
# After a successful restore, validate before starting the service:
/opt/bin/maestro --config /opt/etc/maestro/maestro.toml check-config
/opt/etc/init.d/S99maestro start
```

Replace the archive name with your actual backup. Restore does not load the
current configuration, so it also works when that file is missing or invalid.
It does not stop or start services itself. An explicit `--test-mode` validates
the archive and destination without restoring files; configuration-file
`test_mode` settings do not apply to this recovery command.

To restore into a separate tree for inspection first, create a private destination
and use `--root` on either platform:

```sh
mkdir -m 700 /tmp/maestro-recovery
maestro restore /tmp/maestro-backup-YYYYMMDD-HHMMSS.tar.gz --root /tmp/maestro-recovery
```

Paths in the archive are relative to `/`; for example `etc/maestro/maestro.toml`
is restored beneath `/tmp/maestro-recovery/etc/maestro/maestro.toml` in this
example. The default root is `/`, restoring original locations. Symbolic links
retain their archived targets, including absolute targets; inspection-tree links
can therefore still point outside that tree. Restore never writes through those
links. Existing symlink parents and file/directory type conflicts are rejected.

The entire archive is staged privately and checked before destination writes.
Traversal and absolute entry names, duplicate paths, device/special entries,
and writes beneath archived symlinks are rejected. Archives are limited to
100,000 entries and 2 GiB uncompressed, including headers and padding. Staging
uses the system temporary directory (`TMPDIR`, or `/tmp`). Ensure that temporary
storage and destination storage have space for the restored files.

Restore replaces archived files individually using atomic renames and restores
directory and file permission bits without setuid/setgid bits; directory sticky
bits are preserved. Files belong
to the restoring user; archived owner IDs and timestamps are not applied. Hard links
are restored as independent files with the same contents. Extra destination files
are left in place. Restore is not a transaction across the whole tree: an I/O
failure during application can leave earlier files restored. Keep services stopped
and review the error before retrying. Restoring an executable can roll back its
version; package-manager records are not rolled back by the command.

### Router-only upgrade command

```sh
/opt/bin/maestro upgrade
# Download and verify without attempting opkg installation:
/opt/bin/maestro upgrade --download-only
# Explicitly skip the pre-upgrade backup:
/opt/bin/maestro upgrade --no-backup
```

The CLI checks GitHub's **latest stable** release and compares it against its
compiled version. If newer, it downloads the matching AArch64 Entware IPK and
its SHA-256 checksum, verifies the checksum, then stages the file as
`/tmp/maestro_<version>-1_aarch64-3.10.ipk`. When called as root with an
available compatible `/opt/bin/opkg`, it replaces the one-shot upgrade process
with `opkg install` so the package lifecycle can safely stop the running Router
Hub daemon.

After verifying a newer IPK and before installing it or printing the manual
installation command, `upgrade` creates the same backup as `backup`. This also
applies to `--download-only`. A backup failure aborts the upgrade before installation;
use `--no-backup` to explicitly skip it. No backup is made when already up to date
or when release download/verification fails.

When automatic installation is unavailable (including `--download-only`),
it prints the exact manual command.
If opkg fails, the verified package remains in `/tmp`; the retry command is
printed before launching opkg. Network or checksum errors abort without
installing. During installation, `prerm` stops the running service and `postinst`
executes `migrate-nginx-inputs`, then `init-nginx`, validates the configuration,
and restarts the service. A migration or configuration failure stops the install
hook and leaves the service stopped for administrator review; it never deletes
existing persistent state or silently claims rollback of the installed binary.

This is a separate CLI process, **not** an authenticated API/UI action.
`upgrade` is rejected on native Linux and simulated test-mode runs. The
upgrade requires a published stable IPK; prerelease tags and older tarball-only
releases cannot be installed through this command.

### Router-only NGINX upgrade command

```sh
/opt/bin/maestro upgrade-nginx
/opt/bin/maestro upgrade-nginx --channel mainline
/opt/bin/maestro upgrade-nginx --check
/opt/bin/maestro upgrade-nginx --download-only
/opt/bin/maestro upgrade-nginx --no-backup
/opt/bin/maestro upgrade-nginx --version 1.30.7
/opt/bin/maestro upgrade-nginx --tag nginx-v1.30.7-run44684227015-a1
/opt/bin/maestro upgrade-nginx --force
# Explicitly allow moving from newer mainline to older stable:
/opt/bin/maestro upgrade-nginx --channel stable --allow-downgrade
```

The CLI discovers manually published `nginx-v*` GitHub releases, selecting
the latest stable (even minor) or mainline (odd minor) version unless you
pin `--tag` or `--version`. Tag and version cannot be combined. Release
discovery reads up to ten pages of GitHub Releases; older releases beyond that
limit require `--tag`. A checksum comparison against the installed NGINX binary
**and all four module binaries** detects same-version rebuilds, not just
version increases. `--check` fetches only release metadata and checksums.

The downloader verifies `SHA256SUMS` and all four matching Entware IPKs:
`nginx-ssl`, `nginx-mod-brotli`, `nginx-mod-stream`, and
`nginx-mod-headers-more`. It verifies the old NGINX configuration, checks
available temporary space, stages the bundle in a unique private directory,
and takes a full Maestro backup by default (including `--download-only`).
Use `--no-backup` only when you have a current external backup.

A live router upgrade also saves the previous executable, module directory,
module load directives and `S80nginx` in a **separate private rollback
snapshot** under `/tmp/.nginx-rollback-*`. These files are important because
Maestro's normal backup does not include NGINX package binaries. Both
the staged IPKs and rollback snapshot remain in temporary storage after the
command; copy them off the router before rebooting if needed.

When running as root, it invokes a bounded `opkg install` for the full
bundle and validates the replacement NGINX configuration. Same-version
rebuilds use `--force-reinstall`; selecting an older version explicitly
requires `--allow-downgrade`, which passes `--force-downgrade` to opkg.
If NGINX was running before installation, the command requests the supported
NGINX **live binary upgrade** with SIGUSR2, waits for a different master PID
running the new executable, and gracefully retires the old master with
SIGQUIT. A configuration reload (SIGHUP) by itself cannot activate the
replacement master binary. NGINX is left stopped if it was already stopped.
An empty PID file left by `nginx -t` is accepted only when `/proc` confirms
no NGINX processes exist. A malformed nonempty PID file or an empty file with
NGINX processes still running blocks installation for administrator review.

When opkg returns a definite failure or post-install verification fails,
Maestro attempts to restore the previous NGINX binary, modules and module
configuration from the snapshot and validates them. If opkg cannot be launched
or times out, the installer state may be uncertain, so no automatic rollback
is attempted: first ensure opkg and its package hooks have exited.
That file restoration **does not restore opkg's installed-package database**:
opkg may still report the attempted package version. After SIGUSR2 has been
sent, an activation failure **does not trigger automatic file rollback**,
because a new master may already be active and restoring modules underneath
it could break compatibility. The command reports an error and leaves the
snapshot for manual recovery; inspect process IDs and error logs before
retiring either master. A failure is never reported as a successful upgrade.

If opkg is unavailable, you are not root, or you choose `--download-only`,
the command prints an explicit opkg command using the four verified package
paths. The alias `update-nginx` is supported. The command is unavailable in
Linux and test modes. To verify the running binary after an upgrade:

```sh
/opt/sbin/nginx -v
cat /opt/var/run/nginx.pid
ps | grep '[n]ginx: master'
/opt/sbin/nginx -t -c /opt/etc/nginx/nginx.conf
```

For rollback, use the printed snapshot location to inspect and restore
individual files under their original `/opt` paths only after determining
which NGINX master is active. Keep the old master alive when SIGUSR2 activation
fails; do not blindly restart or overwrite modules. To completely reconcile
opkg metadata, reinstall the matching previously known-good IPK bundle after
recovery. Test the recovered configuration and startup before restoring WAN
traffic. Because `/tmp` is volatile, do not treat these local files as a
permanent disaster-recovery backup.

### Tarball installation (alternative)

On the router, ensure `curl`, `tar`, and `sha256sum` are available. You can
instead download and verify on another Linux machine, then transfer the
extracted directory to the router. For example, **after** `v0.8.1` has been
published:

```sh
VERSION=v0.10.1
TARGET=aarch64-unknown-linux-musl
PACKAGE="maestro-${VERSION}-${TARGET}"
URL="https://github.com/vm75/router-hub/releases/download/${VERSION}"

curl -fLO "${URL}/${PACKAGE}.tar.gz"
curl -fLO "${URL}/${PACKAGE}.tar.gz.sha256"
sha256sum -c "${PACKAGE}.tar.gz.sha256"
tar -xzf "${PACKAGE}.tar.gz"
cd "${PACKAGE}"
# Run as root on the router:
./scripts/install-merlin.sh ./maestro
```

The package includes the executable, `config/`, `scripts/`, and release
documentation. Back up the router's configuration and persistent data before
upgrading; the installer preserves existing `maestro.toml` and should be
reviewed for your environment. AArch64 musl compatibility requires validation
on your router CPU and firmware.

## Build and install from source

Build the release artifact for the target CPU. The helper also writes a SHA-256
file under `dist/`:

```sh
./scripts/build-release.sh aarch64-unknown-linux-musl
```

Alternatively, build and deploy to a remote target in one step using:

```sh
./scripts/build-and-deploy.sh user@router-host
```

Or copy the resulting binary, `config/`, and `scripts/` to the router, then run
the installer as root from that copied repository:

```sh
./scripts/install-merlin.sh ./maestro-aarch64-unknown-linux-musl --mosquitto-user admin --mosquitto-pass mysecretpassword
```

The installer:

1. installs the binary as `/opt/bin/maestro` and the Entware init script as
   `/opt/etc/init.d/S99maestro`;
2. creates `/opt/etc/maestro/maestro.toml` and a random authentication
   token on first install;
3. installs Maestro's main nginx configuration, saving a different existing
   file as `nginx.conf.before-router-hub-<unique-id>` and printing its path;
   preserves saved inputs and existing shared/custom files, creates missing
   bundled files and runtime/data directories;
4. configures Mosquitto credentials in `/opt/etc/mosquitto/passwd` if `--mosquitto-user` and `--mosquitto-pass` (or `MOSQUITTO_USER` / `MOSQUITTO_PASS` env vars) are supplied;
5. adds token-free reconciliation calls to `/jffs/scripts/post-mount` and
   `/jffs/scripts/firewall-start` (with a background retry loop);
6. validates the configuration and restarts Maestro.

Review the generated TOML before starting. In particular, set the correct
Asuswrt extension page (`user1.asp` through `user20.asp`), `menu_tree`,
`menu_index`, nginx paths, certificate paths, bind address, and allowed
origins. The installer’s default paths are examples for a typical Entware
layout, not proof that every firmware image uses the same layout.

The service supports the usual Entware init actions:

```sh
/opt/etc/init.d/S99maestro start
/opt/etc/init.d/S99maestro stop
/opt/etc/init.d/S99maestro restart
/opt/etc/init.d/S99maestro status
```

`reconcile` requests an immediate firewall reconciliation from the running
process and is used by the installed `post-mount` and `firewall-start` hooks.
