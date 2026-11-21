# AArch64 Maestro Lab

This lab boots an AArch64 Alpine Linux guest in QEMU, provisions simulated Asuswrt firmware interfaces and Entware, installs the standard Maestro AArch64 musl IPK, and exercises the live router web interface and WireGuard toggling.

## Architecture

| Component      | In the Lab                                                           |
| -------------- | -------------------------------------------------------------------- |
| Guest OS       | Alpine Linux AArch64 (musl libc, OpenRC)                             |
| Entware        | Generic AArch64 Entware (`/opt`, glibc tools)                        |
| Maestro     | Static AArch64 musl release IPK (`maestro_*_aarch64-3.10.ipk`)    |
| Web Root       | BusyBox httpd serving `/www` on HTTP 8080; stunnel provides HTTPS 8443 |
| Firmware Mocks | `/bin/nvram`, `/usr/local/libexec/router-lab/service`, syslog reader |
| WireGuard      | Linux kernel WireGuard via Entware `wg` and `wg-quick`               |

## 1. Host Prerequisites

The lab requires QEMU AArch64 system emulation, `qemu-img`, AArch64 UEFI firmware,
`curl`, and `sha256sum`.

### Arch Linux

```sh
sudo pacman -S qemu-system-aarch64 qemu-img edk2-aarch64
```

### Ubuntu / Debian

```sh
sudo apt update
sudo apt install qemu-system-arm qemu-utils qemu-efi-aarch64
```

### Fedora / RHEL

```sh
sudo dnf install qemu-system-aarch64 qemu-img edk2-aarch64
```

## 2. Prepare Guest Media

Prepare the media and boot the installer:

```sh
make ipk
make init-lab
```

Build the IPK first so `init-lab` can verify its checksum and support for deferred
service startup before creating the disk. Rebuild older IPKs with `make ipk`.

`lab/aarch64/init.sh` downloads the latest stable Alpine AArch64 **Standard**
ISO and its SHA-256 checksum into ignored `data/lab/`. It reuses the newest
cached Standard AArch64 ISO when preparing a new disk without checking for updates, and
verifies its checksum before booting. Failed downloads are not retained as ISOs.
It creates `data/lab/router-lab.qcow2` as a 4 GB disk only when missing, then
boots the installer. If the disk already exists, `init-lab` exits immediately
without downloading media or starting QEMU. Use `run-lab` to boot an existing
disk, including after installation.

For installer boots, `init.sh` also creates a temporary Alpine configuration
overlay and exposes it as a read-only QEMU virtual FAT disk. No extra ISO tools
or GitHub download are needed. The overlay is removed when QEMU exits.

Set `LAB_DIR` to override the media directory, `LAB_DISK` for a different disk,
and `AARCH64_UEFI` for a firmware path. Both scripts use these defaults regardless
of the host working directory. Direct launcher calls also accept `--disk`,
`--iso`, and `--uefi`.

## 3. Install Alpine Linux in the Guest

`make init-lab` automatically loads `9pnet_virtio`, mounts the repository at
`/mnt/router-hub`, and runs `setup-alpine` with the supplied answer file before
the login prompt. Erasure of the newly created `/dev/vda` is automatically
confirmed using Alpine's `ERASE_DISKS` option.

For a direct `run.sh --iso ...` boot without the overlay, or to retry after an
installation error, log in as root and run these commands manually:

```sh
modprobe 9pnet_virtio
mkdir -p /mnt/router-hub
mount -t 9p -o trans=virtio,version=9p2000.L,ro router-hub /mnt/router-hub
setup-alpine -f /mnt/router-hub/lab/aarch64/setup-alpine.answers
```

The answers select hostname `router.emu`, DHCP on `eth0`, automatic IPv6,
timezone `PST8PDT`, BusyBox NTP, the first CDN mirror, no additional user,
Dropbear SSH, and a **sys** install on `/dev/vda`. The lab-only root password
is `abcd1234`. Manual invocation still asks for disk-erasure confirmation.
Alpine installs into `/mnt/router-lab`, keeping its recursive mount cleanup
separate from the live repository at `/mnt/router-hub`.
After Alpine installs, the installer mounts `/dev/vda3`, prepares a chroot with
DNS, temporary runtime filesystems and the project share, and runs provisioning
against the installed disk. It then unmounts those filesystems and powers off.
Provisioning failures leave the console available for inspection rather than
reporting success or powering off. Services are enabled during setup and start
when `make run-lab` boots the installed guest.
The automatic installer hook is removed before installation so it does not run
on installed-system boots. `make run-lab` attaches neither the ISO nor the overlay.

## 4. Boot the Installed Guest

Run QEMU with only the disk:

```sh
make run-lab
```

Network port forwards:

- Host `127.0.0.1:8080` forwards to guest `:8080` (ASUS HTTP)
- Host `127.0.0.1:8443` forwards to guest `:8443` (ASUS HTTPS)
- Host `127.0.0.1:3030` forwards to guest `:3030` (Maestro API)

These ports match the generated UI API URL and allowed browser origins.
Guest ports 80 and 443 remain available for Entware NGINX. HTTPS uses a
self-signed guest-only certificate; HTTP and HTTPS share the same Basic Auth.

Exit QEMU at any time with `Ctrl+A` then `X`.

## 5. Rebuild the Package on the Host

Before creating a new lab, or to package an update for an existing guest:

```sh
make ipk
```

## 6. Provision an Existing Guest Manually

New guests are provisioned automatically during `make init-lab`. To rerun
provisioning on an existing guest, boot it with `make run-lab`. Installer and
normal disk boots export the project through QEMU 9p as a read-only share.
Run these commands as root inside the VM (omit the mount commands if already mounted):

```sh
modprobe 9pnet_virtio
mkdir -p /mnt/router-hub
mount -t 9p -o trans=virtio,version=9p2000.L,ro router-hub /mnt/router-hub
sh /mnt/router-hub/lab/aarch64/provision.sh
```

Provisioning selects the most recently modified Maestro IPK in the shared
`dist/` directory and requires its matching `.sha256` file. Select a specific
package when needed:

```sh
PACKAGE=/mnt/router-hub/dist/maestro_VERSION-1_aarch64-3.10.ipk \
  sh /mnt/router-hub/lab/aarch64/provision.sh
```

Replace `VERSION` with the packaged version. Provisioning records the mount in
`/etc/fstab` and loads the virtio 9p module on subsequent guest boots. Host edits
and rebuilt packages are available through the mount. Installed services and
settings live on the guest disk.
If `modprobe` reports a missing module, install the matching Alpine kernel
modules with 9p support before continuing.

The provisioning script:

1. Installs Alpine utilities (`ca-certificates`, `curl`, `openssl`, `iproute2`, `busybox-extras`, and `stunnel` from the matching community repository).
2. Bootstraps generic AArch64 Entware under `/opt`.
3. Configures `/etc/init.d/entware` OpenRC service for unslung startup.
4. Installs the `/bin/nvram` mock, `/usr/local/libexec/router-lab/service` mock, and syslog fallback.
5. Installs `wireguard-tools` and `wg-quick`, configures `/opt/etc/wireguard/wgs1.conf`, and sets up short-name links.
6. Launches BusyBox httpd with Basic Auth on port 8080, adds a stunnel TLS listener on 8443, and seeds `/www/require/modules/menuTree.js` and `/www/state.js`.
7. Seeds `/opt/etc/maestro/firewall-policy.json` (disabled) and generates `/opt/etc/maestro/maestro.toml`.
8. Validates the SHA-256 checksum and installs `maestro_*_aarch64-3.10.ipk` via Entware `opkg`.

During ISO installation, provisioning runs with `LAB_OFFLINE=1`: OpenRC service
starts and kernel interface probes are deferred, and the package setup hook uses
`MAESTRO_DEFER_START=1` to initialize configuration without stopping or starting
Maestro. Normal manual provisioning keeps its existing service-start behavior.

Provisioning configures `/root/.bashrc` to display access details when root opens
an interactive shell. Alpine's default ash login also displays the same banner,
once per shell. It reads the current saved files each time:

- ASUS httpd Basic Auth credentials (saved in `/etc/router-lab/httpd-credentials.txt`).
- Maestro API token (saved in `/opt/etc/maestro/auth-token.txt`).

The banner also lists the host browser URLs. Credentials and URLs are no longer
printed in the provisioning completion message. Rerun provisioning to add the
banner to an existing guest.

For an existing lab, shut down and relaunch QEMU with the updated `run.sh` to
apply the new guest port forwards, then rerun provisioning from the shared
project. It moves the mock HTTP service to 8080 and installs HTTPS on 8443,
preserving existing Basic Auth credentials and Maestro settings. Existing
Maestro configurations need `https://127.0.0.1:8443` added to
`server.allowed_origins` if using the HTTPS page. The API remains on HTTP 3030;
for HTTPS browser use, configure `asus_ui.api_base_url` to an HTTPS API reverse
proxy and allow its origin as needed.

## 7. Acceptance Walkthrough

1. Open your host browser to `http://127.0.0.1:8080/user20.asp`.
2. Log in as root in the guest to see the access banner, then sign in to httpd
   with those credentials (`user=lab`).
3. Confirm Maestro renders live system metrics (CPU, RAM, uptime, network interfaces).
4. Navigate to the WireGuard section:
   - Click to turn WireGuard on.
   - In the guest console, run `/opt/bin/wg show wgs1` and verify the interface and assigned IP (`10.77.0.1/24`) are active.
   - Click to turn WireGuard off.
   - In the guest console, verify `ip link show wgs1` indicates the interface was brought down.
5. Check NVRAM mock resolution:
   - Run `/bin/nvram get lan_ipaddr` inside the guest.
   - Query `curl -s -H "Authorization: Bearer <TOKEN>" http://127.0.0.1:3030/api/adguard/config | jq .lan_ip` on the host to verify matching discovery.
