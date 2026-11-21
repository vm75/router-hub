#!/usr/bin/env bash
# Prepare cached installer media and a persistent disk, then boot the installer.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
LAB_DIR="${LAB_DIR:-$REPO_DIR/data/lab}"
DISK="${LAB_DISK:-$LAB_DIR/router-lab.qcow2}"
BASE_URL=https://dl-cdn.alpinelinux.org/alpine

if [[ -e "$DISK" || -L "$DISK" ]]; then
    echo "Lab disk already exists: $DISK. Use make run-lab to boot it."
    exit 0
fi

# A complete lab needs the local release package before creating a new disk.
PACKAGE=""
for candidate in "$REPO_DIR"/dist/maestro_*_aarch64-3.10.ipk; do
    if [[ -f "$candidate" && ( -z "$PACKAGE" || "$candidate" -nt "$PACKAGE" ) ]]; then
        PACKAGE="$candidate"
    fi
done
if [[ -z "$PACKAGE" || ! -f "$PACKAGE.sha256" ]]; then
    echo 'Error: Build the Maestro IPK and checksum with make ipk before make init-lab.' >&2
    exit 1
fi
(cd "$(dirname "$PACKAGE")" && sha256sum -c "$(basename "$PACKAGE").sha256")
if ! tar -xzOf "$PACKAGE" ./data.tar.gz | \
    tar -xzOf - ./opt/libexec/maestro/setup-merlin.sh | \
    grep -F 'MAESTRO_DEFER_START' >/dev/null; then
    echo 'Error: Rebuild the IPK with make ipk; this package cannot defer service startup during provisioning.' >&2
    exit 1
fi

mkdir -p "$LAB_DIR"
WORK_DIR=$(mktemp -d "$LAB_DIR/.init.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

# Reuse the newest cached Standard AArch64 ISO without checking for updates.
shopt -s nullglob
isos=("$LAB_DIR"/alpine-standard-*-aarch64.iso)
ISO=""
if ((${#isos[@]})); then
    ISO=$(printf '%s\n' "${isos[@]}" | sort -V | tail -n 1)
else
    curl -fsSL "$BASE_URL/latest-stable/releases/aarch64/latest-releases.yaml" \
        -o "$WORK_DIR/releases.yaml"
    filename=$(awk '$1 == "file:" && $2 ~ /^alpine-standard-.*-aarch64\.iso$/ { print $2; exit }' \
        "$WORK_DIR/releases.yaml")
    ISO="$LAB_DIR/$filename"
fi

filename=$(basename "$ISO")
if [[ ! "$filename" =~ ^alpine-standard-([0-9]+\.[0-9]+)\.[0-9]+-aarch64\.iso$ ]]; then
    echo "Error: Cannot identify a stable Alpine Standard AArch64 ISO: $filename" >&2
    exit 1
fi
release_url="$BASE_URL/v${BASH_REMATCH[1]}/releases/aarch64/$filename"

if [[ ! -f "$ISO.sha256" ]]; then
    curl -fsSL "$release_url.sha256" -o "$WORK_DIR/checksum"
    # Store only the expected ISO entry, with a local basename.
    checksum=$(awk -v name="$filename" '$2 == name || $2 == "*" name { print $1; exit }' "$WORK_DIR/checksum")
    if [[ ! "$checksum" =~ ^[[:xdigit:]]{64}$ ]]; then
        echo "Error: Invalid Alpine SHA-256 checksum for $filename" >&2
        exit 1
    fi
    printf '%s  %s\n' "$checksum" "$filename" > "$WORK_DIR/$filename.sha256"
    mv "$WORK_DIR/$filename.sha256" "$ISO.sha256"
fi

if [[ ! -f "$ISO" ]]; then
    echo "Downloading $filename..."
    curl -fL "$release_url" -o "$WORK_DIR/$filename"
    cp "$ISO.sha256" "$WORK_DIR/$filename.sha256"
    (cd "$WORK_DIR" && sha256sum -c "$filename.sha256")
    mv "$WORK_DIR/$filename" "$ISO"
else
    (cd "$LAB_DIR" && sha256sum -c "$filename.sha256")
fi

# Refuse to boot the automatic installer unless this invocation creates the disk.
"$SCRIPT_DIR/run.sh" --create-disk 4G --disk "$DISK"

# Alpine discovers this apkovl archive on a read-only QEMU virtual FAT disk.
# Keep it attached for this installer session only, alongside the ISO.
mkdir -p "$WORK_DIR/overlay/etc/router-lab" "$WORK_DIR/seed"
cp "$SCRIPT_DIR/installer/inittab" "$WORK_DIR/overlay/etc/inittab"
cp "$SCRIPT_DIR/installer/install.sh" "$WORK_DIR/overlay/etc/router-lab/install.sh"
touch "$WORK_DIR/overlay/etc/.default_boot_services"
tar --owner=0 --group=0 -czf "$WORK_DIR/seed/router-lab.apkovl.tar.gz" \
    -C "$WORK_DIR/overlay" etc

"$SCRIPT_DIR/run.sh" --disk "$DISK" --iso "$ISO" --installer-seed "$WORK_DIR/seed"
