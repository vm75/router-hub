#!/usr/bin/env bash
# Host launcher for the AArch64 Maestro Alpine lab.
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)

LAB_DIR="${LAB_DIR:-$REPO_DIR/data/lab}"
DISK="${LAB_DISK:-$LAB_DIR/router-lab.qcow2}"
ISO="${ALPINE_ISO:-}"
AARCH64_UEFI="${AARCH64_UEFI:-}"
PORT_HTTP=8080
PORT_HTTPS=8443
PORT_API=3030
CREATE_DISK=""
INSTALLER_SEED=""

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --disk <path>         Path to QCOW2 disk image (default: $LAB_DIR/router-lab.qcow2)
  --iso <path>          Path to Alpine AArch64 Standard ISO (for installer boot)
  --installer-seed <dir>  Read-only directory containing the installer boot overlay
  --uefi <path>         Path to AArch64 UEFI firmware (e.g. QEMU_EFI.fd)
  --create-disk [size]  Create a new QCOW2 disk of given size (default: 4G) and exit
  -h, --help            Show this help message

Environment variables:
  LAB_DIR              Media directory (default: repository data/lab)
  LAB_DISK              Default disk path
  ALPINE_ISO            Default installer ISO path
  AARCH64_UEFI          Default UEFI firmware path
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk)
            DISK="$2"
            shift 2
            ;;
        --iso)
            ISO="$2"
            shift 2
            ;;
        --uefi)
            AARCH64_UEFI="$2"
            shift 2
            ;;
        --installer-seed)
            INSTALLER_SEED="$2"
            shift 2
            ;;
        --create-disk)
            if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
                CREATE_DISK="$2"
                shift 2
            else
                CREATE_DISK="4G"
                shift 1
            fi
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ -n "$INSTALLER_SEED" && ( -z "$ISO" || ! -d "$INSTALLER_SEED" ) ]]; then
    echo 'Error: --installer-seed requires --iso and an existing seed directory.' >&2
    exit 1
fi

# Check for qemu-img and qemu-system-aarch64
check_host_prerequisites() {
    local missing=()
    if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
        missing+=("qemu-system-aarch64")
    fi
    if ! command -v qemu-img >/dev/null 2>&1; then
        missing+=("qemu-img")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        cat >&2 <<EOF
Error: Required host tools missing: ${missing[*]}

Install required packages:
  Arch Linux:    sudo pacman -S qemu-system-aarch64 qemu-img edk2-aarch64
  Ubuntu/Debian: sudo apt update && sudo apt install qemu-system-arm qemu-utils qemu-efi-aarch64
  Fedora/RHEL:   sudo dnf install qemu-system-aarch64 qemu-img edk2-aarch64
EOF
        exit 1
    fi
}

# Handle --create-disk
if [[ -n "$CREATE_DISK" ]]; then
    check_host_prerequisites
    if [[ -e "$DISK" || -L "$DISK" ]]; then
        echo "Error: Disk '$DISK' already exists. Refusing to overwrite." >&2
        exit 1
    fi
    mkdir -p "$(dirname "$DISK")"
    echo "Creating QCOW2 disk '$DISK' (${CREATE_DISK})..."
    qemu-img create -f qcow2 "$DISK" "$CREATE_DISK"
    echo "Disk created: $DISK"
    exit 0
fi

check_host_prerequisites

# Resolve UEFI firmware
if [[ -z "$AARCH64_UEFI" ]]; then
    candidates=(
        "/usr/share/edk2/aarch64/QEMU_EFI.fd"
        "/usr/share/edk2/armvirt/QEMU_EFI.fd"
        "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
        "/usr/share/AAVMF/AAVMF_CODE.fd"
        "/usr/share/edk2-armvirt/aarch64/QEMU_EFI.fd"
        "/usr/share/qemu/edk2-aarch64-code.fd"
        "/usr/share/edk2/aarch64/QEMU_EFI.silent.fd"
    )
    for candidate in "${candidates[@]}"; do
        if [[ -f "$candidate" ]]; then
            AARCH64_UEFI="$candidate"
            break
        fi
    done
fi

if [[ -z "$AARCH64_UEFI" || ! -f "$AARCH64_UEFI" ]]; then
    cat >&2 <<EOF
Error: AArch64 UEFI firmware not found.

Install edk2-aarch64 (Arch/Fedora) or qemu-efi-aarch64 (Debian/Ubuntu),
or set AARCH64_UEFI or --uefi to the path of QEMU_EFI.fd.
EOF
    exit 1
fi

# Check disk exists
if [[ ! -f "$DISK" ]]; then
    cat >&2 <<EOF
Error: Lab disk '$DISK' not found.

Create the disk first with:
  $0 --create-disk 4G --disk "$DISK"
or:
  qemu-img create -f qcow2 "$DISK" 4G
EOF
    exit 1
fi

QEMU_CMD=(
    qemu-system-aarch64
    -machine virt
    -cpu cortex-a53
    -smp 2
    -m 1024
    -nographic
    -bios "$AARCH64_UEFI"
    -drive "file=$DISK,format=qcow2,if=virtio"
    -virtfs "local,path=$REPO_DIR,mount_tag=router-hub,security_model=none,readonly=on"
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:${PORT_HTTP}-:8080,hostfwd=tcp:127.0.0.1:${PORT_HTTPS}-:8443,hostfwd=tcp:127.0.0.1:${PORT_API}-:3030"
)

if [[ -n "$ISO" ]]; then
    if [[ ! -f "$ISO" ]]; then
        echo "Error: Installer ISO '$ISO' not found." >&2
        exit 1
    fi
    echo "Attaching installer ISO: $ISO"
    QEMU_CMD+=(
        -device virtio-scsi-pci
        -drive "if=none,id=cd,media=cdrom,readonly=on,file=$ISO"
        -device "scsi-cd,drive=cd,bootindex=1"
    )
    if [[ -n "$INSTALLER_SEED" ]]; then
        QEMU_CMD+=(
            -drive "file=fat:ro:$INSTALLER_SEED,format=raw,if=virtio,readonly=on"
        )
    fi
fi

cat <<EOF
Starting AArch64 Maestro Lab
  Disk:     $DISK
  UEFI:     $AARCH64_UEFI
  Forwards: 127.0.0.1:${PORT_HTTP} -> guest:8080 (ASUS HTTP)
            127.0.0.1:${PORT_HTTPS} -> guest:8443 (ASUS HTTPS)
            127.0.0.1:${PORT_API}  -> guest:3030 (Maestro API)
EOF

if [[ -n "$ISO" ]]; then
    echo "  Mode:     Installer boot from $ISO"
    if [[ -n "$INSTALLER_SEED" ]]; then
        echo "            setup-alpine automatically installs onto the newly created vda."
    else
        echo "            Run 'setup-alpine' on the console for a 'sys' install on vda."
    fi
else
    echo "  Mode:     Normal guest boot"
fi
echo "  Share:    $REPO_DIR (read-only, mount at /mnt/router-hub)"

echo ""
echo "Press Ctrl+A then X to exit QEMU."
echo "------------------------------------------------------------"

exec "${QEMU_CMD[@]}"
