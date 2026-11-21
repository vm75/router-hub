#!/usr/bin/env bash
# Assemble an Entware AArch64 IPK without requiring the OpenWrt build system.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <vMAJOR.MINOR.PATCH> aarch64-unknown-linux-musl [binary-path]" >&2
  exit 2
fi
TAG=$1
TARGET=$2
BINARY=${3:-target/$TARGET/release/maestro}
ARCH=aarch64-3.10
if [[ ! "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "IPK releases currently require a stable SemVer tag: $TAG" >&2
  exit 2
fi
if [[ "$TARGET" != "aarch64-unknown-linux-musl" ]]; then
  echo "Unsupported IPK target: $TARGET" >&2
  exit 2
fi

REPO_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"
[[ -f "$BINARY" ]] || { echo "Missing binary: $BINARY" >&2; exit 1; }
VERSION=${TAG#v}
NAME="maestro_${VERSION}-1_${ARCH}.ipk"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
DATA="$TMP/data"
CONTROL="$TMP/control"
META="$TMP/meta"
mkdir -p "$DATA/opt/bin" "$DATA/opt/etc/init.d" "$DATA/opt/libexec/maestro" \
  "$DATA/opt/share/maestro" "$DATA/opt/var/lib/maestro/dehydrated" "$CONTROL" "$META" dist
install -m 0755 "$BINARY" "$DATA/opt/bin/maestro"
# Transitional CLI alias; the legacy init service is intentionally not aliased.
ln -s maestro "$DATA/opt/bin/router-hub"
install -m 0755 scripts/S99maestro "$DATA/opt/etc/init.d/S99maestro"
install -m 0755 scripts/setup-merlin.sh "$DATA/opt/libexec/maestro/setup-merlin.sh"
install -m 0755 scripts/dehydrated-dns01-hook.sh "$DATA/opt/share/maestro/dehydrated-dns01-hook.sh"
install -m 0755 scripts/dehydrated-dns01-hook.sh "$DATA/opt/var/lib/maestro/dehydrated/dehydrated-dns01-hook.sh"
install -m 0644 config/maestro.example.toml "$DATA/opt/share/maestro/maestro.example.toml"
install -m 0644 config/firewall-policy.example.json "$DATA/opt/share/maestro/firewall-policy.example.json"
cat > "$CONTROL/control" <<EOF
Package: maestro
Conflicts: router-hub
Version: ${VERSION}-1
Architecture: ${ARCH}
Maintainer: Maestro contributors
Section: admin
Priority: optional
Installed-Size: $(du -sk "$DATA" | cut -f1)
Source: https://github.com/vm75/router-hub
Description: Maestro management UI and services for Asuswrt-Merlin
EOF
cat > "$CONTROL/postinst" <<'EOF'
#!/bin/sh
set -eu
# Do not modify the build host during offline rootfs installations.
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
/opt/libexec/maestro/setup-merlin.sh /opt/share/maestro
EOF
cat > "$CONTROL/prerm" <<'EOF'
#!/bin/sh
set -eu
[ -z "${IPKG_INSTROOT:-}" ] || exit 0
if [ -x /opt/etc/init.d/S99maestro ]; then
    /opt/etc/init.d/S99maestro stop
fi
EOF
chmod 0755 "$CONTROL/postinst" "$CONTROL/prerm"
printf '2.0\n' > "$META/debian-binary"
tar -C "$CONTROL" -czf "$META/control.tar.gz" .
tar -C "$DATA" -czf "$META/data.tar.gz" .
(
  cd "$META"
  # Entware's IPK indexer expects a gzip tar outer archive (not Debian ar).
  tar --numeric-owner --owner=0 --group=0 -czf "$REPO_DIR/dist/$NAME" \
    ./debian-binary ./control.tar.gz ./data.tar.gz
)
(
  cd dist
  sha256sum "$NAME" > "$NAME.sha256"
)
echo "Packaged dist/$NAME and dist/$NAME.sha256"
