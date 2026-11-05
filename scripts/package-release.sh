#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <vMAJOR.MINOR.PATCH[-PRERELEASE]> <rust-target> [binary-path]" >&2
  exit 2
fi

TAG=$1
TARGET=$2
BINARY=${3:-target/$TARGET/release/router-hub}

if [[ ! "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid release tag: $TAG" >&2
  exit 2
fi
if [[ ! "$TARGET" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Invalid Rust target: $TARGET" >&2
  exit 2
fi

REPO_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_DIR"

if [[ ! -f "$BINARY" ]]; then
  echo "Missing binary: $BINARY" >&2
  exit 1
fi

NAME="router-hub-$TAG-$TARGET"
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING/$NAME" dist
install -m 0755 "$BINARY" "$STAGING/$NAME/router-hub"
cp -R config scripts docs "$STAGING/$NAME/"
cp README.md CHANGELOG.md LICENSE "$STAGING/$NAME/"

tar -C "$STAGING" -czf "$PWD/dist/$NAME.tar.gz" "$NAME"
(
  cd dist
  sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256"
)

echo "Packaged dist/$NAME.tar.gz and dist/$NAME.tar.gz.sha256"
