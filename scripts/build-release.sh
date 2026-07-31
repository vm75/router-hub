#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-aarch64-unknown-linux-musl}"
rustup target add "$TARGET"
cargo build --release --target "$TARGET"
mkdir -p dist
cp "target/$TARGET/release/router-hub" "dist/router-hub-$TARGET"
sha256sum "dist/router-hub-$TARGET" >"dist/router-hub-$TARGET.sha256"
echo "Built dist/router-hub-$TARGET"
