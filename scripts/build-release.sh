#!/usr/bin/env bash
set -euo pipefail
TARGET="${1:-aarch64-unknown-linux-musl}"
rustup target add "$TARGET"
cargo build --release --locked --target "$TARGET"
mkdir -p dist
cp "target/$TARGET/release/maestro" "dist/maestro-$TARGET"
(
  cd dist
  sha256sum "maestro-$TARGET" > "maestro-$TARGET.sha256"
)
echo "Built dist/maestro-$TARGET"
