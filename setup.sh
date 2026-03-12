#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Decompress block fixtures if not already present
for gz in "$SCRIPT_DIR"/fixtures/*.dat.gz; do
  dat="${gz%.gz}"
  if [[ ! -f "$dat" ]]; then
    echo "Decompressing $(basename "$gz")..."
    gunzip -k "$gz"
  fi
done

# Build Rust binary
echo "Building sherlock..."
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

echo "Setup complete"
