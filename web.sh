#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PORT="${PORT:-3000}"

# Build if needed
if [[ ! -f "$SCRIPT_DIR/target/release/web" ]]; then
  echo "Building web server..." >&2
  cargo build --release --bin web --manifest-path "$SCRIPT_DIR/Cargo.toml" >&2
fi

exec "$SCRIPT_DIR/target/release/web"
