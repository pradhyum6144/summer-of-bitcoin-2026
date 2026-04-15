#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# web.sh — Coin Smith: PSBT builder web UI and visualizer
#
# Starts the web server for the PSBT transaction builder.
#
# Behavior:
#   - Reads PORT env var (default: 3000)
#   - Prints the URL (e.g., http://127.0.0.1:3000) to stdout
#   - Keeps running until terminated (CTRL+C / SIGTERM)
#   - Must serve GET /api/health -> 200 { "ok": true }
#
# TODO: Replace the stub below with your web server start command.
###############################################################################

PORT="${PORT:-3000}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/coin-smith-web"

# Build if needed
if [[ ! -f "$BINARY" ]]; then
  echo "Building coin-smith-web..." >&2
  cargo build --release --bin coin-smith-web --manifest-path "$SCRIPT_DIR/Cargo.toml" >&2
fi

export PORT
exec "$BINARY"
