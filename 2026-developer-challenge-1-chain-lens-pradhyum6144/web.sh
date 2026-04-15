#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# web.sh — Bitcoin transaction web visualizer
#
# Starts the web visualizer server.
#
# Behavior:
#   - Reads PORT env var (default: 3000)
#   - Prints the URL (e.g., http://127.0.0.1:3000) to stdout
#   - Keeps running until terminated (CTRL+C / SIGTERM)
#   - Must serve GET /api/health -> 200 { "ok": true }
#
# TODO: Replace the stub below with your web server start command.
###############################################################################

export PORT="${PORT:-3000}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "target/release/web" ]; then
    cargo build --release --bin web
fi

exec ./target/release/web
