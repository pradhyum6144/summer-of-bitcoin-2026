#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# cli.sh — Coin Smith: PSBT transaction builder CLI
#
# Usage:
#   ./cli.sh <fixture.json>
#
# Workflow:
#   1. Read the fixture JSON (UTXOs, payments, change template, fee rate)
#   2. Select coins (inputs) to fund the payments
#   3. Compute fee, change, and construct outputs
#   4. Build an unsigned PSBT (BIP-174)
#   5. Write JSON report to out/<fixture_name>.json
#   6. Exit 0 on success, 1 on error
#
# On error, writes { "ok": false, "error": { "code": "...", "message": "..." } }
# to the output file and exits 1.
###############################################################################

error_json() {
  local code="$1"
  local message="$2"
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code" "$message"
}

if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json>"
  echo "Error: No fixture file provided" >&2
  exit 1
fi

FIXTURE="$1"

if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  echo "Error: Fixture file not found: $FIXTURE" >&2
  exit 1
fi

# Create output directory
mkdir -p out

# Derive output filename from fixture basename
# e.g. fixtures/basic_change_p2wpkh.json → out/basic_change_p2wpkh.json
FIXTURE_NAME="$(basename "$FIXTURE")"
OUTPUT_FILE="out/$FIXTURE_NAME"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/coin-smith"

# Build if needed
if [[ ! -f "$BINARY" ]]; then
  echo "Building coin-smith..." >&2
  cargo build --release --bin coin-smith --manifest-path "$SCRIPT_DIR/Cargo.toml" >&2
fi

exec "$BINARY" "$FIXTURE" "$OUTPUT_FILE"
