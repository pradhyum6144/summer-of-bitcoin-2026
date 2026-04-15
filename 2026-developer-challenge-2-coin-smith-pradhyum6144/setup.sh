#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# setup.sh — Install dependencies for Coin Smith (PSBT transaction builder)
#
# Add your install commands below (e.g., npm install, pip install, cargo build).
# This script is run once before grading to set up the environment.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

echo "Setup complete"
