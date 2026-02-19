#!/bin/bash

# Build the CLI binary if needed
if [ ! -f "target/release/cli" ]; then
    cargo build --release --bin cli
fi

# Run the CLI with all arguments passed through
./target/release/cli "$@"
