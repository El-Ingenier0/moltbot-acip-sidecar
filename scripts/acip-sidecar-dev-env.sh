#!/usr/bin/env bash
set -euo pipefail

# Ensure we use the rustup toolchain (Cargo 1.88+) rather than Ubuntu's 1.75.
export PATH="$HOME/.cargo/bin:$PATH"

exec "$@"
