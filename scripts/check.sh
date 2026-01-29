#!/usr/bin/env bash
set -euo pipefail

source "$HOME/.cargo/env" 2>/dev/null || true

cargo fmt
cargo test
cargo clippy -- -D warnings
