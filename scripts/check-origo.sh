#!/usr/bin/env bash
# Explicit, non-ignored ORIGO security regression entry point for local/CI use.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked --release -p zkf-tls13 --lib origo_validation
cargo test --locked --release -p zkf-tls13 --test origo
