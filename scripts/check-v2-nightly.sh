#!/usr/bin/env bash
# Explicit exhaustive mutation budget; called by the nightly workflow.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --locked --release -p zkf-voleith --features parallel every_proof_byte_is_bound -- --ignored --nocapture
