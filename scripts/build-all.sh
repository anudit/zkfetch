#!/usr/bin/env bash
# Build all client/server artifacts from one committed source snapshot.
set -euo pipefail
cd "$(dirname "$0")/.."
if ! git diff --quiet HEAD -- Cargo.toml Cargo.lock rust-toolchain.toml crates vendor packages infra/aws; then
  echo "Commit source changes before building a synchronized release." >&2
  exit 1
fi
# Refuse untracked build inputs, but permit the explicitly excluded .github/.
if [[ -n "$(git ls-files --others --exclude-standard -- crates vendor packages infra/aws)" ]]; then
  echo "Untracked build inputs exist; commit them first." >&2
  exit 1
fi
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export CARGO_NET_OFFLINE=${CARGO_NET_OFFLINE:-true}
bun run build:native
bun run --cwd packages/wasm build
bun run --cwd packages/wasm build:threads
bun run --cwd packages/chrome-extension build
mkdir -p .zkf/build-all/artifacts
docker buildx build --platform linux/arm64 -f infra/aws/Dockerfile.native \
  --output type=local,dest=.zkf/build-all/artifacts .
# This records provenance, not a promise of bit-identical cross-toolchain builds.
python3 scripts/build-provenance.py .zkf/build-all/provenance.json
