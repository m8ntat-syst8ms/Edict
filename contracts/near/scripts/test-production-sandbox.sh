#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUSTFLAGS="${RUSTFLAGS:-} --cfg near" cargo build \
  --locked \
  --target wasm32-unknown-unknown \
  --release \
  -p edict-customer-settlement \
  -p edict-deployment-factory \
  -p edict-global-publisher-test

cargo test --manifest-path integration-tests/Cargo.toml \
  --locked \
  --test production \
  -- \
  --ignored \
  --nocapture
