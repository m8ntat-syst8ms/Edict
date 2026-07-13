#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUSTFLAGS="${RUSTFLAGS:-} --cfg near" cargo build \
  --locked \
  --target wasm32-unknown-unknown \
  --release \
  -p edict-customer-settlement-intents \
  -p edict-intents-deployment-factory \
  -p edict-global-publisher-test

export EDICT_INTENTS_VERIFIER_WASM
EDICT_INTENTS_VERIFIER_WASM="$(node scripts/fetch-pinned-intents-verifier.mjs)"
wasm-tools validate "$EDICT_INTENTS_VERIFIER_WASM"

cargo test --manifest-path integration-tests/Cargo.toml \
  --locked \
  --test intents \
  -- \
  --ignored \
  --nocapture
