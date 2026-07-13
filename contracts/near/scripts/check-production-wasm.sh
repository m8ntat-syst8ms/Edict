#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUSTFLAGS="${RUSTFLAGS:-} --cfg near" cargo build \
  --target wasm32-unknown-unknown \
  --release \
  -p edict-customer-settlement \
  -p edict-deployment-factory

SETTLEMENT="target/wasm32-unknown-unknown/release/edict_customer_settlement.wasm"
FACTORY="target/wasm32-unknown-unknown/release/edict_deployment_factory.wasm"

wasm-tools validate "$SETTLEMENT"
wasm-tools validate "$FACTORY"

settlement_actions="$(wasm-tools print "$SETTLEMENT" | rg -o 'promise_batch_action_[a-z_]+' | sort -u)"
factory_actions="$(wasm-tools print "$FACTORY" | rg -o 'promise_batch_action_[a-z_]+' | sort -u)"

expected_settlement=$'promise_batch_action_function_call\npromise_batch_action_transfer'
expected_factory=$'promise_batch_action_create_account\npromise_batch_action_function_call\npromise_batch_action_transfer\npromise_batch_action_use_global_contract'

if [[ "$settlement_actions" != "$expected_settlement" ]]; then
  printf 'Unexpected settlement action imports:\n%s\n' "$settlement_actions" >&2
  exit 1
fi
if [[ "$factory_actions" != "$expected_factory" ]]; then
  printf 'Unexpected factory action imports:\n%s\n' "$factory_actions" >&2
  exit 1
fi

settlement_exports="$(wasm-tools print "$SETTLEMENT" \
  | rg '^  \(export ' \
  | sed -E 's/^  \(export "([^"]+)".*/\1/' \
  | rg -v '^(__data_end|__heap_base|memory)$' \
  | sort)"
factory_exports="$(wasm-tools print "$FACTORY" \
  | rg '^  \(export ' \
  | sed -E 's/^  \(export "([^"]+)".*/\1/' \
  | rg -v '^(__data_end|__heap_base|memory)$' \
  | sort)"

expected_settlement_exports=$'accept\naccounting\nclaim_of\nclaim_timeout\ncontract_source_metadata\ndeliver\nexecute_liveness_fallback\nfund\nget_config\nget_order\nget_rounds\nis_nonce_used\nnew\non_withdraw_claim\nopen_dispute\norder_storage_deposit\nrequired_funding_deposit\nsubmit_ruling\nwithdraw_claim'
expected_factory_exports=$'contract_source_metadata\ncreate_instance\ndeployment_account\nget_config\nget_deployment\nnew\non_instance_deployed\nrequired_deployment_deposit'

if [[ "$settlement_exports" != "$expected_settlement_exports" ]]; then
  printf 'Unexpected settlement exports:\n%s\n' "$settlement_exports" >&2
  exit 1
fi
if [[ "$factory_exports" != "$expected_factory_exports" ]]; then
  printf 'Unexpected factory exports:\n%s\n' "$factory_exports" >&2
  exit 1
fi

shasum -a 256 "$SETTLEMENT" "$FACTORY"
