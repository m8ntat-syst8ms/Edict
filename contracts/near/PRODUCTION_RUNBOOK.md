# Edict Native-NEAR V1 Production Runbook

This is a release procedure, not evidence that a release has occurred. Stop at
Gate 1 until an independent audit covers the exact final artifacts.

## Gate 0: source and test freeze

```sh
cd contracts/near
cargo fmt --all -- --check
cargo test --workspace
./scripts/check-production-wasm.sh
./scripts/test-production-sandbox.sh
```

Run the Wasm checker twice from clean build environments and compare hashes.
Archive the source commit, `Cargo.lock`, Rust/LLVM versions, build flags, Wasm
bytes, hashes, test logs and `wasm-tools` version.

## Gate 1: independent audit

Give the reviewer `AUDIT_SCOPE.md` and the frozen artifacts. Resolve findings,
rebuild, rerun every test and obtain remediation confirmation for the final
hashes. Publish the report and retain its SHA-256. Do not deploy a public
mainnet factory, invite customers or accept customer value before this gate.

## Gate 2: publish immutable global artifacts

Build no-key publication plans for the audited settlement and factory Wasm:

```sh
node packages/near-deployer/dist/cli.js plan-publish \
  --publisher <release-account> \
  --wasm contracts/near/target/wasm32-unknown-unknown/release/edict_customer_settlement.wasm

node packages/near-deployer/dist/cli.js plan-publish \
  --publisher <release-account> \
  --wasm contracts/near/target/wasm32-unknown-unknown/release/edict_deployment_factory.wasm
```

The release wallet signs locally. Publication by code hash makes the bytes
content-addressed; the publisher cannot replace code at the same hash. Record
both transactions and query the global hashes independently from two RPCs.

## Gate 3: bootstrap the keyless factory

Use a fresh immediate subaccount and the audited hashes:

```sh
node packages/near-deployer/dist/cli.js plan-bootstrap-factory \
  --parent <parent-account> \
  --factory <v1.factory-account> \
  --factory-code-hash <audited-factory-sha256> \
  --code-hash <audited-settlement-sha256> \
  --balance <factory-balance-yocto> \
  --instance-balance <minimum-child-balance-yocto>
```

Execute the plan as one parent-signed action batch: create account, fund it,
use the factory global hash and initialize. It adds no key. Confirm:

- factory code hash equals the audited factory hash;
- `view_access_key_list` is empty;
- `get_config()` reports the exact settlement hash, versions and `adminless`;
- the Wasm export list has no method beyond the release allowlist; and
- Edict has no child-control or code-hash update path.

## Gate 4: mainnet canary

Create one low-value operator-owned canary through the same call customers
will use:

```sh
node packages/near-deployer/dist/cli.js plan-factory \
  --config <customer-config.json> \
  --factory <v1.factory-account> \
  --slug <canary-slug> \
  --deposit <required-deployment-deposit-yocto>
```

Run clean acceptance, dispute, split with odd-unit rounding, redo, fixed
fallback, failed-recipient withdrawal and replay tests. Keep the canary below a
published cap and observation period. Compare events and accounting after each
transition.

## Gate 5: verify and bind a customer instance

Create `audit-evidence.json` with the independent firm, public report URI,
report hash, date and both audited code hashes. Then verify the deployment:

```sh
node packages/near-deployer/dist/cli.js verify \
  --network mainnet \
  --account <customer-instance> \
  --factory <v1.factory-account> \
  --code-hash <audited-settlement-sha256> \
  --factory-code-hash <audited-factory-sha256> \
  --config <customer-config.json> \
  --audit-evidence <audit-evidence.json> \
  > deployment-manifest.json
```

The verifier reads code, keys, configuration and factory record at one finalized
block. The customer should retain and, where its governance process supports
it, sign `manifestSha256Hex`. The SDK binding is then:

```ts
const settlement = customerContractSettlementFromManifest(manifest);
const edict = createEdict({ mode: 'live', settlement });
```

The helper rejects unaudited, testnet, mutable, keyed, tampered or code-mismatched
manifests. Direct use of an adapter string does not replace deployment review.

## Gate 6: controlled launch

- Publish artifact, factory, audit-report and canary manifests.
- Cap value and aggregate exposure for the first cohort.
- Monitor factory callbacks, order liabilities, failed claims, timeout queues,
  signer availability and RPC disagreement.
- Maintain an independent permissionless relayer and documented customer
  fallback instructions; Edict's relayer must never be required.
- Freeze new funding on the integration/UI side if an incident occurs. The
  immutable contracts intentionally have no Edict pause key; existing orders
  finish under their signed rules.
- Ship a new audited hash/factory for any code change. Never upgrade active v1
  instances in place.

## Current hard limits

This native settlement candidate accepts native NEAR only. It does not
implement NEP-141/USDC, fees, a USD Bond floor, appeals or human-review
scheduling.

## Separate NEAR Intents release track

NEAR Intents is the preferred cross-chain product profile, but it is not an
extension flag on the native artifacts. Follow `INTENTS_SETTLEMENT_SPEC.md`
and `INTENTS_AUDIT_SCOPE.md`. Repository source now provides items 1, 2 and the
tooling for item 4; stop before funds until every item is complete:

1. a separate keyless Intents settlement Wasm and version-fixed factory
   (**implemented locally**);
2. local tests against an exact hash-pinned mainnet Verifier Wasm for signed
   transfer, `mt_on_transfer` refund, `auth_call` and claim transfer
   (**passing locally**);
3. reproducible Edict artifact hashes and a separate independent audit whose
   scope includes all assumptions about `intents.near`;
4. finalized-mainnet checks for Edict code/config/zero keys, active factory
   record, pinned upstream code, predecessor auth, account lock and critical
   pause flags (**implemented, awaiting actual deployment**); and
5. a capped small-value mainnet canary and observation period.

NEAR Intents currently has no testnet. Local Verifier-Wasm testing replaces
the functional testnet stage, but not the independent audit or mainnet canary.
`verifyIntentsRuntime()` must run immediately before funding because upstream
code, pause, lock and predecessor-auth state can change after deployment.
