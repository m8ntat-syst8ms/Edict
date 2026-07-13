# Edict NEAR Intents V1 External Audit Scope

This scope covers the public `intents.near` settlement line only. It does not
cover Confidential Intents, a private-shard deployment, TEE bridge/privacy
claims or selective-disclosure receipts. Those require the separate release
profile and a new build-specific audit described in
[`CONFIDENTIAL_INTENTS_PROFILE.md`](./CONFIDENTIAL_INTENTS_PROFILE.md).

Status: audit brief for an independent reviewer. Repository review, unit tests,
Wasm checks and the pinned-Verifier sandbox are not an independent audit. No
artifact in this scope is deployed to mainnet and none may hold customer value.

## Candidate artifacts

The reproducible local candidates produced by
`scripts/check-intents-production-wasm.sh` are:

| Artifact | Candidate SHA-256 |
|---|---|
| `edict_customer_settlement_intents.wasm` | `294baf3e2e52e767538ab1fc987e028336922823ba6a01c5c7473a78b9c4f177` |
| `edict_intents_deployment_factory.wasm` | `f651531dc44a0f83ff82d32ad58375cc188048ad47647342fd6b3bf6dfec4f52` |

These are candidate identifiers, not audited releases. Any source,
dependency, compiler or build-flag change requires new hashes and delta review.

The exact upstream integration test pins the `intents.near` Wasm observed at
final block `GBRYPr7dzEr5FcA8ssCvBkGQEZLrZWYz5SKenicG6ZLH` (height
`206375398`): SHA-256
`f4b908b631562d62c133cc58b0a053dab41d6e243990c54694ac42264679f4ea`,
NEAR code hash `HUJ89jxFhsXF17XS8L5kmxz7te8AKfdWw2xzrVYo7aoj`. This is an
upstream compatibility snapshot, not an endorsement or immutable dependency.

## In scope

- `crates/edict-intents-settlement-common/src/lib.rs`
- `crates/edict-customer-settlement-intents/src/lib.rs`
- `crates/edict-intents-deployment-factory/src/lib.rs`
- shared ruling, verifier-policy and execution-digest code in
  `crates/edict-settlement-common/src/lib.rs`
- `scripts/check-intents-production-wasm.sh`
- `scripts/fetch-pinned-intents-verifier.mjs`
- `scripts/test-intents-sandbox.sh` and `integration-tests/tests/intents.rs`
- `../../packages/near-intents/src/index.ts`
- Intents deployment, manifest and runtime checks in
  `../../packages/near-deployer/src/index.ts`
- the audited-manifest handoff in `../../packages/sdk/src/settlement.ts`
- Cargo/npm lockfiles, compiler and production build environment
- assumptions about the exact pinned upstream Verifier methods and behavior

## Required conclusions

The reviewer should independently establish that:

1. Principal and first-round Bonds can enter only from the configured Verifier,
   as exactly one configured token, with authenticated sender/previous owner,
   exact amount and a versioned order message; a fundable principal always
   produces a positive atomic Bond.
2. A failed `mt_on_transfer` callback cannot leave Edict state funded while the
   upstream transfer is refunded, or vice versa.
3. `on_auth` cannot spoof requester, worker or customer-governance identity.
4. Every terminal allocation and held-Bond redo conserves atomic units and
   matches the native contract and TypeScript vectors across the full `u128`
   range without intermediate multiplication overflow.
5. Claims can call only `intents.near.mt_transfer`, only for the complete fixed
   claim, only to its recorded owner, with exact failed-callback restoration.
6. The settlement Wasm's sole promise action is function-call; no path can add
   keys, deploy code, create/delete accounts, stake, issue native transfers or
   choose an arbitrary contract/method/destination.
7. The factory is adminless, code-hash fixed, exact-deposit and keyless; failed
   creation releases the slug and refunds exactly, while concurrent slugs
   cannot replace a pending child.
8. The deployment manifest binds Edict code/config/zero keys, one asset,
   capacity, factory record, exact upstream code hash, predecessor auth,
   account-lock and pause state at one finalized block.
9. `verifyIntentsRuntime()` fails closed on upstream code drift, disabled
   predecessor auth, account lock, `intents` pause or `mt_transfer` pause.
10. External-audit evidence cannot be reused across a different settlement,
    factory or upstream Verifier hash.

## Upstream and adversarial focus

`intents.near` is managed, upgradeable and pausable and exposes privileged
account-lock and predecessor-auth controls. Those roles cannot select an Edict
ruling, but can affect funding, refunds or claim liveness. Review must cover:

- signed `transfer` notification and resolver behavior on success, panic,
  malformed return and insufficient gas;
- `auth_call` signer derivation across supported wallet standards;
- direct predecessor authorization used by the keyless settlement account;
- `mt_transfer` pause, account lock, forced auth changes and upstream upgrade;
- solver, bridge, token-decimal and 1Click quote/refund assumptions; and
- the impossibility of promising post-funding liveness if upstream governance
  halts the Verifier despite a successful pre-funding runtime check.

## Release gate

Mainnet use requires a public final report with no unresolved critical/high
finding, explicit coverage of both Edict candidate hashes and the selected
upstream Verifier hash, remediation review, repeated reproducible builds,
finalized-block manifest verification, a capped small-value mainnet canary and
a monitored observation period. NEAR Intents has no testnet; the exact-Wasm
sandbox supplements but does not replace that canary.
