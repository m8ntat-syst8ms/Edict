# Edict NEAR V1 External Audit Scope

Status: audit brief for an independent reviewer. Repository review, unit tests
and sandbox tests are not an independent external audit.

This scope is intentionally limited to native-NEAR v1. The preferred
cross-chain profile now has separate implemented artifacts, tests and audit
scope in `INTENTS_AUDIT_SCOPE.md`; passing either audit does not authorize the
other artifact line.

## Release artifacts

The audited release must freeze the compiler, lockfile and Wasm bytes. The
current local candidate produced by `scripts/check-production-wasm.sh` is:

| Artifact | Current SHA-256 |
|---|---|
| `edict_customer_settlement.wasm` | `405b159989f24a1afdd9b01c58c77b5c0d501f947aa17296881ede49bbda8852` |
| `edict_deployment_factory.wasm` | `561b715958cadcc8fbc22bc0e922667b93ef34ce78584a68914ab45952f36f79` |

These hashes are candidates, not audited release identifiers. Any source,
dependency, compiler or build-flag change requires new artifacts and audit
delta review.

## In-scope source

- `crates/edict-settlement-common/src/lib.rs`
- `crates/edict-customer-settlement/src/lib.rs`
- `crates/edict-deployment-factory/src/lib.rs`
- `scripts/check-production-wasm.sh`
- `SETTLEMENT_ECONOMICS_VECTORS.json`
- `../../services/arbiter/src/executionPayload.ts`
- `../../packages/near-deployer/src/index.ts` and `src/cli.ts`
- `../../packages/sdk/src/settlement.ts`, specifically the manifest handoff,
  execution gate and exact atomic allocation helper
- Cargo/npm lockfiles and the production build environment

The test-only global publisher is in scope only as sandbox infrastructure. It
must never be deployed or referenced as a production component.

## Required security conclusions

The reviewer should independently establish that:

1. No Edict, factory, customer-governance or third-party key can upgrade,
   pause, freeze, delete, recover or generically transfer from an instance.
2. Factory creation is atomic, version-fixed, exact-deposit and keyless, and a
   failed child deployment cannot leave an uninitialized or controllable child.
3. Every active-order economic and timing field is immutable after funding,
   and funding cannot create an order whose required Bond rounds to zero.
4. Every state transition preserves solvency across principal, Bonds, claims
   and storage liabilities, including failed asynchronous transfers and the
   full supported `u128` range without intermediate multiplication overflow.
5. Signature recovery rejects malformed/high-s signatures; quorum counts
   distinct immutable operators; replay and cross-order/cross-instance reuse
   fail; and TypeScript/Rust digests are byte-identical.
6. Challenge, acceptance, resolution and redo boundaries have no off-by-one,
   race or overflow path.
7. Every ruling and fallback remains inside the funded decision space; no
   caller can choose an arbitrary recipient or amount.
8. Rounding conserves every atomic unit and sends the required residual to the
   removal account.
9. Wasm imports and exports match the checked allowlists and introduce no
   hidden administrative host action or entry point.
10. The deployment verifier pins one final block, checks both code hashes and
    zero-key state, binds external audit evidence to those exact hashes, and
    fails closed on malformed RPC or manifest data.
11. A failed child initializer rolls back the complete create/transfer/code/init
    action batch before the factory refund callback releases its slug.

## Adversarial focus

- Promise/callback reentrancy, failure and duplicate-callback behavior.
- Storage exhaustion, under-collateralization and state-growth griefing.
- Account deletion/nonexistent payout recipients and failed refund paths.
- Factory slug races and callbacks with mismatched customer or deposit data.
- ECDSA malleability, recovery-id variants, duplicate keys/operators and quorum
  configurations involving Edict-controlled signers.
- Timestamp manipulation, verdicts issued before a round, proof/fallback races,
  redo deadline abuse and round-number confusion.
- Nonce reuse across rounds, orders, instances and networks.
- JSON/Borsh/canonical-string mismatches and integer truncation.
- RPC equivocation, adjacent-block reads, fake factory views and audit evidence
  for a different artifact.

## Explicitly out of scope

- Legal conclusions about custody, payment services, AML or enforceability.
- Model correctness, tribunal procedure or the substantive merits of a verdict.
- Authenticity of an attestation bundle whose hash the customer pins.
- Security of independent signer infrastructure, customer wallets or RPCs.
- NEP-141, USDC, bridges, intents and every non-native-NEAR adapter.
- `../../packages/near-intents` and the separate Intents settlement/factory;
  those are scoped by `INTENTS_AUDIT_SCOPE.md`, including upstream Verifier
  assumptions and mainnet-only canary controls.
- Fee collection, USD conversion/Bond floor, appeals and human bench operation.

These exclusions must remain visible in the audit report and product release.

## Acceptance gate

Mainnet release requires a public final report, no unresolved critical/high
finding, explicit confirmation of both final Wasm hashes, remediation review,
repeated reproducible builds, a time-boxed testnet canary and a published bug
bounty/contact. `externalAuditStatus` may change only when the report hash and
both audited code hashes are attached to the deployment manifest.
