# Customer-Owned Settlement Deployment Profile

Status: implemented and sandbox-tested source candidate. It has not received
an independent external security audit and has not been deployed to mainnet.
No customer value may use it until the gates in `PRODUCTION_RUNBOOK.md` pass.
This document describes the native-NEAR v1 artifact; the preferred cross-chain line is a
separate implemented audit candidate specified in `INTENTS_SETTLEMENT_SPEC.md`
and `INTENTS_AUDIT_SCOPE.md`.

## Product Objective

A crypto customer should enable Edict once:

1. connect the account that will be the immutable customer-governance identity;
2. review the audited artifact hashes, signer policy and removal account;
3. approve one ordinary call to the version-fixed deployment factory;
4. retain the chain-verified deployment manifest and its `adapterRef`; and
5. continue through the ordinary `protectPayment()` API.

Edict may construct the call, sponsor gas, relay permissionless proofs, monitor
state and alert on failures. It never receives the customer's private key,
funds, withdrawal credential, contract key, MPC share or privileged method.

## Implemented NEAR topology

```text
immutable global Wasm hashes
  | settlement v1                         | factory v1
  v                                       v
keyless, adminless version factory  <-----+
  | create_instance(slug, customer config)
  | one customer-governance call; exact setup deposit only
  v
keyless customer settlement instance
  | combined immutable verifier + native-NEAR settlement
  | no owner, upgrade, pause, freeze, recovery or generic transfer method
  | permissionless proof relay and timeout calls
  v
claims paid only to pre-committed requester, worker or removal account
```

Relevant source:

- `crates/edict-settlement-common`: shared wire types and verifier-policy checks.
- `crates/edict-customer-settlement`: combined verifier and settlement state
  machine for native NEAR.
- `crates/edict-deployment-factory`: immutable-hash, adminless factory.
- `../../packages/near-deployer`: no-key plans and finalized-block verifier.
- `../../packages/near-intents`: implemented 1Click quote verification and
  signed Intents funding/payout plans for the preferred cross-chain profile.
- `scripts/check-production-wasm.sh`: Wasm action-import and export allowlists.
- `scripts/test-production-sandbox.sh`: real-Wasm global/factory/settlement run.

The factory creates only subaccounts beneath itself. It adds no access key and
has no method to update its global code hash. A new contract version therefore
requires a new audited global hash and a new keyless factory account. The old
factory and all existing customer instances remain unchanged.

## Cross-Chain Profile

Native-NEAR v1 remains a narrow fallback and independent audit target. It is
not the intended multi-chain product surface. The preferred profile uses NEAR
Intents for source-chain funding, wallet authentication, asset conversion and
beneficiary-controlled destination-chain withdrawal, while a separate keyless
Edict contract keeps the same bounded state machine and exact economics.

The transport layer is implemented in `@edict/near-intents`. It builds
`EXACT_OUTPUT` funding quotes, verifies official 1Click signatures and echoed
fields, creates signed `transfer`/`auth_call` plans and refuses the experimental
direct callback path. The matching Intents-aware settlement/factory,
deployment/runtime verifier and hash-pinned mainnet-Verifier sandbox are now
implemented. Independent audit, mainnet deployment and canary remain hard
gates. Passing the native-v1 audit will not satisfy them.

## Active-order invariants

At funding, the contract snapshots:

- order-mandate hash and Settlement Binding hash;
- requester, worker and native-NEAR principal;
- delivery deadline and acceptance, challenge and resolution windows;
- liveness fallback and permitted ruling kinds;
- opening Bond rate and pro-rata allocation formula; and
- the instance's immutable verifier-policy hash.

No account can change those fields afterward. The customer-governance account
has no generic withdrawal or mutation right. It acts only when an order has
pre-committed `controller_resolution` as its post-timeout fallback, and even
then it can choose only a pre-committed terminal branch.

V1 enforces the DRR's 2-24 hour challenge window and 5-10% opening Bond range.
Funding rejects a principal whose percentage Bond would round to zero atomic
units, so every accepted order retains a usable dispute path.
The USD 1 Bond floor, fees, appeals and any human-review Bond ladder remain
off-chain release gaps and must not be represented as on-chain features.

## Verifier policy

Every instance fixes 2-16 normalized ECDSA signer addresses, a distinct
operator ID and retained attestation hash for each signer, and a quorum of at
least two. Initialization fails unless:

- signer addresses and operator IDs are unique and canonically sorted;
- every attestation hash is nonzero;
- all Edict-controlled signers together are below quorum; and
- the quorum remains satisfiable after removing every Edict-controlled signer.

The contract counts distinct operators, recovers each signature over the
contract-recomputed execution digest, and consumes a nonce per order. Signer
admission cannot change after deployment. Losing the proof relayer does not
affect correctness: `submit_ruling` is permissionless.

The attestation hashes are immutable commitments, not an on-chain DCAP/NRAS
verifier. External review must confirm the retained quote, measurement and key
binding for every production signer before its configuration is approved.

## Settlement behavior

- Clean non-delivery timeout refunds the requester.
- Clean delivery acceptance or acceptance timeout releases to the worker.
- A dispute requires the exact pre-committed Bond.
- A conforming quorum ruling may select requester, worker, split or one redo,
  but only if that kind was pre-committed.
- A redo holds principal and the original Bond, records round 1, permits one
  new delivery, and cannot recur in round 2.
- A terminal ruling allocates principal by basis points. The disputant's Bond
  refund is pro rata to that party's awarded share; half the forfeited amount
  goes to the counterparty and every indivisible residual goes to the immutable
  removal account.
- Payouts become fixed-owner claims. Anyone may trigger withdrawal, but cannot
  redirect it. A failed transfer restores the exact claim in its callback.
- After resolution timeout, the signed fixed fallback is permissionless. A
  signed controller fallback requires customer governance and remains bounded.

The shared vectors in `SETTLEMENT_ECONOMICS_VECTORS.json` are asserted by both
the Rust contract and `@edict/sdk` using integer arithmetic.

## Deployment manifest

`@edict/near-deployer` verifies every fact against one finalized NEAR block and
emits a digest-bound manifest shaped as follows:

```json
{
  "version": "edict-customer-deployment-1",
  "chain": "near",
  "network": "mainnet",
  "settlementAccount": "acme.v1.factory.edict.near",
  "factoryAccount": "v1.factory.edict.near",
  "adapterRef": "near:acme.v1.factory.edict.near:edict-customer-settlement-v1",
  "contractVersion": "edict-customer-settlement-v1",
  "globalCodeSha256Hex": "<64 hex>",
  "globalCodeHashBase58": "<NEAR code hash>",
  "factoryCodeSha256Hex": "<64 hex>",
  "factoryCodeHashBase58": "<NEAR code hash>",
  "customerGovernance": "governance.customer.near",
  "removalAccount": "pool.customer.near",
  "verifierPolicySha256Hex": "<64 hex>",
  "settlementAccessKeys": [],
  "factoryAccessKeys": [],
  "edictAccessKeys": [],
  "immutable": true,
  "nativeNearOnly": true,
  "externalAuditStatus": "independent_audit_evidence_attached",
  "externalAuditEvidence": {
    "auditor": "<independent firm>",
    "reportUri": "https://...",
    "reportSha256Hex": "<64 hex>",
    "completedOn": "YYYY-MM-DD",
    "settlementCodeSha256Hex": "<same settlement hash>",
    "factoryCodeSha256Hex": "<same factory hash>"
  },
  "verifiedBlockHash": "<final block hash>",
  "verifiedBlockHeight": 0,
  "verifiedAtUnixMs": 0,
  "manifestSha256Hex": "<digest of every preceding fact>"
}
```

Without build-specific external-audit evidence, the status is
`required_before_customer_funds`. The SDK helper
`customerContractSettlementFromManifest()` rejects that status, non-mainnet
manifests, changed manifest digests, unexpected keys and audit/code mismatches.
This gate binds evidence to a build; it does not assess the auditor or cure
unresolved findings.

## Conformance evidence

The repository currently proves:

- exact cross-language execution digest and economic vectors;
- every terminal payout, pro-rata Bond branch and odd-unit residual;
- one held-Bond redo and complete two-round accounting;
- challenge and resolution clock enforcement;
- altered ruling/verdict signatures and nonce replay are rejected;
- independent signers can meet quorum without Edict and Edict cannot meet it;
- fixed fallback is permissionless and controller fallback is bounded;
- failed claim transfer restores the claim;
- duplicate factory slugs and non-customer deployment calls fail;
- production Wasm imports no key, account-delete, code-deploy, stake or generic
  administrative actions; and
- a local NEAR sandbox can publish the global artifact, create a keyless
  factory and child, settle with independent signatures, and withdraw a claim.

## Remaining production boundaries

1. Independent external contract and deployment-tool audit is mandatory.
2. No mainnet global artifacts, factory or customer instance exists yet.
3. This native settlement profile accepts native NEAR only. The preferred NEAR
   Intents path has separate
   implemented transport, settlement, factory and exact-Verifier test
   artifacts, but still requires independent audit, mainnet deployment and a
   capped canary. It must not reuse or relabel this artifact by assumption.
4. The fixed signer policy depends on off-chain attestation review and signer
   operations; automated quote admission is not implemented here.
5. Fees, USD Bond floors, appeals, human-review clocks and legal enforcement
   are not implemented by this contract.
6. Per-order storage collateral remains in the instance to retain immutable
   order, round and replay state. It is not an Edict fee and is not reclaimable
   in v1.
