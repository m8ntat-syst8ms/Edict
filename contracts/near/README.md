# Edict NEAR Contracts

This workspace contains the customer-approved settlement and deployment
contracts for Edict Protect.

> **Testnet only:** these contracts have not completed an independent external
> audit and are not deployed on mainnet. Do not use them with production
> value.

## Contract Lines

### Native NEAR

| Crate | Purpose |
|---|---|
| `edict-settlement-common` | Shared verifier-policy validation and economics |
| `edict-customer-settlement` | Keyless native-NEAR protection and claims |
| `edict-deployment-factory` | Adminless factory for immutable customer instances |

### NEAR Intents

| Crate | Purpose |
|---|---|
| `edict-intents-settlement-common` | Intents asset and capacity validation |
| `edict-customer-settlement-intents` | One-asset Intents settlement and fixed-owner claims |
| `edict-intents-deployment-factory` | Adminless factory for Intents instances |

`edict-global-publisher-test` is used only by the local NEAR sandbox to verify
global-contract publication and deployment behavior.

## Security Model

Each customer settlement instance is initialized with immutable:

- requester and worker accounts;
- principal and settlement asset;
- delivery, acceptance, challenge, and resolution clocks;
- Decision Space and Bond rate;
- verifier-policy hash and independent signer policy;
- removal account; and
- liveness fallback.

After initialization the production profile has no access keys, owner,
upgrade method, pause right, freeze right, or arbitrary withdrawal path.

Edict-controlled signers are explicitly insufficient and unnecessary for
quorum. The contract checks that quorum remains satisfiable after excluding
every Edict-controlled signer.

## Settlement Flow

1. The requester funds the exact signed principal and storage reserve.
2. The worker records delivery before the deadline.
3. The requester accepts, the review window expires, or a signed challenge
   opens a dispute and posts the exact Bond.
4. A final ruling is bound to `EDICT_SETTLEMENT_V1` and signed by the configured
   independent quorum.
5. After the challenge window, any account may relay the proof.
6. The contract revalidates every commitment and creates claims for fixed
   beneficiaries.
7. Any account may pay gas to trigger a claim transfer, but cannot change its
   owner.

The contract supports `requester_wins`, `worker_wins`, pro-rata `split`, and
one `redo` round. Principal and Bond arithmetic is checked for conservation
across the full `u128` range.

## Native Testnet Deployment

| Component | Account |
|---|---|
| Factory | [`m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/m2.edict-req-ggrb91.testnet) |
| Settlement | [`protect.m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/protect.m2.edict-req-ggrb91.testnet) |

Both accounts have zero access keys. Artifact hashes and deployment evidence
are recorded in
[`../../scripts/testnet/deployment.json`](../../scripts/testnet/deployment.json).

## NEAR Intents

The Intents contract accepts one pinned NEP-141 settlement asset through the
authenticated Intents callback surface. It enforces exact amount and asset
binding, fixed party Intents identities, claim capacity, and the same ruling,
Bond, redo, and signer-policy constraints as native settlement.

The local sandbox deploys the exact pinned mainnet Verifier Wasm and exercises
funding, authenticated actions, refunds, payouts, and keyless factory
creation. NEAR Intents does not provide a testnet, so an audited low-value
mainnet canary remains a separate release gate.

## Build and Test

```sh
cd contracts/near
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Run the real-Wasm sandboxes from the repository root:

```sh
npm run test:sandbox
```

Build and validate release Wasm:

```sh
contracts/near/scripts/check-production-wasm.sh
contracts/near/scripts/check-intents-production-wasm.sh
```

## Release Documentation

- [Native audit scope](AUDIT_SCOPE.md)
- [Intents audit scope](INTENTS_AUDIT_SCOPE.md)
- [Customer deployment profile](CUSTOMER_DEPLOYMENT_SPEC.md)
- [Intents settlement profile](INTENTS_SETTLEMENT_SPEC.md)
- [Confidential Intents profile](CONFIDENTIAL_INTENTS_PROFILE.md)
- [Production runbook](PRODUCTION_RUNBOOK.md)
- [Execution digest vector](SETTLEMENT_EXECUTION_DIGEST_VECTOR.md)

The audit scopes record candidate hashes for reproducibility. They are not an
audit report or approval to deploy production funds.
