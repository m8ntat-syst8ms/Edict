# @edict/near-deployer

No-key deployment planning and finalized-block verification for Edict's
native-NEAR and NEAR Intents customer settlement lines.

This package never accepts or loads a private key. It emits action plans for a
wallet/DAO to approve and verifies deployed chain state afterward. Its CLI has
no credential argument.

## Flows

- `identifyWasm`: SHA-256 hex and NEAR base58 code hash.
- `buildGlobalContractPublishPlan`: content-addressed global publication.
- `buildFactoryBootstrapPlan`: one atomic keyless factory creation.
- `buildFactoryDeploymentPlan`: the normal one-call customer setup path.
- `buildDirectDeploymentPlan`: optional customer-parent action batch.
- `verifySettlementDeployment`: one-final-block checks for both code hashes,
  zero settlement/factory keys, exact immutable config and active factory
  record; returns a digest-bound manifest.
- `buildIntentsDirectDeploymentPlan` / `buildIntentsFactoryDeploymentPlan`:
  mainnet-only keyless plans that pin `intents.near`, one asset and capacity.
- `verifyIntentsSettlementDeployment`: additionally pins the upstream Verifier
  code hash, predecessor auth, account-lock and critical pause state.
- `verifyIntentsRuntime`: repeats mutable upstream checks immediately before
  funding and fails closed on code, auth, lock or pause drift.

`externalAuditStatus` remains `required_before_customer_funds` unless evidence
for the exact settlement and factory hashes is attached. Intents evidence must
also identify the exact upstream Verifier hash reviewed. The production SDK
helpers reject the former status. That is a release gate, not a claim that the
package can judge an auditor or determine whether findings are resolved.

## CLI

```sh
npm run build -w @edict/near-deployer
node packages/near-deployer/dist/cli.js --help
```

See `contracts/near/PRODUCTION_RUNBOOK.md` for the ordered release procedure.

## Boundary

Both artifact lines remain unaudited and are not deployed on mainnet. Abstract plans must be
translated by a reviewed NEAR wallet/transaction adapter. Edict may provide
that UI and sponsor gas, but transaction signing remains in the customer's
wallet or governance contract. An upstream runtime preflight reduces, but
cannot eliminate, the liveness risk of later Intents governance action.
