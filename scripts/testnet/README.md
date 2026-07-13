# Native NEAR Testnet Runner

These scripts deploy, verify, and run the current Edict Protect native-NEAR
testnet environment.

> The deployment is unaudited and uses test value. Model seats and execution
> signers are test-only.

## Public Manifests

- [`deployment.json`](deployment.json) records artifact hashes,
  deployment transactions, configuration, and access-key verification.
- [`product-run.json`](product-run.json) records completed accepted and disputed
  flows with explorer links.

## Accounts

| Role | Account |
|---|---|
| Customer and requester | `edict-req-ggrb91.testnet` |
| Worker | `edict-wrk-ggrb91.testnet` |
| Gas-only relayer | `edict-relay-ggrb91.testnet` |
| Adminless factory | [`m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/m2.edict-req-ggrb91.testnet) |
| Keyless settlement | [`protect.m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/protect.m2.edict-req-ggrb91.testnet) |

The factory and settlement accounts have zero access keys.

## Run the Product

From the repository root:

```sh
npm ci
npm run testnet:product
```

The command builds the workspace, compiles the testnet scripts, reconciles
saved state with final chain state, starts the Protection Runtime on port
`4890`, and starts the Edict Protect workspace on port `4885`.

The runner is restart-safe. Runtime events, encrypted evidence, API tokens,
test party keys, and test signer material are stored in the gitignored
`.credentials/runtime/` directory.

Set `NEAR_TESTNET_RPC_URL` to override the default final-state RPC endpoint.

## Deploy a Fresh Stack

The deployment command expects testnet account credentials under
`.credentials/` and the suffix in either `EDICT_TESTNET_SUFFIX` or
`.credentials/suffix.txt`.

```sh
npm run testnet:signers
npm run testnet:deploy
```

The deployer:

1. builds and hashes the native settlement and factory Wasm;
2. publishes the fixed settlement artifact;
3. creates the keyless factory;
4. creates the keyless customer settlement instance;
5. verifies code hashes, configuration, and access-key counts at finality; and
6. writes `deployment.json`.

Never commit `.credentials/` or reuse its keys outside this testnet
environment.

## NEAR Intents

NEAR Intents does not provide a testnet. The Intents contracts are exercised
against the pinned mainnet Verifier in a local real-Wasm sandbox:

```sh
contracts/near/scripts/test-intents-sandbox.sh
```

Cross-chain deployment requires an independent audit and capped mainnet
canary; it is not simulated by the native testnet runner.
