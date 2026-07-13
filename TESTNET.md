# Edict Testnet Preview

- **Release:** `v0.1.0-testnet`
- **Network:** NEAR Testnet
- **Status:** unaudited; test value only

Edict Protect has completed accepted and disputed native-NEAR payment flows
through the current keyless native settlement architecture. The committed
manifests provide the account, artifact, transaction, and final-state evidence
for those runs.

## Deployment

| Component | Account | Access keys |
|---|---|---:|
| Adminless factory | [`m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/m2.edict-req-ggrb91.testnet) | 0 |
| Keyless settlement | [`protect.m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/protect.m2.edict-req-ggrb91.testnet) | 0 |

Artifact hashes and deployment transactions are recorded in
[`scripts/testnet/deployment.json`](scripts/testnet/deployment.json).

## Verified Flows

### Accepted Payment

The worker delivered, the requester accepted, the contract credited the fixed
worker claim, and a permissionless relayer completed withdrawal.

- [Funding transaction](https://testnet.nearblocks.io/txns/6KZmRetrsjSgZ85KwnyxK92aR8fNPa6xzcfQTsPC88uM)
- [Delivery transaction](https://testnet.nearblocks.io/txns/Yv35FL8fSHU8mivwP783R4d99uBEPGx5eZgocJ1Foep)
- [Acceptance transaction](https://testnet.nearblocks.io/txns/13PfUZdzG8sFJKp2bpgrM82jLrQuGsyszYjb5ZjD74kL)
- [Claim withdrawal](https://testnet.nearblocks.io/txns/Dq7sJCbD8aJSCjR6x8jbAL5Ner6w6UYxT21jjGXV9Su3)

### Disputed Payment

The flow completed funding, delivery, a signed challenge and Bond, final-state
observation, adjudication, two-operator execution authorization, the challenge
hold, ruling submission, claim creation, and withdrawal.

- [Funding transaction](https://testnet.nearblocks.io/txns/ACvHhp66xp1jqZWEPpp6M18P38HPmUJrqesoFQ3zNrLg)
- [Delivery transaction](https://testnet.nearblocks.io/txns/GmGCErJ5gsotmkDTxfobeDrjLpLEj6B5FbhPNKt8PLTj)
- [Challenge transaction](https://testnet.nearblocks.io/txns/6RkeZrYR2N9Ws65HHTan7KsvaD7htKnuy1W98K9uHcYe)
- [Ruling transaction](https://testnet.nearblocks.io/txns/3hSukXVWQQnmXP2MLCoScWLGiBk7psVHQeCZvMva4NKy)
- [Claim withdrawal](https://testnet.nearblocks.io/txns/A8yMskugjiDgRJbUWwd2myvzwnFupTxBDtL5d4TFBn5B)

The complete public flow manifest is
[`scripts/testnet/product-run.json`](scripts/testnet/product-run.json).

## Capability Status

| Capability | Status |
|---|---|
| Native NEAR keyless settlement and factory | Deployed on NEAR Testnet |
| Persistent Protection Runtime | Implemented; run locally for this release |
| Signed party actions and encrypted evidence | Implemented |
| Automatic deadlines and objective checks | Implemented |
| Multi-model adjudication pipeline | Implemented; testnet product uses deterministic test seats |
| Independent execution-signature collection | Implemented; testnet product uses simulated operator keys |
| Permissionless settlement and claim relays | Implemented and exercised on testnet |
| NEAR Intents settlement | Real-Wasm local sandbox against the pinned mainnet Verifier |
| Confidential Intents | Signed capability gate implemented; live private-shard adapter unavailable |
| Mainnet contracts | Not deployed |

## Reproduce Locally

Build and test the repository:

```sh
npm ci
npm run check
npm run test:sandbox
```

Run the offline product demonstration:

```sh
npm run demo
```

Run the native NEAR testnet product with locally held testnet credentials:

```sh
npm run testnet:product
```

Credentials and test-only signer material are stored under the gitignored
`scripts/testnet/.credentials/` directory.

## Production Gates

Before any production-value deployment:

1. independently audit and remediate the exact settlement, factory, deployer,
   and pinned upstream assumptions;
2. deploy production execution-signing services across independent TEE
   operators;
3. complete operational security, key management, monitoring, recovery, data
   retention, and incident-response controls;
4. publish reproducible mainnet manifests for the audited artifacts;
5. complete capped native and Intents mainnet canaries; and
6. obtain applicable legal, regulatory, tax, and data-protection advice.

This repository and its testnet deployments do not represent an external
security audit or an assurance that customer funds are safe.
