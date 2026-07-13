# Production Readiness

Edict `v0.1.0-testnet` is an unaudited engineering release. It demonstrates
the complete native-NEAR protection path with test value; it is not approved
for production funds.

## Current Status

| Surface | Status |
|---|---|
| Canonical protection events and connector interface | Implemented and tested |
| Durable event recovery and encrypted evidence vault | Implemented and tested |
| Signed party actions with nonce and expiry protection | Implemented and tested |
| Native NEAR final-state observation | Implemented and exercised on testnet |
| NEAR Intents observation and signed-fact validation | Implemented and tested locally |
| Automatic deadlines and objective-failure checks | Implemented and tested |
| Multi-provider adjudication and proof verification | Implemented; production roster not deployed |
| Human-review routing | Implemented as an optional signed policy |
| Execution-signature collection | Implemented; production signer service not deployed |
| Verdict webhooks and permissionless relays | Implemented and tested |
| Native keyless settlement and factory | Deployed on NEAR Testnet |
| Intents keyless settlement and factory | Real-Wasm sandbox complete; not deployed |
| Confidential Intents | Capability gate implemented; live adapter unavailable |
| Mainnet release | Not deployed |

## Testnet Evidence

The native NEAR deployment consists of an adminless factory and a keyless
settlement instance:

- [`m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/m2.edict-req-ggrb91.testnet)
- [`protect.m2.edict-req-ggrb91.testnet`](https://testnet.nearblocks.io/address/protect.m2.edict-req-ggrb91.testnet)

Final-state verification found zero access keys on both accounts and the
expected immutable artifact hashes. Accepted and disputed flows, including
claim withdrawals, are recorded in
[`scripts/testnet/product-run.json`](../scripts/testnet/product-run.json).

The end-to-end runner uses deterministic test model seats and test-only
execution signer keys. Those components validate orchestration and contract
boundaries; they are not evidence of production operator independence or TEE
security.

## Mainnet Release Gates

1. Freeze reproducible settlement, factory, deployer, and upstream verifier
   artifacts.
2. Complete independent audits and remediate every release-blocking finding.
3. Deploy execution-signing services across independent operators. Each
   service must reconstruct the execution digest, verify the complete signed
   request, enforce its own policy, and keep its signing key in an approved
   TEE.
4. Establish production secrets management, backups, restore testing,
   monitoring, alerting, rate limits, retention controls, and incident
   response.
5. Qualify the exact production jury, prompts, provider roster, verifier
   policy, and signer policy against the private holdout and adversarial
   suites. Public example fixtures are not release evidence.
6. Publish mainnet manifests that bind the exact audited code and
   configuration.
7. Complete capped end-to-end canaries for native settlement and NEAR Intents,
   including challenge windows, proof relay, settlement, and withdrawal.
8. Obtain applicable legal, regulatory, tax, and data-protection advice.

## Confidential Intents Gates

Confidential settlement additionally requires:

- stable private-shard deployment and observation interfaces;
- independently verifiable capability and state evidence;
- audited selective disclosure and privacy-failure behavior;
- a private-shard canary using the exact settlement state machine; and
- fail-closed behavior unless an order explicitly permits a public fallback.

## Toolchain Note

`near-sdk 5.28.3` currently resolves `near-vm-runner 0.36.0`, which pins
`wasmparser 0.78.2`. The release builds, tests, and Clippy checks pass, but Rust
reports a future-incompatibility warning for that transitive crate. Upgrade
through the audited NEAR SDK dependency chain rather than patching the VM
parser independently.
