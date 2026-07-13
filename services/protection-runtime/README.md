# Edict Protect Runtime

`@edict/protection-runtime` is the hosted coordination layer for Edict Protect.
It observes protected payments, schedules objective deadlines, verifies signed
party actions and evidence, runs the multi-provider arbiter, publishes signed
webhooks and prepares settlement relay plans.

It is deliberately **not** a wallet, escrow or custodian:

- no customer private key enters the service;
- timeout and claim calls are permissionless and contract-revalidated;
- a dispute Bond is relayed only from a party-signed Intents payload;
- a ruling is relayable only after the immutable contract signer quorum signs
  the exact order, case, round, ruling, verdict, timestamp, policy and nonce;
- the verifier policy must remain satisfiable without every Edict-controlled
  signer, and Edict-controlled signers cannot form a quorum;
- payout recipients are fixed by the customer-owned contract.

## Runtime Loop

```text
SDK registration
  -> append-only ProtectionEvent stream
  -> final NEAR Intents state observation
  -> signed evidence + deadline scheduler
  -> deterministic checks / independent model jury
  -> execution-signature quorum
  -> challenge-window relay plan
  -> contract settlement + fixed-owner claim withdrawal
```

The JSONL event store fsyncs every append. Event identity excludes observation
time, so a repeated final-state poll is idempotent across process restarts. The
file evidence vault uses AES-256-GCM with a process-injected key and binds each
ciphertext to its content hash as associated data.

## Integration

The rail uses `@edict/sdk` to create the signed mandate and this package's
small HTTP client to register it:

```ts
const edict = createEdict({ mode: 'live', settlement });
const protect = new ProtectionRuntimeHttpClient({ baseUrl, apiToken });
const payment = await edict.protectPayment(input);
await protect.protect(payment, { profile: edict.profile, intents, integrationRef: 'rail:acme' });
```

The `intents` registration binds the exact settlement account, asset, party
Intents identities, principal, challenge clock, resolution timeout and
immutable verifier policy. The connector refuses final chain state that does
not match those signed facts. Current public Intents registrations normalize
settlement to `nep141:usdc.omft.near`: the signed mandate asset is `USDC` and
the principal must equal its USD value in micro-USDC. Source and destination
assets may still differ through 1Click.

## Signed Party API

`POST /v1/protections/:id/actions` accepts the canonical
`edict-protect-signed-action-1` envelope for:

- `approve_protection`
- `attach_evidence`
- `open_challenge`

Built-in verification supports EIP-191 and raw Ed25519. Named NEAR accounts,
passkeys or venue-native credentials use an injected `SignedActionVerifier`.
Every message carries an issued time, expiry and one-time nonce. An API bearer
token authenticates the integration; it never substitutes for a party
signature. The envelope and action payloads are closed-schema, and concurrent
reuse of one nonce is rejected before either action can race the event store.

Verdict webhooks use canonical JSON and HMAC-SHA256. Every target and attempt
is recorded in the protection stream; failed delivery uses durable exponential
backoff across ticks and process restarts. Consumers must deduplicate on the
`x-edict-event-id` header because a crash between remote acceptance and the
local delivery record can produce an at-least-once retry.

## Connector Contract

All rails implement `ProtectionConnector` and emit the same canonical
`ProtectionEvent` vocabulary. The shipped `NearIntentsConnector` polls final
contract views and observes funding, delivery, challenge, redo, settlement and
claim state. Stable source ids make repeated polls harmless. An indexer can
provide lower latency without changing runtime semantics.

## Automation Boundary

Clean non-delivery and acceptance timeouts call the contract's permissionless
`claim_timeout`. Objective manifest failures automatically open a dispute only
when the requester pre-signed the exact single-use Bond intent; otherwise the
runtime creates one `party_signature` attention item. This is intentional: an
autonomous service that could post arbitrary customer Bonds would have regained
the custody authority the architecture removes.

## Run

```sh
npm run build -w @edict/protection-runtime
export EDICT_EVIDENCE_KEY_HEX='<64 lowercase hex characters>'
export EDICT_RUNTIME_API_TOKEN='<long random bearer token>'
node services/protection-runtime/dist/cli.js --port 4890
```

Production requires `EDICT_EVIDENCE_KEY_HEX` and
`EDICT_RUNTIME_API_TOKEN`. Configure provider keys, independent execution
signer endpoints and a gas-only relayer through the variables documented in
`.env.example`; the CLI reads the process environment and does not load a
`.env` file implicitly. It polls continuously; the HTTP endpoints also expose
manual `/v1/connectors/poll` and `/v1/tick` triggers for operations.

## Production Gates

The runtime code is implemented and tested, but production value must not use
the Intents settlement path until the exact contract/factory/upstream Verifier
scope has an independent audit, mainnet deployment manifest and capped canary.
The repository also does not yet ship the production execution-signer service:
it ships the HTTPS collector and strict request/digest/policy validators, while
the native NEAR testnet product uses in-process demo keys. Independent TEE signer
implementation, audit and operator deployment are mandatory release gates.
Confidential Intents additionally requires a stable private-shard interface,
audited capability evidence and privacy canary.
