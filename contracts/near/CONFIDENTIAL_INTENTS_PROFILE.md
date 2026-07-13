# Confidential Intents Settlement Profile

Status: **integration contract implemented; private-shard adapter not yet
operational**. The signed Edict schema, capability digest, audit/canary release
gate and SDK binding helper exist in `@edict/near-intents`. NEAR's public
materials describe Confidential Intents and its private shard, but do not yet
publish the stable RPC, contract deployment, bridge-attestation or
selective-disclosure interfaces needed to build and independently verify the
live adapter. No customer funds may use this profile until those interfaces
are supplied, audited and canary-tested.

## Product decision

Confidential Intents should be Edict's preferred crypto mode for commercially
sensitive or high-value agent payments once the release gates below pass.
Standard public Intents remains the simple default while the private-shard
interface is unavailable.

Privacy is selected once in a customer settlement policy, not configured on
every transaction. Once the release gate passes, the product control can offer:

- **Standard settlement**: public Intents settlement, available after its own
  audit and canary gates pass; and
- **Confidential settlement**: private-shard execution with selective
  disclosure, shown only when a verified capability is installed.

The confidential option defaults to `fail_closed`. It must never fall back to
public settlement unless both parties signed `allow_public_settlement` before
funding.

## The important distinction

Confidential transport is not the same as confidential settlement.

| Mode | Hidden from the public chain | What may still be public |
|---|---|---|
| `public` | Sealed Edict evidence only | Settlement parties, asset, amount, state and payout |
| `confidential_transport` | Source route and some transfer metadata | A public Edict contract can still expose parties, amount and outcome |
| `confidential_settlement` | Transport and Edict settlement state/transition | Only policy-authorized commitments or disclosures |

Edict may claim **confidential settlement** only when its customer-approved,
keyless settlement state machine itself executes on the Confidential Intents
private shard. Routing funds privately into the current public `intents.near`
contract is a useful transport property, but it is not end-to-end payment
confidentiality.

## Target architecture

```text
source wallet or agent treasury
  -> Confidential Intents deposit / private-shard bridge
  -> requester private Intents balance
  -> requester-authorized exact funding action
  -> customer-approved keyless Edict settlement on the private shard
  -> private delivery, dispute and fixed-branch accounting
  -> fixed private requester / worker / removal claims
  -> beneficiary-authorized private balance or cross-chain withdrawal
  -> policy-authorized selective-disclosure receipt or public commitment
```

Confidential Intents supplies private execution, routing and cross-chain
transport. Edict supplies the bounded order state machine and verified ruling.
Neither layer may replace the other's decision. Edict receives no wallet key,
private-shard key, bridge credential, validator credential, access key,
upgrade key or withdrawal authority.

## Signed order boundary

`SettlementBinding.confidentiality` is omitted for public settlement. A
confidential order signs all four fields below through both EIP-712 and
NEP-413:

```ts
{
  mode: 'confidential_transport' | 'confidential_settlement',
  capabilitySha256: '<exact verified capability record>',
  disclosurePolicySha256: '<exact selective-disclosure policy>',
  fallback: 'fail_closed' | 'allow_public_settlement',
  publicFallbackAdapterRef?: '<required only for a public fallback>'
}
```

The flattened wallet payload also writes an explicit `public` mode and zero
hashes when the object is absent. A verifier can therefore distinguish public,
transport-private and settlement-private orders without interpreting UI copy.
When public fallback is allowed, it also signs the exact alternate adapter;
without that reference the binding is invalid.

`confidentialIntentsSettlementBinding()` accepts only a
`ConfidentialIntentsCapability` whose digest is valid and whose evidence shows:

- a provider-issued private-shard network and Intents interface;
- customer-approved keyless settlement code and immutable active orders;
- no settlement or Edict access keys;
- public output limited to commitments;
- pinned provider-interface, validator-policy, bridge-attestation,
  disclosure-policy and disclosure-receipt-schema hashes;
- independent audit evidence covering that exact custody/privacy scope; and
- a passed private-shard mainnet canary with a content-addressed receipt.

The helper constructs data only. It cannot submit an intent, sign for a party
or prove that supplied evidence is truthful. Production onboarding must obtain
the capability record from the provider/integrator and independently verify it.

## Selective disclosure

The disclosure policy must state, at minimum:

- which fields are private, committed publicly or discloseable;
- who may view each field: parties, customer, Edict tribunal seats, human
  reviewer, auditor, regulator, court or no one;
- the purpose and legal basis for each disclosure;
- retention, deletion and cross-border-transfer rules;
- how a disclosure is authorized and logged;
- the receipt schema used to prove what was disclosed; and
- mandatory-law and enforcement exceptions.

Confidential settlement is not a promise of absolute anonymity. Depending on
the final provider architecture, private-shard validators, TEE bridge
operators, solvers, the parties, the customer and authorized adjudicators may
see some transaction data. Those roles and their visibility must be disclosed
before signature.

Edict evidence confidentiality is a separate boundary. Confidential Intents
can hide payment and settlement metadata from the public chain; it does not by
itself hide evidence from the models, TEE operators, Human Bench or other
viewers authorized by the Edict evidence policy.

## Failure semantics

1. Before a protected order is funded, the Confidential Intents deposit,
   quote, expiry and refund policy governs.
2. After funding, the signed Edict challenge clock, resolution timeout and
   liveness fallback govern inside the private settlement state machine.
3. If the confidential service is unavailable, `fail_closed` leaves the
   transaction on its pre-committed private refund/timeout path. No component
   may publish it merely to improve availability.
4. `allow_public_settlement` is valid only when signed before funding and when
   the public adapter, destinations and consequences were also disclosed.
5. An outage, privacy degradation or missing attestation must not turn an
   advisory Edict verdict into an executable decision.

## Additional trust boundaries

This profile remains non-custodial for Edict, but adds external dependencies:

- the private-shard validator set and permissioning policy;
- TEE hardware, measured software and attestation verification;
- the bridge between the private shard, NEAR mainnet and destination chains;
- solver visibility, liquidity and routing behavior;
- provider governance, upgrades, pauses, incident response and data access;
- selective-disclosure key management and receipt integrity; and
- availability of an independent audit path despite private execution.

These dependencies can affect privacy, availability and transport. They must
not be able to select an Edict ruling or give Edict custody authority.

## Release gates

1. Obtain a versioned provider technical specification or partner interface
   covering network identity, transaction format, contract execution and RPC.
2. Confirm that customer-approved keyless Edict contracts can run on the
   private shard, or obtain an equivalently constrained provider primitive.
3. Define and test private deposit, exact funding, refund, fixed-beneficiary
   claim and cross-chain withdrawal flows.
4. Verify validator-set policy, TEE measurements, bridge attestations,
   governance, upgrades, pauses and incident behavior.
5. Freeze the selective-disclosure policy and machine-verifiable receipt
   schema; prove that the public record is commitments-only.
6. Build a provider-specific verifier that creates the capability record from
   observed state rather than operator assertions.
7. Obtain an independent external audit covering the exact provider interface,
   Edict settlement artifact, custody separation, privacy leakage and failure
   semantics.
8. Run a capped private-shard mainnet canary and bind its receipt into the
   final capability record.
9. Enable the UX option only after all preceding evidence is installed and
   re-check mutable provider health immediately before funding.

Until those gates pass, the SDK correctly refuses to create a confidential
production binding. This is an implemented readiness boundary, not a claim
that Confidential Intents integration is live.

## Primary references

- [NEAR Intents: Confidential Intents](https://intents.near.org/confidential)
- [NEAR AI: private USDC payments for the agentic economy](https://near.ai/blog/near-ai-brings-private-usdc-payments-to-the-agentic-economy)
- [NEAR Intents documentation](https://docs.near-intents.org/getting-started/what-are-intents)
