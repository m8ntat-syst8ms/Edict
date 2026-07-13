# Edict Protect

Edict is the protocol and product family. **Edict Protect** is the core product:
autonomous, non-custodial protection for an agent payment from signed promise
through evidence, resolution and settlement.

## What the Customer Integrates

A payment rail, marketplace or compute/API platform integrates once. The
platform already knows the parties, payment amount, task promise and delivery
context; Protect turns those facts into a signed order mandate. The requester
approves when funding and the worker approves when accepting the task or
submitting delivery. Neither party needs a separate Edict account.

The primary customer surface has three concepts:

1. **One-time setup** — approve the customer-owned settlement contract and
   connect payment/delivery events.
2. **Activity** — every protected transaction and its current state.
3. **Needs attention** — the small set requiring a party signature, missing
   evidence, connector repair or elected human review.

## Step by Step

1. The rail calls `protectPayment` with the two party references, promise,
   amount and deadline. Its default Standard policy is wallet-native E0 and
   requires no Edict KYB.
2. The SDK creates `edict-om-2`: acceptance criteria, possible outcomes,
   deadlines, Legal Policy, challenge window and an explicit non-custodial
   settlement binding. The linter blocks materially ambiguous or invalid
   terms before funding.
3. The rail registers the immutable protection with the Protection Runtime. The
   append-only event record contains the mandate, profile and their hashes;
   submitted evidence plaintext is stored separately in the encrypted vault.
   This testnet-preview runtime is not a confidential-metadata store.
4. The selected connector observes funding and verifies final state against
   the exact registered parties, principal, asset, settlement hash, clocks,
   and verifier policy. The native NEAR testnet deployment uses native NEAR. The
   public Intents adapter normalizes settlement to `nep141:usdc.omft.near` and
   requires `principalAtomic` to equal the signed USD value in micro-USDC.
5. The worker submits a canonical delivery manifest. Its signature identifies
   the worker; artifact hashes and format claims stay sealed while their
   commitments enter the event stream.
6. If the delivery deadline passes, anyone may relay `claim_timeout`; the
   contract refunds the fixed requester account. If delivery is accepted or
   its review window expires cleanly, the contract credits the fixed worker
   account.
7. A deterministic failure is evaluated from authenticated evidence. If a
   pre-signed single-use Bond intent exists, Protect relays it automatically.
   Otherwise Needs attention asks the requester for exactly one wallet
   signature. Edict never receives general spend authority.
8. A challenged case is assembled from the signed mandate, delivery commitment
   and party evidence. Clear machine-check outcomes short-circuit. Ambiguous
   cases run through multiple model families and infrastructure operators in
   both party orientations; proof, swap and confidence gates exclude unsafe
   votes or hold the case.
9. The Protection Profile decides whether an uncertain or high-value result is
   final, appealable or routed to human review. Human escalation remains a
   toggle rather than a mandatory core workflow.
10. The production design has independently operated signer nodes reconstruct
    the exact `EDICT_SETTLEMENT_V1` digest and sign only if the decision is
    executable. Edict-controlled signers cannot satisfy quorum alone. The
    runtime collector and full-request validators are implemented; native testnet
    currently demonstrates this step with in-process test-only operators, so a
    real TEE signer service remains a release gate.
11. After the signed challenge window, any relayer may submit the proof. The
    contract independently checks order, case, round, permitted ruling,
    verdict hash, issued time, policy, nonce and quorum before allocating value.
12. Settlement creates claims for fixed party Intents accounts. Anyone may pay
    gas to trigger withdrawal, but cannot change the beneficiary. Parties then
    use Intents for their chosen destination chain.

## Additional Layers

The core path is wallet-native or rail-verified E0. Optional enterprise layers
add named legal principals, KYB references, delegated agent authority,
customer policy packs, E1/E2/E3 enforcement, human benches and selective legal
disclosure. They do not make the base payment-protection integration heavier.

Confidential Intents is a separate capability-gated profile. It is not active
merely because transport is private: the settlement state machine itself must
run in the audited private-shard boundary, with commitments-only public state
and a fail-closed privacy fallback.
