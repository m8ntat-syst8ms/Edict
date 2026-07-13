# NEAR Intents Cross-Chain Settlement Profile

Status: transport SDK, separate keyless settlement/factory, Wasm allowlists,
deployment/runtime verification and exact pinned-Verifier sandbox are
implemented and locally tested. Independent audit, mainnet publication,
customer deployment and capped canary remain pending. This is not evidence
that customer funds are ready for use.

## Decision

NEAR Intents is Edict's preferred crypto transport layer. It supplies
cross-chain deposits, asset conversion, wallet-standard authentication and
destination-chain withdrawals. It does not decide disputes and must never be
able to replace an Edict ruling.

Edict's customer-approved, keyless settlement account remains responsible for:

- binding an exact asset and amount to one signed order;
- enforcing delivery, acceptance, challenge and resolution clocks;
- verifying the immutable independent-operator ruling quorum;
- enforcing requester, worker, split or one-redo branches;
- calculating principal and Bond allocations exactly; and
- releasing claims only to the pre-committed beneficiary Intents accounts.

Edict receives no wallet key, Intents signing key, 1Click API credential,
solver credential, bridge credential, access key, owner key or upgrade key.

This document specifies the **public Intents** profile. Confidential Intents
is a separate private-shard profile. Private routing into this public
settlement account does not hide the account's order state, parties, amount or
allocation and must not be sold as end-to-end confidential settlement. See
[`CONFIDENTIAL_INTENTS_PROFILE.md`](./CONFIDENTIAL_INTENTS_PROFILE.md).

## Customer flow

1. The customer deploys one audited, keyless settlement instance through a
   version-fixed factory. Its configuration pins `intents.near`, one
   allowlisted settlement asset, removal Intents identity and verifier policy.
   Each signed order separately pins its requester, worker and normal clocks.
2. For each payment, `@edict/near-intents` requests a 1Click `EXACT_OUTPUT`
   quote. The source may be any supported chain/asset. The exact output lands
   in the requester's Intents account; `refundTo` remains requester-controlled.
3. The SDK verifies the official quote signature, complete request echo,
   destination account, asset, amount and deposit address before the wallet
   sends funds.
4. A successful 1Click status proves transport into the requester balance. It
   does not by itself fund an Edict order.
5. The requester signs one Intents `transfer` for the exact settlement asset
   and amount. Its notification calls `mt_on_transfer` on the keyless
   settlement instance with the order-mandate and Settlement Binding hashes.
6. The contract accepts only calls from its immutable `intents.near` account,
   exactly one allowlisted token, matching sender/previous owner, an unused
   order hash and a byte-exact funding message. A failed callback refunds the
   Intents transfer through the Verifier resolver. Funding also rejects a
   principal whose percentage Bond rounds to zero atomic units.
7. Delivery and acceptance use Verifier-authenticated `auth_call` messages so
   NEP-413, ERC-191 and other supported wallet identities use one role model.
8. The first dispute transfers the exact same-asset Bond with another
   `mt_on_transfer` notification. A redo holds that Bond; the second-round
   dispute uses authenticated `auth_call` and cannot charge it again.
9. Any relayer may submit the signed ruling proof or invoke a fixed timeout.
   Relaying creates no settlement authority.
10. A terminal outcome creates fixed claims for requester, worker and removal
    identities. Anyone may trigger transfer to those identities, but no caller
    can supply or change a destination.
11. A beneficiary may leave the asset in Intents or sign a 1Click
    `INTENTS -> DESTINATION_CHAIN` quote to receive any supported asset/address.
    Edict never signs that withdrawal.

For an end user this is presented as **Fund & protect**, then **Claim**. A rail
that already holds Intents balances can perform both signatures under its own
existing customer mandate without adding an Edict-operated service.

The source-chain transfer and the subsequent Intents transfer are two logical
authorizations. A wallet or rail may safely batch or pre-authorize them, but
the product must not claim one universal prompt while that depends on the
origin wallet. The experimental direct callback is not an acceptable shortcut.

## Required contract interface

The Intents contract artifact must be separate from native-NEAR v1 and expose
only the following behavioral surface:

- `new(config)` with immutable Intents contract, settlement token, verifier
  policy, governance identity, removal identity and storage-capacity limit;
- `mt_on_transfer(...)` for `fund` and first-round `open_dispute` only;
- `on_auth(signer_id, msg)` for delivery, acceptance and held-Bond round two;
- permissionless clean timeouts, proof submission and fixed fallback;
- bounded controller fallback only when pre-committed;
- views for config, order, rounds, claims, nonce use and accounting; and
- permissionless fixed-beneficiary claim transfer with failed-call recovery.

It must have no owner, access key, upgrade, pause, freeze, token allowlist
mutation, signer admission, arbitrary transfer, destination override or
generic promise method. The instance's Intents predecessor authentication must
remain enabled; deployment verification must check that fact at a finalized
block.

## Stable and experimental paths

Production funding uses the Verifier's signed `transfer` plus
`mt_on_transfer`. This gives the settlement contract an authenticated sender
and an atomic refund path.

1Click's `customRecipientMsg` can request `ft_transfer_call` during a NEAR
withdrawal, but the current OpenAPI marks it highly experimental and warns of
fund loss for unsupported tokens, missing storage or missing receiver logic.
Edict therefore sets `directOneClickCallback: false` and rejects any quote that
contains the field. It may be reconsidered only after the upstream interface
is stable and a new audit covers the exact direct-deposit path.

## New trust dependencies

The Intents route removes chain-by-chain Edict adapters, but adds dependencies
that must be disclosed and monitored:

- the deployed `intents.near` Verifier code, roles, pause/upgrade controls and
  predecessor-auth behavior;
- 1Click availability and signed quote/status correctness;
- solver liquidity, slippage and completion latency;
- each origin/destination bridge and token contract; and
- supported-asset metadata and decimal correctness.

These parties cannot choose an Edict ruling, but they can delay, pause, refund
or fail transport. The signed order fallback applies only after funds have
entered the Edict settlement state machine; quote expiry/refund rules govern
the earlier transport stage.

## Release gates

1. **Done locally:** build the separate keyless Intents settlement and
   version-fixed factory.
2. **Done locally:** unit-test state/economic/proof branches, callback recovery,
   spoofed predecessor, amount/version mismatch and factory races.
3. **Done locally:** run the production path against a hash-pinned mainnet
   Verifier Wasm, including signed transfer, resolver refund, `auth_call`,
   fixed claim transfer and keyless global-hash factory deployment.
4. **Candidate frozen:** reproducible settlement/factory hashes and strict
   import/export allowlists are recorded in `INTENTS_AUDIT_SCOPE.md`.
5. **Pending:** obtain an independent audit covering Edict artifacts and their assumptions
   about the pinned Verifier release.
6. **Pending on deployment:** verify zero access keys, exact code/config,
   upstream code hash, predecessor auth, lock and pause state at one finalized
   mainnet block.
7. **Pending:** run a capped small-value mainnet canary because NEAR Intents has no testnet.
8. **Pending:** publish the manifest, audit evidence, supported asset list, limits, incident
   response and rollback-to-new-orders procedure before customer value.

Native-NEAR v1 remains independently auditable as a narrow fallback. Passing
its audit does not authorize this cross-chain profile, and vice versa.
