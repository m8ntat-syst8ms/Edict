# @edict/near-intents

Pure, non-custodial transport plans for funding and paying an Edict-protected
transaction through NEAR Intents and the 1Click API.

This package does not hold funds, call a wallet, store a private key or submit
an intent. It constructs the exact payload a customer wallet or payment rail
signs and verifies the quote/status data returned by 1Click.

Funding builders reject principals whose percentage Bond would round to zero
atomic units, before a wallet is asked to sign an unusable order.

## Production flow

```text
source wallet on any supported chain
  -> 1Click EXACT_OUTPUT quote
  -> exact settlement asset in requester's Intents account
  -> requester-signed Transfer + mt_on_transfer notification
  -> customer-approved keyless Edict settlement account
  -> bounded requester / worker / split / redo state machine
  -> fixed claim in each beneficiary's Intents account
  -> beneficiary-signed 1Click withdrawal to any supported destination chain
```

The intermediate requester balance is intentional. The signed
`transfer`/`mt_on_transfer` pair atomically identifies the requester, exact
asset, exact amount and order message. Sending a 1Click quote directly to an
Edict account would credit an aggregate balance without safely assigning it to
an order.

The package rejects 1Click's `customRecipientMsg` shortcut. The current 1Click
OpenAPI marks that field **highly experimental** and warns that misuse can lose
funds. It is not part of Edict's production release profile.

## Example

```ts
import {
  buildProtectionFundingQuote,
  buildProtectionFundingTransfer,
  nearIntentsRoute,
  nearIntentsSettlementBinding,
} from '@edict/near-intents';

const route = nearIntentsRoute({
  settlementAccount: 'protect.acme.near',
  settlementAsset: 'nep141:base-usdc.omft.near',
  removalIntentsAccount: 'pool.acme.near',
});

const settlement = nearIntentsSettlementBinding(route);
const quoteRequest = buildProtectionFundingQuote({
  originAsset: 'nep141:sol-usdc.omft.near',
  settlementAsset: route.settlementAsset,
  principalAtomic: '25000000',
  requesterIntentsAccount: 'requester.near',
  source: { kind: 'origin_chain', refundTo: '<requester source-chain address>' },
  deadline: new Date(Date.now() + 5 * 60_000).toISOString(),
});
```

`assertSignedProtectionFundingQuote()` uses the official 1Click SDK signature
verifier and then compares every echoed quote field with the locally built
request. `verifiedFundingReceipt()` additionally requires terminal `SUCCESS`
and the exact output amount. `assertSignedClaimPayoutQuote()` applies the same
tamper check before a beneficiary signs its destination-chain withdrawal.

## Confidential Intents Profile

Commercially sensitive orders can use
`confidentialIntentsSettlementBinding(capability)` only after the complete
private-settlement release gate passes. Unlike confidential
transport into a public account, this mode requires the customer-approved
keyless Edict settlement state machine itself to execute on the Confidential
Intents private shard with a commitments-only public record.

The helper checks the exact capability digest, provider interface, settlement
code, validator and bridge policies, disclosure policy/receipt schema, empty
access-key sets, customer approval, immutable active orders, matching
independent-audit scope and a passed canary. It then signs
`confidential_settlement`, the capability/disclosure hashes and a
`fail_closed` privacy fallback into the `SettlementBinding`.

It is not a live adapter. NEAR's public materials do not currently expose the
stable private-shard technical interface required to submit and independently
verify this flow. See
[`CONFIDENTIAL_INTENTS_PROFILE.md`](../../contracts/near/CONFIDENTIAL_INTENTS_PROFILE.md).

## Release Status

The TypeScript layer and corresponding keyless Intents settlement/factory are
implemented and tested, including strict Wasm allowlists, deployment/runtime
verification and a sandbox against one exact hash-pinned `intents.near` mainnet
Wasm. Independent audit, mainnet deployment and a small-value canary are not
complete. NEAR Intents has no testnet. The existing native-NEAR Edict contract
is a separate artifact and must not be represented as this Intents adapter.
The Confidential Intents capability gate is implemented and tested, but its
private-shard adapter, provider verifier, external audit and canary remain
pending and must not be represented as available.
