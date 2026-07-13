import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import bs58 from 'bs58';
import {
  GetExecutionStatusResponse,
  quoteHash,
  type QuoteResponse,
} from '@defuse-protocol/one-click-sdk-typescript';
import {
  acceptAction,
  assertSignedClaimPayoutQuote,
  assertSignedProtectionFundingQuote,
  buildClaimPayoutQuote,
  buildDisputeBondTransfer,
  buildPartyAuthCall,
  buildProtectionFundingQuote,
  buildProtectionFundingTransfer,
  controllerFallbackAction,
  deliverAction,
  disputeBondAtomic,
  nearIntentsAdapterRef,
  nearIntentsRoute,
  nearIntentsRouteDigest,
  nearIntentsSettlementBinding,
  verifiedFundingReceipt,
  type NearIntentsRoute,
  type OneClickExecutionStatus,
} from './index.js';

const HASH_A = '11'.repeat(32);
const HASH_B = '22'.repeat(32);
const USDC_BASE = 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near';
const USDC_SOL = 'nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near';

function route(): NearIntentsRoute {
  return nearIntentsRoute({
    settlementAccount: 'protect.customer.near',
    settlementAsset: USDC_BASE,
    removalIntentsAccount: 'pool.customer.near',
  });
}

function fundingQuote() {
  return buildProtectionFundingQuote({
    originAsset: USDC_SOL,
    settlementAsset: USDC_BASE,
    principalAtomic: '25000000',
    requesterIntentsAccount: 'requester.near',
    source: { kind: 'origin_chain', refundTo: '7YWHMfk9JZe0LM0g1uMZVw' },
    deadline: '2030-01-01T00:05:00.000Z',
  });
}

function signQuote(response: QuoteResponse): { response: QuoteResponse; publicKey: string } {
  const keys = generateKeyPairSync('ed25519');
  const message = Buffer.from(quoteHash(response));
  const signature = sign(null, message, keys.privateKey);
  const spki = keys.publicKey.export({ format: 'der', type: 'spki' });
  const publicKey = `ed25519:${bs58.encode(spki.subarray(spki.length - 32))}`;
  return {
    response: { ...response, signature: `ed25519:${bs58.encode(signature)}` },
    publicKey,
  };
}

function quoteResponse(): { response: QuoteResponse; publicKey: string } {
  return signQuote({
    correlationId: 'quote-123',
    timestamp: '2030-01-01T00:00:00.000Z',
    signature: 'pending',
    quoteRequest: fundingQuote(),
    quote: {
      depositAddress: 'solana-deposit-address',
      amountIn: '25100000',
      amountInFormatted: '25.1',
      amountInUsd: '25.1',
      minAmountIn: '25000000',
      amountOut: '25000000',
      amountOutFormatted: '25',
      amountOutUsd: '25',
      minAmountOut: '25000000',
      timeEstimate: 45,
    },
  });
}

test('route digest and signed settlement binding pin the reusable Intents configuration', () => {
  const value = route();
  const digest = nearIntentsRouteDigest(value);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.match(nearIntentsAdapterRef(value), new RegExp(`${digest}$`));

  const binding = nearIntentsSettlementBinding(value);
  assert.equal(binding.custodyMode, 'M2_external_escrow');
  assert.equal(binding.fundsController, 'customer_contract');
  assert.equal(binding.edictOperatorCanTransfer, false);

  const changed = { ...value, removalIntentsAccount: 'different-pool.near' };
  assert.notEqual(nearIntentsRouteDigest(changed), digest);
});

test('funding uses exact output into requester Intents before atomic settlement transfer', () => {
  const quote = fundingQuote();
  assert.equal(quote.swapType, 'EXACT_OUTPUT');
  assert.equal(quote.recipientType, 'INTENTS');
  assert.equal(quote.recipient, 'requester.near');
  assert.equal(quote.amount, '25000000');
  assert.equal(quote.customRecipientMsg, undefined);

  const transfer = buildProtectionFundingTransfer(route(), {
    orderMandateSha256: HASH_A,
    settlementBindingSha256: HASH_B,
    workerIntentsAccount: 'worker.near',
    principalAtomic: '25000000',
    deadlineMs: 1_900_000_000_000,
    acceptanceWindowMs: 86_400_000,
    challengeWindowMs: 7_200_000,
    resolutionTimeoutMs: 259_200_000,
    livenessFallback: 'refund_requester',
    permittedRulings: ['requester_wins', 'worker_wins', 'split', 'redo'],
    disputeBondBps: 500,
  });
  assert.equal(transfer.receiver_id, 'protect.customer.near');
  assert.deepEqual(transfer.tokens, { [USDC_BASE]: '25000000' });
  const message = JSON.parse(transfer.msg) as Record<string, unknown>;
  assert.equal(message['action'], 'fund');
  assert.equal(message['version'], 'edict-intents-funding-1');
});

test('quote signature, exact amount and SUCCESS receipt are all verified', () => {
  const signed = quoteResponse();
  assert.doesNotThrow(() => {
    assertSignedProtectionFundingQuote(signed.response, fundingQuote(), signed.publicKey);
  });

  const status: OneClickExecutionStatus = {
    correlationId: 'status-123',
    quoteResponse: signed.response,
    status: GetExecutionStatusResponse.status.SUCCESS,
    updatedAt: '2030-01-01T00:01:00.000Z',
    swapDetails: {
      intentHashes: ['intent-hash'],
      nearTxHashes: ['near-hash'],
      amountOut: '25000000',
      originChainTxHashes: [{ hash: 'origin-hash', explorerUrl: 'https://example.test/origin' }],
      destinationChainTxHashes: [{ hash: 'destination-hash', explorerUrl: 'https://example.test/destination' }],
    },
  };
  const receipt = verifiedFundingReceipt(status, fundingQuote(), signed.publicKey);
  assert.equal(receipt.amountOutAtomic, '25000000');
  assert.deepEqual(receipt.intentHashes, ['intent-hash']);
});

test('tampered or experimental funding quotes fail closed', () => {
  const signed = quoteResponse();
  const tampered: QuoteResponse = {
    ...signed.response,
    quoteRequest: { ...signed.response.quoteRequest, recipient: 'attacker.near' },
  };
  assert.throws(
    () => assertSignedProtectionFundingQuote(tampered, fundingQuote(), signed.publicKey),
    /signature is invalid/,
  );

  const experimental = signQuote({
    ...signed.response,
    signature: 'pending',
    quote: { ...signed.response.quote, customRecipientMsg: '{"action":"fund"}' },
  });
  assert.throws(
    () => assertSignedProtectionFundingQuote(experimental.response, fundingQuote(), experimental.publicKey),
    /customRecipientMsg is forbidden/,
  );
});

test('claims remain party controlled and can route to any supported destination chain', () => {
  const quote = buildClaimPayoutQuote({
    settlementAsset: USDC_BASE,
    claimAtomic: '12500000',
    partyIntentsAccount: 'worker.near',
    destinationAsset: USDC_SOL,
    destinationAddress: 'solana-worker-address',
    deadline: '2030-01-01T00:05:00.000Z',
  });
  assert.equal(quote.depositType, 'INTENTS');
  assert.equal(quote.refundType, 'INTENTS');
  assert.equal(quote.refundTo, 'worker.near');
  assert.equal(quote.recipientType, 'DESTINATION_CHAIN');
  assert.equal(quote.swapType, 'EXACT_INPUT');

  const signed = signQuote({
    correlationId: 'payout-quote',
    timestamp: '2030-01-01T00:00:00.000Z',
    signature: 'pending',
    quoteRequest: quote,
    quote: {
      depositAddress: 'worker.near',
      amountIn: '12500000',
      amountInFormatted: '12.5',
      amountInUsd: '12.5',
      minAmountIn: '12500000',
      amountOut: '12400000',
      amountOutFormatted: '12.4',
      amountOutUsd: '12.4',
      minAmountOut: '12300000',
      timeEstimate: 30,
    },
  });
  assert.doesNotThrow(() => assertSignedClaimPayoutQuote(signed.response, quote, signed.publicKey));
});

test('Bond and party actions use the same fixed asset and authenticated socket', () => {
  assert.equal(disputeBondAtomic('25000000', 500), '1250000');
  assert.throws(
    () => disputeBondAtomic('1', 500),
    /too small for a positive atomic Bond/,
  );
  const bond = buildDisputeBondTransfer(route(), {
    orderMandateSha256: HASH_A,
    caseIdSha256: HASH_B,
    bondAtomic: '1250000',
  });
  assert.deepEqual(bond.tokens, { [USDC_BASE]: '1250000' });

  const deliver = buildPartyAuthCall(route(), deliverAction(HASH_A, HASH_B));
  assert.equal(deliver.contract_id, 'protect.customer.near');
  assert.equal((JSON.parse(deliver.msg) as { action: string }).action, 'deliver');

  const accept = buildPartyAuthCall(route(), acceptAction(HASH_A));
  assert.equal((JSON.parse(accept.msg) as { action: string }).action, 'accept');

  const fallback = buildPartyAuthCall(route(), controllerFallbackAction(HASH_A, {
    kind: 'split',
    requesterBps: 2_500,
  }));
  assert.deepEqual((JSON.parse(fallback.msg) as { ruling: unknown }).ruling, {
    kind: 'split',
    requesterBps: 2_500,
  });
});

test('funding cannot create an order whose percentage Bond rounds to zero', () => {
  assert.throws(
    () => buildProtectionFundingTransfer(route(), {
      orderMandateSha256: HASH_A,
      settlementBindingSha256: HASH_B,
      workerIntentsAccount: 'worker.near',
      principalAtomic: '1',
      deadlineMs: 1_900_000_000_000,
      acceptanceWindowMs: 86_400_000,
      challengeWindowMs: 7_200_000,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'refund_requester',
      permittedRulings: ['requester_wins', 'worker_wins'],
      disputeBondBps: 500,
    }),
    /too small for a positive atomic Bond/,
  );
});

test('atomic amounts are bounded to the settlement contract uint128 range', () => {
  assert.equal(
    disputeBondAtomic(((1n << 128n) - 1n).toString(), 500),
    '17014118346046923173168730371588410572',
  );
  assert.throws(
    () => disputeBondAtomic((1n << 128n).toString(), 500),
    /exceeds the uint128 settlement limit/,
  );
});

test('route rejects a removal beneficiary that is also the settlement account', () => {
  assert.throws(
    () => nearIntentsRoute({
      settlementAccount: 'protect.customer.near',
      settlementAsset: USDC_BASE,
      removalIntentsAccount: 'protect.customer.near',
    }),
    /must differ from the removal beneficiary/,
  );
});
