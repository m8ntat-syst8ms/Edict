import { test } from 'node:test';
import assert from 'node:assert/strict';

import { canonicalize, sha256Canonical } from './hash.js';
import {
  canonicalOrderMandateHash,
  verifyOrderMandateHash,
  flattenOrderMandate,
  buildEip712TypedData,
  buildNep413Payload,
} from './orderMandate.js';
import { makeOrderMandate } from './fixtures.test.js';

// ---------------------------------------------------------------------------
// Canonical hash + verification
// ---------------------------------------------------------------------------

test('canonicalOrderMandateHash: deterministic and verifiable', () => {
  const om = makeOrderMandate();
  const hash = canonicalOrderMandateHash(om);
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(canonicalOrderMandateHash(makeOrderMandate()), hash); // rebuilt fixture, same hash
  assert.equal(verifyOrderMandateHash(om, hash), true);
  assert.equal(verifyOrderMandateHash(om, `0x${hash.toUpperCase()}`), true); // prefix/case tolerant
});

test('verifyOrderMandateHash: rejects wrong or malformed hashes', () => {
  const om = makeOrderMandate();
  const other = canonicalOrderMandateHash(makeOrderMandate({ nonce: 'nonce-0002' }));
  assert.equal(verifyOrderMandateHash(om, other), false);
  assert.equal(verifyOrderMandateHash(om, 'not-a-hash'), false);
});

test('canonicalOrderMandateHash: any field change changes the hash', () => {
  const base = canonicalOrderMandateHash(makeOrderMandate());
  assert.notEqual(canonicalOrderMandateHash(makeOrderMandate({ priceUsd: 125.51 })), base);
  assert.notEqual(canonicalOrderMandateHash(makeOrderMandate({ description: 'other' })), base);
  // The canonical hash covers decisionSpace, so any change changes the hash.
  assert.notEqual(
    canonicalOrderMandateHash(makeOrderMandate({ decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins'] } })),
    base,
  );
  assert.notEqual(
    canonicalOrderMandateHash(
      makeOrderMandate({ decisionSpace: { kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' } }),
    ),
    base,
  );
});

// ---------------------------------------------------------------------------
// EIP-712
// ---------------------------------------------------------------------------

test('buildEip712TypedData: envelope shape', () => {
  const om = makeOrderMandate();
  const typed = buildEip712TypedData(om);

  assert.deepEqual(typed.domain, { name: 'EdictOrderMandate', version: '1' });
  assert.equal(typed.primaryType, 'OrderMandate');
  assert.deepEqual(Object.keys(typed.types), ['OrderMandate']); // no EIP712Domain (ethers v6 compat)

  // types field list and message keys agree exactly, in order
  const typeNames = typed.types.OrderMandate.map((f) => f.name);
  assert.deepEqual(typeNames, Object.keys(typed.message));
});

test('buildEip712TypedData: documented field mapping is honoured', () => {
  const om = makeOrderMandate();
  const { message } = buildEip712TypedData(om);

  assert.equal(message.version, 'edict-om-1');
  assert.equal(message.requesterAgentId, om.requester.agentId); // parties flattened to ids
  assert.equal(message.workerAgentId, om.worker.agentId);
  assert.equal(message.description, om.description);
  assert.equal(message.acceptanceCriteriaSha256, `0x${sha256Canonical(om.acceptanceCriteria)}`);
  assert.equal(message.priceUsdE6, '125500000'); // 125.5 USD -> micro-USD decimal string
  assert.equal(message.currencyAsset, 'usdc');
  assert.equal(message.currencyRail, 'near-agent-market');
  assert.equal(message.deadlineUnixMs, String(om.deadlineUnixMs));
  assert.equal(message.acceptanceWindowMs, String(om.acceptanceWindowMs));
  assert.equal(message.governingLaw, 'england_wales');
  assert.equal(message.seat, 'london');
  assert.equal(message.rules, 'edict-drr-v0.1');
  assert.equal(message.enforcementTier, 'E1');
  assert.equal(message.decisionSpaceSha256, `0x${sha256Canonical(om.decisionSpace)}`);
  assert.deepEqual(message.maeEvents, ['upstream_api_shutdown']);
  assert.equal(message.nonce, om.nonce);

  // KYB refs are deliberately not part of the signed message
  assert.equal(Object.values(message).flat().includes(om.requester.principalKybRef!), false);
});

test('buildEip712TypedData: chainId included only when provided, validated', () => {
  const om = makeOrderMandate();
  assert.equal('chainId' in buildEip712TypedData(om).domain, false);
  assert.equal(buildEip712TypedData(om, 8453).domain.chainId, 8453);
  assert.throws(() => buildEip712TypedData(om, 0), TypeError);
  assert.throws(() => buildEip712TypedData(om, 1.5), TypeError);
});

test('buildEip712TypedData: bytes32/uint256 fields carry the declared types', () => {
  const typed = buildEip712TypedData(makeOrderMandate());
  const typeOf = (name: string) => typed.types.OrderMandate.find((f) => f.name === name)?.type;
  assert.equal(typeOf('acceptanceCriteriaSha256'), 'bytes32');
  assert.equal(typeOf('priceUsdE6'), 'uint256');
  assert.equal(typeOf('deadlineUnixMs'), 'uint256');
  assert.equal(typeOf('acceptanceWindowMs'), 'uint256');
  assert.equal(typeOf('decisionSpaceSha256'), 'bytes32');
  assert.equal(typeOf('permittedRulings'), undefined); // retired v0.1 field is gone
  assert.equal(typeOf('maeEvents'), 'string[]');
  assert.match(typed.message.acceptanceCriteriaSha256, /^0x[0-9a-f]{64}$/);
  assert.match(typed.message.decisionSpaceSha256, /^0x[0-9a-f]{64}$/);
});

test('flattenOrderMandate: decisionSpaceSha256 binds the whole decision space', () => {
  const escrow = flattenOrderMandate(makeOrderMandate()).decisionSpaceSha256;
  // fewer branches -> different digest
  assert.notEqual(
    flattenOrderMandate(makeOrderMandate({ decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins'] } }))
      .decisionSpaceSha256,
    escrow,
  );
  // a different space kind -> different digest
  const categorical = flattenOrderMandate(
    makeOrderMandate({ decisionSpace: { kind: 'categorical', outcomes: ['YES', 'NO'] } }),
  ).decisionSpaceSha256;
  assert.notEqual(categorical, escrow);
  // deterministic: rebuilt mandate, same digest
  assert.equal(flattenOrderMandate(makeOrderMandate()).decisionSpaceSha256, escrow);
});

test('flattenOrderMandate: rejects unrepresentable numerics', () => {
  assert.throws(() => flattenOrderMandate(makeOrderMandate({ priceUsd: -1 })), TypeError);
  assert.throws(() => flattenOrderMandate(makeOrderMandate({ priceUsd: NaN })), TypeError);
  assert.throws(() => flattenOrderMandate(makeOrderMandate({ deadlineUnixMs: 1.5 })), TypeError);
});

test('flattenOrderMandate: wallet-native v2 uses zero authority hashes without KYB credentials', () => {
  const om = makeOrderMandate({
    version: 'edict-om-2',
    requester: { agentId: 'near:req.alice.near' },
    worker: { agentId: 'near:wrk.bob.near' },
    legalProfile: {
      governingLaw: 'england_wales',
      seat: 'london',
      rules: 'edict-drr-v0.1',
      enforcementTier: 'E0',
    },
    legalPolicy: {
      version: 'edict-legal-policy-1',
      policyId: 'wallet-native-v1',
      assuranceMode: 'wallet_native',
      rules: { id: 'edict-drr-v0.1', version: '0.1', sha256: 'a'.repeat(64) },
      challengeWindowMs: 86_400_000,
      humanEscalation: { mode: 'off' },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protocol_burn',
    },
    settlement: {
      custodyMode: 'M2_external_escrow',
      fundsController: 'payment_rail',
      adapterRef: 'rail:near-agent-market:escrow-v1',
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'controller_resolution',
    },
  });
  const flattened = flattenOrderMandate(om);
  assert.equal(flattened.assuranceMode, 'wallet_native');
  assert.equal(flattened.custodyMode, 'M2_external_escrow');
  assert.equal(flattened.fundsController, 'payment_rail');
  assert.equal(flattened.settlementAdapterRef, 'rail:near-agent-market:escrow-v1');
  assert.equal(flattened.edictOperatorCanTransfer, false);
  assert.equal(flattened.edictOperatorCanFreeze, false);
  assert.equal(flattened.edictRequiredSigner, false);
  assert.equal(flattened.resolutionTimeoutMs, '259200000');
  assert.equal(flattened.livenessFallback, 'controller_resolution');
  assert.equal(flattened.settlementPrivacyMode, 'public');
  assert.equal(flattened.privacyCapabilitySha256, `0x${'0'.repeat(64)}`);
  assert.equal(flattened.disclosurePolicySha256, `0x${'0'.repeat(64)}`);
  assert.equal(flattened.privacyFallback, 'not_applicable');
  assert.equal(flattened.publicFallbackAdapterRef, '');
  assert.equal(flattened.requesterAuthoritySha256, `0x${'0'.repeat(64)}`);
  assert.equal(flattened.workerAuthoritySha256, `0x${'0'.repeat(64)}`);
  assert.deepEqual(
    buildEip712TypedData(om).types.OrderMandate.map((field) => field.name),
    Object.keys(buildEip712TypedData(om).message),
  );
});

test('flattenOrderMandate: v2 signs confidential capability, disclosure and fallback', () => {
  const om = makeOrderMandate({
    version: 'edict-om-2',
    legalPolicy: {
      version: 'edict-legal-policy-1',
      policyId: 'private-v1',
      assuranceMode: 'wallet_native',
      rules: { id: 'edict-drr-v0.1', version: '0.1', sha256: 'a'.repeat(64) },
      challengeWindowMs: 86_400_000,
      humanEscalation: { mode: 'off' },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protocol_burn',
    },
    settlement: {
      custodyMode: 'M2_external_escrow',
      fundsController: 'customer_contract',
      adapterRef: `near-confidential-intents:v1:${'b'.repeat(64)}`,
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'controller_resolution',
      confidentiality: {
        mode: 'confidential_settlement',
        capabilitySha256: 'b'.repeat(64),
        disclosurePolicySha256: 'c'.repeat(64),
        fallback: 'fail_closed',
      },
    },
  });
  const flattened = flattenOrderMandate(om);
  assert.equal(flattened.settlementPrivacyMode, 'confidential_settlement');
  assert.equal(flattened.privacyCapabilitySha256, `0x${'b'.repeat(64)}`);
  assert.equal(flattened.disclosurePolicySha256, `0x${'c'.repeat(64)}`);
  assert.equal(flattened.privacyFallback, 'fail_closed');
  assert.equal(flattened.publicFallbackAdapterRef, '');
  assert.deepEqual(
    buildEip712TypedData(om).types.OrderMandate.map((field) => field.name),
    Object.keys(buildEip712TypedData(om).message),
  );
  assert.throws(
    () => flattenOrderMandate({
      ...om,
      settlement: {
        ...om.settlement!,
        confidentiality: {
          ...om.settlement!.confidentiality!,
          fallback: 'allow_public_settlement',
        },
      },
    }),
    /publicFallbackAdapterRef/,
  );
});

test('flattenOrderMandate: v2 refuses a missing or Edict-controlled settlement boundary', () => {
  const base = makeOrderMandate({
    version: 'edict-om-2',
    legalPolicy: {
      version: 'edict-legal-policy-1',
      policyId: 'no-custody-v1',
      assuranceMode: 'wallet_native',
      rules: { id: 'edict-drr-v0.1', version: '0.1', sha256: 'a'.repeat(64) },
      challengeWindowMs: 86_400_000,
      humanEscalation: { mode: 'off' },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protocol_burn',
    },
  });
  assert.throws(() => flattenOrderMandate(base), /customer-controlled settlement binding/);
  assert.throws(
    () => flattenOrderMandate({
      ...base,
      settlement: {
        custodyMode: 'M2_external_escrow',
        fundsController: 'payment_rail',
        adapterRef: 'rail:test',
        edictOperatorCanTransfer: true as false,
        edictOperatorCanFreeze: false,
        edictOperatorIsRequiredSigner: false,
        resolutionTimeoutMs: 259_200_000,
        livenessFallback: 'controller_resolution',
      },
    }),
    /must be false/,
  );
});

// ---------------------------------------------------------------------------
// NEP-413
// ---------------------------------------------------------------------------

test('buildNep413Payload: message is canonical JSON of the same flattened mapping', () => {
  const om = makeOrderMandate();
  const nonce = new Uint8Array(32).fill(7);
  const payload = buildNep413Payload(om, 'court.edict.near', nonce);

  assert.equal(payload.recipient, 'court.edict.near');
  assert.equal(payload.nonce.length, 32);
  assert.equal(payload.message, canonicalize(flattenOrderMandate(om)));
  // parseable, and content-identical to what EIP-712 signs
  assert.deepEqual(JSON.parse(payload.message), buildEip712TypedData(om).message);
  assert.equal('callbackUrl' in payload, false);
  assert.equal(
    buildNep413Payload(om, 'court.edict.near', nonce, 'https://example.invalid/cb').callbackUrl,
    'https://example.invalid/cb',
  );
});

test('buildNep413Payload: nonce is copied, not aliased', () => {
  const om = makeOrderMandate();
  const nonce = new Uint8Array(32).fill(1);
  const payload = buildNep413Payload(om, 'court.edict.near', nonce);
  nonce[0] = 99;
  assert.equal(payload.nonce[0], 1);
});

test('buildNep413Payload: validates nonce length and recipient', () => {
  const om = makeOrderMandate();
  assert.throws(() => buildNep413Payload(om, 'court.edict.near', new Uint8Array(31)), TypeError);
  assert.throws(() => buildNep413Payload(om, 'court.edict.near', new Uint8Array(33)), TypeError);
  assert.throws(() => buildNep413Payload(om, '', new Uint8Array(32)), TypeError);
});
