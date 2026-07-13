import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCustomerSettlementCanonicalVector,
  buildCustomerSettlementExecutionDigest,
} from './executionPayload.js';

const EXPECTED = '16964bc5fb584f55c88cc6535482b781abb996d032bbf4511b124143febe2ea7';

test('EDICT_SETTLEMENT_V1 canonical vector is stable across TypeScript and Rust', () => {
  const vector = buildCustomerSettlementCanonicalVector();
  assert.equal(vector.digestHex, EXPECTED);
  assert.equal(buildCustomerSettlementExecutionDigest(vector.input), EXPECTED);
});

test('EDICT_SETTLEMENT_V1 binds every execution-sensitive field', () => {
  const { input, digestHex } = buildCustomerSettlementCanonicalVector();
  const variants = [
    { ...input, settlementAccountId: 'other.customer-settlement.near' },
    { ...input, orderMandateSha256Hex: '11'.repeat(32) },
    { ...input, caseIdSha256Hex: '12'.repeat(32) },
    { ...input, round: 2 },
    { ...input, rulingCanonical: 'worker_wins' },
    { ...input, verdictSha256Hex: '13'.repeat(32) },
    { ...input, issuedAtUnixMs: input.issuedAtUnixMs + 1 },
    { ...input, verifierPolicySha256Hex: '14'.repeat(32) },
    { ...input, nonce: new Uint8Array(32).fill(0x15) },
  ];
  for (const variant of variants) {
    assert.notEqual(buildCustomerSettlementExecutionDigest(variant), digestHex);
  }
});

test('EDICT_SETTLEMENT_V1 rejects malformed rounds, hashes, timestamps and nonces', () => {
  const { input } = buildCustomerSettlementCanonicalVector();
  assert.throws(() => buildCustomerSettlementExecutionDigest({ ...input, round: 0 }), /round/);
  assert.throws(
    () => buildCustomerSettlementExecutionDigest({ ...input, verdictSha256Hex: '00' }),
    /64 hex/,
  );
  assert.throws(
    () => buildCustomerSettlementExecutionDigest({ ...input, issuedAtUnixMs: 0 }),
    /positive safe integer/,
  );
  assert.throws(
    () => buildCustomerSettlementExecutionDigest({ ...input, nonce: new Uint8Array(31) }),
    /32 bytes/,
  );
});
