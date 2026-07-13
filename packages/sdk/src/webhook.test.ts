/**
 * Verdict webhooks: canonical-payload HMAC signing, constant-time verify,
 * tamper rejection.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { VerdictObject } from '@edict/core';
import { canonicalize } from '@edict/evidence';
import { WEBHOOK_SIGNATURE_PREFIX, signVerdictWebhook, verifyVerdictWebhook } from './webhook.js';

const VERDICT: VerdictObject = {
  caseId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  ruling: { kind: 'worker_wins' },
  final: true,
  reasoningSha256: '1'.repeat(64),
  votes: [],
  quality: { majority: 'unanimous', swapFlipRate: 0, injectionFlags: [], escalated: false },
  legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E1' },
  issuedAtUnixMs: 1_750_000_000_000,
};

test('sign/verify round-trip over canonical verdict JSON', () => {
  const { payload, signature } = signVerdictWebhook(VERDICT, 'shh');
  assert.equal(payload, canonicalize(VERDICT));
  assert.ok(signature.startsWith(WEBHOOK_SIGNATURE_PREFIX));
  assert.equal(verifyVerdictWebhook(payload, signature, 'shh'), true);
  // Prefix-less and case-insensitive headers verify too.
  assert.equal(verifyVerdictWebhook(payload, signature.slice(WEBHOOK_SIGNATURE_PREFIX.length), 'shh'), true);
  assert.equal(verifyVerdictWebhook(payload, signature.toUpperCase(), 'shh'), true);
});

test('signing is deterministic: same verdict, same secret → same signature', () => {
  assert.deepEqual(signVerdictWebhook(VERDICT, 'shh'), signVerdictWebhook(VERDICT, 'shh'));
});

test('tampered payloads and wrong secrets are rejected', () => {
  const { payload, signature } = signVerdictWebhook(VERDICT, 'shh');
  const tampered = payload.replace('"worker_wins"', '"requester_wins"');
  assert.equal(verifyVerdictWebhook(tampered, signature, 'shh'), false);
  assert.equal(verifyVerdictWebhook(payload, signature, 'wrong-secret'), false);
});

test('malformed input never throws — it just fails verification', () => {
  const { payload } = signVerdictWebhook(VERDICT, 'shh');
  assert.equal(verifyVerdictWebhook(payload, 'sha256=not-hex', 'shh'), false);
  assert.equal(verifyVerdictWebhook(payload, 'sha256=abcd', 'shh'), false); // wrong length
  assert.equal(verifyVerdictWebhook(payload, '', 'shh'), false);
  assert.equal(verifyVerdictWebhook(payload, 'sha256=' + 'a'.repeat(64), ''), false); // empty secret
  assert.throws(() => signVerdictWebhook(VERDICT, ''), TypeError);
});
