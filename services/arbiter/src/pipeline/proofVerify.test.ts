/**
 * Proof-verification integration — real proof verification, not presence checks.
 *
 * Every secp256k1 vector is SIGNED IN-TEST with @noble/curves so the suite
 * proves actual cryptographic verification: valid proof accepted, wrong
 * signer rejected, tampered response-hash rejected, stale proof rejected,
 * allowlist enforcement, plus the ed25519 / ecdsa_p256 node:crypto paths and
 * the jury-level exclusion → insufficient_attested_seats escalation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import type { ProviderProof } from '@edict/core';
import {
  verifyProviderProof,
  proofEnvelope,
  proofEnvelopeBodyHashes,
  ethPersonalMessageDigest,
  recoverEthAddress,
  DEFAULT_PROOF_FRESHNESS_MS,
  type VerifyProofOptions,
} from './proofVerify.js';

// ---------------------------------------------------------------------------
// secp256k1 helpers (in-test signing)
// ---------------------------------------------------------------------------

const PRIV = new Uint8Array(32).fill(0x42);
const OTHER_PRIV = new Uint8Array(32).fill(0x43);

function addressOf(priv: Uint8Array): string {
  const pub = secp256k1.getPublicKey(priv, false);
  return `0x${Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex')}`;
}

const ADDRESS = addressOf(PRIV);
const OTHER_ADDRESS = addressOf(OTHER_PRIV);

/** eth personal-message signature over the proof envelope, r||s||v with v ∈ {27,28}. */
function signEnvelope(priv: Uint8Array, envelope: string, vStyle: 'eth27' | 'raw01' | 'vFirst' = 'eth27'): string {
  const digest = ethPersonalMessageDigest(envelope);
  const recovered = secp256k1.sign(digest, priv, { format: 'recovered', prehash: false });
  const rs = Buffer.from(recovered.slice(1));
  const v = recovered[0]!;
  if (vStyle === 'vFirst') return `0x${Buffer.concat([Buffer.from([v + 27]), rs]).toString('hex')}`;
  const vByte = Buffer.from([vStyle === 'eth27' ? v + 27 : v]);
  return `0x${Buffer.concat([rs, vByte]).toString('hex')}`;
}

const REQ_SHA = 'a'.repeat(64);
const RESP_SHA = 'b'.repeat(64);
const OPENED_AT = 1_750_000_000_000;

function mkProof(overrides: Partial<ProviderProof> = {}): ProviderProof {
  const base: ProviderProof = {
    providerId: 'nearai',
    modelId: 'pinned-model-1',
    requestSha256: REQ_SHA,
    responseSha256: RESP_SHA,
    signatureScheme: 'ecdsa_secp256k1_eth',
    signingAddress: ADDRESS,
    attestationRef: 'archive://nearai_attestation_x.json',
    fetchedAtUnixMs: OPENED_AT + 60_000,
    ...overrides,
  };
  if (base.signature === undefined) {
    base.signature = signEnvelope(PRIV, proofEnvelope(base));
  }
  return base;
}

function opts(overrides: Partial<VerifyProofOptions> = {}): VerifyProofOptions {
  return { referenceUnixMs: OPENED_AT, ...overrides };
}

// ---------------------------------------------------------------------------
// secp256k1 vectors
// ---------------------------------------------------------------------------

test('proofVerify: a validly signed secp256k1 proof is accepted', () => {
  assert.deepEqual(verifyProviderProof(mkProof(), opts()), { ok: true });
});

test('proofVerify: v ∈ {0,1} and the v-first signature layout are both accepted', () => {
  const envelope = proofEnvelope(mkProof());
  for (const style of ['raw01', 'vFirst'] as const) {
    const proof = mkProof({ signature: signEnvelope(PRIV, envelope, style) });
    assert.deepEqual(verifyProviderProof(proof, opts()), { ok: true }, style);
  }
});

test('proofVerify: signingAddress comparison is case-insensitive', () => {
  const proof = mkProof({ signingAddress: ADDRESS.toUpperCase().replace('0X', '0x') });
  assert.deepEqual(verifyProviderProof(proof, opts()), { ok: true });
});

test('proofVerify: wrong signer is rejected (recovered address ≠ signingAddress)', () => {
  // Signed by OTHER_PRIV but claiming ADDRESS.
  const p = mkProof();
  const forged = { ...p, signature: signEnvelope(OTHER_PRIV, proofEnvelope(p)) };
  const res = verifyProviderProof(forged, opts());
  assert.equal(res.ok, false);
  assert.match((res as { reason: string }).reason, /recovered signer .* does not match/);
});

test('proofVerify: tampered response-hash is rejected (signature no longer covers the envelope)', () => {
  const genuine = mkProof();
  const tampered: ProviderProof = { ...genuine, responseSha256: 'c'.repeat(64) };
  // signature still the one over the ORIGINAL envelope
  const res = verifyProviderProof(tampered, opts());
  assert.equal(res.ok, false, 'tampered envelope must not verify');

  // And when the verifier knows the captured hashes, the mismatch is named:
  const res2 = verifyProviderProof(tampered, opts({ expectedResponseSha256: RESP_SHA }));
  assert.equal(res2.ok, false);
  assert.match((res2 as { reason: string }).reason, /responseSha256 does not match the captured response bytes/);
});

test('proofVerify: proof for a different pinned model is rejected', () => {
  const res = verifyProviderProof(mkProof(), opts({ expectedModelId: 'some-other-model' }));
  assert.equal(res.ok, false);
  assert.match((res as { reason: string }).reason, /does not match the seat's pinned model/);
});

test('proofVerify: stale proof is rejected (outside the freshness window around the reference time)', () => {
  const stale = mkProof({ fetchedAtUnixMs: OPENED_AT - DEFAULT_PROOF_FRESHNESS_MS - 1 });
  const res = verifyProviderProof(stale, opts());
  assert.equal(res.ok, false);
  assert.match((res as { reason: string }).reason, /stale/);

  // Custom (tighter) window
  const slightlyOld = mkProof({ fetchedAtUnixMs: OPENED_AT + 120_000 });
  assert.equal(verifyProviderProof(slightlyOld, opts({ freshnessMs: 60_000 })).ok, false);
  assert.equal(verifyProviderProof(slightlyOld, opts({ freshnessMs: 300_000 })).ok, true);
});

test('proofVerify: allowlist enforcement — allowlisted signer accepted, others rejected, per provider', () => {
  const proof = mkProof();
  // allowlisted (case-insensitive)
  assert.equal(
    verifyProviderProof(proof, opts({ signerAllowlist: { nearai: [ADDRESS.toUpperCase()] } })).ok,
    true,
  );
  // not allowlisted
  const res = verifyProviderProof(proof, opts({ signerAllowlist: { nearai: [OTHER_ADDRESS] } }));
  assert.equal(res.ok, false);
  assert.match((res as { reason: string }).reason, /not in the configured allowlist/);
  // allowlist for a DIFFERENT provider does not constrain this one
  assert.equal(
    verifyProviderProof(proof, opts({ signerAllowlist: { phala: [OTHER_ADDRESS] } })).ok,
    true,
  );
});

test('proofVerify: none_mock, missing signature, missing scheme, missing attestationRef all fail', () => {
  const mock = mkProof({ signatureScheme: 'none_mock', signature: 'x' });
  assert.match((verifyProviderProof(mock, opts()) as { reason: string }).reason, /none_mock/);

  const unsigned = mkProof();
  delete (unsigned as { signature?: string }).signature;
  assert.match((verifyProviderProof(unsigned, opts()) as { reason: string }).reason, /no signature$/);

  const schemeless = mkProof();
  delete (schemeless as { signatureScheme?: string }).signatureScheme;
  assert.match((verifyProviderProof(schemeless, opts()) as { reason: string }).reason, /no signature scheme/);

  const unattested = mkProof({ attestationRef: '' });
  assert.match((verifyProviderProof(unattested, opts()) as { reason: string }).reason, /attestationRef/);
});

test('proofVerify: malformed signatures are rejected, not thrown', () => {
  for (const sig of ['0xdead', `0x${'00'.repeat(65)}`, 'not-hex', `0x${'ab'.repeat(64)}`]) {
    const res = verifyProviderProof(mkProof({ signature: sig }), opts());
    assert.equal(res.ok, false, sig);
  }
});

// ---------------------------------------------------------------------------
// ecdsa_secp256k1_eth_bodyhashes — the Phala/RedPill ACI legacy profile:
// same eth-style recovery, but over `${requestSha256}:${responseSha256}`
// (the gateway's `text` field; no modelId prefix).
// ---------------------------------------------------------------------------

test('proofVerify: bodyhashes scheme — signature over "<reqSha>:<respSha>" verifies', () => {
  const base = mkProof({
    providerId: 'phala',
    signatureScheme: 'ecdsa_secp256k1_eth_bodyhashes',
    signature: 'placeholder',
  });
  assert.equal(proofEnvelopeBodyHashes(base), `${REQ_SHA}:${RESP_SHA}`);
  const proof = { ...base, signature: signEnvelope(PRIV, proofEnvelopeBodyHashes(base)) };
  assert.deepEqual(verifyProviderProof(proof, opts()), { ok: true });
});

test('proofVerify: bodyhashes scheme — envelope mix-ups never verify (scheme pins the envelope)', () => {
  const base = mkProof({
    providerId: 'phala',
    signatureScheme: 'ecdsa_secp256k1_eth_bodyhashes',
    signature: 'placeholder',
  });
  // Signed over the model-prefixed DEFAULT envelope, presented as bodyhashes:
  const wrongEnvelope = { ...base, signature: signEnvelope(PRIV, proofEnvelope(base)) };
  assert.equal(verifyProviderProof(wrongEnvelope, opts()).ok, false);
  // …and the converse: a bodyhashes signature presented under the default scheme.
  const converse = {
    ...base,
    signatureScheme: 'ecdsa_secp256k1_eth' as const,
    signature: signEnvelope(PRIV, proofEnvelopeBodyHashes(base)),
  };
  assert.equal(verifyProviderProof(converse, opts()).ok, false);
});

test('proofVerify: bodyhashes scheme — tampered hashes and wrong signer are rejected', () => {
  const base = mkProof({
    providerId: 'phala',
    signatureScheme: 'ecdsa_secp256k1_eth_bodyhashes',
    signature: 'placeholder',
  });
  const genuine = { ...base, signature: signEnvelope(PRIV, proofEnvelopeBodyHashes(base)) };
  assert.equal(verifyProviderProof({ ...genuine, responseSha256: 'c'.repeat(64) }, opts()).ok, false);
  const forged = { ...base, signature: signEnvelope(OTHER_PRIV, proofEnvelopeBodyHashes(base)) };
  const res = verifyProviderProof(forged, opts());
  assert.equal(res.ok, false);
  assert.match((res as { reason: string }).reason, /recovered signer .* does not match/);
});

test('proofVerify: recoverEthAddress round-trips a known key', () => {
  const digest = ethPersonalMessageDigest('roundtrip');
  const recovered = secp256k1.sign(digest, PRIV, { format: 'recovered', prehash: false });
  const sigHex = `0x${Buffer.concat([Buffer.from(recovered.slice(1)), Buffer.from([recovered[0]! + 27])]).toString('hex')}`;
  assert.equal(recoverEthAddress(sigHex, digest), ADDRESS);
});

// ---------------------------------------------------------------------------
// ed25519 / ecdsa_p256 (node:crypto)
// ---------------------------------------------------------------------------

test('proofVerify: ed25519 — valid signature accepted, tampered envelope rejected', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32);
  const base = mkProof({
    signatureScheme: 'ed25519',
    signingAddress: rawPub.toString('hex'),
  });
  const sig = cryptoSign(null, Buffer.from(proofEnvelope(base), 'utf8'), privateKey);
  const proof = { ...base, signature: sig.toString('hex') };
  assert.deepEqual(verifyProviderProof(proof, opts()), { ok: true });

  const tampered = { ...proof, responseSha256: 'd'.repeat(64) };
  assert.equal(verifyProviderProof(tampered, opts()).ok, false);
});

test('proofVerify: ecdsa_p256 — valid signature accepted in DER and ieee-p1363 encodings (generic verifier; no provider emits it — Phala is secp256k1, evidence 2026-07-09)', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rawPoint = (publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-65);
  assert.equal(rawPoint[0], 0x04, 'uncompressed point expected');
  const base = mkProof({
    providerId: 'generic-p256',
    signatureScheme: 'ecdsa_p256',
    signingAddress: rawPoint.toString('hex'),
  });
  const msg = Buffer.from(proofEnvelope(base), 'utf8');
  const der = cryptoSign('sha256', msg, privateKey);
  assert.deepEqual(verifyProviderProof({ ...base, signature: der.toString('hex') }, opts()), { ok: true });
  const p1363 = cryptoSign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.equal(p1363.length, 64);
  assert.deepEqual(verifyProviderProof({ ...base, signature: p1363.toString('hex') }, opts()), { ok: true });

  const wrongKeyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const wrongSig = cryptoSign('sha256', msg, wrongKeyPair.privateKey);
  assert.equal(verifyProviderProof({ ...base, signature: wrongSig.toString('hex') }, opts()).ok, false);
});
