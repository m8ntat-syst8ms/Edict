/**
 * Proof-format tests: the node's signatures must be byte-compatible with the
 * arbiter's `ecdsa_secp256k1_eth` verification (services/arbiter/src/
 * pipeline/proofVerify.ts) — model-prefixed envelope, eth personal-message
 * digest, r||s||v (v = recid+27) recovery back to the published address.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keccak_256 } from '@noble/hashes/sha3.js';
import {
  SIGNING_ENVELOPE_FORMAT,
  SIGNING_SCHEME,
  ethAddressOfPrivateKey,
  ethPersonalMessageDigest,
  proofEnvelope,
  recoverEthAddress,
  signEnvelopeEth,
} from './signer.js';

const PRIV = new Uint8Array(32).fill(0x42);
const OTHER_PRIV = new Uint8Array(32).fill(0x43);
const REQ_SHA = 'a'.repeat(64);
const RESP_SHA = 'b'.repeat(64);

test('proofEnvelope is the NEAR-AI-style model-prefixed triple', () => {
  assert.equal(SIGNING_SCHEME, 'ecdsa_secp256k1_eth');
  assert.equal(SIGNING_ENVELOPE_FORMAT, '{model_id}:{sha256(request)}:{sha256(response)}');
  assert.equal(proofEnvelope('gpt-oss-20b', REQ_SHA, RESP_SHA), `gpt-oss-20b:${REQ_SHA}:${RESP_SHA}`);
});

test('ethPersonalMessageDigest matches manual keccak over the prefixed bytes', () => {
  const msg = 'hello proof';
  const manual = keccak_256(
    Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${Buffer.byteLength(msg)}`), Buffer.from(msg)]),
  );
  assert.deepEqual(ethPersonalMessageDigest(msg), manual);
});

test('signature is 65-byte r||s||v hex with v in {27,28}', () => {
  const sig = signEnvelopeEth(PRIV, proofEnvelope('m', REQ_SHA, RESP_SHA));
  assert.match(sig, /^0x[0-9a-f]{130}$/);
  const v = parseInt(sig.slice(-2), 16);
  assert.ok(v === 27 || v === 28, `v byte was ${v}`);
});

test('signature recovers to the signer address (round-trip with arbiter-style recovery)', () => {
  const envelope = proofEnvelope('gpt-oss-20b', REQ_SHA, RESP_SHA);
  const sig = signEnvelopeEth(PRIV, envelope);
  const recovered = recoverEthAddress(sig, ethPersonalMessageDigest(envelope));
  assert.equal(recovered, ethAddressOfPrivateKey(PRIV));
  assert.match(recovered!, /^0x[0-9a-f]{40}$/);
});

test('a different envelope or key does NOT recover to the same address', () => {
  const envelope = proofEnvelope('gpt-oss-20b', REQ_SHA, RESP_SHA);
  const sig = signEnvelopeEth(PRIV, envelope);
  const address = ethAddressOfPrivateKey(PRIV);

  const tampered = proofEnvelope('gpt-oss-20b', REQ_SHA, 'c'.repeat(64));
  assert.notEqual(recoverEthAddress(sig, ethPersonalMessageDigest(tampered)), address);

  const otherSig = signEnvelopeEth(OTHER_PRIV, envelope);
  assert.notEqual(recoverEthAddress(otherSig, ethPersonalMessageDigest(envelope)), address);
});

test('recoverEthAddress rejects malformed signatures', () => {
  const digest = ethPersonalMessageDigest('x');
  assert.equal(recoverEthAddress('0x1234', digest), null);
  assert.equal(recoverEthAddress(`0x${'00'.repeat(64)}ff`, digest), null); // bad v byte
  assert.equal(recoverEthAddress('not-hex', digest), null);
});
