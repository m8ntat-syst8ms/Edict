/**
 * PhalaProvider (RedPill / ACI gateway) proof wiring, against a stubbed
 * gateway that reproduces the ACI legacy signature profile byte-for-byte
 * (evidence 2026-07-09 — see the module doc in ./phala.ts):
 *
 *   GET /signature/{chat_id} → { api_version, text: "<reqSha>:<respSha>",
 *     signature: eth-personal-message secp256k1 r||s||v, signing_address,
 *     signing_algo: "ecdsa", receipt: {…} }
 *   GET /aci/attestation?model=…&nonce=… → attestation report
 *
 * The stub SIGNS IN-TEST with a known secp256k1 key, so the suite proves the
 * produced ProviderProof passes verifyProviderProof recovery — the
 * exact check the attestation gate runs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { PhalaProvider, PHALA_DEFAULT_BASE_URL } from './phala.js';
import { verifyProviderProof, ethPersonalMessageDigest } from '../pipeline/proofVerify.js';
import { sha256Hex } from '../util.js';

const PRIV = new Uint8Array(32).fill(0x51);
const SIGNER = `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(PRIV, false).slice(1)).slice(-20)).toString('hex')}`;

function signText(text: string): string {
  const digest = ethPersonalMessageDigest(text);
  const recovered = secp256k1.sign(digest, PRIV, { format: 'recovered', prehash: false });
  // Gateway layout: r||s||v with v = recid + 27, 0x-prefixed.
  return `0x${Buffer.concat([Buffer.from(recovered.slice(1)), Buffer.from([recovered[0]! + 27])]).toString('hex')}`;
}

const CHAT_ID = 'chatcmpl-test-1';
const MODEL = 'qwen/qwen3-30b-a3b-instruct-2507';

interface StubOptions {
  signingAlgo?: string;
  signatureStatus?: number;
  omitChatId?: boolean;
}

/** Stubbed ACI gateway: chat completion + legacy signature + attestation. */
function stubGateway(opts: StubOptions = {}) {
  const seen: string[] = [];
  const completionBody = JSON.stringify({
    id: opts.omitChatId ? undefined : CHAT_ID,
    object: 'chat.completion',
    model: MODEL,
    choices: [{ index: 0, message: { role: 'assistant', content: '{"ok":true}' }, finish_reason: 'stop' }],
  });
  const responseSha256 = sha256Hex(completionBody);
  let requestSha256 = '';

  const fetchImpl = (async (url: unknown, init?: { body?: unknown }) => {
    const u = String(url);
    seen.push(u);
    if (u.endsWith('/chat/completions')) {
      requestSha256 = sha256Hex(String(init?.body ?? ''));
      return new Response(completionBody, {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-receipt-id': 'rcpt-test-1' },
      });
    }
    if (u.includes('/signature/')) {
      if (opts.signatureStatus !== undefined && opts.signatureStatus !== 200) {
        return new Response('{"error":"receipt expired"}', { status: opts.signatureStatus });
      }
      const text = `${requestSha256}:${responseSha256}`;
      return new Response(
        JSON.stringify({
          api_version: 'aci/1',
          text,
          signature: signText(text),
          signing_address: SIGNER,
          signing_algo: opts.signingAlgo ?? 'ecdsa',
          receipt: { receipt_id: 'rcpt-test-1', event_log: [] },
        }),
        { status: 200 },
      );
    }
    if (u.includes('/aci/attestation')) {
      return new Response(JSON.stringify({ api_version: 'aci/1', attestation: { tee_type: 'tdx' } }), { status: 200 });
    }
    throw new Error(`unexpected fetch: ${u}`);
  }) as typeof fetch;

  return { fetchImpl, seen };
}

test('phala: default base URL is the RedPill ACI gateway', () => {
  assert.equal(PHALA_DEFAULT_BASE_URL, 'https://api.redpill.ai/v1');
});

test('phala: getProof produces an ecdsa_secp256k1_eth_bodyhashes proof that passes cryptographic verification', async () => {
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-phala-proof-'));
  const { fetchImpl, seen } = stubGateway();
  const provider = new PhalaProvider({ archiveDir, apiKey: 'test-key', fetchImpl });

  const completion = await provider.complete({
    modelId: MODEL,
    messages: [{ role: 'user', content: 'hi' }],
    maxTokens: 16,
  });
  const proof = await provider.getProof(completion.raw);

  assert.equal(proof.providerId, 'phala');
  assert.equal(proof.signatureScheme, 'ecdsa_secp256k1_eth_bodyhashes');
  assert.equal(proof.signingAddress, SIGNER);
  assert.equal(proof.requestSha256, completion.requestSha256);
  assert.equal(proof.responseSha256, completion.responseSha256);
  assert.ok(proof.attestationRef && proof.attestationRef.length > 0);

  // The attestation gate's actual check: recovery over "<reqSha>:<respSha>".
  const verdict = verifyProviderProof(proof, {
    expectedModelId: MODEL,
    expectedRequestSha256: completion.requestSha256,
    expectedResponseSha256: completion.responseSha256,
    referenceUnixMs: proof.fetchedAtUnixMs,
  });
  assert.deepEqual(verdict, { ok: true });

  // Raw receipt + attestation archived immediately; attestation nonce binds
  // the report to THIS completion's response hash.
  const archived = readdirSync(archiveDir).sort();
  assert.ok(archived.some((f) => f.startsWith('phala_receipt_')), archived.join(','));
  assert.ok(archived.some((f) => f.startsWith('phala_attestation_')), archived.join(','));
  const attUrl = seen.find((u) => u.includes('/aci/attestation'));
  assert.ok(attUrl?.includes(`nonce=${completion.responseSha256}`), attUrl ?? 'attestation url missing');
  assert.ok(seen.some((u) => u.includes(`/signature/${CHAT_ID}`)));
});

test('phala: a non-ecdsa signing_algo degrades to attestationRef-only (fails closed under requireProofs)', async () => {
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-phala-algo-'));
  const { fetchImpl } = stubGateway({ signingAlgo: 'ed25519' });
  const provider = new PhalaProvider({ archiveDir, apiKey: 'test-key', fetchImpl });
  const completion = await provider.complete({ modelId: MODEL, messages: [{ role: 'user', content: 'hi' }] });
  const proof = await provider.getProof(completion.raw);
  assert.equal(proof.signature, undefined, 'a signature we cannot verify is never mislabelled');
  assert.equal(proof.signatureScheme, undefined);
  const res = verifyProviderProof(proof, { referenceUnixMs: proof.fetchedAtUnixMs });
  assert.equal(res.ok, false);
});

test('phala: an expired/missing signature (HTTP 404) throws — proof fetch failed, seat excluded', async () => {
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-phala-404-'));
  const { fetchImpl } = stubGateway({ signatureStatus: 404 });
  const provider = new PhalaProvider({ archiveDir, apiKey: 'test-key', fetchImpl });
  const completion = await provider.complete({ modelId: MODEL, messages: [{ role: 'user', content: 'hi' }] });
  await assert.rejects(provider.getProof(completion.raw), /GET \/signature\/.* HTTP 404/);
});

test('phala: a completion without a chat id cannot fetch a signature — throws after archiving headers', async () => {
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-phala-noid-'));
  const { fetchImpl } = stubGateway({ omitChatId: true });
  const provider = new PhalaProvider({ archiveDir, apiKey: 'test-key', fetchImpl });
  const completion = await provider.complete({ modelId: MODEL, messages: [{ role: 'user', content: 'hi' }] });
  await assert.rejects(provider.getProof(completion.raw), /no chat id/);
  const archived = readdirSync(archiveDir);
  assert.ok(archived.some((f) => f.startsWith('phala_receipt_')), 'headers archived for the audit trail');
});
