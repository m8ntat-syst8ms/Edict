import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ethPersonalMessageDigest, verifyProviderProof } from '../pipeline/proofVerify.js';
import { sha256Hex } from '../util.js';
import {
  EDICT_NODE_REPORT_DATA_CONTEXT,
  EdictNodeProvider,
} from './edictNode.js';

const PRIVATE_KEY = new Uint8Array(32).fill(0x61);
const SIGNER = `0x${Buffer.from(keccak_256(secp256k1.getPublicKey(PRIVATE_KEY, false).slice(1)).slice(-20)).toString('hex')}`;
const MODEL = 'gpt-oss-20b';
const CHAT_ID = 'edictcmpl-provider-test';

function sign(envelope: string): string {
  const raw = secp256k1.sign(ethPersonalMessageDigest(envelope), PRIVATE_KEY, {
    format: 'recovered',
    prehash: false,
  });
  return `0x${Buffer.concat([Buffer.from(raw.slice(1)), Buffer.from([raw[0]! + 27])]).toString('hex')}`;
}

function stubNode(opts: { devMode?: boolean; badReportData?: boolean } = {}): typeof fetch {
  let requestSha256 = '';
  const responseBody = JSON.stringify({
    id: CHAT_ID,
    model: MODEL,
    choices: [{ message: { role: 'assistant', content: '{"ruling":{"kind":"worker_wins"}}' } }],
  });
  const responseSha256 = sha256Hex(responseBody);
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/chat/completions')) {
      requestSha256 = sha256Hex(String(init?.body));
      return new Response(responseBody, { status: 200 });
    }
    if (url.includes('/signature/')) {
      const text = `${MODEL}:${requestSha256}:${responseSha256}`;
      return new Response(JSON.stringify({
        api_version: 'edict-node/1',
        chat_id: CHAT_ID,
        model_id: MODEL,
        request_sha256: requestSha256,
        response_sha256: responseSha256,
        text,
        signature: sign(text),
        signing_address: SIGNER,
        signature_scheme: 'ecdsa_secp256k1_eth',
      }));
    }
    if (url.includes('/attestation/report')) {
      if (opts.devMode === true) {
        return new Response(JSON.stringify({
          provider: 'edict-node', api_version: 'edict-node/1', signing_address: SIGNER, dev_mode: true,
        }));
      }
      const reportData = sha256Hex(`${EDICT_NODE_REPORT_DATA_CONTEXT}:${SIGNER}:${responseSha256}`);
      return new Response(JSON.stringify({
        provider: 'edict-node',
        api_version: 'edict-node/1',
        signing_address: SIGNER,
        dev_mode: false,
        nonce: responseSha256,
        report_data: opts.badReportData === true ? '0'.repeat(64) : reportData,
        quote: '04deadbeef',
      }));
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
}

test('edict-node provider validates online attestation binding and emits a verifiable proof', async () => {
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-node-provider-'));
  const provider = new EdictNodeProvider({
    archiveDir,
    baseUrl: 'https://node.example/v1',
    apiKey: 'test',
    fetchImpl: stubNode(),
  });
  const completion = await provider.complete({ modelId: MODEL, messages: [{ role: 'user', content: 'decide' }] });
  const proof = await provider.getProof(completion.raw);
  assert.deepEqual(
    verifyProviderProof(proof, {
      expectedModelId: MODEL,
      expectedRequestSha256: completion.requestSha256,
      expectedResponseSha256: completion.responseSha256,
      referenceUnixMs: proof.fetchedAtUnixMs,
      signerAllowlist: { 'edict-node': [SIGNER] },
    }),
    { ok: true },
  );
  const files = readdirSync(archiveDir);
  assert.ok(files.some((f) => f.startsWith('edict_node_signature_')));
  assert.ok(files.some((f) => f.startsWith('edict_node_attestation_')));
});

test('edict-node provider rejects dev attestations and broken report-data binding', async () => {
  for (const [fetchImpl, pattern] of [
    [stubNode({ devMode: true }), /dev_mode attestation/],
    [stubNode({ badReportData: true }), /report_data mismatch/],
  ] as const) {
    const provider = new EdictNodeProvider({
      archiveDir: mkdtempSync(join(tmpdir(), 'edict-node-provider-bad-')),
      baseUrl: 'https://node.example/v1',
      fetchImpl,
    });
    const completion = await provider.complete({ modelId: MODEL, messages: [{ role: 'user', content: 'decide' }] });
    await assert.rejects(provider.getProof(completion.raw), pattern);
  }
});
