#!/usr/bin/env node
/**
 * Dev-mode end-to-end verification of the edict-node proof chain, using the
 * ARBITER'S OWN client + verifier (no re-implementation):
 *
 *   1. boot a stub OpenAI-compatible "LLM" (node:http echo — no model
 *      download) and the edict-node service in DEV MODE in front of it
 *   2. run one completion through services/arbiter's OpenAICompatibleProvider
 *      pointed at the node
 *   3. GET /v1/signature/{chat_id} + /v1/attestation/report (archived)
 *   4. verifyProviderProof(scheme ecdsa_secp256k1_eth) → MUST be ok:true,
 *      plus tamper/allowlist negative controls that MUST fail
 *
 * Prereqs: `npm run build -w @edict/arbiter -w @edict/dstack-node` from the
 * repo root. Run: `node infra/dstack-node/scripts/dev-verify.mjs`
 */
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// --- arbiter side (the consumer we must satisfy) ---------------------------
import { OpenAICompatibleProvider } from '../../../services/arbiter/dist/providers/openaiCompatible.js';
import { verifyProviderProof } from '../../../services/arbiter/dist/index.js';

// --- node side (the operator #3 service under test) -------------------------
import { createNodeServer } from '../app/dist/server.js';
import { SignatureStore } from '../app/dist/store.js';
import { resolveDevIdentity } from '../app/dist/identity.js';
import { startStubLlm } from '../app/dist/stubLlm.js';

const MODEL_ID = 'gpt-oss-20b';

function check(name, cond, detail = '') {
  if (!cond) {
    console.error(`FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
    process.exitCode = 1;
    return false;
  }
  console.log(`ok    ${name}`);
  return true;
}

const workDir = await mkdtemp(join(tmpdir(), 'edict-dev-verify-'));
console.log(`[dev-verify] work dir: ${workDir}`);

// 1. stub model server + edict-node (dev mode) in-process
const stub = await startStubLlm({});
const identity = await resolveDevIdentity({ dataDir: workDir, devPrivateKeyHex: undefined });
const node = createNodeServer({
  mode: 'dev',
  identity,
  store: new SignatureStore(join(workDir, 'signatures')),
  localModelUrl: stub.url,
});
await new Promise((resolve) => node.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${node.address().port}`;
console.log(`[dev-verify] edict-node (DEV MODE) at ${base}, signer ${identity.address}`);

try {
  // 2. one completion through the ARBITER's provider
  const provider = new OpenAICompatibleProvider({
    id: 'edict-node',
    baseUrl: `${base}/v1`,
    supportsSeed: true,
  });
  const completion = await provider.complete({
    modelId: MODEL_ID,
    messages: [
      { role: 'system', content: 'You are jury seat edict-node:gpt-oss-20b.' },
      { role: 'user', content: 'State the verdict for the fixture case.' },
    ],
    maxTokens: 64,
  });
  const capture = completion.raw;
  const chatId = capture.parsed?.id;
  check('completion returned text through OpenAICompatibleProvider', completion.text.length > 0);
  check('completion response carries a chat id', typeof chatId === 'string' && chatId.length > 0);

  // 3. fetch the persistent signature + the (dev, mock) attestation report
  const sigRes = await fetch(`${base}/v1/signature/${encodeURIComponent(chatId)}`);
  check('GET /v1/signature/{chat_id} → 200', sigRes.status === 200, `got ${sigRes.status}`);
  const sigDoc = await sigRes.json();
  check(
    'signature doc envelope matches the captured hashes',
    sigDoc.text === `${MODEL_ID}:${completion.requestSha256}:${completion.responseSha256}`,
    sigDoc.text,
  );

  const attRes = await fetch(`${base}/v1/attestation/report`);
  check('GET /v1/attestation/report → 200', attRes.status === 200, `got ${attRes.status}`);
  const attBody = await attRes.text();
  const att = JSON.parse(attBody);
  check('attestation is clearly-labeled DEV MODE (dev_mode:true)', att.dev_mode === true);
  check('dev attestation fabricates NO quote fields', !('quote' in att) && !('report_data' in att));
  const attPath = join(workDir, 'edict-node_attestation_dev.json');
  await writeFile(attPath, attBody, 'utf8');

  // 4. verifyProviderProof — the arbiter's REAL gate (scheme ecdsa_secp256k1_eth)
  const proof = {
    providerId: 'edict-node',
    modelId: MODEL_ID,
    requestSha256: completion.requestSha256,
    responseSha256: completion.responseSha256,
    signature: sigDoc.signature,
    signatureScheme: 'ecdsa_secp256k1_eth',
    signingAddress: sigDoc.signing_address,
    attestationRef: attPath,
    fetchedAtUnixMs: Date.now(),
  };
  const opts = {
    expectedModelId: MODEL_ID,
    expectedRequestSha256: completion.requestSha256,
    expectedResponseSha256: completion.responseSha256,
    referenceUnixMs: Date.now(),
    signerAllowlist: { 'edict-node': [sigDoc.signing_address] },
  };

  const verdict = verifyProviderProof(proof, opts);
  check(
    'verifyProviderProof(ecdsa_secp256k1_eth) → ok:true',
    verdict.ok === true,
    verdict.ok ? '' : verdict.reason,
  );

  // negative controls — the gate must actually bite
  const tampered = verifyProviderProof({ ...proof, responseSha256: 'f'.repeat(64) }, opts);
  check('tampered responseSha256 → ok:false', tampered.ok === false);
  const wrongSigner = verifyProviderProof(proof, {
    ...opts,
    signerAllowlist: { 'edict-node': [`0x${'00'.repeat(20)}`] },
  });
  check('non-allowlisted signer → ok:false', wrongSigner.ok === false);

  if (process.exitCode !== 1) {
    console.log('');
    console.log('PASS — edict-node proof chain verifies through the arbiter pipeline.');
    console.log(`      signer: ${sigDoc.signing_address}  (DEV key — never allowlist for real cases)`);
    console.log(`      envelope: ${sigDoc.text.slice(0, 80)}…`);
    console.log(`      archived attestation: ${attPath}`);
  }
} finally {
  await new Promise((resolve) => node.close(resolve));
  await stub.close();
}
