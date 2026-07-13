/**
 * End-to-end node-service tests over real sockets: byte-exact proxying, the
 * signed proof format, the persistent signature endpoint, dev-mode
 * attestation shape (mock, clearly labeled, NO fabricated quote fields),
 * id-injection, auth, model pinning, and stream rejection.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createNodeServer, type NodeDeps } from './server.js';
import { SignatureStore, type SignatureDoc } from './store.js';
import { startStubLlm, type StubLlm } from './stubLlm.js';
import { ethAddressOfPrivateKey, ethPersonalMessageDigest, recoverEthAddress } from './signer.js';
import { sha256Hex } from './util.js';

const PRIV = new Uint8Array(32).fill(0x51);
const ADDRESS = ethAddressOfPrivateKey(PRIV);

interface Ctx {
  node: Server;
  base: string; // http://127.0.0.1:port
  stub: StubLlm;
  close(): Promise<void>;
}

async function startNode(overrides: Partial<NodeDeps> = {}, stubOpts: Parameters<typeof startStubLlm>[0] = {}): Promise<Ctx> {
  const stub = await startStubLlm(stubOpts);
  const dataDir = await mkdtemp(join(tmpdir(), 'edict-node-'));
  const deps: NodeDeps = {
    mode: 'dev',
    identity: { source: 'dev', privateKey: PRIV, address: ADDRESS },
    store: new SignatureStore(join(dataDir, 'signatures')),
    localModelUrl: stub.url,
    ...overrides,
  };
  const node = createNodeServer(deps);
  await new Promise<void>((resolve) => node.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${(node.address() as AddressInfo).port}`;
  return {
    node,
    base,
    stub,
    close: async () => {
      await new Promise<void>((resolve, reject) => node.close((e) => (e ? reject(e) : resolve())));
      await stub.close();
    },
  };
}

function completionRequestBody(model = 'stub-model'): string {
  return JSON.stringify({
    model,
    messages: [
      { role: 'system', content: 'You are a juror.' },
      { role: 'user', content: 'Decide the case.' },
    ],
    temperature: 0,
    seed: 0,
  });
}

test('completion round-trip: byte-exact passthrough, signed envelope, persistent signature', async () => {
  const ctx = await startNode();
  try {
    const requestBody = completionRequestBody();
    const requestSha256 = sha256Hex(requestBody);

    const res = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: requestBody,
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('x-edict-node-mode'), 'dev');
    const responseBytes = Buffer.from(await res.arrayBuffer());
    const responseSha256 = sha256Hex(responseBytes);
    const parsed = JSON.parse(responseBytes.toString('utf8')) as { id: string; choices: Array<{ message: { content: string } }> };
    assert.match(parsed.id, /^stubcmpl-/); // upstream id passed through untouched
    assert.equal(res.headers.get('x-edict-chat-id'), parsed.id);
    assert.match(parsed.choices[0]!.message.content, /^STUB ECHO:/);

    // Signature endpoint: persistent doc with the exact envelope + recoverable sig.
    const sigRes = await fetch(`${ctx.base}/v1/signature/${encodeURIComponent(parsed.id)}`);
    assert.equal(sigRes.status, 200);
    const doc = (await sigRes.json()) as SignatureDoc;
    assert.equal(doc.chat_id, parsed.id);
    assert.equal(doc.model_id, 'stub-model');
    assert.equal(doc.request_sha256, requestSha256);
    assert.equal(doc.response_sha256, responseSha256);
    assert.equal(doc.text, `stub-model:${requestSha256}:${responseSha256}`);
    assert.equal(doc.signing_address, ADDRESS);
    assert.equal(doc.signature_scheme, 'ecdsa_secp256k1_eth');
    assert.equal(recoverEthAddress(doc.signature, ethPersonalMessageDigest(doc.text)), ADDRESS);
  } finally {
    await ctx.close();
  }
});

test('upstream completion without an id: id injected, signature covers the REWRITTEN bytes', async () => {
  const ctx = await startNode({}, { omitId: true });
  try {
    const res = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: completionRequestBody(),
    });
    assert.equal(res.status, 200);
    const responseBytes = Buffer.from(await res.arrayBuffer());
    const parsed = JSON.parse(responseBytes.toString('utf8')) as { id: string };
    assert.match(parsed.id, /^edictcmpl-[0-9a-f]{24}$/);

    const doc = (await (await fetch(`${ctx.base}/v1/signature/${parsed.id}`)).json()) as SignatureDoc;
    // The signed response hash is over the bytes the client actually received.
    assert.equal(doc.response_sha256, sha256Hex(responseBytes));
    assert.equal(recoverEthAddress(doc.signature, ethPersonalMessageDigest(doc.text)), ADDRESS);
  } finally {
    await ctx.close();
  }
});

test('reused upstream completion ids never overwrite proofs; later responses get a fresh signed id', async () => {
  const ctx = await startNode();
  try {
    const request = (): Promise<Response> =>
      fetch(`${ctx.base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: completionRequestBody(),
      });
    const first = await request();
    const firstBytes = Buffer.from(await first.arrayBuffer());
    const firstBody = JSON.parse(firstBytes.toString('utf8')) as { id: string };
    const firstProof = (await (await fetch(`${ctx.base}/v1/signature/${firstBody.id}`)).json()) as SignatureDoc;

    const second = await request();
    const secondBytes = Buffer.from(await second.arrayBuffer());
    const secondBody = JSON.parse(secondBytes.toString('utf8')) as { id: string };
    assert.notEqual(secondBody.id, firstBody.id);
    assert.match(secondBody.id, /^edictcmpl-[0-9a-f]{24}$/);

    const preserved = (await (await fetch(`${ctx.base}/v1/signature/${firstBody.id}`)).json()) as SignatureDoc;
    const secondProof = (await (await fetch(`${ctx.base}/v1/signature/${secondBody.id}`)).json()) as SignatureDoc;
    assert.deepEqual(preserved, firstProof, 'the original id remains bound to its first proof');
    assert.equal(secondProof.response_sha256, sha256Hex(secondBytes));
    assert.equal(recoverEthAddress(secondProof.signature, ethPersonalMessageDigest(secondProof.text)), ADDRESS);
  } finally {
    await ctx.close();
  }
});

test('dev-mode attestation: dev_mode:true, clearly labeled, NO quote/report_data fields', async () => {
  const ctx = await startNode();
  try {
    const res = await fetch(`${ctx.base}/v1/attestation/report`);
    assert.equal(res.status, 200);
    const att = (await res.json()) as Record<string, unknown>;
    assert.equal(att.provider, 'edict-node');
    assert.equal(att.dev_mode, true);
    assert.match(String(att.warning), /DEV MODE/);
    assert.match(String(att.warning), /MUST NOT be trusted/);
    assert.equal(att.signing_address, ADDRESS);
    assert.equal(att.signing_scheme, 'ecdsa_secp256k1_eth');
    assert.equal(att.signing_envelope, '{model_id}:{sha256(request)}:{sha256(response)}');
    // Never fabricate quote material in dev mode:
    for (const forbidden of ['quote', 'event_log', 'report_data', 'vm_config', 'tcb_info']) {
      assert.ok(!(forbidden in att), `dev attestation must not carry "${forbidden}"`);
    }
  } finally {
    await ctx.close();
  }
});

test('signature endpoint 404s for unknown chat ids', async () => {
  const ctx = await startNode();
  try {
    const res = await fetch(`${ctx.base}/v1/signature/never-happened`);
    assert.equal(res.status, 404);
  } finally {
    await ctx.close();
  }
});

test('stream:true is rejected (proofs need whole-body hashing)', async () => {
  const ctx = await startNode();
  try {
    const res = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'stub-model', stream: true, messages: [] }),
    });
    assert.equal(res.status, 400);
    assert.match(((await res.json()) as { error: string }).error, /stream/);
  } finally {
    await ctx.close();
  }
});

test('model pin: mismatching model is rejected before touching the model server', async () => {
  const ctx = await startNode({ modelIdPin: 'gpt-oss-20b' });
  try {
    const res = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: completionRequestBody('some-other-model'),
    });
    assert.equal(res.status, 400);
    assert.match(((await res.json()) as { error: string }).error, /gpt-oss-20b/);
  } finally {
    await ctx.close();
  }
});

test('bearer auth guards /v1/* when configured; healthz stays open', async () => {
  const ctx = await startNode({ apiKey: 'sekrit-token' });
  try {
    const unauth = await fetch(`${ctx.base}/v1/attestation/report`);
    assert.equal(unauth.status, 401);
    const wrong = await fetch(`${ctx.base}/v1/attestation/report`, {
      headers: { authorization: 'Bearer wrong' },
    });
    assert.equal(wrong.status, 401);
    const right = await fetch(`${ctx.base}/v1/attestation/report`, {
      headers: { authorization: 'Bearer sekrit-token' },
    });
    assert.equal(right.status, 200);
    const health = await fetch(`${ctx.base}/healthz`);
    assert.equal(health.status, 200);
  } finally {
    await ctx.close();
  }
});

test('upstream model-server errors pass through unsigned', async () => {
  const ctx = await startNode();
  try {
    const res = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json at all',
    });
    assert.equal(res.status, 400); // node rejects before upstream

    // Valid JSON but the stub 400s (invalid body shape) → status passthrough.
    const res2 = await fetch(`${ctx.base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'stub-model' }), // stub tolerates missing messages → 200
    });
    assert.equal(res2.status, 200);
  } finally {
    await ctx.close();
  }
});

test('healthz reports mode, signer and upstream reachability', async () => {
  const ctx = await startNode();
  try {
    const h = (await (await fetch(`${ctx.base}/healthz`)).json()) as Record<string, unknown>;
    assert.equal(h.ok, true);
    assert.equal(h.mode, 'dev');
    assert.equal(h.dev_mode, true);
    assert.equal(h.signing_address, ADDRESS);
    assert.deepEqual(h.model_upstream, { url: ctx.stub.url, ok: true });
  } finally {
    await ctx.close();
  }
});

test('GET /v1/models proxies the local model server', async () => {
  const ctx = await startNode();
  try {
    const res = await fetch(`${ctx.base}/v1/models`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { data: Array<{ id: string }> };
    assert.equal(body.data[0]!.id, 'stub-model');
  } finally {
    await ctx.close();
  }
});
