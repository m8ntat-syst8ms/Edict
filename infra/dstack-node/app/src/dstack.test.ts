/**
 * DstackClient tests against a local unix-socket HTTP stub that mimics the
 * guest agent RPC surface (POST /GetKey, POST /GetQuote, GET /Info — shapes
 * per Dstack-TEE/dstack sdk/curl/api.md). Pins the exact request bodies the
 * client sends.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DstackClient } from './dstack.js';

interface Captured {
  method: string;
  path: string;
  body: unknown;
}

async function startAgentStub(): Promise<{ socketPath: string; captured: Captured[]; close(): Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'dstk-'));
  const socketPath = join(dir, 'agent.sock');
  const captured: Captured[] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const body = raw.length > 0 ? (JSON.parse(raw) as unknown) : undefined;
      captured.push({ method: req.method ?? '', path: req.url ?? '', body });
      const send = (status: number, obj: unknown): void => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(obj));
      };
      if (req.url === '/GetKey') {
        send(200, { key: 'ab'.repeat(32), signature_chain: ['cd'.repeat(65), 'ef'.repeat(65)] });
      } else if (req.url === '/GetQuote') {
        const rd = (body as { report_data?: string })?.report_data ?? '';
        send(200, { quote: '040002'.repeat(10), event_log: '[]', report_data: rd.padEnd(128, '0'), vm_config: '{}' });
      } else if (req.url === '/Info') {
        send(200, { app_id: 'app_123', instance_id: 'inst_456', compose_hash: 'ch_789', tcb_info: {} });
      } else if (req.url === '/Boom') {
        send(500, { error: 'kaboom' });
      } else {
        send(400, { error: `no route ${req.url}` });
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  return {
    socketPath,
    captured,
    close: () => new Promise((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

test('getKey POSTs {path,purpose,algorithm} to /GetKey and parses key + signature_chain', async () => {
  const stub = await startAgentStub();
  try {
    const client = new DstackClient(stub.socketPath);
    const res = await client.getKey('edict/proof-signing', 'edict-node-proof-signing-v1');
    assert.equal(res.key, 'ab'.repeat(32));
    assert.equal(res.signature_chain.length, 2);
    assert.deepEqual(stub.captured[0], {
      method: 'POST',
      path: '/GetKey',
      body: { path: 'edict/proof-signing', purpose: 'edict-node-proof-signing-v1', algorithm: 'secp256k1' },
    });
  } finally {
    await stub.close();
  }
});

test('getQuote POSTs hex report_data and returns the quote fields', async () => {
  const stub = await startAgentStub();
  try {
    const client = new DstackClient(stub.socketPath);
    const rd = 'a1'.repeat(32); // 32 bytes
    const res = await client.getQuote(rd);
    assert.equal(res.quote, '040002'.repeat(10));
    assert.equal(res.event_log, '[]');
    assert.deepEqual(stub.captured[0]!.body, { report_data: rd });
  } finally {
    await stub.close();
  }
});

test('getQuote rejects non-hex / oversized report_data locally', async () => {
  const client = new DstackClient('/nonexistent.sock');
  await assert.rejects(() => client.getQuote('zz'), /report_data/);
  await assert.rejects(() => client.getQuote('ab'.repeat(65)), /report_data/); // 65 bytes > 64
});

test('info GETs /Info', async () => {
  const stub = await startAgentStub();
  try {
    const client = new DstackClient(stub.socketPath);
    const res = await client.info();
    assert.equal(res.app_id, 'app_123');
    assert.equal(res.compose_hash, 'ch_789');
    assert.equal(stub.captured[0]!.method, 'GET');
    assert.equal(stub.captured[0]!.path, '/Info');
  } finally {
    await stub.close();
  }
});

test('agent error responses surface as thrown errors', async () => {
  const stub = await startAgentStub();
  try {
    const client = new DstackClient(stub.socketPath);
    await assert.rejects(
      () => (client as unknown as { rpc(p: string, m: 'POST', b: unknown): Promise<unknown> }).rpc('/Boom', 'POST', {}),
      /kaboom/,
    );
  } finally {
    await stub.close();
  }
});

test('unreachable socket → clear error', async () => {
  const client = new DstackClient('/definitely/not/a/socket.sock');
  await assert.rejects(() => client.info(), /unreachable/);
});
