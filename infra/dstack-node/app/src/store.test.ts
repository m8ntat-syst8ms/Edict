/**
 * Signature store tests — persistence with NO expiry (the fix for the
 * NEAR AI / Phala signature-cache weakness), atomicity, and filename safety.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SignatureConflictError, SignatureStore, type SignatureDoc } from './store.js';

function mkDoc(chatId: string): SignatureDoc {
  return {
    api_version: 'edict-node/1',
    chat_id: chatId,
    model_id: 'gpt-oss-20b',
    request_sha256: 'a'.repeat(64),
    response_sha256: 'b'.repeat(64),
    text: `gpt-oss-20b:${'a'.repeat(64)}:${'b'.repeat(64)}`,
    signature: `0x${'11'.repeat(65)}`,
    signing_address: `0x${'22'.repeat(20)}`,
    signing_algo: 'ecdsa',
    signature_scheme: 'ecdsa_secp256k1_eth',
    created_at_unix_ms: 1_750_000_000_000,
  };
}

test('put/get round-trip and persistence across store instances (no expiry)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edict-store-'));
  const store = new SignatureStore(dir);
  await store.put(mkDoc('chatcmpl-123'));

  // A NEW instance over the same dir still serves it — pure on-disk state.
  const reopened = new SignatureStore(dir);
  const got = await reopened.get('chatcmpl-123');
  assert.deepEqual(got, mkDoc('chatcmpl-123'));

  // No temp files left behind (atomic rename).
  const files = await readdir(dir);
  assert.equal(files.length, 1);
  assert.ok(!files[0]!.includes('.tmp-'), `leftover temp file: ${files[0]}`);
});

test('missing chat id → undefined', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edict-store-'));
  const store = new SignatureStore(dir);
  assert.equal(await store.get('nope'), undefined);
});

test('hostile chat ids are sanitized AND disambiguated (no collision, no traversal)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edict-store-'));
  const store = new SignatureStore(dir);
  const a = '../../etc/passwd';
  const b = './../.etc.passwd'; // sanitizes to a similar name — hash suffix must split them
  await store.put(mkDoc(a));
  await store.put(mkDoc(b));

  assert.equal((await store.get(a))!.chat_id, a);
  assert.equal((await store.get(b))!.chat_id, b);
  const files = await readdir(dir);
  assert.equal(files.length, 2);
  for (const f of files) assert.ok(!f.includes('/'), `path separator escaped sanitization: ${f}`);
});

test('chat ids are immutable: exact replay is idempotent, different proof conflicts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edict-store-'));
  const store = new SignatureStore(dir);
  const original = mkDoc('x');
  await store.put(original);
  await store.put(original);
  const updated = { ...mkDoc('x'), created_at_unix_ms: 1_750_000_000_999 };
  await assert.rejects(store.put(updated), SignatureConflictError);
  assert.deepEqual(await store.get('x'), original);
});
