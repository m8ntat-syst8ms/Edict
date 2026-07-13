import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { archiveWriteImmutable } from './util.js';

test('archiveWriteImmutable content-addresses reused provider ids instead of overwriting proof material', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'edict-proof-archive-'));
  const first = await archiveWriteImmutable(dir, 'provider_signature_same-id.json', '{"proof":1}');
  const second = await archiveWriteImmutable(dir, 'provider_signature_same-id.json', '{"proof":2}');
  assert.notEqual(first, second);
  assert.equal(await readFile(first, 'utf8'), '{"proof":1}');
  assert.equal(await readFile(second, 'utf8'), '{"proof":2}');
  assert.equal(await archiveWriteImmutable(dir, 'provider_signature_same-id.json', '{"proof":1}'), first);
});
