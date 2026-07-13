import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  canonicalize,
  sha256Hex,
  sha256Canonical,
  normalizeSha256,
  GENESIS_HEAD,
  appendToChain,
  HashChain,
} from './hash.js';

// ---------------------------------------------------------------------------
// canonicalize
// ---------------------------------------------------------------------------

test('canonicalize: key insertion order does not change the output', () => {
  const a = { b: 1, a: 2, c: { z: true, y: [1, 2] } };
  const c1 = { z: true, y: [1, 2] };
  const b: Record<string, unknown> = {};
  b.c = c1;
  b.a = 2;
  b.b = 1;
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(sha256Canonical(a), sha256Canonical(b));
});

test('canonicalize: nested keys are sorted and output has no whitespace', () => {
  assert.equal(canonicalize({ b: { d: 1, c: 2 }, a: 'x' }), '{"a":"x","b":{"c":2,"d":1}}');
});

test('canonicalize: undefined object properties are omitted', () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }));
});

test('canonicalize: undefined array elements serialise as null', () => {
  assert.equal(canonicalize([1, undefined, 2]), '[1,null,2]');
});

test('canonicalize: array order is significant', () => {
  assert.notEqual(canonicalize([1, 2]), canonicalize([2, 1]));
});

test('canonicalize: round-trips through JSON.parse', () => {
  const obj = { z: [1, 'two', null, { b: false, a: 1.5 }], a: 'end' };
  assert.deepEqual(JSON.parse(canonicalize(obj)), obj);
});

test('canonicalize: rejects non-finite numbers, bigint, and non-plain objects', () => {
  assert.throws(() => canonicalize(NaN), TypeError);
  assert.throws(() => canonicalize(Infinity), TypeError);
  assert.throws(() => canonicalize(10n as unknown), TypeError);
  assert.throws(() => canonicalize(new Date() as unknown), TypeError);
  assert.throws(() => canonicalize(new Map() as unknown), TypeError);
});

test('canonicalize: escapes strings exactly like JSON.stringify', () => {
  assert.equal(canonicalize('a"b\n '), JSON.stringify('a"b\n '));
});

// ---------------------------------------------------------------------------
// sha256 helpers
// ---------------------------------------------------------------------------

test('sha256Hex: matches node:crypto directly for bytes and strings', () => {
  const bytes = new TextEncoder().encode('edict');
  assert.equal(sha256Hex(bytes), createHash('sha256').update(bytes).digest('hex'));
  assert.equal(sha256Hex('edict'), sha256Hex(bytes)); // string input = UTF-8 bytes
});

test('normalizeSha256: lowercases, strips 0x, rejects malformed', () => {
  const h = sha256Hex('x');
  assert.equal(normalizeSha256(`0x${h.toUpperCase()}`), h);
  assert.equal(normalizeSha256(h), h);
  assert.equal(normalizeSha256('deadbeef'), null);
  assert.equal(normalizeSha256(`${h}00`), null);
  assert.equal(normalizeSha256('zz'.repeat(32)), null);
});

// ---------------------------------------------------------------------------
// hash chain
// ---------------------------------------------------------------------------

test('appendToChain: newHead = sha256(prevHeadHex + entryHex)', () => {
  const entry = sha256Hex('entry-1');
  assert.equal(appendToChain(GENESIS_HEAD, entry), sha256Hex(GENESIS_HEAD + entry));
});

test('appendToChain: normalises case and 0x prefix, rejects garbage', () => {
  const entry = sha256Hex('entry-1');
  assert.equal(appendToChain(GENESIS_HEAD, `0x${entry.toUpperCase()}`), appendToChain(GENESIS_HEAD, entry));
  assert.throws(() => appendToChain(GENESIS_HEAD, 'not-a-hash'), TypeError);
  assert.throws(() => appendToChain('short', entry), TypeError);
});

test('HashChain: head/length track appends; empty chain heads at genesis', () => {
  const chain = new HashChain();
  assert.equal(chain.head(), GENESIS_HEAD);
  assert.equal(chain.length(), 0);

  const e1 = sha256Hex('log line 1');
  const e2 = sha256Hex('log line 2');
  const h1 = chain.append(e1);
  const h2 = chain.append(e2);
  assert.equal(h1, appendToChain(GENESIS_HEAD, e1));
  assert.equal(h2, appendToChain(h1, e2));
  assert.equal(chain.head(), h2);
  assert.equal(chain.length(), 2);
});

test('HashChain.verify: accepts the true sequence, rejects any tampering', () => {
  const entries = ['a', 'b', 'c'].map((s) => sha256Hex(s));
  const chain = new HashChain(entries);

  assert.equal(chain.verify(entries), true);
  assert.equal(chain.verify([entries[0], entries[2], entries[1]]), false); // reordered
  assert.equal(chain.verify(entries.slice(0, 2)), false); // truncated
  assert.equal(chain.verify([...entries, sha256Hex('d')]), false); // extended
  const tampered = [...entries];
  tampered[1] = sha256Hex('B');
  assert.equal(chain.verify(tampered), false); // modified
  assert.equal(chain.verify(['nonsense']), false); // invalid entries do not throw
});

test('HashChain: constructor replay equals incremental appends and computeHead', () => {
  const entries = [sha256Hex('1'), sha256Hex('2'), sha256Hex('3')];
  const replayed = new HashChain(entries);
  const incremental = new HashChain();
  for (const e of entries) incremental.append(e);
  assert.equal(replayed.head(), incremental.head());
  assert.equal(HashChain.computeHead(entries), replayed.head());
  assert.equal(HashChain.computeHead([]), GENESIS_HEAD);
});
