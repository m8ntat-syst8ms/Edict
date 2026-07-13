/**
 * DocketStore unit tests over the committed illustrative corpus
 * (resilient to absent generated reports — only committed data is required).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { DocketStore, tokenize } from './docket.js';

test('loadCases reads every committed case with groundtruth', () => {
  const store = new DocketStore();
  const cases = store.loadCases();
  assert.equal(cases.length, 5, `expected 5 public examples, got ${cases.length}`);
  for (const c of cases) {
    assert.equal(typeof c.caseObj.caseId, 'string');
    assert.equal(typeof c.caseObj.decisionSpace.kind, 'string');
    assert.ok(c.groundtruth.expected !== undefined, `${c.slug} groundtruth.expected missing`);
  }
});

test('findCase resolves slugs and uuids case-insensitively', () => {
  const store = new DocketStore();
  const bySlug = store.findCase('c01-minerals-attestation');
  assert.ok(bySlug !== undefined);
  const byUuid = store.findCase(bySlug!.caseObj.caseId.toUpperCase());
  assert.equal(byUuid?.slug, 'c01-minerals-attestation');
  assert.equal(store.findCase('no-such-case'), undefined);
});

test('evidencePlaintext returns only bytes that hash to their commitments', () => {
  const store = new DocketStore();
  const c = store.findCase('c01-minerals-attestation')!;
  const plaintext = store.evidencePlaintext(c);
  const keys = Object.keys(plaintext);
  assert.ok(keys.length >= 3, 'c01 commits several uri-backed evidence files');
  for (const [sha, text] of Object.entries(plaintext)) {
    assert.equal(createHash('sha256').update(text).digest('hex'), sha);
  }
});

test('queryPrecedent ranks by keyword weight and honours tag filters', () => {
  const store = new DocketStore();
  const hits = store.queryPrecedent('partial milestone delivery split');
  assert.ok(hits.length >= 1);
  assert.ok(hits.some((h) => h.ref === 'c12-milestone-split'));
  assert.ok(hits[0]!.score >= hits[hits.length - 1]!.score, 'results sorted by descending score');

  const tagged = store.queryPrecedent('anything at all really', ['split']);
  for (const hit of tagged) assert.ok(hit.tags.includes('split'));

  assert.deepEqual(store.queryPrecedent('zzzunmatchable'), []);
});

test('tokenize drops stopwords and dedupes', () => {
  assert.deepEqual(tokenize('the case of the FORGED forged manifest'), ['forged', 'manifest']);
});
