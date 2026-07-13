/**
 * Path-containment + evidence-integrity tests for the DocketStore (and the
 * `edict_explain_ruling` tool output built on it), over a throwaway fixture
 * corpus: a copy of the real c01 case with hostile evidence commitments added
 * (traversal uri, absolute-path uri, symlink escaping the case dir, tampered
 * bytes) plus a secret file OUTSIDE the docket root that must never leak.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from '@edict/evidence';
import { DocketStore, type EvidenceIntegrityFailure } from './docket.js';
import { explainRuling } from './docketTools.js';
import { containedRealpath, EVIDENCE_URI_RE, readFileContained, SLUG_RE } from './safeRead.js';
import type { SessionStore } from './session.js';

const SECRET = 'TOP-SECRET: bytes outside the docket root must never appear in tool output';
const TAMPERED_COMMITTED_TEXT = 'the originally committed pleading text';
const TAMPERED_SHA = sha256Hex(TAMPERED_COMMITTED_TEXT);
const GOOD_TEXT = 'a verified extra pleading\n';
const GOOD_SHA = sha256Hex(GOOD_TEXT);

interface Fixture {
  tmp: string;
  root: string; // the docket root (contains cases/)
  caseDir: string;
  secretFile: string; // OUTSIDE root
}

/** Copy the real c01 case into <tmp>/docket and add hostile evidence entries. */
function makeFixture(): Fixture {
  const here = dirname(fileURLToPath(import.meta.url)); // apps/mcp-server/dist
  const realCase = join(here, '..', '..', 'shadow-docket', 'cases', 'c01-minerals-attestation');

  const tmp = mkdtempSync(join(tmpdir(), 'edict-docket-sec-'));
  const root = join(tmp, 'docket');
  const caseDir = join(root, 'cases', 'f01-fixture');
  mkdirSync(join(root, 'cases'), { recursive: true });
  cpSync(realCase, caseDir, { recursive: true });

  const outside = join(tmp, 'outside');
  mkdirSync(outside);
  const secretFile = join(outside, 'secrets');
  writeFileSync(secretFile, SECRET);
  const secretSha = sha256Hex(SECRET);

  // Tampered file: bytes on disk differ from the committed hash.
  writeFileSync(join(caseDir, 'evidence', 'tampered.txt'), 'EDITED AFTER COMMITMENT');
  // Verified extra file: happy path.
  writeFileSync(join(caseDir, 'evidence', 'good.txt'), GOOD_TEXT);
  // Real symlink inside evidence/ pointing OUTSIDE the case dir (and root).
  symlinkSync(secretFile, join(caseDir, 'evidence', 'escape-link.txt'));

  const caseJson = join(caseDir, 'case.json');
  const caseObj = JSON.parse(readFileContained(root, caseJson)!) as {
    evidence: Array<Record<string, unknown>>;
  };
  const hostile = (uri: string, sha256: string): Record<string, unknown> => ({
    kind: 'party_submission',
    sha256,
    submitter: 'worker',
    uri,
    authenticated: false,
  });
  caseObj.evidence.push(
    // Committed hashes MATCH the secret bytes → only containment can stop these.
    hostile('../../../outside/secrets', secretSha),
    hostile(secretFile, secretSha), // absolute path
    hostile('evidence/escape-link.txt', secretSha), // symlink escape
    hostile('evidence/tampered.txt', TAMPERED_SHA), // bytes edited after commitment
    hostile('evidence/good.txt', GOOD_SHA), // verified happy path
    hostile('vault://sealed-elsewhere', sha256Hex('sealed')), // non-local uri stays sealed
  );
  writeFileSync(caseJson, JSON.stringify(caseObj, null, 2));
  return { tmp, root, caseDir, secretFile };
}

test('docket evidence loading: containment + integrity', async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.tmp, { recursive: true, force: true }));
  const store = new DocketStore(fx.root);
  const c = store.findCase('f01-fixture');
  assert.ok(c !== undefined, 'fixture case loads');

  const { plaintext, integrityFailed } = store.loadEvidence(c!);

  await t.test('traversal, absolute-path and symlink uris never leak outside bytes', () => {
    const values = Object.values(plaintext);
    assert.ok(!values.includes(SECRET), 'secret bytes must not be loaded');
    assert.equal(plaintext[sha256Hex(SECRET)], undefined, 'no entry under the secret hash');
    // Containment rejections are "sealed", NOT integrity failures (nothing was read).
    assert.ok(!integrityFailed.some((f) => f.uri.includes('secrets') || f.uri.includes('escape-link')));
  });

  await t.test('hash mismatch is excluded with an explicit integrity_failed marker', () => {
    assert.equal(plaintext[TAMPERED_SHA], undefined, 'tampered bytes excluded from plaintext');
    const marker = integrityFailed.find((f) => f.uri === 'evidence/tampered.txt');
    assert.deepEqual(marker, {
      sha256: TAMPERED_SHA,
      uri: 'evidence/tampered.txt',
      status: 'integrity_failed',
    } satisfies EvidenceIntegrityFailure);
  });

  await t.test('happy path: verified evidence still loads, keyed by committed sha256', () => {
    assert.equal(plaintext[GOOD_SHA], GOOD_TEXT);
    // The six original (untampered) c01 files still verify.
    for (const [sha, text] of Object.entries(plaintext)) assert.equal(sha256Hex(text), sha);
    assert.ok(Object.keys(plaintext).length >= 6, `expected ≥6 verified plaintexts, got ${Object.keys(plaintext).length}`);
    assert.deepEqual(store.evidencePlaintext(c!), plaintext, 'evidencePlaintext is the verified map');
  });

  await t.test('edict_explain_ruling excludes tampered evidence and marks it integrity_failed', () => {
    const session: SessionStore = new Map();
    const out = explainRuling({ caseId: 'f01-fixture' }, store, session);
    const failures = out['evidenceIntegrityFailures'] as EvidenceIntegrityFailure[];
    assert.ok(Array.isArray(failures), 'tool output carries evidenceIntegrityFailures');
    assert.deepEqual(failures, [{ sha256: TAMPERED_SHA, uri: 'evidence/tampered.txt', status: 'integrity_failed' }]);
    const notes = (out['notes'] ?? []) as string[];
    assert.ok(notes.some((n) => n.includes('integrity_failed')), 'notes mention the exclusion');
    assert.ok(!JSON.stringify(out).includes(SECRET), 'secret bytes never reach tool output');
  });

  await t.test('verdict/reasoning lookups refuse traversal caseIds', () => {
    // A hash-valid JSON file outside the reports tree that traversal would reach.
    writeFileSync(join(fx.tmp, 'outside', 'evil.json'), JSON.stringify({ caseId: 'evil', ruling: 'worker_wins' }));
    assert.equal(store.verdict('../../outside/evil'), undefined);
    assert.equal(store.verdict('/etc/hosts'), undefined);
    assert.equal(store.reasoning('../../outside'), undefined);
    assert.equal(store.reasoning('.hidden'), undefined);
  });

  await t.test('verdict/reasoning still resolve legitimate generated reports', () => {
    const caseId = c!.caseObj.caseId;
    mkdirSync(join(fx.root, 'reports', 'verdicts'), { recursive: true });
    mkdirSync(join(fx.root, 'reports', 'archive', caseId), { recursive: true });
    writeFileSync(
      join(fx.root, 'reports', 'verdicts', `${caseId}.json`),
      JSON.stringify({ caseId, ruling: 'worker_wins', final: true }),
    );
    writeFileSync(
      join(fx.root, 'reports', 'archive', caseId, 'reasoning.json'),
      JSON.stringify({ version: 'arbiter-reasoning-v1' }),
    );
    assert.equal(store.verdict(caseId)?.ruling, 'worker_wins');
    assert.equal(store.reasoning(caseId)?.['version'], 'arbiter-reasoning-v1');
    // A verdicts/ symlink target outside the root is refused even with a safe caseId.
    symlinkSync(join(fx.tmp, 'outside', 'evil.json'), join(fx.root, 'reports', 'verdicts', 'linked.json'));
    assert.equal(store.verdict('linked'), undefined);
  });
});

test('safeRead primitives', async (t) => {
  await t.test('EVIDENCE_URI_RE allows exactly one segment under evidence/', () => {
    assert.ok(EVIDENCE_URI_RE.test('evidence/order_mandate.json'));
    for (const bad of [
      '../../secrets',
      '/etc/passwd',
      'evidence/../case.json',
      'evidence/nested/file.txt',
      'evidence/.hidden',
      'vault://abc',
      'ipfs://Qm123',
      'evidence\\..\\case.json',
    ]) {
      assert.ok(!EVIDENCE_URI_RE.test(bad), `must reject ${bad}`);
    }
  });

  await t.test('SLUG_RE rejects separators and dot-prefixed names', () => {
    assert.ok(SLUG_RE.test('c01-minerals-attestation'));
    assert.ok(SLUG_RE.test('d0c4e7a0-0001-4e01-8e01-000000000001'));
    for (const bad of ['../up', 'a/b', '..', '.git', '', 'a b']) assert.ok(!SLUG_RE.test(bad), `must reject ${bad}`);
  });

  await t.test('containedRealpath requires strict containment after symlink resolution', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'edict-saferead-'));
    t.after(() => rmSync(tmp, { recursive: true, force: true }));
    const root = join(tmp, 'root');
    mkdirSync(join(root, 'sub'), { recursive: true });
    writeFileSync(join(root, 'sub', 'ok.txt'), 'ok');
    writeFileSync(join(tmp, 'outside.txt'), 'outside');
    symlinkSync(join(tmp, 'outside.txt'), join(root, 'sub', 'link.txt'));

    assert.ok(containedRealpath(root, join(root, 'sub', 'ok.txt')) !== undefined);
    assert.equal(containedRealpath(root, root), undefined, 'the root itself is not strictly inside');
    assert.equal(containedRealpath(root, join(root, 'sub', 'link.txt')), undefined, 'symlink escape refused');
    assert.equal(containedRealpath(root, join(root, '..', 'outside.txt')), undefined, 'traversal refused');
    assert.equal(containedRealpath(root, join(root, 'missing.txt')), undefined, 'missing file refused');
    assert.equal(readFileContained(root, join(root, 'sub', 'link.txt')), undefined);
    assert.equal(readFileContained(root, join(root, 'sub', 'ok.txt')), 'ok');
  });
});
