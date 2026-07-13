import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { AcceptanceCriterion } from '@edict/core';
import { sha256Hex, sha256Canonical } from './hash.js';
import {
  assertValidDeliveryManifest,
  canonicalDeliveryManifestHash,
  validateDeliveryManifest,
  verifyDeliveryManifestHash,
  buildEvidenceCommitment,
} from './deliveryManifest.js';
import { runMachineChecks, validateStructuralSchema } from './acceptance.js';
import { makeOrderMandate, makeManifest, artifacts, ARTIFACT_SHA256 } from './fixtures.test.js';

function statusOf(report: ReturnType<typeof runMachineChecks>, id: string) {
  const r = report.results.find((x) => x.criterionId === id);
  assert.ok(r, `no result for ${id}`);
  return r.status;
}

// ---------------------------------------------------------------------------
// Happy path across all kinds
// ---------------------------------------------------------------------------

test('runMachineChecks: full fixture — passes deterministic checks, skips non-deterministic ones', () => {
  const om = makeOrderMandate();
  const report = runMachineChecks(om, makeManifest(om), artifacts());

  assert.equal(report.mandateBound, true);
  assert.equal(statusOf(report, 'AC-1'), 'pass'); // hash_equals (manifest + bytes)
  assert.equal(statusOf(report, 'AC-2'), 'pass'); // deadline_before
  assert.equal(statusOf(report, 'AC-3'), 'pass'); // contains in artifact
  assert.equal(statusOf(report, 'AC-4'), 'pass'); // schema_valid
  assert.equal(statusOf(report, 'AC-5'), 'skipped'); // custom -> arbiter
  assert.equal(statusOf(report, 'AC-6'), 'skipped'); // no machineCheck -> arbiter
  assert.equal(report.passed, 4);
  assert.equal(report.failed, 0);
  assert.equal(report.skipped, 2);
  assert.equal(report.allDeterministicPassed, true);
});

test('runMachineChecks: is deterministic (same inputs, same report)', () => {
  const om = makeOrderMandate();
  const a = runMachineChecks(om, makeManifest(om), artifacts());
  const b = runMachineChecks(om, makeManifest(om), artifacts());
  assert.deepEqual(a, b);
});

// ---------------------------------------------------------------------------
// hash_equals failure paths
// ---------------------------------------------------------------------------

test('hash_equals: fails when the artifact is missing from the manifest', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om, { artifactHashes: [] });
  const report = runMachineChecks(om, manifest, artifacts());
  assert.equal(statusOf(report, 'AC-1'), 'fail');
  assert.equal(report.allDeterministicPassed, false);
});

test('hash_equals: fails when the manifest claims a different hash', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om, {
    artifactHashes: [{ path: 'report.json', sha256: sha256Hex('imposter'), mediaType: 'application/json' }],
  });
  assert.equal(statusOf(runMachineChecks(om, manifest, artifacts()), 'AC-1'), 'fail');
});

test('hash_equals: fails when actual artifact bytes do not hash to the expectation', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om); // manifest still claims the right hash
  const lyingBytes = new Map([['report.json', new TextEncoder().encode('tampered')]]);
  const report = runMachineChecks(om, manifest, lyingBytes);
  const r = report.results.find((x) => x.criterionId === 'AC-1');
  assert.equal(r?.status, 'fail');
  assert.match(r?.detail ?? '', /bytes/);
});

test('hash_equals: passes on manifest alone when artifact bytes are not supplied', () => {
  const om = makeOrderMandate();
  const report = runMachineChecks(om, makeManifest(om)); // no artifacts map
  assert.equal(statusOf(report, 'AC-1'), 'pass');
  assert.equal(statusOf(report, 'AC-3'), 'skipped'); // contains needs bytes
  assert.equal(statusOf(report, 'AC-4'), 'skipped'); // schema_valid needs bytes
});

test('hash_equals: malformed params are skipped, not failed (ambiguity against drafter)', () => {
  const om = makeOrderMandate({
    acceptanceCriteria: [
      { id: 'AC-X', statement: 'bad params', machineCheck: { kind: 'hash_equals', params: { sha256: 'zzz' } } },
    ],
  });
  const report = runMachineChecks(om, makeManifest(om), artifacts());
  assert.equal(statusOf(report, 'AC-X'), 'skipped');
});

// ---------------------------------------------------------------------------
// deadline_before
// ---------------------------------------------------------------------------

test('deadline_before: fails on late delivery; param override respected', () => {
  const om = makeOrderMandate();
  const late = makeManifest(om, { deliveredAtUnixMs: om.deadlineUnixMs + 1 });
  assert.equal(statusOf(runMachineChecks(om, late, artifacts()), 'AC-2'), 'fail');

  const omOverride = makeOrderMandate({
    acceptanceCriteria: [
      {
        id: 'AC-2',
        statement: 'earlier interim deadline',
        machineCheck: { kind: 'deadline_before', params: { deadlineUnixMs: om.deadlineUnixMs - 7_200_000 } },
      },
    ],
  });
  // delivered 1h before the mandate deadline, but 1h after the overridden one
  const manifest = makeManifest(omOverride, { deliveredAtUnixMs: om.deadlineUnixMs - 3_600_000 });
  assert.equal(statusOf(runMachineChecks(omOverride, manifest), 'AC-2'), 'fail');
});

test('deadline_before: exactly-on-deadline passes', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om, { deliveredAtUnixMs: om.deadlineUnixMs });
  assert.equal(statusOf(runMachineChecks(om, manifest), 'AC-2'), 'pass');
});

// ---------------------------------------------------------------------------
// contains
// ---------------------------------------------------------------------------

test('contains: fails when the needle is absent from the artifact', () => {
  const om = makeOrderMandate({
    acceptanceCriteria: [
      { id: 'AC-3', statement: 'mentions Q9', machineCheck: { kind: 'contains', params: { path: 'report.json', needle: 'Q9' } } },
    ],
  });
  assert.equal(statusOf(runMachineChecks(om, makeManifest(om), artifacts()), 'AC-3'), 'fail');
});

test('contains: without path searches manifest formatClaims', () => {
  const mk = (needle: string): AcceptanceCriterion[] => [
    { id: 'AC-3', statement: 'claims utf-8', machineCheck: { kind: 'contains', params: { needle } } },
  ];
  const omPass = makeOrderMandate({ acceptanceCriteria: mk('utf-8') });
  assert.equal(statusOf(runMachineChecks(omPass, makeManifest(omPass)), 'AC-3'), 'pass');
  const omFail = makeOrderMandate({ acceptanceCriteria: mk('latin-1') });
  assert.equal(statusOf(runMachineChecks(omFail, makeManifest(omFail)), 'AC-3'), 'fail');
});

// ---------------------------------------------------------------------------
// schema_valid
// ---------------------------------------------------------------------------

test('schema_valid: fails on missing required property and wrong type', () => {
  const om = makeOrderMandate();
  const badJson = new Map([['report.json', new TextEncoder().encode('{"title":42}')]]);
  const manifest = makeManifest(om, {
    artifactHashes: [
      { path: 'report.json', sha256: sha256Hex(badJson.get('report.json')!), mediaType: 'application/json' },
    ],
  });
  const report = runMachineChecks(om, manifest, badJson);
  const r = report.results.find((x) => x.criterionId === 'AC-4');
  assert.equal(r?.status, 'fail');
  assert.match(r?.detail ?? '', /missing required property "pages"/);
  assert.match(r?.detail ?? '', /expected type string, got integer/);
});

test('schema_valid: non-JSON artifact bytes fail', () => {
  const om = makeOrderMandate();
  const notJson = new Map([['report.json', new TextEncoder().encode('<html>')]]);
  assert.equal(statusOf(runMachineChecks(om, makeManifest(om), notJson), 'AC-4'), 'fail');
});

test('validateStructuralSchema: type unions, items, enum, const', () => {
  assert.deepEqual(validateStructuralSchema('x', { type: ['string', 'null'] }), []);
  assert.deepEqual(validateStructuralSchema(null, { type: ['string', 'null'] }), []);
  assert.equal(validateStructuralSchema(5, { type: 'string' }).length, 1);
  assert.deepEqual(validateStructuralSchema(3, { type: 'number' }), []); // integer satisfies number
  assert.equal(validateStructuralSchema([1, 'a'], { type: 'array', items: { type: 'integer' } }).length, 1);
  assert.deepEqual(validateStructuralSchema('b', { enum: ['a', 'b'] }), []);
  assert.equal(validateStructuralSchema('c', { enum: ['a', 'b'] }).length, 1);
  assert.deepEqual(validateStructuralSchema({ a: 1 }, { const: { a: 1 } }), []);
  assert.equal(validateStructuralSchema({ a: 2 }, { const: { a: 1 } }).length, 1);
});

// ---------------------------------------------------------------------------
// Mandate binding
// ---------------------------------------------------------------------------

test('runMachineChecks: unbound manifest flips mandateBound and allDeterministicPassed', () => {
  const om = makeOrderMandate();
  const foreign = makeManifest(om, { orderMandateHash: sha256Hex('some other mandate') });
  const report = runMachineChecks(om, foreign, artifacts());
  assert.equal(report.mandateBound, false);
  assert.equal(report.failed, 0); // individual checks may still pass...
  assert.equal(report.allDeterministicPassed, false); // ...but the report cannot
});

// ---------------------------------------------------------------------------
// Delivery manifest hash + evidence commitments
// ---------------------------------------------------------------------------

test('canonicalDeliveryManifestHash: stable under key reordering, verifiable', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om);
  const hash = canonicalDeliveryManifestHash(manifest);
  assert.match(hash, /^[0-9a-f]{64}$/);
  // same content, rebuilt (different insertion order via overrides) -> same hash
  assert.equal(canonicalDeliveryManifestHash(makeManifest(om, { deliveredAtUnixMs: manifest.deliveredAtUnixMs })), hash);
  assert.equal(verifyDeliveryManifestHash(manifest, hash), true);
  assert.equal(verifyDeliveryManifestHash(manifest, `0x${hash.toUpperCase()}`), true);
  assert.equal(verifyDeliveryManifestHash({ ...manifest, formatClaims: [] }, hash), false);
});

test('delivery manifest validation rejects ambiguous or malformed signed wire data', () => {
  const manifest = makeManifest(makeOrderMandate());
  assert.deepEqual(validateDeliveryManifest(manifest), []);
  assert.doesNotThrow(() => assertValidDeliveryManifest(manifest));

  const malformed = structuredClone(manifest) as unknown as Record<string, unknown>;
  malformed.extra = true;
  malformed.deliveredAtUnixMs = -1;
  const artifacts = malformed.artifactHashes as Array<Record<string, unknown>>;
  artifacts.push({ ...artifacts[0] });
  const problems = validateDeliveryManifest(malformed);
  assert.ok(problems.some((problem) => problem.includes('unknown field')), problems.join('\n'));
  assert.ok(problems.some((problem) => problem.includes('positive unix-ms')), problems.join('\n'));
  assert.ok(problems.some((problem) => problem.includes('duplicate artifact path')), problems.join('\n'));
  assert.throws(() => assertValidDeliveryManifest(malformed), /deliveryManifest/);
});

test('buildEvidenceCommitment: bytes hash raw, objects hash canonically, authenticated defaults false', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om);

  const fromObj = buildEvidenceCommitment('delivery_manifest', manifest, 'worker', 'vault://m1');
  assert.equal(fromObj.kind, 'delivery_manifest');
  assert.equal(fromObj.sha256, canonicalDeliveryManifestHash(manifest));
  assert.equal(fromObj.sha256, sha256Canonical(manifest));
  assert.equal(fromObj.submitter, 'worker');
  assert.equal(fromObj.uri, 'vault://m1');
  assert.equal(fromObj.authenticated, false);

  const bytes = new TextEncoder().encode('raw artifact');
  const fromBytes = buildEvidenceCommitment('party_submission', bytes, 'requester');
  assert.equal(fromBytes.sha256, sha256Hex(bytes));
  assert.equal('uri' in fromBytes, false);
  assert.equal(fromBytes.authenticated, false);
});

test('buildEvidenceCommitment: fixture artifact hash matches precomputed constant', () => {
  const om = makeOrderMandate();
  const manifest = makeManifest(om);
  assert.equal(manifest.artifactHashes[0].sha256, ARTIFACT_SHA256);
});
