import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { errorsOf, validateCaseObject, validateGroundTruth, validateSeats } from './validate.js';
import { sha256Hex } from './hash.js';
import type { CaseObject } from '@edict/core';

const MANDATE_SHA = sha256Hex('mandate-bytes');
const MANIFEST_SHA = sha256Hex('manifest-bytes');

function validCase(): Record<string, unknown> {
  return {
    caseId: 'a1b2c3d4-0000-4000-8000-0000000000aa',
    caseType: 'bilateral',
    publicity: 'sealed',
    requester: { agentId: 'near:req.near', principalKybRef: 'kyb:v0:req' },
    worker: { agentId: 'near:wrk.near', principalKybRef: 'kyb:v0:wrk' },
    orderMandateHash: MANDATE_SHA,
    deliveryManifestHash: MANIFEST_SHA,
    evidence: [
      { kind: 'order_mandate', sha256: MANDATE_SHA, submitter: 'system', uri: 'evidence/order_mandate.json', authenticated: true },
      { kind: 'delivery_manifest', sha256: MANIFEST_SHA, submitter: 'worker', uri: 'evidence/delivery_manifest.json', authenticated: true },
    ],
    valueUsd: 500,
    tier: 'B',
    custodyMode: 'M1_native_escrow',
    railRef: { rail: 'near-agent-market', jobId: 'job-1' },
    legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E1' },
    openedAtUnixMs: 1_777_000_000_000,
    decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins'] },
  };
}

/** A public_resolution case with a categorical decision space (pseudonymous parties, E1). */
function categoricalCase(): Record<string, unknown> {
  const c = validCase();
  c.caseType = 'public_resolution';
  c.publicity = 'public';
  c.requester = { agentId: 'near:challenger.near' }; // pseudonymous — valid at E1
  c.worker = { agentId: 'near:proposer.near' };
  delete c.deliveryManifestHash;
  c.evidence = [
    { kind: 'order_mandate', sha256: MANDATE_SHA, submitter: 'venue', uri: 'evidence/rules.json', authenticated: true },
    { kind: 'zktls_proof', sha256: MANIFEST_SHA, submitter: 'third_party', uri: 'evidence/extract.json', authenticated: true },
  ];
  c.decisionSpace = { kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' };
  return c;
}

/** A claim case with a bounded_scalar decision space. */
function scalarCase(): Record<string, unknown> {
  const c = validCase();
  c.caseType = 'claim';
  delete c.deliveryManifestHash;
  c.evidence = [
    { kind: 'order_mandate', sha256: MANDATE_SHA, submitter: 'system', uri: 'evidence/policy.json', authenticated: true },
  ];
  c.decisionSpace = { kind: 'bounded_scalar', min: 0, max: 50_000, unit: 'USD' };
  return c;
}

describe('validateCaseObject', () => {
  it('accepts a well-formed case', () => {
    assert.deepEqual(errorsOf(validateCaseObject(validCase())), []);
  });

  it('accepts a public_resolution/categorical and a claim/bounded_scalar case', () => {
    assert.deepEqual(errorsOf(validateCaseObject(categoricalCase())), []);
    assert.deepEqual(errorsOf(validateCaseObject(scalarCase())), []);
  });

  it('rejects a non-uuid caseId', () => {
    const c = validCase();
    c.caseId = 'not-a-uuid';
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.caseId'));
  });

  it('rejects unknown top-level keys (closed field set), including retired permittedRulings', () => {
    const c1 = validCase();
    c1.extraField = true;
    assert.ok(errorsOf(validateCaseObject(c1)).some((i) => i.path === 'case.extraField'));
    const c2 = validCase();
    c2.permittedRulings = ['requester_wins'];
    assert.ok(errorsOf(validateCaseObject(c2)).some((i) => i.path === 'case.permittedRulings'));
  });

  it('rejects bad caseType / publicity enum values', () => {
    const c1 = validCase();
    c1.caseType = 'class_action';
    assert.ok(errorsOf(validateCaseObject(c1)).some((i) => i.path === 'case.caseType'));
    const c2 = validCase();
    c2.publicity = 'secret';
    assert.ok(errorsOf(validateCaseObject(c2)).some((i) => i.path === 'case.publicity'));
  });

  it('rejects an unknown evidence kind and bad submitter', () => {
    const c = validCase();
    (c.evidence as Array<Record<string, unknown>>).push({
      kind: 'sworn_affidavit', sha256: sha256Hex('x'), submitter: 'lawyer', uri: 'evidence/x', authenticated: true,
    });
    const errs = errorsOf(validateCaseObject(c));
    assert.ok(errs.some((i) => i.path === 'case.evidence[2].kind'));
    assert.ok(errs.some((i) => i.path === 'case.evidence[2].submitter'));
  });

  it('third_party submitters are rejected on bilateral cases but valid on public_resolution', () => {
    const c = validCase();
    (c.evidence as Array<Record<string, unknown>>).push({
      kind: 'zktls_proof', sha256: sha256Hex('x'), submitter: 'third_party', uri: 'evidence/x.json', authenticated: true,
    });
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.evidence[2].submitter'));
    assert.deepEqual(errorsOf(validateCaseObject(categoricalCase())), []);
  });

  it('principalKybRef is optional on E0/E1 case records and required at E2/E3', () => {
    const bilateral = validCase();
    (bilateral.requester as Record<string, unknown>).principalKybRef = undefined;
    assert.deepEqual(
      errorsOf(validateCaseObject(bilateral)),
      [],
      'the standalone case schema permits pseudonymous E1; SDK assurance profiles gate enterprise E1 creation',
    );

    const e2 = categoricalCase();
    (e2.legalProfile as Record<string, unknown>).enforcementTier = 'E2';
    assert.ok(errorsOf(validateCaseObject(e2)).some((i) => i.path.endsWith('principalKybRef')));

    assert.deepEqual(errorsOf(validateCaseObject(categoricalCase())), [], 'pseudonymous at E1 non-bilateral is valid');
  });

  it('public_resolution with sealed publicity is a WARNING (never an error)', () => {
    const c = categoricalCase();
    c.publicity = 'sealed';
    const issues = validateCaseObject(c);
    assert.deepEqual(errorsOf(issues), []);
    assert.ok(issues.some((i) => i.level === 'warn' && i.path === 'case.publicity'));
  });

  it('rejects tier inconsistent with valueUsd', () => {
    const c = validCase();
    c.valueUsd = 50_000; // tier C band
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.tier'));
  });

  it('requires orderMandateHash to match an order_mandate commitment', () => {
    const c = validCase();
    c.orderMandateHash = sha256Hex('some-other-bytes');
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.orderMandateHash'));
  });

  it('requires deliveryManifestHash, when present, to match a delivery_manifest commitment', () => {
    const c = validCase();
    c.deliveryManifestHash = sha256Hex('rogue-manifest');
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.deliveryManifestHash'));
  });

  it('accepts an absent deliveryManifestHash (non-delivery claim path)', () => {
    const c = validCase();
    delete c.deliveryManifestHash;
    assert.deepEqual(errorsOf(validateCaseObject(c)), []);
  });

  it('rejects structurally bad escrow decision spaces (empty / duplicate / unknown kinds)', () => {
    const c1 = validCase();
    c1.decisionSpace = { kind: 'escrow_branches', permitted: [] };
    assert.ok(errorsOf(validateCaseObject(c1)).length > 0);
    const c2 = validCase();
    c2.decisionSpace = { kind: 'escrow_branches', permitted: ['worker_wins', 'worker_wins'] };
    assert.ok(errorsOf(validateCaseObject(c2)).some((i) => i.message.includes('duplicate')));
    const c3 = validCase();
    c3.decisionSpace = { kind: 'escrow_branches', permitted: ['worker_wins', 'draw'] };
    assert.ok(errorsOf(validateCaseObject(c3)).some((i) => i.path === 'case.decisionSpace.permitted[1]'));
  });

  it('rejects structurally bad categorical and scalar decision spaces', () => {
    const c1 = categoricalCase();
    c1.decisionSpace = { kind: 'categorical', outcomes: ['ONLY'] };
    assert.ok(errorsOf(validateCaseObject(c1)).some((i) => i.path.startsWith('case.decisionSpace')));
    const c2 = categoricalCase();
    c2.decisionSpace = { kind: 'categorical', outcomes: ['A', 'B'], invalidOutcome: 'C' };
    assert.ok(errorsOf(validateCaseObject(c2)).some((i) => i.path === 'case.decisionSpace.invalidOutcome'));
    const c3 = scalarCase();
    c3.decisionSpace = { kind: 'bounded_scalar', min: 10, max: 10, unit: 'USD' };
    assert.ok(errorsOf(validateCaseObject(c3)).some((i) => i.path.startsWith('case.decisionSpace')));
  });

  it('rejects a disallowed seat', () => {
    const c = validCase();
    (c.legalProfile as Record<string, unknown>).seat = 'paris';
    assert.ok(errorsOf(validateCaseObject(c)).some((i) => i.path === 'case.legalProfile.seat'));
  });
});

describe('validateGroundTruth', () => {
  const caseObj = validCase() as unknown as CaseObject;
  const catCase = categoricalCase() as unknown as CaseObject;
  const scalCase = scalarCase() as unknown as CaseObject;

  function validGt(): Record<string, unknown> {
    return {
      caseId: caseObj.caseId,
      title: 'Fixture case',
      expected: { kind: 'requester_wins' },
      rationale: 'because the evidence says so',
      difficulty: 'easy',
      tags: ['synthetic', 'non_delivery'],
    };
  }

  it('accepts a well-formed groundtruth', () => {
    assert.deepEqual(errorsOf(validateGroundTruth(validGt(), caseObj)), []);
  });

  it('rejects an expected escrow kind outside the case decisionSpace (verdict-oracle invariant)', () => {
    const g = validGt();
    g.expected = { kind: 'split', requesterBps: 5000 };
    assert.ok(errorsOf(validateGroundTruth(g, caseObj)).some((i) => i.path === 'groundtruth.expected.kind'));
  });

  it('rejects an escrow expectation on a categorical case (space-shape mismatch)', () => {
    const g = validGt();
    g.caseId = catCase.caseId;
    assert.ok(errorsOf(validateGroundTruth(g, catCase)).some((i) => i.path === 'groundtruth.expected.kind'));
  });

  it('categorical expectations must use a committed outcome label', () => {
    const ok = { ...validGt(), caseId: catCase.caseId, expected: { kind: 'categorical', outcome: 'NO' } };
    assert.deepEqual(errorsOf(validateGroundTruth(ok, catCase)), []);
    const bad = { ...validGt(), caseId: catCase.caseId, expected: { kind: 'categorical', outcome: 'MAYBE' } };
    assert.ok(errorsOf(validateGroundTruth(bad, catCase)).some((i) => i.path === 'groundtruth.expected.outcome'));
  });

  it('scalar expectations must be finite and inside the bounded range', () => {
    const ok = { ...validGt(), caseId: scalCase.caseId, expected: { kind: 'scalar', value: 30_000 }, scalarToleranceBps: 1000 };
    assert.deepEqual(errorsOf(validateGroundTruth(ok, scalCase)), []);
    const outOfRange = { ...validGt(), caseId: scalCase.caseId, expected: { kind: 'scalar', value: 60_000 } };
    assert.ok(errorsOf(validateGroundTruth(outOfRange, scalCase)).some((i) => i.path === 'groundtruth.expected.value'));
    const notANumber = { ...validGt(), caseId: scalCase.caseId, expected: { kind: 'scalar', value: 'lots' } };
    assert.ok(errorsOf(validateGroundTruth(notANumber, scalCase)).some((i) => i.path === 'groundtruth.expected.value'));
  });

  it('rejects out-of-range split/scalar tolerances', () => {
    const g1 = { ...validGt(), splitToleranceBps: 20_000 };
    assert.ok(errorsOf(validateGroundTruth(g1, caseObj)).some((i) => i.path === 'groundtruth.splitToleranceBps'));
    const g2 = { ...validGt(), scalarToleranceBps: -1 };
    assert.ok(errorsOf(validateGroundTruth(g2, caseObj)).some((i) => i.path === 'groundtruth.scalarToleranceBps'));
  });

  it('requires requesterBps for split expectations', () => {
    const g = validGt();
    g.expected = { kind: 'split' };
    // validate without a case so the decisionSpace does not interfere
    assert.ok(errorsOf(validateGroundTruth(g)).some((i) => i.path === 'groundtruth.expected.requesterBps'));
  });

  it('rejects a caseId mismatch', () => {
    const g = validGt();
    g.caseId = 'ffffffff-0000-4000-8000-00000000ffff';
    assert.ok(errorsOf(validateGroundTruth(g, caseObj)).some((i) => i.path === 'groundtruth.caseId'));
  });
});

describe('validateSeats', () => {
  it('accepts three seats on three providers with disjoint families', () => {
    const seats = [
      { seatId: 'a:x', providerId: 'a', modelId: 'x-1', modelFamily: 'x' },
      { seatId: 'b:y', providerId: 'b', modelId: 'y-1', modelFamily: 'y' },
      { seatId: 'c:z', providerId: 'c', modelId: 'z-1', modelFamily: 'z' },
    ];
    assert.deepEqual(errorsOf(validateSeats(seats)), []);
  });

  it('accepts a 2-operator roster with a provider majority (legal at tiers A/B) — warn only', () => {
    const seats = [
      { seatId: 'a:x', providerId: 'a', modelId: 'x-1', modelFamily: 'x' },
      { seatId: 'a:y', providerId: 'a', modelId: 'y-1', modelFamily: 'y' },
      { seatId: 'c:z', providerId: 'c', modelId: 'z-1', modelFamily: 'z' },
    ];
    const issues = validateSeats(seats);
    assert.deepEqual(errorsOf(issues), [], 'majority is not a roster error under per-tier placement ');
    assert.ok(
      issues.some((i) => i.level === 'warn' && /tier-C cases will be skipped/.test(i.message)),
      'the tier-C consequence is surfaced as a warning',
    );
  });

  it('rejects a single-operator roster (tiers A/B need >= 2 distinct providers)', () => {
    const seats = [
      { seatId: 'a:x', providerId: 'a', modelId: 'x-1', modelFamily: 'x' },
      { seatId: 'a:y', providerId: 'a', modelId: 'y-1', modelFamily: 'y' },
      { seatId: 'a:z', providerId: 'a', modelId: 'z-1', modelFamily: 'z' },
    ];
    assert.ok(errorsOf(validateSeats(seats)).some((i) => /require >= 2/.test(i.message)));
  });

  it('rejects duplicate model families across seats', () => {
    const seats = [
      { seatId: 'a:x', providerId: 'a', modelId: 'x-1', modelFamily: 'x' },
      { seatId: 'b:x', providerId: 'b', modelId: 'x-2', modelFamily: 'x' },
      { seatId: 'c:z', providerId: 'c', modelId: 'z-1', modelFamily: 'z' },
    ];
    assert.ok(errorsOf(validateSeats(seats)).some((i) => i.message.includes('disjoint')));
  });

  it('rejects an empty roster', () => {
    assert.ok(errorsOf(validateSeats([])).length > 0);
  });
});
