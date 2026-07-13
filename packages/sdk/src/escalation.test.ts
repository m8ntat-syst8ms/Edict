/**
 * Human escalation policy mapping (review policy): default-mode resolution per
 * tier, trigger extraction from arbiter quality signals, every
 * dispositionFor branch, profile validation of the humanEscalation object,
 * and profileHash coverage (the election IS policy).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { EscalationTrigger, ValueTier, VerdictObject } from '@edict/core';
import { dispositionFor, effectiveEscalationMode, triggerFromVerdict } from './escalation.js';
import { defaultProfile, profileHash, validateProfile, type ProtectionProfile } from './profile.js';

function verdict(overrides: Partial<VerdictObject> = {}): VerdictObject {
  return {
    caseId: 'a1b2c3d4-0000-4000-8000-0000000000aa',
    ruling: { kind: 'requester_wins' },
    final: true,
    reasoningSha256: '0'.repeat(64),
    votes: [],
    quality: { majority: 'unanimous', swapFlipRate: 0, injectionFlags: [], escalated: false },
    legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E1' },
    issuedAtUnixMs: 1_777_000_000_000,
    ...overrides,
  };
}

function escalatedVerdict(
  quality: Partial<VerdictObject['quality']> = {},
): VerdictObject {
  return verdict({
    final: false,
    quality: {
      majority: 'majority',
      swapFlipRate: 0,
      injectionFlags: [],
      escalated: true,
      escalationReason: 'no_majority',
      ...quality,
    },
  });
}

function profileWith(humanEscalation?: ProtectionProfile['humanEscalation']): ProtectionProfile {
  const p = defaultProfile();
  if (humanEscalation !== undefined) p.humanEscalation = humanEscalation;
  return p;
}

// ---------------------------------------------------------------------------
// effectiveEscalationMode
// ---------------------------------------------------------------------------

test('effectiveEscalationMode: tier defaults when the profile makes no election (A off, B optional_appeal, C quality_gate)', () => {
  const p = defaultProfile();
  assert.equal(p.humanEscalation, undefined, 'default profile makes no election');
  assert.equal(effectiveEscalationMode(p, 'A'), 'off');
  assert.equal(effectiveEscalationMode(p, 'B'), 'optional_appeal');
  assert.equal(effectiveEscalationMode(p, 'C'), 'quality_gate');
});

test('effectiveEscalationMode: explicit mode overrides every tier; perTier overrides the mode', () => {
  const modeOnly = profileWith({ mode: 'off' });
  for (const tier of ['A', 'B', 'C'] as ValueTier[]) {
    assert.equal(effectiveEscalationMode(modeOnly, tier), 'off');
  }
  const perTier = profileWith({ mode: 'off', perTier: { C: 'required_above_value' } });
  assert.equal(effectiveEscalationMode(perTier, 'A'), 'off');
  assert.equal(effectiveEscalationMode(perTier, 'B'), 'off');
  assert.equal(effectiveEscalationMode(perTier, 'C'), 'required_above_value');
});

// ---------------------------------------------------------------------------
// triggerFromVerdict
// ---------------------------------------------------------------------------

test('triggerFromVerdict: undefined for non-escalated verdicts', () => {
  assert.equal(triggerFromVerdict(verdict()), undefined);
});

test('triggerFromVerdict: maps every arbiter signal onto the closed trigger vocabulary', () => {
  const cases: Array<[Partial<VerdictObject['quality']>, EscalationTrigger]> = [
    // escalationReason token mappings
    [{ escalationReason: 'insufficient_attested_seats' }, 'insufficient_attested_seats'],
    [{ escalationReason: 'insufficient_attested_seats; no_majority' }, 'insufficient_attested_seats'],
    [{ escalationReason: 'injection_flags_at_tier_C' }, 'injection_attack'],
    [{ escalationReason: 'scalar_spread' }, 'no_majority'],
    [{ escalationReason: 'no_majority; swap_flip_rate=1.00>0.34' }, 'no_majority'],
    // majority 'none' with an unrelated reason still reads as no_majority
    [{ majority: 'none', escalationReason: 'mean_confidence=0.50<0.60' }, 'no_majority'],
    // swap inconsistency (reason token or raw rate)
    [{ escalationReason: 'swap_flip_rate=0.67>0.34' }, 'swap_inconsistency'],
    [{ swapFlipRate: 0.5, escalationReason: 'mean_confidence=0.55<0.60' }, 'swap_inconsistency'],
    // out-of-policy evidence flags beat generic low confidence
    [
      { escalationReason: 'mean_confidence=0.55<0.60', injectionFlags: ['evidence_hash_mismatch:delivery_manifest'] },
      'out_of_policy_evidence',
    ],
    [
      { escalationReason: 'mean_confidence=0.55<0.60', injectionFlags: ['note:withheld_mandate_text:description'] },
      'out_of_policy_evidence',
    ],
    // low-confidence reasons
    [{ escalationReason: 'mean_confidence=0.50<0.60' }, 'low_confidence'],
    // defensive default: an unclassifiable escalation is low confidence
    [{ escalationReason: 'some_future_reason' }, 'low_confidence'],
    [{ escalationReason: undefined }, 'low_confidence'],
  ];
  for (const [quality, expected] of cases) {
    assert.equal(
      triggerFromVerdict(escalatedVerdict({ escalationReason: undefined, ...quality })),
      expected,
      `quality ${JSON.stringify(quality)} should map to ${expected}`,
    );
  }
});

// ---------------------------------------------------------------------------
// dispositionFor — every branch
// ---------------------------------------------------------------------------

test('dispositionFor: escalated + mode off → programmatic_fallback (advisory ruling is a recommendation only)', () => {
  const d = dispositionFor(escalatedVerdict(), profileWith({ mode: 'off' }), 'C');
  assert.deepEqual(d, { route: 'programmatic_fallback', trigger: 'no_majority', mode: 'off' });
  // tier A default is 'off' with no election at all
  const dA = dispositionFor(escalatedVerdict(), defaultProfile(), 'A');
  assert.deepEqual(dA, { route: 'programmatic_fallback', trigger: 'no_majority', mode: 'off' });
});

test('dispositionFor: escalated + quality_gate → human_review for every quality trigger (default coverage)', () => {
  const p = defaultProfile(); // tier C default: quality_gate
  for (const quality of [
    { escalationReason: 'no_majority' },
    { escalationReason: 'insufficient_attested_seats' },
    { escalationReason: 'injection_flags_at_tier_C' },
    { escalationReason: 'swap_flip_rate=0.67>0.34' },
    { escalationReason: 'mean_confidence=0.50<0.60' },
    { escalationReason: 'x', injectionFlags: ['evidence_hash_mismatch:delivery_manifest'] },
  ] as Array<Partial<VerdictObject['quality']>>) {
    const d = dispositionFor(escalatedVerdict({ escalationReason: undefined, ...quality }), p, 'C');
    assert.equal(d.route, 'human_review', JSON.stringify(quality));
    assert.equal(d.mode, 'quality_gate');
    assert.ok(d.trigger !== undefined);
  }
});

test('dispositionFor: explicit triggers NARROW quality_gate coverage — uncovered triggers fall back programmatically', () => {
  const p = profileWith({ mode: 'quality_gate', triggers: ['injection_attack'] });
  const covered = dispositionFor(escalatedVerdict({ escalationReason: 'injection_flags_at_tier_C' }), p, 'C');
  assert.deepEqual(covered, { route: 'human_review', trigger: 'injection_attack', mode: 'quality_gate' });
  const uncovered = dispositionFor(escalatedVerdict({ escalationReason: 'no_majority' }), p, 'C');
  assert.deepEqual(uncovered, { route: 'programmatic_fallback', trigger: 'no_majority', mode: 'quality_gate' });
});

test("dispositionFor: escalated + optional_appeal → programmatic_fallback unless triggers override", () => {
  // Default optional_appeal covers only party_appeal: a quality escalation
  // does NOT route to the bench.
  const p = profileWith({ mode: 'optional_appeal' });
  const d = dispositionFor(escalatedVerdict(), p, 'B');
  assert.deepEqual(d, { route: 'programmatic_fallback', trigger: 'no_majority', mode: 'optional_appeal' });
  // Explicit triggers override: the listed quality trigger now routes.
  const overridden = profileWith({ mode: 'optional_appeal', triggers: ['party_appeal', 'no_majority'] });
  const d2 = dispositionFor(escalatedVerdict(), overridden, 'B');
  assert.deepEqual(d2, { route: 'human_review', trigger: 'no_majority', mode: 'optional_appeal' });
});

test('dispositionFor: escalated + required_above_value → human_review (full default coverage)', () => {
  const p = profileWith({ mode: 'required_above_value' });
  const d = dispositionFor(escalatedVerdict(), p, 'C');
  assert.deepEqual(d, { route: 'human_review', trigger: 'no_majority', mode: 'required_above_value' });
});

test('dispositionFor: final + optional_appeal → appealable (tier B default)', () => {
  const d = dispositionFor(verdict(), defaultProfile(), 'B');
  assert.deepEqual(d, { route: 'appealable', mode: 'optional_appeal' });
});

test('dispositionFor: final + required_above_value routes by VALUE, tier-agnostic (default threshold $1000)', () => {
  const p = profileWith({ mode: 'required_above_value' });
  // At/above the default $1000 threshold → held for review, whatever the tier.
  assert.deepEqual(dispositionFor(verdict(), p, 'C', 5_000), { route: 'human_review', mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'B', 1_000), { route: 'human_review', mode: 'required_above_value' });
  // Below the threshold → settles normally.
  assert.deepEqual(dispositionFor(verdict(), p, 'A', 5), { route: 'none', mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'B', 999.99), { route: 'none', mode: 'required_above_value' });
});

test('dispositionFor: required_above_value honours an explicit thresholdUsd', () => {
  const p = profileWith({ mode: 'required_above_value', thresholdUsd: 10_000 });
  assert.deepEqual(dispositionFor(verdict(), p, 'C', 9_999), { route: 'none', mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'C', 10_000), { route: 'human_review', mode: 'required_above_value' });
  // The threshold is tier-agnostic: a tier-B case above a low threshold holds too.
  const low = profileWith({ mode: 'required_above_value', thresholdUsd: 100 });
  assert.deepEqual(dispositionFor(verdict(), low, 'B', 500), { route: 'human_review', mode: 'required_above_value' });
});

test('dispositionFor: required_above_value without a case value falls back to holding tier C only (band-consistent)', () => {
  const p = profileWith({ mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'C'), { route: 'human_review', mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'A'), { route: 'none', mode: 'required_above_value' });
  assert.deepEqual(dispositionFor(verdict(), p, 'B'), { route: 'none', mode: 'required_above_value' });
});

test('dispositionFor: final + off / quality_gate → none (nothing routes; settle proceeds normally)', () => {
  assert.deepEqual(dispositionFor(verdict(), profileWith({ mode: 'off' }), 'B'), { route: 'none', mode: 'off' });
  assert.deepEqual(dispositionFor(verdict(), defaultProfile(), 'C'), { route: 'none', mode: 'quality_gate' });
  assert.deepEqual(dispositionFor(verdict(), defaultProfile(), 'A'), { route: 'none', mode: 'off' });
});

// ---------------------------------------------------------------------------
// Profile validation of the humanEscalation object
// ---------------------------------------------------------------------------

test('validateProfile: accepts well-formed humanEscalation elections', () => {
  assert.deepEqual(validateProfile(profileWith({ mode: 'off' })), []);
  assert.deepEqual(
    validateProfile(profileWith({ mode: 'quality_gate', triggers: ['no_majority', 'injection_attack'] })),
    [],
  );
  assert.deepEqual(
    validateProfile(profileWith({ mode: 'optional_appeal', perTier: { A: 'off', C: 'required_above_value' } })),
    [],
  );
  // Full user-facing config schema: thresholdUsd + appeal mechanics + reviewer pool.
  assert.deepEqual(
    validateProfile(
      profileWith({
        mode: 'optional_appeal',
        perTier: { C: 'required_above_value' },
        thresholdUsd: 10_000,
        appealWindowMs: 172_800_000,
        appealBondMultiplier: 2,
        reviewerPool: 'edict_bench',
      }),
    ),
    [],
  );
  assert.deepEqual(
    validateProfile(profileWith({ mode: 'required_above_value', thresholdUsd: 2_500, reviewerPool: 'customer_panel' })),
    [],
  );
});

test('validateProfile: new humanEscalation fields — types, enums and mode cross-checks', () => {
  const cases: Array<[unknown, RegExp]> = [
    [{ mode: 'required_above_value', thresholdUsd: 0 }, /thresholdUsd: must be a positive finite number/],
    [{ mode: 'required_above_value', thresholdUsd: 'high' }, /thresholdUsd: must be a positive finite number/],
    [{ mode: 'quality_gate', thresholdUsd: 1_000 }, /thresholdUsd: only meaningful when 'required_above_value'/],
    [{ mode: 'optional_appeal', appealWindowMs: 0 }, /appealWindowMs: must be a positive integer/],
    [{ mode: 'optional_appeal', appealWindowMs: 1.5 }, /appealWindowMs: must be a positive integer/],
    [{ mode: 'quality_gate', appealWindowMs: 3_600_000 }, /appealWindowMs: only meaningful when 'optional_appeal'/],
    [{ mode: 'optional_appeal', appealBondMultiplier: -1 }, /appealBondMultiplier: must be a positive finite number/],
    [{ mode: 'off', appealBondMultiplier: 2 }, /appealBondMultiplier: only meaningful when 'optional_appeal'/],
    [{ mode: 'quality_gate', reviewerPool: 'my_mates' }, /reviewerPool: must be one of/],
  ];
  for (const [he, re] of cases) {
    const p = defaultProfile() as unknown as Record<string, unknown>;
    p.humanEscalation = he;
    const errors = validateProfile(p);
    assert.ok(errors.some((e) => re.test(e)), `${JSON.stringify(he)} → ${errors.join('; ')}`);
  }
  // perTier elections legitimize the cross-checked fields.
  assert.deepEqual(
    validateProfile(profileWith({ mode: 'quality_gate', perTier: { C: 'required_above_value' }, thresholdUsd: 5_000 })),
    [],
  );
  assert.deepEqual(
    validateProfile(profileWith({ mode: 'quality_gate', perTier: { B: 'optional_appeal' }, appealWindowMs: 60_000 })),
    [],
  );
});

test('validateProfile: humanEscalation closed enums, unknown keys, duplicate/empty triggers, bad perTier', () => {
  const cases: Array<[unknown, RegExp]> = [
    [{ mode: 'ask_a_friend' }, /humanEscalation\.mode: must be one of/],
    [{ mode: 'off', escalate: true }, /humanEscalation\.escalate: unknown key/],
    [{ mode: 'quality_gate', triggers: ['no_majority', 'no_majority'] }, /duplicate trigger 'no_majority'/],
    [{ mode: 'quality_gate', triggers: [] }, /triggers: must be a non-empty array/],
    [{ mode: 'quality_gate', triggers: ['sixth_sense'] }, /triggers\[0\]: must be one of/],
    [{ mode: 'quality_gate', perTier: { D: 'off' } }, /perTier\.D: unknown key/],
    [{ mode: 'quality_gate', perTier: { C: 'sometimes' } }, /perTier\.C: must be one of/],
    ['quality_gate', /humanEscalation: must be an object/],
  ];
  for (const [he, re] of cases) {
    const p = defaultProfile() as unknown as Record<string, unknown>;
    p.humanEscalation = he;
    const errors = validateProfile(p);
    assert.ok(errors.some((e) => re.test(e)), `${JSON.stringify(he)} → ${errors.join('; ')}`);
  }
});

// ---------------------------------------------------------------------------
// profileHash coverage — the election IS policy
// ---------------------------------------------------------------------------

test('profileHash: changes when the humanEscalation policy changes (and only then)', () => {
  const base = defaultProfile();
  const off = profileWith({ mode: 'off' });
  const gate = profileWith({ mode: 'quality_gate' });
  const gateNarrowed = profileWith({ mode: 'quality_gate', triggers: ['injection_attack'] });
  const perTier = profileWith({ mode: 'quality_gate', perTier: { C: 'required_above_value' } });
  const withThreshold = profileWith({ mode: 'required_above_value', thresholdUsd: 5_000 });
  const withAppealMechanics = profileWith({
    mode: 'optional_appeal',
    appealWindowMs: 86_400_000,
    appealBondMultiplier: 2,
  });
  const withPool = profileWith({ mode: 'quality_gate', reviewerPool: 'external_arbitrator' });

  const hashes = [base, off, gate, gateNarrowed, perTier, withThreshold, withAppealMechanics, withPool].map((p) =>
    profileHash(p),
  );
  assert.equal(new Set(hashes).size, hashes.length, 'every distinct election yields a distinct profileHash');

  // Identical elections hash identically (canonical JSON, key order irrelevant).
  const again = profileWith({ triggers: ['injection_attack'], mode: 'quality_gate' });
  assert.equal(profileHash(gateNarrowed), profileHash(again));
});
