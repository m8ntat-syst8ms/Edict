/**
 * Preset protection policies (product interface step 1): structural validity,
 * escalation semantics per preset, determinism, and the CANONICAL pinned
 * profile hashes — a preset content change MUST be a deliberate act (bump
 * the version, update the pins here).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PRESETS,
  basicProfile,
  enterpriseLegalProfile,
  highAssuranceProfile,
  presetByKey,
  standardProfile,
} from './presets.js';
import { defaultProfile, profileHash, validateProfile } from './profile.js';
import { dispositionFor, effectiveEscalationMode } from './escalation.js';
import type { VerdictObject } from '@edict/core';

/** The canonical, committed preset hashes. Changing preset content changes these — deliberately. */
const CANONICAL_HASHES = {
  basic: 'f081421c013ef7bc3c9924199bf0364174f1235763f0177c7b5f3273b9bd2f54',
  standard: '0e66cd3ef210f8c4d22e0242a7ab055018ef3076d81d154fd8f28b7a3d202e08',
  high_assurance: '508389f1a306fc524f778937ee7d4b1587b4b6c80861366f0cdba8ae20189e7d',
} as const;

function finalVerdict(): VerdictObject {
  return {
    caseId: 'a1b2c3d4-0000-4000-8000-0000000000bb',
    ruling: { kind: 'requester_wins' },
    final: true,
    reasoningSha256: '0'.repeat(64),
    votes: [],
    quality: { majority: 'unanimous', swapFlipRate: 0, injectionFlags: [], escalated: false },
    legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E0' },
    issuedAtUnixMs: 1_777_000_000_000,
  };
}

function escalatedVerdict(): VerdictObject {
  const v = finalVerdict();
  v.final = false;
  v.quality = { majority: 'none', swapFlipRate: 0, injectionFlags: [], escalated: true, escalationReason: 'no_majority' };
  return v;
}

test('presets: all three validate cleanly and are deterministic across calls', () => {
  for (const make of [basicProfile, standardProfile, highAssuranceProfile]) {
    assert.deepEqual(validateProfile(make()), [], make.name);
    assert.equal(profileHash(make()), profileHash(make()), `${make.name} must be deterministic`);
  }
});

test('managed profiles expose the complete two-round settlement vocabulary', () => {
  for (const profile of [defaultProfile(), ...PRESETS().map((def) => def.profile)]) {
    assert.equal(profile.defaults.decisionSpace.kind, 'escrow_branches');
    if (profile.defaults.decisionSpace.kind === 'escrow_branches') {
      assert.deepEqual(profile.defaults.decisionSpace.permitted, ['requester_wins', 'worker_wins', 'split', 'redo']);
    }
  }
});

test('presets: canonical hashes are pinned (hash-committed policies)', () => {
  const defs = PRESETS();
  assert.equal(defs.length, 3);
  for (const def of defs) {
    assert.equal(def.profileHash, CANONICAL_HASHES[def.key], `${def.key} canonical hash`);
    assert.equal(profileHash(def.profile), def.profileHash, `${def.key} exported hash matches its content`);
  }
  assert.equal(presetByKey('basic')!.profileHash, CANONICAL_HASHES.basic);
  assert.equal(presetByKey('nope'), undefined);
});

test('presets: step-1 copy is plain English (no protocol jargon in user-facing strings)', () => {
  for (const def of PRESETS()) {
    for (const text of [def.title, def.copy, def.humanReviewCopy]) {
      assert.doesNotMatch(text, /mandate|verdict|jury|attestation|tier [ABC]|escrow_branches|quality_gate/i, text);
    }
  }
});

test('basic: fast checks, no human review — mode off, proofs not required', () => {
  const p = basicProfile();
  assert.equal(p.humanEscalation!.mode, 'off');
  assert.equal(p.juryPolicy.requireProofs, false);
  for (const tier of ['A', 'B', 'C'] as const) {
    assert.equal(effectiveEscalationMode(p, tier), 'off');
  }
  // Escalations fall back programmatically; finals settle normally.
  assert.equal(dispositionFor(escalatedVerdict(), p, 'C', 5_000).route, 'programmatic_fallback');
  assert.equal(dispositionFor(finalVerdict(), p, 'B', 500).route, 'none');
});

test('standard: real providers are proof-gated automatically; human review is off by default', () => {
  const p = standardProfile();
  assert.equal(p.juryPolicy.requireProofs, undefined, 'arbiter selects proof gating from provider type');
  assert.equal(p.humanEscalation!.mode, 'off');
  assert.equal(p.legalPolicy.assuranceMode, 'wallet_native');
  assert.equal(p.defaults.legalProfile.enforcementTier, 'E0');
  // A quality trip remains non-executable and uses the pre-agreed fallback.
  assert.equal(dispositionFor(escalatedVerdict(), p, 'A', 5).route, 'programmatic_fallback');
  assert.equal(dispositionFor(finalVerdict(), p, 'C', 50_000).route, 'none');
});

test('enterprise legal profile is explicit, E1 and structurally valid', () => {
  const p = enterpriseLegalProfile();
  assert.equal(p.legalPolicy.assuranceMode, 'enterprise_legal');
  assert.equal(p.defaults.legalProfile.enforcementTier, 'E1');
  assert.deepEqual(validateProfile(p), []);
});

test('high assurance: optional appeal + full quality-trigger coverage + required review above $10k', () => {
  const p = highAssuranceProfile();
  const he = p.humanEscalation!;
  assert.equal(he.mode, 'optional_appeal');
  assert.equal(he.thresholdUsd, 10_000);
  assert.equal(he.appealWindowMs, 172_800_000);
  assert.equal(he.appealBondMultiplier, 2);
  assert.equal(he.reviewerPool, 'edict_bench');
  assert.equal(p.juryPolicy.requireProofs, true);
  assert.deepEqual(p.juryPolicy.provenanceAllowlist, ['mock-alpha', 'mock-beta', 'mock-gamma']);
  assert.equal(p.lintGate.minScore, 90, 'more detailed evidence requirements');

  // Quality escalations route to a human EVEN under optional_appeal (explicit triggers).
  assert.equal(dispositionFor(escalatedVerdict(), p, 'B', 500).route, 'human_review');
  // Finals below tier C are appealable (optional appeal).
  assert.equal(dispositionFor(finalVerdict(), p, 'B', 500).route, 'appealable');
  assert.deepEqual(dispositionFor(finalVerdict(), p, 'C', 5_000), {
    route: 'appealable',
    mode: 'optional_appeal',
  });
  // Tier-C finals at/above the $10k threshold are ALWAYS reviewed…
  assert.deepEqual(dispositionFor(finalVerdict(), p, 'C', 25_000), {
    route: 'human_review',
    mode: 'required_above_value',
  });
  // Below the mandatory threshold, the profile-wide optional appeal remains in force.
});
