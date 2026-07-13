/**
 * ProtectionProfile: hash stability + structural validation.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SANDBOX_MOCK_SEATS,
  assertValidProfile,
  defaultProfile,
  profileHash,
  validateProfile,
  type ProtectionProfile,
} from './profile.js';
import { ProfileValidationError } from './errors.js';

test('profileHash: key order never matters (canonical JSON)', () => {
  const legalPolicy = defaultProfile().legalPolicy;
  const a: ProtectionProfile = {
    name: 'p',
    version: '1.0.0',
    legalPolicy,
    defaults: {
      decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins'] },
      legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E1' },
      acceptanceWindowMs: 86_400_000,
    },
    juryPolicy: { requireProofs: false },
    lintGate: { minScore: 80, blockOnError: true },
  };
  // Same content, different insertion order everywhere.
  const b = {
    lintGate: { blockOnError: true, minScore: 80 },
    juryPolicy: { requireProofs: false },
    defaults: {
      acceptanceWindowMs: 86_400_000,
      legalProfile: { enforcementTier: 'E1', rules: 'edict-drr-v0.1', seat: 'london', governingLaw: 'england_wales' },
      decisionSpace: { permitted: ['requester_wins', 'worker_wins'], kind: 'escrow_branches' },
    },
    legalPolicy,
    version: '1.0.0',
    name: 'p',
  } as unknown as ProtectionProfile;
  assert.equal(profileHash(a), profileHash(b));
  assert.notEqual(profileHash(a), profileHash({ ...a, version: '1.0.1' }));
});

test('profileHash: stable across defaultProfile() calls (fresh objects)', () => {
  assert.equal(profileHash(defaultProfile()), profileHash(defaultProfile()));
});

test('defaultProfile validates clean; sandbox seats are placement-legal', () => {
  assert.deepEqual(validateProfile(defaultProfile()), []);
  assert.equal(SANDBOX_MOCK_SEATS.length, 3);
  assert.equal(new Set(SANDBOX_MOCK_SEATS.map((s) => s.providerId)).size, 3);
  assert.equal(new Set(SANDBOX_MOCK_SEATS.map((s) => s.modelFamily)).size, 3);
});

test('validateProfile: wallet/rail assurance is E0-only; legal enforcement is explicit', () => {
  const wallet = defaultProfile();
  wallet.defaults.legalProfile.enforcementTier = 'E1';
  assert.ok(validateProfile(wallet).some((e) => e.includes("requires enterprise_legal")));

  const rail = defaultProfile();
  rail.legalPolicy.assuranceMode = 'rail_verified';
  assert.deepEqual(validateProfile(rail), []);

  const enterprise = defaultProfile();
  enterprise.legalPolicy.assuranceMode = 'enterprise_legal';
  enterprise.defaults.legalProfile.enforcementTier = 'E2';
  assert.deepEqual(validateProfile(enterprise), []);
});

test('validateProfile: rejects structural defects with pathed errors', () => {
  assert.match(validateProfile(null)[0]!, /must be a JSON object/);

  const bad = defaultProfile() as unknown as Record<string, any>;
  bad.defaults.decisionSpace = { kind: 'escrow_branches', permitted: [] };
  bad.defaults.legalProfile.governingLaw = 'mars';
  bad.defaults.acceptanceWindowMs = -5;
  bad.lintGate.minScore = 101;
  bad.tierThresholds = { aMaxUsd: 1_000, bMaxUsd: 10 };
  bad.extra = true;
  const errors = validateProfile(bad);
  assert.ok(errors.some((e) => e.includes('decisionSpace.permitted')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('governingLaw')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('acceptanceWindowMs')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('minScore')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('aMaxUsd must be strictly less')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('profile.extra: unknown key')), errors.join('\n'));
});

test('validateProfile: jury placement rules (families disjoint, provider floor, allowlist)', () => {
  const p = defaultProfile();
  p.juryPolicy.seats = [
    { seatId: 's1', providerId: 'prov-a', modelId: 'm1', modelFamily: 'fam1' },
    { seatId: 's2', providerId: 'prov-a', modelId: 'm2', modelFamily: 'fam2' },
    { seatId: 's3', providerId: 'prov-b', modelId: 'm3', modelFamily: 'fam1' },
  ];
  p.juryPolicy.provenanceAllowlist = ['prov-a'];
  const errors = validateProfile(p);
  assert.ok(errors.some((e) => e.includes('duplicate family "fam1"')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('"prov-b" is not in the provenanceAllowlist')), errors.join('\n'));

  const oneProvider = defaultProfile();
  oneProvider.juryPolicy.seats = [
    { seatId: 's1', providerId: 'prov-a', modelId: 'm1', modelFamily: 'fam1' },
    { seatId: 's2', providerId: 'prov-a', modelId: 'm2', modelFamily: 'fam2' },
  ];
  const providerFloorErrors = validateProfile(oneProvider);
  assert.ok(providerFloorErrors.some((e) => e.includes('tiers A/B require >= 2 providers')), providerFloorErrors.join('\n'));
});

test('validateProfile: provider majority is legal at profile time for lower-tier rosters', () => {
  const p = defaultProfile();
  p.juryPolicy.seats = [
    { seatId: 's1', providerId: 'prov-a', modelId: 'm1', modelFamily: 'fam1' },
    { seatId: 's2', providerId: 'prov-a', modelId: 'm2', modelFamily: 'fam2' },
    { seatId: 's3', providerId: 'prov-b', modelId: 'm3', modelFamily: 'fam3' },
  ];
  assert.deepEqual(validateProfile(p), []);
});

test('validateProfile: proofPolicy exposes signer allowlists and freshness controls', () => {
  const p = defaultProfile();
  p.juryPolicy.proofPolicy = {
    signerAllowlist: { nearai: [`0x${'11'.repeat(20)}`] },
    freshnessMs: 300_000,
    nowUnixMs: 1_750_000_000_000,
  };
  assert.deepEqual(validateProfile(p), []);

  const bad = defaultProfile() as unknown as Record<string, any>;
  bad.juryPolicy.proofPolicy = {
    signerAllowlist: { nearai: [] },
    freshnessMs: 0,
    nowUnixMs: 'now',
    extra: true,
  };
  const errors = validateProfile(bad);
  assert.ok(errors.some((e) => e.includes('proofPolicy.extra')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('signerAllowlist.nearai')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('freshnessMs')), errors.join('\n'));
  assert.ok(errors.some((e) => e.includes('nowUnixMs')), errors.join('\n'));
});

test('assertValidProfile throws ProfileValidationError with the problem list attached', () => {
  assert.throws(
    () => assertValidProfile({ name: 'x' }),
    (err: unknown) => err instanceof ProfileValidationError && err.problems.length > 0,
  );
});
