/**
 * Core CaseObject validator regression tests:
 * closed enums (incl. caseType/publicity), unknown-key rejection, format
 * checks, tier/value consistency, decisionSpace structural checks, the
 * outcome-in-space checker, third_party submitter restriction, conditional
 * KYB, warn-level publicity rule, evidence cross-references, ruling bounds.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { DecisionSpace, FinalVerdict, VerdictObject } from './types.js';
import {
  assertExecutableVerdict,
  decisionSpaceForRound,
  ExecutableVerdictError,
  validateCaseObject,
  validateAgentAuthorityCredential,
  validateCustomerPolicyPack,
  validateDecisionSpace,
  validateEvidenceCommitment,
  validateLegalPolicy,
  validateOrderMandate,
  validateOutcome,
  validateRuling,
  validateSettlementBinding,
  tierForValueUsd,
} from './validate.js';

const MANDATE_SHA = 'a'.repeat(64);
const MANIFEST_SHA = 'b'.repeat(64);

function validMandate(): Record<string, unknown> {
  return {
    version: 'edict-om-2',
    requester: { agentId: 'requester.near' },
    worker: { agentId: 'worker.near' },
    description: 'Deliver result.json matching the committed checksum.',
    acceptanceCriteria: [{
      id: 'AC-1',
      statement: 'result.json matches the committed checksum',
      machineCheck: { kind: 'hash_equals', params: { path: 'result.json', sha256: 'a'.repeat(64) } },
    }],
    priceUsd: 100,
    currency: { asset: 'USDC', rail: 'near-intents' },
    deadlineUnixMs: 1_800_000_000_000,
    acceptanceWindowMs: 86_400_000,
    legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E0' },
    legalPolicy: {
      version: 'edict-legal-policy-1',
      policyId: 'standard',
      assuranceMode: 'wallet_native',
      rules: { id: 'edict-drr-v0.1', version: '0.1', sha256: 'd'.repeat(64) },
      challengeWindowMs: 86_400_000,
      humanEscalation: { mode: 'off' },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protocol_burn',
    },
    decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins'] },
    settlement: {
      custodyMode: 'M2_external_escrow',
      fundsController: 'customer_contract',
      adapterRef: 'near-intents:v1:protect.customer.near',
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'refund_requester',
    },
    maeEvents: [],
    nonce: 'payment-001',
  };
}

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
      { kind: 'order_mandate', sha256: MANDATE_SHA, submitter: 'system', uri: 'evidence/om.json', authenticated: true },
      { kind: 'delivery_manifest', sha256: MANIFEST_SHA, submitter: 'worker', authenticated: true },
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

/** A well-formed public_resolution case: categorical space, anonymous parties (E1), public. */
function publicResolutionCase(): Record<string, unknown> {
  const c = validCase();
  c.caseType = 'public_resolution';
  c.publicity = 'public';
  c.requester = { agentId: 'near:challenger.near' }; // bonded CHALLENGER, no KYB at E1
  c.worker = { agentId: 'near:proposer.near' };      // PROPOSER defending the resolution
  c.decisionSpace = { kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' };
  return c;
}

/** A well-formed claim case: bounded_scalar space, anonymous parties (E1). */
function claimCase(): Record<string, unknown> {
  const c = validCase();
  c.caseType = 'claim';
  c.requester = { agentId: 'near:claimant.near' };   // CLAIMANT
  c.worker = { agentId: 'near:pool.near' };          // POOL / UNDERWRITER
  c.decisionSpace = { kind: 'bounded_scalar', min: 0, max: 500, unit: 'usd' };
  return c;
}

describe('validateCaseObject', () => {
  it('accepts a well-formed bilateral case', () => {
    const r = validateCaseObject(validCase());
    assert.deepEqual(r.errors, []);
    assert.equal(r.ok, true);
  });

  it('accepts a well-formed public_resolution case (categorical space, no KYB, third_party evidence)', () => {
    const c = publicResolutionCase();
    (c.evidence as Array<Record<string, unknown>>).push({
      kind: 'party_submission', sha256: 'c'.repeat(64), submitter: 'third_party', authenticated: false,
    });
    const r = validateCaseObject(c);
    assert.deepEqual(r.errors, []);
    assert.equal(r.ok, true);
  });

  it('accepts a well-formed claim case (bounded_scalar space, no KYB at E1)', () => {
    const r = validateCaseObject(claimCase());
    assert.deepEqual(r.errors, []);
    assert.equal(r.ok, true);
  });

  it('rejects non-objects', () => {
    for (const bad of [null, 42, 'case', [validCase()]]) {
      assert.equal(validateCaseObject(bad).ok, false);
    }
  });

  it('rejects unknown top-level keys (closed field set) — incl. the retired permittedRulings', () => {
    const c = validCase();
    c.extraField = true;
    const r = validateCaseObject(c);
    assert.ok(r.errors.some((e) => e.startsWith('case.extraField:')), r.errors.join('; '));
    // v0.1-shaped cases (permittedRulings) are now unknown-key rejected.
    const old = validCase();
    old.permittedRulings = ['requester_wins'];
    assert.ok(validateCaseObject(old).errors.some((e) => e.startsWith('case.permittedRulings:')));
  });

  it('rejects unknown keys on nested closed objects', () => {
    const c = validCase();
    (c.requester as Record<string, unknown>).nickname = 'bob';
    (c.legalProfile as Record<string, unknown>).court = 'high';
    (c.evidence as Array<Record<string, unknown>>)[0].notes = 'hi';
    (c.decisionSpace as Record<string, unknown>).extra = 1;
    const errs = validateCaseObject(c).errors;
    assert.ok(errs.some((e) => e.startsWith('case.requester.nickname:')));
    assert.ok(errs.some((e) => e.startsWith('case.legalProfile.court:')));
    assert.ok(errs.some((e) => e.startsWith('case.evidence[0].notes:')));
    assert.ok(errs.some((e) => e.startsWith('case.decisionSpace.extra:')));
  });

  it('railRef stays open (rail adapters own extra keys) but requires rail', () => {
    const ok = validCase();
    (ok.railRef as Record<string, unknown>).anything = { nested: true };
    assert.equal(validateCaseObject(ok).ok, true);
    const bad = validCase();
    bad.railRef = { jobId: 'job-1' };
    assert.ok(validateCaseObject(bad).errors.some((e) => e.startsWith('case.railRef.rail:')));
  });

  it('rejects a non-uuid-v4 caseId and malformed hashes', () => {
    const c1 = validCase();
    c1.caseId = 'not-a-uuid';
    assert.ok(validateCaseObject(c1).errors.some((e) => e.startsWith('case.caseId:')));
    const c2 = validCase();
    c2.caseId = 'a1b2c3d4-0000-1000-8000-0000000000aa'; // version nibble 1, not 4
    assert.ok(validateCaseObject(c2).errors.some((e) => e.startsWith('case.caseId:')));
    const c3 = validCase();
    c3.orderMandateHash = '0xABC';
    assert.ok(validateCaseObject(c3).errors.some((e) => e.startsWith('case.orderMandateHash:')));
  });

  it('closed enums: evidence kind, submitter, custody, law, seat, tier, enforcement', () => {
    const c = validCase();
    (c.evidence as Array<Record<string, unknown>>).push({
      kind: 'sworn_affidavit', sha256: 'c'.repeat(64), submitter: 'lawyer', authenticated: true,
    });
    c.custodyMode = 'M9_hyperspace';
    (c.legalProfile as Record<string, unknown>).governingLaw = 'france';
    (c.legalProfile as Record<string, unknown>).seat = 'paris';
    (c.legalProfile as Record<string, unknown>).enforcementTier = 'E9';
    c.tier = 'D';
    const errs = validateCaseObject(c).errors;
    assert.ok(errs.some((e) => e.startsWith('case.evidence[2].kind:')));
    assert.ok(errs.some((e) => e.startsWith('case.evidence[2].submitter:')));
    assert.ok(errs.some((e) => e.startsWith('case.custodyMode:')));
    assert.ok(errs.some((e) => e.startsWith('case.legalProfile.governingLaw:')));
    assert.ok(errs.some((e) => e.startsWith('case.legalProfile.seat:')));
    assert.ok(errs.some((e) => e.startsWith('case.legalProfile.enforcementTier:')));
    assert.ok(errs.some((e) => e.startsWith('case.tier:')));
  });

  it('closed enums: caseType and publicity', () => {
    const c1 = validCase();
    c1.caseType = 'tripartite';
    assert.ok(validateCaseObject(c1).errors.some((e) => e.startsWith('case.caseType:')));
    const c2 = validCase();
    c2.publicity = 'secret';
    assert.ok(validateCaseObject(c2).errors.some((e) => e.startsWith('case.publicity:')));
    const c3 = validCase();
    delete c3.caseType;
    delete c3.publicity;
    const errs = validateCaseObject(c3).errors;
    assert.ok(errs.some((e) => e.startsWith('case.caseType:')));
    assert.ok(errs.some((e) => e.startsWith('case.publicity:')));
  });

  it('tier/value consistency: A <$10, B $10–1k, C $1k–100k', () => {
    const badB = validCase();
    badB.valueUsd = 50_000; // tier C band, declared B
    assert.ok(validateCaseObject(badB).errors.some((e) => e.startsWith('case.tier:')));
    const okEdge = validCase();
    okEdge.valueUsd = 1_000; // shared edge: B or C both fine
    okEdge.tier = 'C';
    assert.equal(validateCaseObject(okEdge).ok, true);
    const tooBig = validCase();
    tooBig.valueUsd = 250_000;
    tooBig.tier = 'C';
    assert.ok(validateCaseObject(tooBig).errors.some((e) => e.includes('outside all value bands')));
    const nonPositive = validCase();
    nonPositive.valueUsd = 0;
    assert.ok(validateCaseObject(nonPositive).errors.some((e) => e.startsWith('case.valueUsd:')));
  });

  it('Tier A is a hard E0 boundary', () => {
    const tierA = validCase();
    tierA.valueUsd = 5;
    tierA.tier = 'A';
    assert.ok(validateCaseObject(tierA).errors.some((e) => e.includes('Tier A must use E0')));
    (tierA.legalProfile as Record<string, unknown>).enforcementTier = 'E0';
    assert.equal(validateCaseObject(tierA).ok, true);
  });

  it('decisionSpace: structural errors surface under case.decisionSpace', () => {
    const missing = validCase();
    delete missing.decisionSpace;
    assert.ok(validateCaseObject(missing).errors.some((e) => e.startsWith('case.decisionSpace:')));
    const empty = validCase();
    empty.decisionSpace = { kind: 'escrow_branches', permitted: [] };
    assert.ok(validateCaseObject(empty).errors.some((e) => e.startsWith('case.decisionSpace.permitted:')));
    const dup = validCase();
    dup.decisionSpace = { kind: 'escrow_branches', permitted: ['worker_wins', 'worker_wins'] };
    assert.ok(validateCaseObject(dup).errors.some((e) => e.includes('duplicate')));
    const badCat = publicResolutionCase();
    badCat.decisionSpace = { kind: 'categorical', outcomes: ['YES'] };
    assert.ok(validateCaseObject(badCat).errors.some((e) => e.includes('at least 2 distinct outcomes')));
    const badScalar = claimCase();
    badScalar.decisionSpace = { kind: 'bounded_scalar', min: 500, max: 500, unit: 'usd' };
    assert.ok(validateCaseObject(badScalar).errors.some((e) => e.includes('strictly less than max')));
    assert.ok(validateDecisionSpace({ kind: 'escrow_branches', permitted: ['redo'] })
      .some((e) => e.includes('terminal ruling')));

    const roundTwo = validCase();
    roundTwo.decisionSpace = { kind: 'escrow_branches', permitted: ['worker_wins', 'redo'] };
    roundTwo.round = {
      number: 2,
      effectiveDeadlineUnixMs: 1_778_000_000_000,
      priorCaseId: 'b1b2c3d4-0000-4000-8000-0000000000bb',
      priorVerdictSha256: 'c'.repeat(64),
    };
    assert.ok(validateCaseObject(roundTwo).errors.some((e) => e.includes('redo is unavailable in round 2')));
    assert.deepEqual(
      decisionSpaceForRound(roundTwo.decisionSpace as DecisionSpace, 2),
      { kind: 'escrow_branches', permitted: ['worker_wins'] },
    );
  });

  it("third_party submitter: only valid on public_resolution cases", () => {
    const bilateral = validCase();
    (bilateral.evidence as Array<Record<string, unknown>>).push({
      kind: 'party_submission', sha256: 'c'.repeat(64), submitter: 'third_party', authenticated: false,
    });
    const errs = validateCaseObject(bilateral).errors;
    assert.ok(errs.some((e) => e.startsWith('case.evidence[2].submitter:') && e.includes('public_resolution')), errs.join('; '));

    const claim = claimCase();
    (claim.evidence as Array<Record<string, unknown>>).push({
      kind: 'party_submission', sha256: 'c'.repeat(64), submitter: 'third_party', authenticated: false,
    });
    assert.ok(validateCaseObject(claim).errors.some((e) => e.startsWith('case.evidence[2].submitter:')));

    const pub = publicResolutionCase();
    (pub.evidence as Array<Record<string, unknown>>).push({
      kind: 'party_submission', sha256: 'c'.repeat(64), submitter: 'third_party', authenticated: false,
    });
    assert.equal(validateCaseObject(pub).ok, true);
  });

  it('wallet-native bilateral cases do not require KYB', () => {
    const c = validCase();
    c.requester = { agentId: 'near:req.near' };
    c.worker = { agentId: 'near:wrk.near' };
    assert.deepEqual(validateCaseObject(c).errors, []);
  });

  it('conditional KYB: E2/E3 enforcement requires principalKybRef on any caseType', () => {
    for (const tier of ['E2', 'E3']) {
      const c = publicResolutionCase();
      (c.legalProfile as Record<string, unknown>).enforcementTier = tier;
      const errs = validateCaseObject(c).errors;
      assert.ok(errs.some((e) => e.startsWith('case.requester.principalKybRef:')), `${tier}: ${errs.join('; ')}`);
      assert.ok(errs.some((e) => e.startsWith('case.worker.principalKybRef:')));
    }
    // E0/E1 non-bilateral: anonymous parties allowed.
    const anon = claimCase();
    (anon.legalProfile as Record<string, unknown>).enforcementTier = 'E0';
    assert.equal(validateCaseObject(anon).ok, true);
    // present-but-malformed KYB refs are still format-checked.
    const bad = validCase();
    (bad.requester as Record<string, unknown>).principalKybRef = '';
    assert.ok(validateCaseObject(bad).errors.some((e) => e.startsWith('case.requester.principalKybRef:')));
  });

  it("warn-level: sealed public_resolution warns but stays ok", () => {
    const c = publicResolutionCase();
    c.publicity = 'sealed';
    const r = validateCaseObject(c);
    assert.equal(r.ok, true); // SHOULD, not MUST
    assert.ok(r.errors.some((e) => e.startsWith('warn:case.publicity:')), r.errors.join('; '));
    // public public_resolution: no warning at all
    assert.deepEqual(validateCaseObject(publicResolutionCase()).errors, []);
    // sealed bilateral: no warning either
    assert.deepEqual(validateCaseObject(validCase()).errors, []);
  });

  it('timestamps must be sane unix ms', () => {
    const past = validCase();
    past.openedAtUnixMs = 1_777_000_000; // seconds, not ms → year 1970-ish in ms
    assert.ok(validateCaseObject(past).errors.some((e) => e.startsWith('case.openedAtUnixMs:')));
    const frac = validCase();
    frac.openedAtUnixMs = 1_777_000_000_000.5;
    assert.ok(validateCaseObject(frac).errors.some((e) => e.startsWith('case.openedAtUnixMs:')));
  });

  it('requires the order_mandate cross-reference (and delivery_manifest when present)', () => {
    const c1 = validCase();
    c1.orderMandateHash = 'd'.repeat(64);
    assert.ok(validateCaseObject(c1).errors.some((e) => e.startsWith('case.orderMandateHash:')));
    const c2 = validCase();
    c2.deliveryManifestHash = 'e'.repeat(64);
    assert.ok(validateCaseObject(c2).errors.some((e) => e.startsWith('case.deliveryManifestHash:')));
    const c3 = validCase();
    delete c3.deliveryManifestHash; // non-delivery claim path
    assert.equal(validateCaseObject(c3).ok, true);
  });

  it('rejects an empty evidence array', () => {
    const c = validCase();
    c.evidence = [];
    assert.ok(validateCaseObject(c).errors.some((e) => e.startsWith('case.evidence:')));
  });

  it('validates v2 Legal Policy and authority evidence cross-references', () => {
    const c = validCase();
    const policyHash = 'e'.repeat(64);
    const requesterAuthority = 'c'.repeat(64);
    const workerAuthority = 'd'.repeat(64);
    c.legalPolicyHash = policyHash;
    (c.legalProfile as Record<string, unknown>).enforcementTier = 'E2';
    c.requester = {
      agentId: 'near:req.near',
      principalKybRef: 'kyb:v0:req',
      authorityCredentialRef: {
        credentialId: 'authority:req', sha256: requesterAuthority, issuer: 'did:issuer', revocationRegistry: 'https://issuer/revocations',
      },
    };
    c.worker = {
      agentId: 'near:wrk.near',
      principalKybRef: 'kyb:v0:wrk',
      authorityCredentialRef: {
        credentialId: 'authority:wrk', sha256: workerAuthority, issuer: 'did:issuer', revocationRegistry: 'https://issuer/revocations',
      },
    };
    (c.evidence as unknown[]).push(
      { kind: 'legal_policy', sha256: policyHash, submitter: 'system', authenticated: true },
      { kind: 'authority_credential', sha256: requesterAuthority, submitter: 'venue', authenticated: true },
      { kind: 'authority_credential', sha256: workerAuthority, submitter: 'venue', authenticated: true },
    );
    assert.equal(validateCaseObject(c).ok, true);
    delete (c.requester as Record<string, unknown>).authorityCredentialRef;
    assert.ok(validateCaseObject(c).errors.some((e) => e.includes('authorityCredentialRef: required')));
  });

  it('accepts a Legal-Policy-bound wallet-native case without authority credentials', () => {
    const c = validCase();
    const policyHash = 'e'.repeat(64);
    c.legalPolicyHash = policyHash;
    c.requester = { agentId: 'near:req.near' };
    c.worker = { agentId: 'near:wrk.near' };
    (c.legalProfile as Record<string, unknown>).enforcementTier = 'E0';
    (c.evidence as unknown[]).push({
      kind: 'legal_policy', sha256: policyHash, submitter: 'system', authenticated: true,
    });
    assert.equal(validateCaseObject(c).ok, true, validateCaseObject(c).errors.join('; '));
  });
});

describe('validateOrderMandate', () => {
  it('accepts the complete non-custodial v2 wire shape', () => {
    assert.deepEqual(validateOrderMandate(validMandate()), []);
  });

  it('rejects malformed, ambiguous and policy-inconsistent mandate bytes', () => {
    const malformed = validMandate();
    malformed.extra = true;
    malformed.acceptanceCriteria = [
      { id: 'AC-1', statement: 'one' },
      { id: 'AC-1', statement: 'two', machineCheck: { kind: 'arbitrary_code', params: [] } },
    ];
    (malformed.legalProfile as Record<string, unknown>).rules = 'other-rules';
    const problems = validateOrderMandate(malformed);
    assert.ok(problems.some((problem) => problem.includes('unknown key')), problems.join('\n'));
    assert.ok(problems.some((problem) => problem.includes('duplicate criterion')), problems.join('\n'));
    assert.ok(problems.some((problem) => problem.includes('machineCheck.kind')), problems.join('\n'));
    assert.ok(problems.some((problem) => problem.includes('machineCheck.params')), problems.join('\n'));
    assert.ok(problems.some((problem) => problem.includes('must match mandate.legalPolicy.rules.id')), problems.join('\n'));
  });

  it('validates standalone evidence commitments as closed wire objects', () => {
    assert.deepEqual(validateEvidenceCommitment({
      kind: 'order_mandate', sha256: 'a'.repeat(64), submitter: 'system', authenticated: true,
    }), []);
    assert.ok(validateEvidenceCommitment({
      kind: 'order_mandate', sha256: 'bad', submitter: 'system', authenticated: true, extra: true,
    }).length >= 2);
  });
});

describe('signed legal schemas', () => {
  const ref = { id: 'edict-drr-v0.1', version: '0.1', sha256: 'a'.repeat(64) };

  it('allows only customer, wallet or rail-controlled settlement bindings', () => {
    const binding = {
      custodyMode: 'M2_external_escrow',
      fundsController: 'payment_rail',
      adapterRef: 'rail:acme-payments:escrow-v2',
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'controller_resolution',
    };
    assert.deepEqual(validateSettlementBinding(binding), []);
    assert.deepEqual(validateSettlementBinding({
      ...binding,
      custodyMode: 'M4_no_custody',
      fundsController: 'requester_wallet',
    }), []);
    assert.ok(validateSettlementBinding({ ...binding, custodyMode: 'M1_native_escrow' }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, fundsController: 'edict' }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, edictOperatorCanTransfer: true }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, edictOperatorCanFreeze: true }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, edictOperatorIsRequiredSigner: true }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, resolutionTimeoutMs: 0 }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, livenessFallback: 'wait_for_edict' }).length > 0);
    assert.ok(validateSettlementBinding({ ...binding, adapterRef: '' }).length > 0);

    const confidential = {
      ...binding,
      confidentiality: {
        mode: 'confidential_settlement',
        capabilitySha256: 'b'.repeat(64),
        disclosurePolicySha256: 'c'.repeat(64),
        fallback: 'fail_closed',
      },
    };
    assert.deepEqual(validateSettlementBinding(confidential), []);
    assert.match(
      validateSettlementBinding({
        ...confidential,
        confidentiality: { ...confidential.confidentiality, capabilitySha256: '0'.repeat(64) },
      }).join('; '),
      /zero hash/,
    );
    assert.match(
      validateSettlementBinding({
        ...confidential,
        confidentiality: { ...confidential.confidentiality, fallback: 'silently_public' },
      }).join('; '),
      /must be one of/,
    );
    assert.match(
      validateSettlementBinding({
        ...confidential,
        confidentiality: {
          ...confidential.confidentiality,
          fallback: 'allow_public_settlement',
        },
      }).join('; '),
      /publicFallbackAdapterRef/,
    );
    assert.deepEqual(validateSettlementBinding({
      ...confidential,
      confidentiality: {
        ...confidential.confidentiality,
        fallback: 'allow_public_settlement',
        publicFallbackAdapterRef: 'near-intents:v1:public-fallback',
      },
    }), []);
  });

  it('validates a complete Legal Policy and rejects a malformed Rules hash', () => {
    const policy = {
      version: 'edict-legal-policy-1',
      policyId: 'standard-v1',
      assuranceMode: 'wallet_native',
      rules: ref,
      challengeWindowMs: 86_400_000,
      humanEscalation: { mode: 'quality_gate', reviewerPool: 'edict_bench' },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protection_pool',
    };
    assert.deepEqual(validateLegalPolicy(policy), []);
    assert.ok(validateLegalPolicy({ ...policy, rules: { ...ref, sha256: 'bad' } }).some((e) => e.includes('sha256')));
    assert.ok(validateLegalPolicy({ ...policy, challengeWindowMs: 2 * 60 * 60 * 1_000 - 1 }).some((e) => e.includes('2 and 24 hours')));
    assert.ok(validateLegalPolicy({ ...policy, challengeWindowMs: 24 * 60 * 60 * 1_000 + 1 }).some((e) => e.includes('2 and 24 hours')));
  });

  it('validates Customer Policy Pack precedence and source-clause mappings', () => {
    const pack = {
      version: 'edict-customer-policy-1',
      policyId: 'processor-terms-v4',
      sourceTerms: [{ id: 'processor-tos', version: '4', sha256: 'b'.repeat(64) }],
      rulesOfDecision: [{ id: 'CP-1', statement: 'The authenticated ledger controls.', sourceClauseIds: ['7.2'] }],
      orderOfPrecedence: ['mandatory_law', 'order_mandate', 'customer_policy', 'edict_drr'],
    };
    assert.deepEqual(validateCustomerPolicyPack(pack), []);
    assert.ok(validateCustomerPolicyPack({ ...pack, orderOfPrecedence: ['order_mandate'] }).length > 0);
    assert.ok(
      validateCustomerPolicyPack({
        ...pack,
        orderOfPrecedence: ['customer_policy', 'mandatory_law', 'order_mandate', 'edict_drr'],
      }).some((e) => e.includes('fixed safe hierarchy')),
    );
  });

  it('validates the full principal-to-agent credential shape', () => {
    const credential = {
      version: 'edict-authority-1',
      credentialId: 'authority:req:1',
      principalKybRef: 'kyb:req',
      agentId: 'agent:req',
      scope: { actions: ['protect', 'dispute'], maxValueUsd: 10_000, rails: ['near'] },
      validFromUnixMs: 1_750_000_000_000,
      validUntilUnixMs: 1_850_000_000_000,
      issuer: { id: 'did:req', keyId: 'did:req#authority' },
      revocation: { registry: 'https://req/revocations', nonce: '1' },
      proof: { scheme: 'jws', signature: 'signed-value' },
    };
    assert.deepEqual(validateAgentAuthorityCredential(credential), []);
    assert.ok(validateAgentAuthorityCredential({ ...credential, validUntilUnixMs: 1_700_000_000_000 }).length > 0);
  });
});

describe('validateDecisionSpace', () => {
  it('accepts every well-formed space kind', () => {
    assert.deepEqual(validateDecisionSpace({ kind: 'escrow_branches', permitted: ['requester_wins'] }), []);
    assert.deepEqual(
      validateDecisionSpace({ kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins', 'split', 'redo'] }),
      [],
    );
    assert.deepEqual(validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 'NO'] }), []);
    assert.deepEqual(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' }),
      [],
    );
    assert.deepEqual(validateDecisionSpace({ kind: 'bounded_scalar', min: 0, max: 10_000, unit: 'usd' }), []);
    assert.deepEqual(validateDecisionSpace({ kind: 'bounded_scalar', min: -5.5, max: 5.5, unit: 'pct' }), []);
  });

  it('rejects non-objects and unknown kinds', () => {
    assert.ok(validateDecisionSpace(null).length > 0);
    assert.ok(validateDecisionSpace('escrow_branches').length > 0);
    assert.ok(validateDecisionSpace({ kind: 'coin_flip' }).some((e) => e.startsWith('decisionSpace.kind:')));
  });

  it('escrow_branches: permitted non-empty, closed kinds, deduplicated, closed keys', () => {
    assert.ok(
      validateDecisionSpace({ kind: 'escrow_branches', permitted: [] })
        .some((e) => e.startsWith('decisionSpace.permitted:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'escrow_branches' })
        .some((e) => e.startsWith('decisionSpace.permitted:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'escrow_branches', permitted: ['requester_wins', 'draw'] })
        .some((e) => e.startsWith('decisionSpace.permitted[1]:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'escrow_branches', permitted: ['split', 'split'] })
        .some((e) => e.includes("duplicate ruling kind 'split'")),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'escrow_branches', permitted: ['split'], outcomes: ['YES'] })
        .some((e) => e.startsWith('decisionSpace.outcomes: unknown key')),
    );
  });

  it('categorical: >=2 distinct outcomes, no duplicates, invalidOutcome ∈ outcomes', () => {
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES'] })
        .some((e) => e.includes('at least 2 distinct outcomes')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: [] })
        .some((e) => e.includes('at least 2 distinct outcomes')),
    );
    const dup = validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 'YES'] });
    assert.ok(dup.some((e) => e.includes("duplicate outcome 'YES'")));
    assert.ok(dup.some((e) => e.includes('at least 2 distinct outcomes'))); // 2 entries, 1 distinct
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', ''] })
        .some((e) => e.startsWith('decisionSpace.outcomes[1]:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 42] })
        .some((e) => e.startsWith('decisionSpace.outcomes[1]:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 'NO'], invalidOutcome: 'VOID' })
        .some((e) => e.startsWith('decisionSpace.invalidOutcome:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'categorical', outcomes: ['YES', 'NO'], permitted: [] })
        .some((e) => e.startsWith('decisionSpace.permitted: unknown key')),
    );
  });

  it('bounded_scalar: finite min < max, non-empty unit, closed keys', () => {
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: 10, max: 10, unit: 'usd' })
        .some((e) => e.includes('strictly less than max')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: 11, max: 10, unit: 'usd' })
        .some((e) => e.includes('strictly less than max')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: Number.NEGATIVE_INFINITY, max: 10, unit: 'usd' })
        .some((e) => e.startsWith('decisionSpace.min:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: 0, max: NaN, unit: 'usd' })
        .some((e) => e.startsWith('decisionSpace.max:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: 0, max: 10, unit: '' })
        .some((e) => e.startsWith('decisionSpace.unit:')),
    );
    assert.ok(
      validateDecisionSpace({ kind: 'bounded_scalar', min: 0, max: 10, unit: 'usd', step: 1 })
        .some((e) => e.startsWith('decisionSpace.step: unknown key')),
    );
  });
});

describe('validateOutcome', () => {
  const escrow: DecisionSpace = { kind: 'escrow_branches', permitted: ['requester_wins', 'split'] };
  const categorical: DecisionSpace = { kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' };
  const scalar: DecisionSpace = { kind: 'bounded_scalar', min: 0, max: 1_000, unit: 'usd' };

  it('escrow_branches: accepts permitted rulings, rejects unpermitted and malformed ones', () => {
    assert.deepEqual(validateOutcome({ kind: 'requester_wins' }, escrow), []);
    assert.deepEqual(validateOutcome({ kind: 'split', requesterBps: 2500 }, escrow), []);
    assert.ok(
      validateOutcome({ kind: 'worker_wins' }, escrow)
        .some((e) => e.includes('not among the permitted escrow branches')),
    );
    assert.ok(
      validateOutcome({ kind: 'redo', newDeadlineUnixMs: 1_777_000_000_000 }, escrow)
        .some((e) => e.includes('not among the permitted escrow branches')),
    );
    // still a full Ruling check: bounds and unknown keys apply
    assert.ok(validateOutcome({ kind: 'split', requesterBps: 10_001 }, escrow).length > 0);
    assert.ok(validateOutcome({ kind: 'requester_wins', note: 'x' }, escrow).length > 0);
    // wrong outcome family for the space
    assert.ok(validateOutcome({ kind: 'categorical', outcome: 'YES' }, escrow).length > 0);
    assert.ok(validateOutcome({ kind: 'scalar', value: 5 }, escrow).length > 0);
    assert.ok(validateOutcome('requester_wins', escrow).length > 0);
  });

  it('categorical: accepts members (incl. invalidOutcome), rejects non-members and bad shapes', () => {
    assert.deepEqual(validateOutcome({ kind: 'categorical', outcome: 'YES' }, categorical), []);
    assert.deepEqual(validateOutcome({ kind: 'categorical', outcome: 'INVALID' }, categorical), []);
    assert.ok(
      validateOutcome({ kind: 'categorical', outcome: 'MAYBE' }, categorical)
        .some((e) => e.includes('not in the decision space outcomes')),
    );
    assert.ok(validateOutcome({ kind: 'categorical', outcome: '' }, categorical).length > 0);
    assert.ok(validateOutcome({ kind: 'categorical' }, categorical).length > 0);
    assert.ok(
      validateOutcome({ kind: 'categorical', outcome: 'YES', reason: 'x' }, categorical)
        .some((e) => e.startsWith('outcome.reason: unknown key')),
    );
    assert.ok(
      validateOutcome({ kind: 'requester_wins' }, categorical)
        .some((e) => e.includes("must be 'categorical'")),
    );
    assert.ok(validateOutcome({ kind: 'scalar', value: 1 }, categorical).length > 0);
  });

  it('bounded_scalar: accepts finite in-range values (bounds inclusive), rejects the rest', () => {
    assert.deepEqual(validateOutcome({ kind: 'scalar', value: 500 }, scalar), []);
    assert.deepEqual(validateOutcome({ kind: 'scalar', value: 0 }, scalar), []);
    assert.deepEqual(validateOutcome({ kind: 'scalar', value: 1_000 }, scalar), []);
    assert.deepEqual(validateOutcome({ kind: 'scalar', value: 0.01 }, scalar), []);
    assert.ok(
      validateOutcome({ kind: 'scalar', value: -0.01 }, scalar)
        .some((e) => e.includes('outside the bounded scalar range')),
    );
    assert.ok(
      validateOutcome({ kind: 'scalar', value: 1_000.01 }, scalar)
        .some((e) => e.includes('outside the bounded scalar range')),
    );
    assert.ok(validateOutcome({ kind: 'scalar', value: NaN }, scalar).length > 0);
    assert.ok(validateOutcome({ kind: 'scalar', value: Infinity }, scalar).length > 0);
    assert.ok(validateOutcome({ kind: 'scalar', value: '500' }, scalar).length > 0);
    assert.ok(
      validateOutcome({ kind: 'scalar', value: 5, unit: 'usd' }, scalar)
        .some((e) => e.startsWith('outcome.unit: unknown key')),
    );
    assert.ok(
      validateOutcome({ kind: 'worker_wins' }, scalar)
        .some((e) => e.includes("must be 'scalar'")),
    );
  });

  it('fails closed against a structurally invalid decision space', () => {
    const badSpace = { kind: 'categorical', outcomes: ['ONLY'] } as unknown as DecisionSpace;
    const errs = validateOutcome({ kind: 'categorical', outcome: 'ONLY' }, badSpace);
    assert.ok(errs.some((e) => e.includes('structurally invalid decision space')));
    assert.ok(errs.some((e) => e.startsWith('decisionSpace.outcomes:')));
  });
});

describe('validateRuling', () => {
  it('accepts every well-formed ruling shape', () => {
    assert.deepEqual(validateRuling({ kind: 'requester_wins' }), []);
    assert.deepEqual(validateRuling({ kind: 'worker_wins' }), []);
    assert.deepEqual(validateRuling({ kind: 'split', requesterBps: 2500 }), []);
    assert.deepEqual(validateRuling({ kind: 'redo', newDeadlineUnixMs: 1_777_000_000_000 }), []);
  });

  it('rejects out-of-vocabulary kinds and out-of-range split bps', () => {
    assert.ok(validateRuling({ kind: 'draw' }).length > 0);
    assert.ok(validateRuling({ kind: 'split', requesterBps: 10_001 }).length > 0);
    assert.ok(validateRuling({ kind: 'split', requesterBps: -1 }).length > 0);
    assert.ok(validateRuling({ kind: 'split', requesterBps: 12.5 }).length > 0);
  });

  it('rejects unknown keys per kind', () => {
    assert.ok(validateRuling({ kind: 'worker_wins', requesterBps: 5000 }).length > 0);
    assert.ok(validateRuling({ kind: 'split', requesterBps: 5000, note: 'x' }).length > 0);
  });
});

describe('tierForValueUsd', () => {
  it('bands and shared edges', () => {
    assert.deepEqual(tierForValueUsd(5), ['A']);
    assert.deepEqual(tierForValueUsd(10), ['B']);
    assert.deepEqual(tierForValueUsd(1_000), ['B', 'C']);
    assert.deepEqual(tierForValueUsd(100_000), ['C']);
    assert.deepEqual(tierForValueUsd(100_001), []);
  });
});

// ---------------------------------------------------------------------------
// assertExecutableVerdict is the executable-verdict gate.
// ---------------------------------------------------------------------------

describe('assertExecutableVerdict', () => {
  const ESCROW_SPACE: DecisionSpace = { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins'] };
  const SCALAR_SPACE: DecisionSpace = { kind: 'bounded_scalar', min: 0, max: 50_000, unit: 'USD' };

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

  it('happy path: a clean final in-space verdict passes and narrows to FinalVerdict', () => {
    const v = verdict();
    assertExecutableVerdict(v, ESCROW_SPACE);
    const fv: FinalVerdict = v; // compile-time proof the assertion narrowed
    assert.equal(fv.final, true);
  });

  it('rejects final=false (escalated verdicts are never executable)', () => {
    const v = verdict({
      final: false,
      quality: { majority: 'none', swapFlipRate: 0.5, injectionFlags: [], escalated: true, escalationReason: 'no_majority' },
    });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) =>
        err instanceof ExecutableVerdictError &&
        err.caseId === v.caseId &&
        err.problems.some((p) => p.includes('final=false')) &&
        err.problems.some((p) => p.includes('no_majority')),
    );
  });

  it('rejects the inconsistent final=true + quality.escalated=true (fails closed on pipeline bugs)', () => {
    const v = verdict({
      quality: { majority: 'unanimous', swapFlipRate: 0, injectionFlags: [], escalated: true },
    });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.includes('quality.escalated=true')),
    );
  });

  it('rejects an out-of-space ruling (verdict-oracle invariant at the money boundary)', () => {
    // split is not among the permitted escrow branches of this space
    const v = verdict({ ruling: { kind: 'split', requesterBps: 5000 } });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.includes("not among the permitted escrow branches")),
    );
    // scalar out of bounds
    const s = verdict({ ruling: { kind: 'scalar', value: 60_000 } });
    assert.throws(
      () => assertExecutableVerdict(s, SCALAR_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.includes('outside the bounded scalar range')),
    );
    // in-bounds scalar passes
    const ok = verdict({ ruling: { kind: 'scalar', value: 30_000 } });
    assertExecutableVerdict(ok, SCALAR_SPACE);
  });

  it('rejects attack-severity injection flags by default; allowAttackFlags opts in explicitly', () => {
    const v = verdict({
      quality: {
        majority: 'unanimous',
        swapFlipRate: 0,
        injectionFlags: ['attack:instruction_override:party_submission:worker:deadbeef', 'note:stylistic'],
        escalated: false,
      },
    });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.includes('attack-severity')),
    );
    assertExecutableVerdict(v, ESCROW_SPACE, { allowAttackFlags: true });
  });

  it('accepts attack-flag verdicts WHEN a well-formed humanReview marker is present (review policy bench resolution)', () => {
    // A human reviewer inspected the contaminated record and issued the
    // ruling: the attack flags stay on the record for audit, but no longer
    // block execution — humanReview is the audit marker of the bench pass.
    const v = verdict({
      quality: {
        majority: 'unanimous',
        swapFlipRate: 0,
        injectionFlags: ['attack:instruction_override:party_submission:worker:deadbeef'],
        escalated: false,
      },
      humanReview: { reviewerRef: 'bench:reviewer-1', decidedAtUnixMs: 1_777_000_100_000, basis: 'quality_gate' },
    });
    assertExecutableVerdict(v, ESCROW_SPACE); // no throw, no opt-in needed
    // basis 'appeal' works identically
    const appealed = verdict({
      quality: { majority: 'majority', swapFlipRate: 0, injectionFlags: ['attack:x:y'], escalated: false },
      humanReview: { reviewerRef: 'bench:reviewer-2', decidedAtUnixMs: 1_777_000_100_000, basis: 'appeal' },
    });
    assertExecutableVerdict(appealed, ESCROW_SPACE);
  });

  it('a MALFORMED humanReview marker earns no attack-flag exemption and is itself a problem (fails closed)', () => {
    const attackQuality = {
      majority: 'unanimous',
      swapFlipRate: 0,
      injectionFlags: ['attack:x:y'],
      escalated: false,
    } as VerdictObject['quality'];
    for (const junk of [
      { reviewerRef: '', decidedAtUnixMs: 1_777_000_100_000, basis: 'quality_gate' }, // empty reviewer
      { reviewerRef: 'bench:r', decidedAtUnixMs: 1_777_000_100_000, basis: 'vibes' }, // bad basis
      { reviewerRef: 'bench:r', decidedAtUnixMs: 42, basis: 'appeal' },               // insane timestamp
      { reviewerRef: 'bench:r', decidedAtUnixMs: 1_777_000_100_000, basis: 'appeal', extra: 1 }, // unknown key
      'bench:r',                                                                       // not an object
    ]) {
      const v = verdict({ quality: { ...attackQuality }, humanReview: junk as never });
      assert.throws(
        () => assertExecutableVerdict(v, ESCROW_SPACE),
        (err: unknown) =>
          err instanceof ExecutableVerdictError &&
          err.problems.some((p) => p.startsWith('humanReview')) &&
          err.problems.some((p) => p.includes('attack-severity')),
        `junk humanReview should fail closed: ${JSON.stringify(junk)}`,
      );
    }
    // Malformed humanReview is a problem even WITHOUT attack flags on the record.
    const clean = verdict({ humanReview: { reviewerRef: '' } as never });
    assert.throws(
      () => assertExecutableVerdict(clean, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.startsWith('humanReview')),
    );
  });

  it('INVARIANT: humanReview never bypasses the final/escalated gates — an escalated verdict stays non-executable', () => {
    // The policy governs where an escalated verdict routes next, NOT whether
    // it can settle: even a (bogus) humanReview marker on an escalated
    // verdict does not make it executable. A bench resolution is a NEW
    // verdict (final=true, escalated=false) — this one is not it.
    const v = verdict({
      final: false,
      quality: { majority: 'none', swapFlipRate: 0.5, injectionFlags: [], escalated: true, escalationReason: 'no_majority' },
      humanReview: { reviewerRef: 'bench:reviewer-1', decidedAtUnixMs: 1_777_000_100_000, basis: 'quality_gate' },
    });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) =>
        err instanceof ExecutableVerdictError &&
        err.problems.some((p) => p.includes('final=false')) &&
        err.problems.some((p) => p.includes('quality.escalated=true')),
    );
    // Forged final=true over an escalated quality record: still refused.
    const forged = verdict({
      final: true,
      quality: { majority: 'none', swapFlipRate: 0.5, injectionFlags: [], escalated: true },
      humanReview: { reviewerRef: 'bench:reviewer-1', decidedAtUnixMs: 1_777_000_100_000, basis: 'appeal' },
    });
    assert.throws(
      () => assertExecutableVerdict(forged, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.some((p) => p.includes('quality.escalated=true')),
    );
  });

  it('note:-prefixed and deterministic flags never block execution', () => {
    const v = verdict({
      quality: {
        majority: 'unanimous',
        swapFlipRate: 0,
        injectionFlags: ['note:imperative_advocacy', 'deterministic:all_machine_checks_passed'],
        escalated: false,
      },
    });
    assertExecutableVerdict(v, ESCROW_SPACE);
  });

  it('aggregates multiple problems into one error', () => {
    const v = verdict({
      final: false,
      ruling: { kind: 'scalar', value: 1 },
      quality: {
        majority: 'none',
        swapFlipRate: 1,
        injectionFlags: ['attack:x:y'],
        escalated: true,
      },
    });
    assert.throws(
      () => assertExecutableVerdict(v, ESCROW_SPACE),
      (err: unknown) => err instanceof ExecutableVerdictError && err.problems.length >= 3,
    );
  });
});
