/**
 * Preset protection policies — product interface ("Policy builder —
 * preset-first"), step 1. Three canonical, hash-committed
 * ProtectionProfiles a customer picks before touching any advanced field:
 *
 * - **Basic** — for small automated tasks: fast checks, no human review.
 * - **Standard** — for most agent payments: adaptive provider verification,
 *   human review off, and a safe non-execution fallback when uncertain.
 * - **High Assurance** — for higher-value or sensitive work: stronger
 *   evidence requirements, optional human appeal plus the safety valve, and
 *   required human review above a value threshold.
 *
 * Each preset is deterministic (same content every call) so its
 * `profileHash` is CANONICAL — tests pin the hashes, and a verdict under a
 * preset is attributable to exactly this policy content.
 */

import type { AssuranceMode, DecisionSpace, EscalationTrigger, HumanEscalationPolicy, LegalPolicy } from '@edict/core';
import { SANDBOX_MOCK_SEATS, profileHash, type ProtectionProfile } from './profile.js';

export type PresetKey = 'basic' | 'standard' | 'high_assurance';

/** A preset with its user-facing copy (preset wording) and canonical hash. */
export interface PresetDefinition {
  key: PresetKey;
  /** User-facing name. */
  title: string;
  /** user-facing step-1 copy: who it is for + what it does, plain English. */
  copy: string;
  /** Plain-English wording of the human-review election (product interface). */
  humanReviewCopy: string;
  profile: ProtectionProfile;
  /** sha256 over the canonical profile JSON — the policy identity. */
  profileHash: string;
}

const LEGAL_PROFILE = {
  governingLaw: 'england_wales',
  seat: 'london',
  rules: 'edict-drr-v0.1',
  enforcementTier: 'E0',
} as const;

function legalPolicy(
  policyId: string,
  humanEscalation: HumanEscalationPolicy,
  assuranceMode: AssuranceMode = 'wallet_native',
): LegalPolicy {
  return {
    version: 'edict-legal-policy-1',
    policyId,
    assuranceMode,
    rules: {
      id: 'edict-drr-v0.1',
      version: '0.1',
      sha256: '17701fa24d618290fb28da1315fdaa4480e7634aeccba074f3fbd393e2f848c5',
      uri: 'legal/edict-dispute-resolution-rules-v0.1.md',
    },
    challengeWindowMs: 86_400_000,
    humanEscalation,
    e2ImplementationTiming: 'implement_then_arbitrate',
    bondRemovalDestination: 'protocol_burn',
  };
}

function fullEscrowSpace(): DecisionSpace {
  return { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins', 'split', 'redo'] };
}

/** Every arbiter-emitted quality trigger + the party appeal (High Assurance coverage). */
const ALL_TRIGGERS: readonly EscalationTrigger[] = [
  'no_majority',
  'insufficient_attested_seats',
  'swap_inconsistency',
  'low_confidence',
  'injection_attack',
  'out_of_policy_evidence',
  'party_appeal',
];

/**
 * **Basic** — "Small automated tasks. Fast checks, no human review."
 * Deterministic checks and the AI panel decide; the human-review toggle is
 * OFF ("AI/protocol decision is final when quality gates pass").
 */
export function basicProfile(): ProtectionProfile {
  const humanEscalation: HumanEscalationPolicy = { mode: 'off' };
  return {
    name: 'edict-preset-basic',
    version: '1.2.0',
    legalPolicy: legalPolicy('edict-basic-legal-v0.1', humanEscalation),
    defaults: {
      decisionSpace: fullEscrowSpace(),
      legalProfile: { ...LEGAL_PROFILE },
      acceptanceWindowMs: 86_400_000, // 24h auto-accept window
      maeEvents: [],
    },
    tierThresholds: { aMaxUsd: 10, bMaxUsd: 1_000 },
    juryPolicy: {
      seats: SANDBOX_MOCK_SEATS.map((s) => ({ ...s })),
      requireProofs: false, // fast checks — no attestation execution gate
    },
    lintGate: { minScore: 60, blockOnError: true },
    humanEscalation,
  };
}

/**
 * **Standard** — most agent payments. Real providers are proof-gated by the
 * arbiter's adaptive default; bundled deterministic mocks remain usable in an
 * offline sandbox. Human review remains off by default; an uncertain result
 * fails safe and stays unexecuted unless the customer elects a review path.
 */
export function standardProfile(): ProtectionProfile {
  const humanEscalation: HumanEscalationPolicy = { mode: 'off' };
  return {
    name: 'edict-preset-standard',
    version: '1.2.0',
    legalPolicy: legalPolicy('edict-standard-legal-v0.1', humanEscalation),
    defaults: {
      decisionSpace: fullEscrowSpace(),
      legalProfile: { ...LEGAL_PROFILE },
      acceptanceWindowMs: 86_400_000,
      maeEvents: [],
    },
    tierThresholds: { aMaxUsd: 10, bMaxUsd: 1_000 },
    juryPolicy: {
      seats: SANDBOX_MOCK_SEATS.map((s) => ({ ...s })),
      // Omitted = proof-gate real providers automatically, but allow the
      // deterministic MockProvider used by the offline quickstart.
    },
    lintGate: { minScore: 80, blockOnError: true },
    humanEscalation,
  };
}

/**
 * **High Assurance** — "Higher-value or sensitive work. Stronger provider
 * diversity, human review available, more detailed evidence requirements."
 * Optional appeal (bonded) + every quality trigger routed to a human, and
 * cases at/above $10,000 ALWAYS reviewed before settlement
 * (required_above_value — the user-facing threshold example).
 */
export function highAssuranceProfile(): ProtectionProfile {
  const humanEscalation: HumanEscalationPolicy = {
    mode: 'optional_appeal',
    triggers: [...ALL_TRIGGERS],
    perTier: { C: 'required_above_value' },
    thresholdUsd: 10_000,
    appealWindowMs: 172_800_000,
    appealBondMultiplier: 2,
    reviewerPool: 'edict_bench',
  };
  return {
    name: 'edict-preset-high-assurance',
    version: '1.2.0',
    legalPolicy: legalPolicy('edict-high-assurance-legal-v0.1', humanEscalation),
    defaults: {
      decisionSpace: fullEscrowSpace(),
      legalProfile: { ...LEGAL_PROFILE },
      acceptanceWindowMs: 172_800_000, // 48h — more time to inspect sensitive work
      maeEvents: [],
    },
    tierThresholds: { aMaxUsd: 10, bMaxUsd: 1_000 },
    juryPolicy: {
      seats: SANDBOX_MOCK_SEATS.map((s) => ({ ...s })),
      requireProofs: true,
      // Stronger evidence requirements: only the committed provider roster
      // may seat jurors (provenance allowlist pins the providers).
      provenanceAllowlist: SANDBOX_MOCK_SEATS.map((s) => s.providerId),
    },
    // More detailed evidence requirements: mandates must lint ≥90 and any
    // error-severity finding blocks before funds lock.
    lintGate: { minScore: 90, blockOnError: true },
    humanEscalation,
  };
}

/**
 * Explicit enterprise-only starting point. Unlike the customer presets, this
 * elects E1 and therefore requires KYB-linked delegated authority for both
 * parties when an order is protected.
 */
export function enterpriseLegalProfile(): ProtectionProfile {
  const profile = highAssuranceProfile();
  profile.name = 'edict-enterprise-legal';
  profile.version = '1.0.0';
  profile.legalPolicy = legalPolicy(
    'edict-enterprise-legal-v0.1',
    profile.humanEscalation ?? { mode: 'quality_gate', reviewerPool: 'edict_bench' },
    'enterprise_legal',
  );
  profile.defaults.legalProfile = { ...LEGAL_PROFILE, enforcementTier: 'E1' };
  return profile;
}

/** The three step-1 presets with their user-facing copy and canonical hashes. */
export function PRESETS(): PresetDefinition[] {
  const basic = basicProfile();
  const standard = standardProfile();
  const high = highAssuranceProfile();
  return [
    {
      key: 'basic',
      title: 'Basic',
      copy: 'Small automated tasks. Fast checks, no human review.',
      humanReviewCopy: 'Off — the automated decision is final when quality gates pass.',
      profile: basic,
      profileHash: profileHash(basic),
    },
    {
      key: 'standard',
      title: 'Standard',
      copy: 'Most agent payments. Verified AI review with a safe hold when Edict cannot decide.',
      humanReviewCopy: 'Off by default — uncertain decisions stay safely unexecuted unless you enable human review.',
      profile: standard,
      profileHash: profileHash(standard),
    },
    {
      key: 'high_assurance',
      title: 'High Assurance',
      copy: 'Higher-value or sensitive work. Stronger provider diversity, human review available, more detailed evidence requirements.',
      humanReviewCopy:
        'Optional appeal + safety valve — either party may request human review before settlement, ' +
        'quality issues route to a human automatically, and decisions at or above $10,000 are always reviewed.',
      profile: high,
      profileHash: profileHash(high),
    },
  ];
}

/** Look up one preset by key (undefined for unknown keys). */
export function presetByKey(key: string): PresetDefinition | undefined {
  return PRESETS().find((p) => p.key === key);
}
