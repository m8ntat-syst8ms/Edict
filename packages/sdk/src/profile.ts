/**
 * ProtectionProfile — the reusable policy object an integrator commits to
 * once and applies to every order (SDK integration contract).
 *
 * A profile bundles: mandate defaults (decision space, legal profile,
 * acceptance window, MAE events), value-tier preferences, jury policy
 * (seat roster / proof requirements / provider provenance allowlist), the
 * pre-commitment lint gate and the human escalation policy (review policy).
 * The signed Legal Policy also elects an assurance mode. Ordinary presets use
 * wallet-native E0 settlement; enterprise legal identity is opt-in.
 * `profileHash` (sha256 over canonical JSON) is the
 * identity the SDK records on every dispute's `railRef`, so a verdict is
 * always attributable to the exact policy it was adjudicated under.
 */

import type {
  CustomerPolicyPack,
  DecisionSpace,
  EscalationTrigger,
  HumanEscalationMode,
  JurySeatSpec,
  LegalProfile,
  LegalPolicy,
  Publicity,
  ReviewerPool,
  ValueTier,
} from '@edict/core';
import {
  ENFORCEMENT_TIERS,
  ESCALATION_TRIGGERS,
  GOVERNING_LAWS,
  HUMAN_ESCALATION_MODES,
  PUBLICITIES,
  REVIEWER_POOLS,
  SEATS,
  VALUE_TIERS,
  validateDecisionSpace,
  validateCustomerPolicyPack,
  validateLegalPolicy,
} from '@edict/core';
import { sha256Canonical } from '@edict/evidence';
import type { ProofPolicy } from '@edict/arbiter';
import { ProfileValidationError } from './errors.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProtectionProfile {
  /** Human-readable profile name, e.g. "acme-agent-commerce". */
  name: string;
  /** Profile version string — bump when policy changes; the hash changes with it. */
  version: string;
  /** Exact legal election embedded in and signed by every edict-om-2 order. */
  legalPolicy: LegalPolicy;
  /** Optional full customer T&Cs module; legalPolicy carries its canonical hash. */
  customerPolicyPack?: CustomerPolicyPack;
  /** Mandate defaults applied by `protect()` unless overridden per order. */
  defaults: {
    decisionSpace: DecisionSpace;
    legalProfile: LegalProfile;
    acceptanceWindowMs: number;
    maeEvents?: string[];
    /**
     * Publicity for cases opened under this profile. Default when absent:
     * 'sealed' ('public' for public_resolution disputes).
     */
    publicity?: Publicity;
  };
  /**
   * Value-tier preferences (USD). Reconciled against the canonical value bands
   * bands (A <$10, B $10–1k, C $1k–100k): a preference outside the canonical
   * band for a given value falls back to the canonical tier, so assembled
   * cases always validate.
   */
  tierThresholds?: { aMaxUsd: number; bMaxUsd: number };
  /** Jury policy for disputes raised under this profile. */
  juryPolicy: {
    /** Seat roster; defaults to {@link SANDBOX_MOCK_SEATS} (3 disjoint-family mock seats). */
    seats?: JurySeatSpec[];
    /** Attestation execution gate override (see ArbiterConfig.requireProofs). */
    requireProofs?: boolean;
    /** When present, every seat's providerId MUST be in this allowlist. */
    provenanceAllowlist?: string[];
    /**
     * Real proof-verification policy passed through to the arbiter:
     * signer allowlists, freshness window and optional injected "now".
     *
     * NOTE: this object is covered by `profileHash` — signer allowlists and
     * freshness windows are policy and SHOULD be committed here. `nowUnixMs`,
     * however, is a runtime/testing knob: committing it would pin a fixed
     * "now" into the profile forever. Live deployments should leave it unset
     * here and inject it per-instance via `CreateEdictOptions.proofPolicy`.
     */
    proofPolicy?: ProofPolicy;
  };
  /** Pre-commitment lint gate applied by `protect()` BEFORE funds lock. */
  lintGate: {
    /** Minimum LintReport score (0–100); below it `protect()` throws LintGateError. */
    minScore: number;
    /** When true, any error-severity finding blocks regardless of score. */
    blockOnError: boolean;
  };
  /**
   * Human escalation policy (review-policy invariant): a PROFILE-LEVEL ELECTION
   * of where escalated/uncertain verdicts route next — never whether they can
   * settle (escalated verdicts stay non-executable regardless of mode).
   * This object IS policy and is covered by `profileHash`.
   *
   * Resolution per case tier (see `effectiveEscalationMode` in
   * ./escalation.ts): `perTier[tier]` → `mode` → tier defaults when the
   * whole object is absent (A → 'off', B → 'optional_appeal',
   * C → 'quality_gate').
   *
   * `triggers`, when present, REPLACES the mode's default covered-trigger
   * set for routing escalations to human review ('off' routes nothing
   * regardless): under 'optional_appeal' quality triggers are NOT covered
   * unless listed here; under 'quality_gate'/'required_above_value' every
   * trigger is covered unless narrowed here.
   */
  humanEscalation?: {
    mode: HumanEscalationMode;
    triggers?: EscalationTrigger[];
    perTier?: Partial<Record<ValueTier, HumanEscalationMode>>;
    /**
     * 'required_above_value' only: cases with valueUsd >= thresholdUsd wait
     * for human review even when the verdict is clean and final — routing is
     * TIER-AGNOSTIC (the value decides, not the tier). Default when absent:
     * the tier-C floor, $1000 (DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD).
     */
    thresholdUsd?: number;
    /**
     * 'optional_appeal' only: how long after the verdict a party may post an
     * appeal (milliseconds). Advisory policy metadata for v0 — the SDK does
     * not clock-enforce the window (DRR territory, legal/README.md Q17).
     */
    appealWindowMs?: number;
    /**
     * 'optional_appeal' only: appeal bond as a multiple of the dispute bond
     * (e.g. 2 = double bond to appeal). Advisory policy metadata for v0.
     */
    appealBondMultiplier?: number;
    /** Who staffs the review when a case routes to a human. */
    reviewerPool?: ReviewerPool;
  };
}

// ---------------------------------------------------------------------------
// Default sandbox jury (mirrors apps/shadow-docket/seats/mock-seats.json)
// ---------------------------------------------------------------------------

/**
 * Three deterministic MockProvider seats across three providers and three
 * disjoint model families — satisfies every jury placement rule (no provider
 * majority, tier-C 3-provider spread, disjoint families) fully offline.
 */
export const SANDBOX_MOCK_SEATS: readonly JurySeatSpec[] = [
  { seatId: 'mock-alpha:anna', providerId: 'mock-alpha', modelId: 'mock-anna-1.0', modelFamily: 'anna' },
  { seatId: 'mock-beta:boris', providerId: 'mock-beta', modelId: 'mock-boris-1.0', modelFamily: 'boris' },
  { seatId: 'mock-gamma:clara', providerId: 'mock-gamma', modelId: 'mock-clara-1.0', modelFamily: 'clara' },
];

/** A fresh, valid sandbox profile — the quickstart default. */
export function defaultProfile(): ProtectionProfile {
  return {
    name: 'edict-sandbox-default',
    version: '0.4.0',
    legalPolicy: {
      version: 'edict-legal-policy-1',
      policyId: 'edict-standard-legal-v0.1',
      assuranceMode: 'wallet_native',
      rules: {
        id: 'edict-drr-v0.1',
        version: '0.1',
        sha256: '17701fa24d618290fb28da1315fdaa4480e7634aeccba074f3fbd393e2f848c5',
        uri: 'legal/edict-dispute-resolution-rules-v0.1.md',
      },
      challengeWindowMs: 86_400_000,
      humanEscalation: {
        mode: 'optional_appeal',
        perTier: { A: 'off', B: 'optional_appeal', C: 'quality_gate' },
        appealWindowMs: 86_400_000,
        appealBondMultiplier: 2,
        reviewerPool: 'edict_bench',
      },
      e2ImplementationTiming: 'implement_then_arbitrate',
      bondRemovalDestination: 'protocol_burn',
    },
    defaults: {
      decisionSpace: {
        kind: 'escrow_branches',
        permitted: ['requester_wins', 'worker_wins', 'split', 'redo'],
      },
      legalProfile: {
        governingLaw: 'england_wales',
        seat: 'london',
        rules: 'edict-drr-v0.1',
        enforcementTier: 'E0',
      },
      acceptanceWindowMs: 86_400_000, // 24h post-delivery review window
      maeEvents: [],
    },
    tierThresholds: { aMaxUsd: 10, bMaxUsd: 1_000 },
    juryPolicy: {
      seats: SANDBOX_MOCK_SEATS.map((s) => ({ ...s })),
      requireProofs: false,
    },
    lintGate: { minScore: 80, blockOnError: true },
  };
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/**
 * sha256 (lowercase hex) over the canonical JSON of the profile. Key order
 * never matters; two semantically identical profiles always hash the same.
 */
export function profileHash(profile: ProtectionProfile): string {
  const normalized = structuredClone(profile);
  if (normalized.humanEscalation !== undefined) {
    normalized.legalPolicy.humanEscalation = structuredClone(normalized.humanEscalation);
  }
  return sha256Canonical(normalized);
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const PROFILE_KEYS = [
  'name', 'version', 'legalPolicy', 'customerPolicyPack', 'defaults', 'tierThresholds', 'juryPolicy', 'lintGate',
  'humanEscalation',
] as const;
const HUMAN_ESCALATION_KEYS = [
  'mode', 'triggers', 'perTier', 'thresholdUsd', 'appealWindowMs', 'appealBondMultiplier', 'reviewerPool',
] as const;
const DEFAULTS_KEYS = ['decisionSpace', 'legalProfile', 'acceptanceWindowMs', 'maeEvents', 'publicity'] as const;
const TIER_KEYS = ['aMaxUsd', 'bMaxUsd'] as const;
const JURY_KEYS = ['seats', 'requireProofs', 'provenanceAllowlist', 'proofPolicy'] as const;
const PROOF_POLICY_KEYS = ['signerAllowlist', 'freshnessMs', 'nowUnixMs'] as const;
const LINT_GATE_KEYS = ['minScore', 'blockOnError'] as const;
const SEAT_KEYS = ['seatId', 'providerId', 'modelId', 'modelFamily'] as const;
const LEGAL_KEYS = ['governingLaw', 'seat', 'rules', 'enforcementTier'] as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function rejectUnknownKeys(
  errors: string[],
  v: Record<string, unknown>,
  path: string,
  allowed: readonly string[],
): void {
  for (const k of Object.keys(v)) {
    if (!allowed.includes(k)) errors.push(`${path}.${k}: unknown key — this object has a closed field set`);
  }
}

function checkString(errors: string[], v: unknown, path: string): v is string {
  if (typeof v !== 'string' || v.length === 0) {
    errors.push(`${path}: must be a non-empty string`);
    return false;
  }
  return true;
}

function checkEnum<T extends string>(
  errors: string[],
  v: unknown,
  path: string,
  allowed: ReadonlyArray<T>,
): v is T {
  if (typeof v !== 'string' || !(allowed as ReadonlyArray<string>).includes(v)) {
    errors.push(`${path}: must be one of: ${allowed.join(', ')}`);
    return false;
  }
  return true;
}

function validateProofPolicy(errors: string[], value: unknown, path: string): void {
  if (!isRecord(value)) {
    errors.push(`${path}: must be an object`);
    return;
  }
  rejectUnknownKeys(errors, value, path, PROOF_POLICY_KEYS);
  if (value.signerAllowlist !== undefined) {
    if (!isRecord(value.signerAllowlist)) {
      errors.push(`${path}.signerAllowlist: must be an object mapping providerId to signer arrays`);
    } else {
      for (const [providerId, signers] of Object.entries(value.signerAllowlist)) {
        if (providerId.length === 0) errors.push(`${path}.signerAllowlist: provider ids must be non-empty strings`);
        if (!Array.isArray(signers) || signers.length === 0) {
          errors.push(`${path}.signerAllowlist.${providerId}: must be a non-empty array of signer identities`);
          continue;
        }
        signers.forEach((s, i) => checkString(errors, s, `${path}.signerAllowlist.${providerId}[${i}]`));
      }
    }
  }
  if (
    value.freshnessMs !== undefined &&
    (typeof value.freshnessMs !== 'number' || !Number.isSafeInteger(value.freshnessMs) || value.freshnessMs <= 0)
  ) {
    errors.push(`${path}.freshnessMs: must be a positive integer (milliseconds)`);
  }
  if (
    value.nowUnixMs !== undefined &&
    (typeof value.nowUnixMs !== 'number' || !Number.isSafeInteger(value.nowUnixMs) || value.nowUnixMs <= 0)
  ) {
    errors.push(`${path}.nowUnixMs: must be a positive unix-ms integer`);
  }
}

/**
 * Structural validation of an unknown value against the ProtectionProfile
 * shape. Reuses the core validators for the decision space and the legal
 * enums. Returns `<path>: <message>` error strings ([] = valid); never throws.
 */
export function validateProfile(p: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(p)) return ['profile: must be a JSON object (ProtectionProfile)'];
  rejectUnknownKeys(errors, p, 'profile', PROFILE_KEYS);

  checkString(errors, p.name, 'profile.name');
  checkString(errors, p.version, 'profile.version');
  errors.push(...validateLegalPolicy(p.legalPolicy, 'profile.legalPolicy'));
  if (p.customerPolicyPack !== undefined) {
    errors.push(...validateCustomerPolicyPack(p.customerPolicyPack, 'profile.customerPolicyPack'));
  }

  // --- defaults --------------------------------------------------------------
  if (!isRecord(p.defaults)) {
    errors.push('profile.defaults: must be an object');
  } else {
    const d = p.defaults;
    rejectUnknownKeys(errors, d, 'profile.defaults', DEFAULTS_KEYS);
    errors.push(...validateDecisionSpace(d.decisionSpace, 'profile.defaults.decisionSpace'));
    if (!isRecord(d.legalProfile)) {
      errors.push('profile.defaults.legalProfile: must be an object (LegalProfile)');
    } else {
      const lp = d.legalProfile;
      rejectUnknownKeys(errors, lp, 'profile.defaults.legalProfile', LEGAL_KEYS);
      checkEnum(errors, lp.governingLaw, 'profile.defaults.legalProfile.governingLaw', GOVERNING_LAWS);
      checkEnum(errors, lp.seat, 'profile.defaults.legalProfile.seat', SEATS);
      checkString(errors, lp.rules, 'profile.defaults.legalProfile.rules');
      checkEnum(errors, lp.enforcementTier, 'profile.defaults.legalProfile.enforcementTier', ENFORCEMENT_TIERS);
    }
    if (typeof d.acceptanceWindowMs !== 'number' || !Number.isSafeInteger(d.acceptanceWindowMs) || d.acceptanceWindowMs <= 0) {
      errors.push('profile.defaults.acceptanceWindowMs: must be a positive integer (milliseconds)');
    }
    if (d.maeEvents !== undefined) {
      if (!Array.isArray(d.maeEvents)) {
        errors.push('profile.defaults.maeEvents: must be an array of non-empty strings');
      } else {
        d.maeEvents.forEach((e, i) => checkString(errors, e, `profile.defaults.maeEvents[${i}]`));
      }
    }
    if (d.publicity !== undefined) {
      checkEnum(errors, d.publicity, 'profile.defaults.publicity', PUBLICITIES);
    }
  }

  // --- tierThresholds ----------------------------------------------------------
  if (p.tierThresholds !== undefined) {
    if (!isRecord(p.tierThresholds)) {
      errors.push('profile.tierThresholds: must be an object { aMaxUsd, bMaxUsd }');
    } else {
      const t = p.tierThresholds;
      rejectUnknownKeys(errors, t, 'profile.tierThresholds', TIER_KEYS);
      const aOk = typeof t.aMaxUsd === 'number' && Number.isFinite(t.aMaxUsd) && t.aMaxUsd > 0;
      const bOk = typeof t.bMaxUsd === 'number' && Number.isFinite(t.bMaxUsd) && t.bMaxUsd > 0;
      if (!aOk) errors.push('profile.tierThresholds.aMaxUsd: must be a positive finite number');
      if (!bOk) errors.push('profile.tierThresholds.bMaxUsd: must be a positive finite number');
      if (aOk && bOk && (t.aMaxUsd as number) >= (t.bMaxUsd as number)) {
        errors.push('profile.tierThresholds: aMaxUsd must be strictly less than bMaxUsd');
      }
    }
  }

  // --- juryPolicy ---------------------------------------------------------------
  let allowlist: string[] | undefined;
  let seatProviderIds: string[] = [];
  if (!isRecord(p.juryPolicy)) {
    errors.push('profile.juryPolicy: must be an object');
  } else {
    const j = p.juryPolicy;
    rejectUnknownKeys(errors, j, 'profile.juryPolicy', JURY_KEYS);
    if (j.requireProofs !== undefined && typeof j.requireProofs !== 'boolean') {
      errors.push('profile.juryPolicy.requireProofs: must be a boolean');
    }
    if (j.provenanceAllowlist !== undefined) {
      if (!Array.isArray(j.provenanceAllowlist)) {
        errors.push('profile.juryPolicy.provenanceAllowlist: must be an array of provider ids');
      } else {
        j.provenanceAllowlist.forEach((e, i) =>
          checkString(errors, e, `profile.juryPolicy.provenanceAllowlist[${i}]`),
        );
        allowlist = j.provenanceAllowlist.filter((e): e is string => typeof e === 'string');
      }
    }
    if (j.proofPolicy !== undefined) {
      validateProofPolicy(errors, j.proofPolicy, 'profile.juryPolicy.proofPolicy');
    }
    if (j.seats !== undefined) {
      if (!Array.isArray(j.seats) || j.seats.length === 0) {
        errors.push('profile.juryPolicy.seats: must be a non-empty array of JurySeatSpec when present');
      } else {
        const families = new Map<string, string>();
        const perProvider = new Map<string, number>();
        j.seats.forEach((s, i) => {
          const path = `profile.juryPolicy.seats[${i}]`;
          if (!isRecord(s)) {
            errors.push(`${path}: must be an object (JurySeatSpec)`);
            return;
          }
          rejectUnknownKeys(errors, s, path, SEAT_KEYS);
          checkString(errors, s.seatId, `${path}.seatId`);
          checkString(errors, s.providerId, `${path}.providerId`);
          checkString(errors, s.modelId, `${path}.modelId`);
          checkString(errors, s.modelFamily, `${path}.modelFamily`);
          if (typeof s.providerId === 'string') {
            seatProviderIds.push(s.providerId);
            perProvider.set(s.providerId, (perProvider.get(s.providerId) ?? 0) + 1);
          }
          if (typeof s.modelFamily === 'string' && typeof s.seatId === 'string') {
            const prior = families.get(s.modelFamily);
            if (prior !== undefined) {
              errors.push(
                `${path}.modelFamily: duplicate family "${s.modelFamily}" (already on seat ${prior}) — families must be disjoint across seats`,
              );
            } else {
              families.set(s.modelFamily, s.seatId);
            }
          }
        });
        if (perProvider.size > 0 && perProvider.size < 2) {
          errors.push(
            `profile.juryPolicy.seats: roster spans ${perProvider.size} distinct provider(s) — tiers A/B require >= 2 providers`,
          );
        }
      }
    }
  }
  if (allowlist !== undefined) {
    for (const providerId of seatProviderIds) {
      if (!allowlist.includes(providerId)) {
        errors.push(
          `profile.juryPolicy.seats: providerId "${providerId}" is not in the provenanceAllowlist (${allowlist.join(', ')})`,
        );
      }
    }
  }

  // --- lintGate -------------------------------------------------------------------
  if (!isRecord(p.lintGate)) {
    errors.push('profile.lintGate: must be an object { minScore, blockOnError }');
  } else {
    const g = p.lintGate;
    rejectUnknownKeys(errors, g, 'profile.lintGate', LINT_GATE_KEYS);
    if (typeof g.minScore !== 'number' || !Number.isFinite(g.minScore) || g.minScore < 0 || g.minScore > 100) {
      errors.push('profile.lintGate.minScore: must be a number in 0..100');
    }
    if (typeof g.blockOnError !== 'boolean') {
      errors.push('profile.lintGate.blockOnError: must be a boolean');
    }
  }

  // --- humanEscalation (review policy — optional; absent = tier defaults) --------------
  if (p.humanEscalation !== undefined) {
    if (!isRecord(p.humanEscalation)) {
      errors.push('profile.humanEscalation: must be an object { mode, triggers?, perTier? }');
    } else {
      const he = p.humanEscalation;
      rejectUnknownKeys(errors, he, 'profile.humanEscalation', HUMAN_ESCALATION_KEYS);
      checkEnum(errors, he.mode, 'profile.humanEscalation.mode', HUMAN_ESCALATION_MODES);
      if (he.triggers !== undefined) {
        if (!Array.isArray(he.triggers) || he.triggers.length === 0) {
          errors.push('profile.humanEscalation.triggers: must be a non-empty array of escalation triggers when present');
        } else {
          const seen = new Set<string>();
          he.triggers.forEach((t, i) => {
            if (checkEnum(errors, t, `profile.humanEscalation.triggers[${i}]`, ESCALATION_TRIGGERS)) {
              if (seen.has(t)) errors.push(`profile.humanEscalation.triggers[${i}]: duplicate trigger '${t}'`);
              seen.add(t);
            }
          });
        }
      }
      if (he.perTier !== undefined) {
        if (!isRecord(he.perTier)) {
          errors.push('profile.humanEscalation.perTier: must be an object mapping value tiers to modes');
        } else {
          rejectUnknownKeys(errors, he.perTier, 'profile.humanEscalation.perTier', VALUE_TIERS);
          for (const tier of VALUE_TIERS) {
            if (he.perTier[tier] !== undefined) {
              checkEnum(errors, he.perTier[tier], `profile.humanEscalation.perTier.${tier}`, HUMAN_ESCALATION_MODES);
            }
          }
        }
      }
      // Which modes are elected anywhere (mode or a per-tier override)?
      const electedModes = new Set<unknown>([
        he.mode,
        ...(isRecord(he.perTier) ? Object.values(he.perTier) : []),
      ]);
      if (he.thresholdUsd !== undefined) {
        if (typeof he.thresholdUsd !== 'number' || !Number.isFinite(he.thresholdUsd) || he.thresholdUsd <= 0) {
          errors.push('profile.humanEscalation.thresholdUsd: must be a positive finite number (USD)');
        }
        if (!electedModes.has('required_above_value')) {
          errors.push(
            "profile.humanEscalation.thresholdUsd: only meaningful when 'required_above_value' is elected (mode or perTier)",
          );
        }
      }
      if (he.appealWindowMs !== undefined) {
        if (typeof he.appealWindowMs !== 'number' || !Number.isSafeInteger(he.appealWindowMs) || he.appealWindowMs <= 0) {
          errors.push('profile.humanEscalation.appealWindowMs: must be a positive integer (milliseconds)');
        }
        if (!electedModes.has('optional_appeal')) {
          errors.push(
            "profile.humanEscalation.appealWindowMs: only meaningful when 'optional_appeal' is elected (mode or perTier)",
          );
        }
      }
      if (he.appealBondMultiplier !== undefined) {
        if (
          typeof he.appealBondMultiplier !== 'number' ||
          !Number.isFinite(he.appealBondMultiplier) ||
          he.appealBondMultiplier <= 0
        ) {
          errors.push('profile.humanEscalation.appealBondMultiplier: must be a positive finite number');
        }
        if (!electedModes.has('optional_appeal')) {
          errors.push(
            "profile.humanEscalation.appealBondMultiplier: only meaningful when 'optional_appeal' is elected (mode or perTier)",
          );
        }
      }
      if (he.reviewerPool !== undefined) {
        checkEnum(errors, he.reviewerPool, 'profile.humanEscalation.reviewerPool', REVIEWER_POOLS);
      }
    }
  }

  // Cross-object commitments: the compact routing fields, full customer pack,
  // and runtime escalation policy must describe the same signed Legal Policy.
  if (isRecord(p.legalPolicy)) {
    const legal = p.legalPolicy;
    if (isRecord(p.defaults) && isRecord(p.defaults.legalProfile) &&
        typeof legal.rules === 'object' && legal.rules !== null &&
        (legal.rules as Record<string, unknown>).id !== p.defaults.legalProfile.rules) {
      errors.push('profile.legalPolicy.rules.id: must equal profile.defaults.legalProfile.rules');
    }
    if (
      isRecord(p.defaults) &&
      isRecord(p.defaults.legalProfile) &&
      p.defaults.legalProfile.enforcementTier !== 'E0' &&
      legal.assuranceMode !== 'enterprise_legal'
    ) {
      errors.push(
        'profile.legalPolicy.assuranceMode: E1/E2/E3 requires enterprise_legal; ' +
          'wallet_native and rail_verified are technical E0 settlement modes',
      );
    }
    if (p.customerPolicyPack !== undefined) {
      const expected = sha256Canonical(p.customerPolicyPack);
      const ref = isRecord(legal.customerPolicyPack) ? legal.customerPolicyPack : undefined;
      if (ref?.sha256 !== expected) {
        errors.push(`profile.legalPolicy.customerPolicyPack.sha256: must equal canonical customerPolicyPack hash ${expected}`);
      }
    } else if (legal.customerPolicyPack !== undefined) {
      errors.push('profile.customerPolicyPack: full pack is required when legalPolicy references one');
    }
  }

  return errors;
}

/** Throw {@link ProfileValidationError} unless `p` is a valid ProtectionProfile. */
export function assertValidProfile(p: unknown): asserts p is ProtectionProfile {
  const problems = validateProfile(p);
  if (problems.length > 0) throw new ProfileValidationError(problems);
}
