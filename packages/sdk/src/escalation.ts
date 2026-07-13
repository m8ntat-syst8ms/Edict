/**
 * Maps a signed human-escalation policy to the next routing disposition.
 * Human review is configurable rather than a default mode.
 *
 * LAYERING: the arbiter stays policy-free — it only emits the raw quality
 * signals (`quality.escalated`, `escalationReason`, `injectionFlags`,
 * `excludedSeats`, `majority`, `swapFlipRate`). THIS module maps those
 * signals plus the profile's `humanEscalation` election into a routing
 * disposition; surfaces (console / MCP) merely render it.
 *
 * Invariant: an escalated or
 * uncertain verdict NEVER executes, regardless of mode. The mode governs
 * where the case routes next — a programmatic fallback recommendation, the
 * human bench, or a party-paid appeal — not whether the escalated verdict
 * can settle. Settlement gating stays with `assertExecutableVerdict`
 * (@edict/core) and the client/escrow settle guards.
 */

import type { EscalationTrigger, HumanEscalationMode, ValueTier, VerdictObject } from '@edict/core';
import { SWAP_FLIP_ESCALATION_THRESHOLD } from '@edict/arbiter';
import type { ProtectionProfile } from './profile.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Where a verdict routes next under the profile's human escalation policy:
 *
 * - `none`                  — nothing further; a final verdict settles normally.
 * - `programmatic_fallback` — the verdict escalated and no human is elected
 *                             for its trigger: the advisory fallback ruling is
 *                             a RECOMMENDATION for the venue's pre-committed
 *                             fallback policy. The escalated verdict itself
 *                             remains non-settleable as-is (the invariant).
 * - `human_review`          — the case queues for a human reviewer; a
 *                             resolution produces a NEW final verdict
 *                             (`humanReview` set) which is what settles.
 * - `appealable`            — the final verdict stands, but a party may appeal
 *                             to the human bench within the acceptance window
 *                             (`optional_appeal`). Window/bond mechanics are a
 *                             DRR matter (Rule 26) —
 *                             the SDK does not clock-enforce the window.
 */
export type EscalationRoute = 'none' | 'programmatic_fallback' | 'human_review' | 'appealable';

export interface EscalationDisposition {
  route: EscalationRoute;
  /** The trigger that caused the routing (escalations and appeals only). */
  trigger?: EscalationTrigger;
  /** The mode that was in effect for the case's tier (after resolution). */
  mode: HumanEscalationMode;
}

// ---------------------------------------------------------------------------
// Mode resolution
// ---------------------------------------------------------------------------

/**
 * Tier defaults when the profile makes no election (review policy): Tier A is
 * rules/AI only, Tier B gets the optional paid human appeal, Tier C routes
 * quality-gate trips to the human bench by default.
 */
const TIER_DEFAULT_MODE: Record<ValueTier, HumanEscalationMode> = {
  A: 'off',
  B: 'optional_appeal',
  C: 'quality_gate',
};

/**
 * THE documented mode-resolution function: which HumanEscalationMode governs
 * a case at `tier` under `profile`?
 *
 * Precedence: `humanEscalation.perTier[tier]` (explicit per-tier override)
 * → `humanEscalation.mode` (profile-wide election) → tier defaults
 * (A → 'off', B → 'optional_appeal', C → 'quality_gate').
 *
 * Note 'required_above_value' is only *distinct* from 'quality_gate' for
 * cases at/above the profile's `thresholdUsd` (clean finals there also wait
 * for review); below the threshold it behaves like 'quality_gate' for
 * escalations and like a plain final for clean verdicts.
 */
export function effectiveEscalationMode(profile: ProtectionProfile, tier: ValueTier): HumanEscalationMode {
  return profile.humanEscalation?.perTier?.[tier] ?? profile.humanEscalation?.mode ?? TIER_DEFAULT_MODE[tier];
}

/**
 * Default USD threshold for 'required_above_value' when the profile elects
 * no `thresholdUsd`: the canonical tier-C floor (canonical value bands).
 */
export const DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD = 1_000;

/**
 * Does 'required_above_value' hold THIS case for review? TIER-AGNOSTIC by
 * design (profile schema): the case VALUE decides, never the tier —
 * `valueUsd >= thresholdUsd` (default: the $1000 tier-C floor). When the
 * caller cannot supply a value, tier C is the
 * band-consistent fallback: under the canonical bands every tier-C case is
 * at/above the default threshold.
 */
export function requiredAboveValueApplies(
  profile: ProtectionProfile,
  tier: ValueTier,
  valueUsd?: number,
): boolean {
  const threshold = profile.humanEscalation?.thresholdUsd ?? DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD;
  if (valueUsd !== undefined) return valueUsd >= threshold;
  return tier === 'C';
}

// ---------------------------------------------------------------------------
// Trigger extraction (verdict quality signals → closed trigger vocabulary)
// ---------------------------------------------------------------------------

/** injectionFlags prefixes that mean the evidence record itself is out of policy. */
const OUT_OF_POLICY_FLAG_MARKERS = ['evidence_hash_mismatch', 'withheld_mandate_text'] as const;

/**
 * Map an ESCALATED verdict's arbiter-emitted quality signals onto the closed
 * {@link EscalationTrigger} vocabulary. Returns `undefined` for
 * non-escalated verdicts ('party_appeal' is never derived here — it is
 * raised by `EdictClient.appeal`).
 *
 * `quality.escalationReason` is the arbiter's '; '-joined reason list (see
 * services/arbiter/src/pipeline/aggregate.ts); several reasons can coexist,
 * so extraction runs in a documented precedence order — most
 * structural/adversarial first:
 *
 * 1. reason 'insufficient_attested_seats'      → 'insufficient_attested_seats'
 * 2. reason 'injection_flags_at_tier_C'        → 'injection_attack'
 * 3. reason 'no_majority' / 'scalar_spread',
 *    or quality.majority === 'none'            → 'no_majority'
 *    (scalar spread means the counted seats did not meaningfully agree —
 *    the scalar analogue of a missing majority)
 * 4. reason 'swap_flip_rate=…',
 *    or swapFlipRate > 0.34                    → 'swap_inconsistency'
 * 5. out-of-policy evidence flags
 *    (evidence_hash_mismatch / withheld_mandate_text on injectionFlags)
 *                                              → 'out_of_policy_evidence'
 * 6. reason 'mean_confidence=…'                → 'low_confidence'
 * 7. anything else (defensive default: an escalation we cannot classify is
 *    treated as the tribunal not being confident) → 'low_confidence'
 */
export function triggerFromVerdict(verdict: VerdictObject): EscalationTrigger | undefined {
  const q = verdict.quality;
  if (q === undefined || q.escalated !== true) return undefined;
  const reason = q.escalationReason ?? '';
  if (reason.includes('insufficient_attested_seats')) return 'insufficient_attested_seats';
  if (reason.includes('injection_flags_at_tier_C')) return 'injection_attack';
  if (reason.includes('no_majority') || reason.includes('scalar_spread') || q.majority === 'none') {
    return 'no_majority';
  }
  if (reason.includes('swap_flip_rate') || q.swapFlipRate > SWAP_FLIP_ESCALATION_THRESHOLD) {
    return 'swap_inconsistency';
  }
  if ((q.injectionFlags ?? []).some((f) => OUT_OF_POLICY_FLAG_MARKERS.some((m) => f.includes(m)))) {
    return 'out_of_policy_evidence';
  }
  // 'mean_confidence=…' reasons and the defensive default both land here.
  return 'low_confidence';
}

// ---------------------------------------------------------------------------
// Disposition
// ---------------------------------------------------------------------------

/** Every trigger the arbiter can emit (i.e. all but the party-raised appeal). */
const QUALITY_TRIGGERS: readonly EscalationTrigger[] = [
  'no_majority',
  'insufficient_attested_seats',
  'swap_inconsistency',
  'low_confidence',
  'injection_attack',
  'out_of_policy_evidence',
];

/**
 * Which triggers route to human review under `mode`? Explicit
 * `profile.humanEscalation.triggers` REPLACES the default set; otherwise:
 * 'quality_gate' / 'required_above_value' cover every quality trigger,
 * 'optional_appeal' covers only 'party_appeal' (quality escalations fall
 * back programmatically unless triggers override), 'off' covers nothing.
 */
function coveredTriggers(profile: ProtectionProfile, mode: HumanEscalationMode): readonly EscalationTrigger[] {
  if (mode === 'off') return [];
  if (profile.humanEscalation?.triggers !== undefined) return profile.humanEscalation.triggers;
  if (mode === 'optional_appeal') return ['party_appeal'];
  return QUALITY_TRIGGERS; // quality_gate | required_above_value
}

/**
 * Compute the routing disposition for a verdict under a profile's human
 * escalation policy (review policy). Pure and deterministic.
 *
 * Escalated verdicts (`quality.escalated`):
 * - mode 'off' → `programmatic_fallback` — the advisory fallback ruling on
 *   the verdict is a RECOMMENDATION for the venue's pre-committed fallback
 *   policy; the escalated verdict itself is still never settle-able as-is.
 * - mode covers the extracted trigger → `human_review`.
 * - mode does not cover it (notably 'optional_appeal' without a triggers
 *   override, or a narrowed triggers list) → `programmatic_fallback`.
 *
 * Final verdicts:
 * - 'required_above_value' with `valueUsd >= thresholdUsd` (default: the
 *   $1000 tier-C floor; TIER-AGNOSTIC — see {@link requiredAboveValueApplies})
 *   → `human_review` (even clean verdicts wait for the bench before
 *   settlement — `EdictClient.settle` enforces the wait with
 *   PendingReviewError).
 * - 'optional_appeal' → `appealable` (within the acceptance window; window
 *   mechanics are DRR territory, not clock-enforced here).
 * - otherwise → `none`.
 *
 * `valueUsd` is the case value (CaseObject.valueUsd). Optional for
 * backwards compatibility: when absent, 'required_above_value' falls back
 * to holding tier-C cases (band-consistent with the default threshold).
 */
export function dispositionFor(
  verdict: VerdictObject,
  profile: ProtectionProfile,
  tier: ValueTier,
  valueUsd?: number,
): EscalationDisposition {
  const mode = effectiveEscalationMode(profile, tier);
  if (verdict.quality?.escalated === true) {
    // triggerFromVerdict's defensive default guarantees a trigger here.
    const trigger = triggerFromVerdict(verdict) ?? 'low_confidence';
    if (mode !== 'off' && coveredTriggers(profile, mode).includes(trigger)) {
      return { route: 'human_review', trigger, mode };
    }
    return { route: 'programmatic_fallback', trigger, mode };
  }
  if (mode === 'required_above_value') {
    if (requiredAboveValueApplies(profile, tier, valueUsd)) {
      return { route: 'human_review', mode };
    }
    // A per-tier required-above-value election is an overlay, not a deletion
    // of the profile-wide policy below its threshold. This is how High
    // Assurance combines optional appeals with mandatory review above $10k.
    const isTierOverlay = profile.humanEscalation?.perTier?.[tier] === 'required_above_value';
    const fallbackMode = isTierOverlay ? profile.humanEscalation?.mode : undefined;
    if (fallbackMode === 'optional_appeal') {
      return { route: 'appealable', mode: fallbackMode };
    }
  }
  if (mode === 'optional_appeal') {
    return { route: 'appealable', mode };
  }
  return { route: 'none', mode };
}
