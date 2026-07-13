/**
 * Verdict aggregation and confidence gating across each decision-space kind.
 *
 * Majority / value computation per space kind:
 * - `escrow_branches` and `categorical`: majority across counted seats on the
 *   CANONICAL OUTCOME STRING (see canonicalOutcome — "worker_wins",
 *   "split:<bps>", "outcome:<label>", …) of each seat's merged, swap-consistent
 *   outcome. Swap-consistency rules are unchanged (same kind across passes;
 *   split bps within SPLIT_SWAP_TOLERANCE_BPS; categorical labels identical).
 * - `bounded_scalar`: per-seat scalar votes (the two passes of a
 *   swap-consistent seat are averaged); the verdict value is the MEDIAN of the
 *   counted votes (true median, no integer rounding), clamped into the space.
 *
 * Escalation gates (any one trips the gate):
 *   - no majority (escrow/categorical: no canonical-string majority across
 *     counted seats; scalar: half or more counted seats unusable)
 *   - swapFlipRate > 0.34
 *   - scalar spread: (max - min) of counted scalar votes > 20% of
 *     (space.max - space.min) — escalationReason 'scalar_spread'
 *   - any ATTACK-severity injection flag ("attack:"-prefixed) on a tier-C
 *     case — stylistic advocacy notes ("note:") and deterministic findings
 *     flags are recorded but never escalate
 *   - mean pass confidence < 0.6
 *
 * When a gate trips, the arbiter NEVER fabricates a final outcome: it emits
 * the pre-committed fallback for the space (see fallbackOutcome) with
 * quality.escalated=true and final=false so the rail routes the case up a
 * tier. Per-space fallbacks:
 *   - escrow: redo +72h → split 50/50 → requester_wins → worker_wins, first
 *     branch permitted by the space, using deterministic tie-breaking;
 *   - categorical: the designated invalidOutcome when the space defines one;
 *     otherwise the escalation has NO executable outcome — the advisory
 *     ruling is the FIRST committed outcome label, and final=false marks it
 *     as never executable (escalate-without-executable-outcome);
 *   - bounded_scalar: the clamped median of the counted scalar votes (the
 *     midpoint of the space when no counted votes exist), final=false.
 */
import type { CaseObject, JuryVote, Outcome, ValueTier, VerdictObject } from '@edict/core';
import { isAttackFlag } from './injectionScreen.js';
import { canonicalOutcome } from '../executionPayload.js';
import { clamp, dedupSorted, SEVENTY_TWO_HOURS_MS } from '../util.js';

export const SWAP_FLIP_ESCALATION_THRESHOLD = 0.34;
export const MEAN_CONFIDENCE_FLOOR = 0.6;
/** Two split passes within this bps distance still count as swap-consistent. */
export const SPLIT_SWAP_TOLERANCE_BPS = 500;
/**
 * Two scalar passes within this fraction of the space range (max - min) still
 * count as swap-consistent — the scalar analogue of SPLIT_SWAP_TOLERANCE_BPS
 * (500 bps = 5% of the 0..10000 split range).
 */
export const SCALAR_SWAP_TOLERANCE_FRACTION = 0.05;
/**
 * Scalar-spread escalation gate: when (max - min) of the counted seats'
 * scalar votes exceeds this fraction of the space range, the seats are too
 * far apart for a median to be a credible verdict — escalate ('scalar_spread').
 */
export const SCALAR_SPREAD_ESCALATION_FRACTION = 0.2;

export interface Decision {
  ruling: Outcome;
  quality: VerdictObject['quality'];
  /**
   * Execution gate: true only on a clean majority with every
   * quality gate passed. Escalated decisions keep their advisory fallback
   * outcome but are never executable (final=false).
   */
  final: boolean;
}

export interface AggregateOptions {
  /**
   * Seats excluded from the majority calculation by the attestation gate
   * Their votes stay in the verdict record but do not count;
   * if exclusions drop counted seats to half or fewer of the configured
   * seats, the decision escalates with 'insufficient_attested_seats'.
   */
  excludedSeats?: Array<{ seatId: string; reason: string }>;
}

/** True median without integer rounding (scalar quanta may be fractional). */
function scalarMedian(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  return n % 2 === 1 ? s[(n - 1) / 2]! : (s[n / 2 - 1]! + s[n / 2]!) / 2;
}

/**
 * Fallback outcome used whenever the pipeline cannot stand behind a final
 * outcome (gates tripped, unparseable juror output). Deterministic — no wall
 * clock (the escrow redo deadline anchors to the case's openedAt +72h),
 * preserving the same-case → same-verdict invariant.
 *
 * Verdict-oracle invariant: the fallback is ALWAYS selected from the case's
 * pre-committed decisionSpace (validation guarantees the space is
 * well-formed). Per-space behaviour is documented in the module doc above.
 * A fallback verdict always carries quality.escalated=true — the rail routes
 * it up a tier instead of treating it as final.
 *
 * @param countedScalarVotes for bounded_scalar spaces only: the counted
 *   seats' scalar votes; the fallback is their clamped median (the space
 *   midpoint when empty).
 */
export function fallbackOutcome(caseObj: CaseObject, countedScalarVotes: number[] = []): Outcome {
  const space = caseObj.decisionSpace;
  switch (space.kind) {
    case 'escrow_branches': {
      const permitted = space.permitted;
      if (permitted.includes('redo')) {
        return { kind: 'redo', newDeadlineUnixMs: caseObj.openedAtUnixMs + SEVENTY_TWO_HOURS_MS };
      }
      if (permitted.includes('split')) {
        return { kind: 'split', requesterBps: 5000 };
      }
      if (permitted.includes('requester_wins')) {
        return { kind: 'requester_wins' };
      }
      return { kind: 'worker_wins' };
    }
    case 'categorical': {
      // invalidOutcome when the space designates one; otherwise the FIRST
      // committed outcome as an ADVISORY placeholder only — the caller marks
      // the decision final=false (escalate-without-executable-outcome).
      return { kind: 'categorical', outcome: space.invalidOutcome ?? space.outcomes[0]! };
    }
    case 'bounded_scalar': {
      const v = countedScalarVotes.length > 0 ? scalarMedian(countedScalarVotes) : (space.min + space.max) / 2;
      return { kind: 'scalar', value: clamp(v, space.min, space.max) };
    }
  }
}

/**
 * Shared injection-flag finality gate for the jury path
 * (aggregateDecision) and the deterministic short-circuit path
 * (finalizeDeterministic in ../index.ts).
 *
 * Policy (identical for both paths):
 * - tier C: any attack-severity flag ("attack:"-prefixed) forces escalation
 *   with reason 'injection_flags_at_tier_C' — the verdict is never final.
 * - tier A/B: attack flags are recorded but do not escalate on their own.
 * - "note:"-prefixed stylistic flags and "deterministic:"/"evidence_*" flags
 *   never escalate at any tier.
 *
 * Returns the escalation reasons this gate contributes ([] = gate passes).
 */
export function injectionEscalationReasons(tier: ValueTier, injectionFlags: string[]): string[] {
  return tier === 'C' && injectionFlags.some(isAttackFlag) ? ['injection_flags_at_tier_C'] : [];
}

/** Merge a swap-consistent seat's two passes into one effective outcome. */
function mergePasses(vote: JuryVote): Outcome {
  const a = vote.passes[0]!.ruling;
  const b = vote.passes[1]?.ruling ?? a;
  if (a.kind === 'split' && b.kind === 'split') {
    return { kind: 'split', requesterBps: Math.round((a.requesterBps + b.requesterBps) / 2) };
  }
  if (a.kind === 'redo' && b.kind === 'redo') {
    return { kind: 'redo', newDeadlineUnixMs: Math.round((a.newDeadlineUnixMs + b.newDeadlineUnixMs) / 2) };
  }
  if (a.kind === 'scalar' && b.kind === 'scalar') {
    return { kind: 'scalar', value: (a.value + b.value) / 2 };
  }
  // requester_wins / worker_wins / categorical: swap-consistent ⇒ identical.
  return a;
}

export function aggregateDecision(
  caseObj: CaseObject,
  votes: JuryVote[],
  passConfidences: number[],
  injectionFlags: string[],
  opts: AggregateOptions = {},
): Decision {
  const space = caseObj.decisionSpace;
  const excludedSeats = opts.excludedSeats ?? [];
  const excludedIds = new Set(excludedSeats.map((e) => e.seatId));
  const totalSeats = votes.length;
  const counted = votes.filter((v) => !excludedIds.has(v.seat.seatId));

  const n = counted.length;
  const effective: Outcome[] = counted.filter((v) => v.swapConsistent).map((v) => mergePasses(v));
  const consistentCount = effective.length;

  const swapFlipRate = n === 0 ? 0 : (n - consistentCount) / n;
  const meanConfidence =
    passConfidences.length === 0 ? 0 : passConfidences.reduce((s, c) => s + c, 0) / passConfidences.length;

  // --- per-space majority + candidate outcome --------------------------------
  let majority: VerdictObject['quality']['majority'];
  let candidate: Outcome | undefined;
  let scalarVotes: number[] = [];
  let scalarSpreadExceeded = false;

  if (space.kind === 'bounded_scalar') {
    scalarVotes = effective.map((o) => (o as { kind: 'scalar'; value: number }).value);
    const allEqual = scalarVotes.length > 0 && scalarVotes.every((v) => v === scalarVotes[0]);
    majority =
      n > 0 && consistentCount === n && allEqual
        ? 'unanimous'
        : consistentCount * 2 > n
          ? 'majority'
          : 'none';
    if (scalarVotes.length > 0) {
      candidate = { kind: 'scalar', value: clamp(scalarMedian(scalarVotes), space.min, space.max) };
      const spread = Math.max(...scalarVotes) - Math.min(...scalarVotes);
      scalarSpreadExceeded = spread > SCALAR_SPREAD_ESCALATION_FRACTION * (space.max - space.min);
    }
  } else {
    // escrow_branches + categorical: majority on the canonical outcome string.
    const buckets = new Map<string, { count: number; outcome: Outcome }>();
    for (const o of effective) {
      const key = canonicalOutcome(o);
      const bucket = buckets.get(key);
      if (bucket === undefined) buckets.set(key, { count: 1, outcome: o });
      else bucket.count += 1;
    }
    let topKey: string | null = null;
    let topCount = 0;
    // Deterministic tie-break: count desc, then canonical string asc.
    for (const [key, { count }] of [...buckets.entries()].sort(
      (x, y) => y[1].count - x[1].count || x[0].localeCompare(y[0]),
    )) {
      topKey = key;
      topCount = count;
      break;
    }
    majority =
      n > 0 && consistentCount === n && buckets.size === 1
        ? 'unanimous'
        : topCount * 2 > n
          ? 'majority'
          : 'none';
    if (topKey !== null) candidate = buckets.get(topKey)!.outcome;
  }

  // --- confidence gate ------------------------------------------------------
  const reasons: string[] = [];
  // Counted seats must be a strict majority of configured seats.
  // of the configured seats — otherwise no attested quorum exists.
  if (excludedSeats.length > 0 && n * 2 <= totalSeats) {
    reasons.push('insufficient_attested_seats');
  }
  if (majority === 'none') reasons.push('no_majority');
  if (swapFlipRate > SWAP_FLIP_ESCALATION_THRESHOLD) {
    reasons.push(`swap_flip_rate=${swapFlipRate.toFixed(2)}>${SWAP_FLIP_ESCALATION_THRESHOLD}`);
  }
  if (scalarSpreadExceeded) reasons.push('scalar_spread');
  // Shared injection-flag gate (same policy as the deterministic path —
  // see injectionEscalationReasons): only attack-severity flags escalate,
  // and only at tier C.
  reasons.push(...injectionEscalationReasons(caseObj.tier, injectionFlags));
  if (meanConfidence < MEAN_CONFIDENCE_FLOOR) {
    reasons.push(`mean_confidence=${meanConfidence.toFixed(2)}<${MEAN_CONFIDENCE_FLOOR.toFixed(2)}`);
  }
  const escalated = reasons.length > 0;

  // candidate is defined whenever majority !== 'none' (topCount >= 1 /
  // scalarVotes non-empty); an undefined candidate therefore always escalates.
  const ruling: Outcome =
    escalated || candidate === undefined ? fallbackOutcome(caseObj, scalarVotes) : candidate;

  const quality: VerdictObject['quality'] = {
    majority,
    swapFlipRate,
    injectionFlags: dedupSorted(injectionFlags),
    escalated,
    ...(escalated ? { escalationReason: reasons.join('; ') } : {}),
    ...(excludedSeats.length > 0 ? { excludedSeats } : {}),
  };
  // Escalated verdicts are never executable. The advisory fallback
  // outcome stays on the verdict, but final=false makes it non-executable by
  // type (SettlementDirective construction accepts FinalVerdict only).
  return { ruling, quality, final: !escalated };
}
