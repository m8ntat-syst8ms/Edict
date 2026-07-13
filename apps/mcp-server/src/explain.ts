/**
 * Tribunal-instruction reconstruction — shared by `edict_sandbox_dispute` and
 * `edict_explain_ruling`.
 *
 * `buildJudicialInstructions` (the @edict/arbiter implementation, not a copy) is a
 * deterministic function of the case, the parsed mandate, the machine-check
 * report and the evidence commitments — so the exact blocks a past
 * adjudication rendered into the jury frames can be recomputed from the
 * committed case data alone, with no dependency on generated archives.
 */

import type { CaseObject } from '@edict/core';
import {
  analyzeDeterministic,
  buildJudicialInstructions,
  verifyEvidenceCommitments,
  JUDICIAL_INSTRUCTIONS_TITLE,
} from '@edict/arbiter';

export interface TribunalInstructions {
  title: string;
  /** The instruction blocks that applied, in the fixed render order. */
  blocks: string[];
  /** Note-level screen flags raised over mandate-originated quoted text. */
  flags: string[];
  /** Set when reconstruction had to fall back to an empty plaintext map. */
  note?: string;
}

/**
 * Recompute the judicial-instruction blocks that applied to a case. Falls
 * back to the always-on blocks (computed over an empty plaintext map) when
 * the provided plaintexts fail evidence-integrity verification.
 */
export function tribunalInstructionsFor(
  caseObj: CaseObject,
  plaintext: Record<string, string>,
): TribunalInstructions {
  try {
    const verified = verifyEvidenceCommitments(caseObj, plaintext);
    const analysis = analyzeDeterministic(caseObj, verified);
    const judicial = buildJudicialInstructions(caseObj, analysis.parsedMandate, analysis.report, caseObj.evidence);
    return { title: JUDICIAL_INSTRUCTIONS_TITLE, blocks: judicial.blocks, flags: judicial.flags };
  } catch (err) {
    const verified = verifyEvidenceCommitments(caseObj, {});
    const analysis = analyzeDeterministic(caseObj, verified);
    const judicial = buildJudicialInstructions(caseObj, analysis.parsedMandate, analysis.report, caseObj.evidence);
    return {
      title: JUDICIAL_INSTRUCTIONS_TITLE,
      blocks: judicial.blocks,
      flags: judicial.flags,
      note: `local evidence plaintexts failed integrity verification (${String(err)}); blocks recomputed without sealed plaintexts`,
    };
  }
}

/** Compact view of an archived arbiter reasoning document (trims proof noise). */
export function compactReasoning(reasoning: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of ['version', 'ruling', 'final', 'quality', 'machineChecks', 'deterministic', 'blockedDeterministicFinding']) {
    if (reasoning[key] !== undefined) out[key] = reasoning[key];
  }
  const seats = reasoning['seats'];
  if (Array.isArray(seats)) {
    out['seats'] = seats.map((s) => {
      if (typeof s !== 'object' || s === null) return s;
      const seat = s as Record<string, unknown>;
      const passes = Array.isArray(seat['passes'])
        ? (seat['passes'] as Array<Record<string, unknown>>).map((p) => ({
            orientation: p['orientation'],
            ruling: p['ruling'],
            confidence: p['confidence'],
            reasons: p['reasons'],
          }))
        : seat['passes'];
      return { seatId: seat['seatId'], swapConsistent: seat['swapConsistent'], passes };
    });
  }
  return out;
}
