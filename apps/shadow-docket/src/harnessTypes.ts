/**
 * Shadow-docket local types. These are harness-only concepts (ground truth,
 * evaluation results). All canonical dispute types come from @edict/core and
 * are imported, never redefined.
 */
import type {
  CaseObject,
  InferenceProvider,
  JurySeatSpec,
  Ruling,
  VerdictObject,
} from '@edict/core';

// ---------------------------------------------------------------------------
// Ground truth
// ---------------------------------------------------------------------------

/** An expected escrow ruling: a ruling kind plus, for splits, the expected requester share. */
export interface ExpectedRuling {
  kind: Ruling['kind'];
  /** Only meaningful when kind === 'split'. */
  requesterBps?: number;
}

/**
 * An expected outcome in any of the three decision spaces:
 * - escrow_branches  → `{ kind: 'requester_wins' | 'worker_wins' | 'split' | 'redo', requesterBps? }`
 * - categorical      → `{ kind: 'categorical', outcome }` (agreement = exact label match)
 * - bounded_scalar   → `{ kind: 'scalar', value }` (agreement = within
 *                      `groundtruth.scalarToleranceBps` of the expected value)
 */
export type ExpectedOutcome =
  | ExpectedRuling
  | { kind: 'categorical'; outcome: string }
  | { kind: 'scalar'; value: number };

export type Difficulty = 'deterministic' | 'easy' | 'medium' | 'hard';

export interface GroundTruth {
  /** Must equal the caseId of the sibling case.json. */
  caseId: string;
  /** Human-readable case name for reports. */
  title: string;
  /** The evidence-supported outcome (must lie within the case's decisionSpace). */
  expected: ExpectedOutcome;
  /**
   * Alternative outcomes that also count as agreement (e.g. spec-ambiguity
   * cases where split OR against-drafter default are both defensible).
   */
  acceptableAlternatives?: ExpectedOutcome[];
  /** Split matching tolerance in bps (default 1000 = ±10%). */
  splitToleranceBps?: number;
  /**
   * Scalar matching tolerance in bps OF THE EXPECTED VALUE (default 1000 =
   * ±10%): a scalar verdict agrees when
   * |actual − expected| <= |expected| * scalarToleranceBps / 10000.
   */
  scalarToleranceBps?: number;
  /** Why the expected ruling is correct on the evidence. */
  rationale: string;
  difficulty: Difficulty;
  /** Free-form tags; bucket tags (real_dispute | synthetic | adversarial | edge) required. */
  tags: string[];
  /** Adversarial cases: the verdict MUST carry non-empty quality.injectionFlags. */
  expectInjectionFlag?: boolean;
  /** If true, an escalated (non-final) verdict also counts as agreement. */
  allowEscalation?: boolean;
  /**
   * For cases adapted from real public disputes: how the historical outcome
   * diverged from the evidence-supported outcome (and why groundtruth is NOT
   * the manipulated historical result).
   */
  historicalDivergence?: string;
}

// ---------------------------------------------------------------------------
// Arbiter bridge
// ---------------------------------------------------------------------------

/**
 * Config shape accepted by the built-in baseline adjudicator
 * (./baselineArbiter.js) — a structural superset of @edict/arbiter's real
 * ArbiterConfig, which the docket CLI now imports and types against
 * statically (see ./arbiterBridge.ts). The baseline also accepts a plain
 * Record for providers. Extra keys pass through untouched.
 */
export interface ArbiterConfigLike {
  seats: JurySeatSpec[];
  /** providerId -> InferenceProvider. Mock providers by default (offline). */
  providers?: Map<string, InferenceProvider> | Record<string, InferenceProvider>;
  /** Where the arbiter archives proofs/reasoning/verdicts (required by @edict/arbiter). */
  archiveDir?: string;
  [k: string]: unknown;
}

/** The exact arbiter entrypoint signature the shadow docket replays cases through. */
export type AdjudicateFn = (
  caseObj: CaseObject,
  /** sha256(canonical bytes) -> plaintext, unsealing the case's EvidenceCommitments. */
  evidencePlaintext: Record<string, string>,
  config: ArbiterConfigLike,
) => Promise<VerdictObject>;

// ---------------------------------------------------------------------------
// Validation / loading
// ---------------------------------------------------------------------------

export interface ValidationIssue {
  level: 'error' | 'warn';
  path: string;
  message: string;
}

/** A fully-loaded docket case: canonical case object + unsealed evidence + groundtruth. */
export interface CaseBundle {
  /** Absolute path of the case directory. */
  dir: string;
  caseObj: CaseObject;
  groundTruth: GroundTruth;
  /** sha256 -> plaintext for every evidence commitment (keys match commitment.sha256). */
  evidencePlaintext: Record<string, string>;
  issues: ValidationIssue[];
}
