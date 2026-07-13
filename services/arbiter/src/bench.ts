/**
 * Bench-trial mode is a single-judge quality benchmark, explicitly separate
 * from the attested jury path and the quality gate.
 *
 * It measures whether one unattested model resolves the
 * semantic cases given the tribunal instructions. It reuses the production
 * pipeline pieces so the judge sees exactly what a juror would see:
 *
 *   evidence-commitment verification (verifyEvidenceCommitments)
 *     → deterministic machine-check layer incl. short-circuits
 *       (analyzeDeterministic) and the shared escalation gate
 *       (injectionEscalationReasons)
 *     → judicial instructions (buildJudicialInstructions)
 *     → evidence frames WITH those instructions, BOTH orientations
 *       (renderEvidenceFrame)
 *     → the pre-committed juror system prompt + strict outcome parsing
 *       (jurorSystemPrompt / parseJurorOutput) and the jury's
 *       swap-consistency rule (computeSwapConsistent)
 *
 * …but with exactly ONE judge seat and NO majority logic, NO placement
 * rules, NO attestation gate, and NO settlement:
 *
 * - The result is a distinct {@link BenchResult}, NOT a VerdictObject — it
 *   carries no `final`, no `votes`, no ruling that anything downstream can
 *   settle or execute. Nothing on the bench path can ever reach a rail.
 * - Results are labeled UNATTESTED BENCH and never feed the quality gate.
 * - Cases the deterministic layer short-circuits never reach the judge at
 *   all (`deterministicShortCircuit: true`, model unused) — the bench only
 *   exercises the judge on jury-path cases.
 *
 * Determinism: the same temperature-0 / thinking-disabled posture as the
 * jury path, to the extent the target model's API still accepts sampling
 * parameters (see providers/anthropic.ts — Sonnet 5 / Opus 4.7+ / Fable
 * reject non-default temperature, so full API-level determinism is
 * best-effort there).
 */
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import type { CaseObject, InferenceProvider, Outcome } from '@edict/core';
import { verifyEvidenceCommitments } from './pipeline/evidenceIntegrity.js';
import { analyzeDeterministic } from './pipeline/deterministic.js';
import { buildJudicialInstructions } from './pipeline/judicialInstructions.js';
import {
  renderEvidenceFrame,
  ORIENTATIONS,
  type EvidenceFrameResult,
  type Orientation,
} from './pipeline/evidenceFrame.js';
import {
  jurorSystemPrompt,
  parseJurorOutput,
  computeSwapConsistent,
  JUROR_MAX_TOKENS,
  type SeatPassRecord,
} from './pipeline/jury.js';
import { injectionEscalationReasons } from './pipeline/aggregate.js';
import { archiveWrite, dedupSorted, sanitizeName } from './util.js';

/** Distinct result marker — a BenchResult is never a VerdictObject. */
export const BENCH_RESULT_TYPE = 'unattested_single_judge_bench' as const;

/** Label stamped on every archived bench artifact. */
export const BENCH_LABEL = 'UNATTESTED BENCH — quality instrument, not an Edict verdict' as const;

export interface BenchOptions {
  /** The single judge (typically AnthropicProvider — BENCH-ONLY, unattested). */
  provider: InferenceProvider;
  modelId: string;
  /** Judge outputs + the bench summary are archived here (per-case subdir). */
  archiveDir: string;
  /**
   * Per-pass completion budget. Default JUROR_MAX_TOKENS (1024) — raise for
   * reasoning models that exhaust the default budget on <think> preambles
   * before the strict-JSON verdict (mirrors ArbiterConfig.jurorMaxTokens).
   */
  maxTokens?: number;
}

export interface BenchPassRecord {
  orientation: Orientation;
  /** Parsed outcome (the pipeline fallback when parseError is set). */
  outcome: Outcome;
  confidence: number;
  parseError?: string;
}

export interface BenchUsage {
  inputTokens: number;
  outputTokens: number;
}

/**
 * The bench summary for one case. Deliberately NOT a VerdictObject: no
 * `final`, no `votes`, no settlement path — nothing downstream can execute
 * a BenchResult.
 */
export interface BenchResult {
  benchType: typeof BENCH_RESULT_TYPE;
  caseId: string;
  providerId: string;
  modelId: string;
  /**
   * True when the deterministic layer disposed of the case before any model
   * call (the jury path would not have convened either). The judge was NOT
   * exercised; both orientation outcomes carry the deterministic ruling.
   */
  deterministicShortCircuit: boolean;
  shortCircuitRule?: string;
  shortCircuitDetail?: string;
  /** Outcome per orientation (verdict-like summary — never settled). */
  outcomes: Partial<Record<Orientation, Outcome>>;
  /** One record per judge pass (empty on deterministic short-circuits). */
  passes: BenchPassRecord[];
  /** The jury's swap-consistency rule applied to the single judge's 2 passes. */
  swapConsistent: boolean;
  /** True iff every judge pass parsed cleanly (vacuously true when model unused). */
  parsedOk: boolean;
  /**
   * The SHARED escalation gate (injectionEscalationReasons — same policy as
   * the jury and deterministic paths) applied to the run's flags. Recorded
   * for parity with the real pipeline; the bench never settles regardless.
   */
  escalatedByGate: boolean;
  escalationReasons: string[];
  injectionFlags: string[];
  /** Summed provider-reported token usage across passes, when available. */
  usage?: BenchUsage;
}

/**
 * Run one case through bench-trial mode. See the module doc: real pipeline
 * pieces, ONE unattested judge, no majority, no settlement.
 *
 * Throws EvidenceIntegrityError for a tampered order mandate exactly like
 * the real pipeline (the mandate is the contract; not even a bench opinion
 * is rendered on a substituted mandate).
 */
export async function benchAdjudicate(
  caseObj: CaseObject,
  evidencePlaintext: Record<string, string>,
  opts: BenchOptions,
): Promise<BenchResult> {
  // Same boundary as adjudicate(): commitments verified before anything else.
  const verified = verifyEvidenceCommitments(caseObj, evidencePlaintext);

  // NOTE: validateCase() is deliberately NOT run — it enforces jury placement
  // rules (provider majority, family disjointness) that have no meaning for a
  // single bench judge. Case-structure validation is the harness's job.

  const caseDir = join(opts.archiveDir, sanitizeName(caseObj.caseId));
  await mkdir(caseDir, { recursive: true });

  const analysis = analyzeDeterministic(caseObj, verified);
  const judicial = buildJudicialInstructions(caseObj, analysis.parsedMandate, analysis.report, caseObj.evidence);

  // --- deterministic short-circuit: model unused --------------------------
  if (analysis.shortCircuit !== undefined) {
    const sc = analysis.shortCircuit;
    // Mirror finalizeDeterministic: the injection screen still runs over the
    // rendered frames, and the SAME escalation gate is applied to the flags.
    const frames = {} as Record<Orientation, EvidenceFrameResult>;
    for (const o of ORIENTATIONS) {
      frames[o] = renderEvidenceFrame(caseObj, verified.plaintext, o, undefined, judicial.blocks);
    }
    const injectionFlags = dedupSorted([
      ...frames.requester_first.injectionFlags,
      ...frames.worker_first.injectionFlags,
      ...analysis.flags,
      ...judicial.flags,
      ...sc.flags,
    ]);
    const gateReasons = injectionEscalationReasons(caseObj.tier, injectionFlags);
    const result: BenchResult = {
      benchType: BENCH_RESULT_TYPE,
      caseId: caseObj.caseId,
      providerId: opts.provider.id,
      modelId: opts.modelId,
      deterministicShortCircuit: true,
      shortCircuitRule: sc.rule,
      shortCircuitDetail: sc.detail,
      outcomes: { requester_first: sc.ruling, worker_first: sc.ruling },
      passes: [],
      swapConsistent: true,
      parsedOk: true,
      escalatedByGate: gateReasons.length > 0,
      escalationReasons: gateReasons,
      injectionFlags,
    };
    await archiveBenchResult(caseDir, opts.modelId, result);
    return result;
  }

  // --- jury-path case: exercise the single judge on BOTH orientations -----
  const frames = {} as Record<Orientation, EvidenceFrameResult>;
  for (const o of ORIENTATIONS) {
    frames[o] = renderEvidenceFrame(caseObj, verified.plaintext, o, analysis.findingsSection, judicial.blocks);
  }
  const injectionFlags = dedupSorted([
    ...frames.requester_first.injectionFlags,
    ...frames.worker_first.injectionFlags,
    ...analysis.flags,
    ...judicial.flags,
  ]);

  const system = jurorSystemPrompt(caseObj.decisionSpace);
  const passes: BenchPassRecord[] = [];
  const seatPasses: SeatPassRecord[] = [];
  const outcomes: Partial<Record<Orientation, Outcome>> = {};
  let usage: BenchUsage | undefined;

  for (const orientation of ORIENTATIONS) {
    const completion = await opts.provider.complete({
      modelId: opts.modelId,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: frames[orientation].frame },
      ],
      maxTokens: opts.maxTokens ?? JUROR_MAX_TOKENS,
    });
    const parsed = parseJurorOutput(completion.text, caseObj);
    outcomes[orientation] = parsed.ruling;
    passes.push({
      orientation,
      outcome: parsed.ruling,
      confidence: parsed.confidence,
      ...(parsed.parseError !== undefined ? { parseError: parsed.parseError } : {}),
    });
    seatPasses.push({
      orientation,
      ruling: parsed.ruling,
      confidence: parsed.confidence,
      reasons: parsed.reasons,
      ...(parsed.parseError !== undefined ? { parseError: parsed.parseError } : {}),
    });
    const passUsage = usageFromCompletionRaw(completion.raw);
    if (passUsage !== undefined) {
      usage = {
        inputTokens: (usage?.inputTokens ?? 0) + passUsage.inputTokens,
        outputTokens: (usage?.outputTokens ?? 0) + passUsage.outputTokens,
      };
    }

    await archiveWrite(
      caseDir,
      `bench_${sanitizeName(opts.modelId)}_${orientation}.json`,
      JSON.stringify(
        {
          label: BENCH_LABEL,
          modelId: opts.modelId,
          orientation,
          judgeText: completion.text,
          requestSha256: completion.requestSha256,
          responseSha256: completion.responseSha256,
        },
        null,
        2,
      ),
    );
  }

  const gateReasons = injectionEscalationReasons(caseObj.tier, injectionFlags);
  const result: BenchResult = {
    benchType: BENCH_RESULT_TYPE,
    caseId: caseObj.caseId,
    providerId: opts.provider.id,
    modelId: opts.modelId,
    deterministicShortCircuit: false,
    outcomes,
    passes,
    swapConsistent: computeSwapConsistent(seatPasses, caseObj.decisionSpace),
    parsedOk: passes.length === ORIENTATIONS.length && passes.every((p) => p.parseError === undefined),
    escalatedByGate: gateReasons.length > 0,
    escalationReasons: gateReasons,
    injectionFlags,
    ...(usage !== undefined ? { usage } : {}),
  };
  await archiveBenchResult(caseDir, opts.modelId, result);
  return result;
}

async function archiveBenchResult(caseDir: string, modelId: string, result: BenchResult): Promise<void> {
  await archiveWrite(
    caseDir,
    `bench_${sanitizeName(modelId)}_result.json`,
    JSON.stringify({ label: BENCH_LABEL, ...result }, null, 2),
  );
}

/**
 * Best-effort token-usage extraction from a provider's opaque completion
 * capture. Understands the Anthropic Messages shape
 * (`usage.input_tokens/output_tokens`) and the OpenAI-compatible shape
 * (`usage.prompt_tokens/completion_tokens`); anything else → undefined
 * (MockProvider captures carry no usage).
 */
export function usageFromCompletionRaw(raw: unknown): BenchUsage | undefined {
  if (raw === null || typeof raw !== 'object') return undefined;
  const parsed = (raw as { parsed?: unknown }).parsed;
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const usage = (parsed as { usage?: unknown }).usage;
  if (usage === null || typeof usage !== 'object') return undefined;
  const u = usage as Record<string, unknown>;
  const input = typeof u.input_tokens === 'number' ? u.input_tokens : typeof u.prompt_tokens === 'number' ? u.prompt_tokens : undefined;
  const output = typeof u.output_tokens === 'number' ? u.output_tokens : typeof u.completion_tokens === 'number' ? u.completion_tokens : undefined;
  if (input === undefined && output === undefined) return undefined;
  return { inputTokens: input ?? 0, outputTokens: output ?? 0 };
}
