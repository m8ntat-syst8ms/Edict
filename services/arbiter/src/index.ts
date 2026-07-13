/**
 * Deterministic checks, multi-provider adjudication, and verdict aggregation.
 *
 * intake (CaseObject) → evidence-commitment verification → validate →
 * injection screen → deterministic machine-check layer (short-circuits
 * non-delivery / forged-manifest / fully-conformant cases WITHOUT a jury) →
 * normalized evidence frame → multi-provider jury (2 orientations per seat,
 * attestation-gated) → swap-debias + confidence gate → VerdictObject, with
 * all proofs and reasoning archived.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { CaseObject, VerdictObject } from '@edict/core';
import { effectiveRequireProofs, type ArbiterConfig } from './config.js';
import { validateCase } from './pipeline/validate.js';
import { runJury } from './pipeline/jury.js';
import { aggregateDecision, injectionEscalationReasons } from './pipeline/aggregate.js';
import { verifyEvidenceCommitments } from './pipeline/evidenceIntegrity.js';
import { analyzeDeterministic, type DeterministicShortCircuit } from './pipeline/deterministic.js';
import { buildJudicialInstructions } from './pipeline/judicialInstructions.js';
import { renderEvidenceFrame, ORIENTATIONS, type EvidenceFrameResult, type Orientation } from './pipeline/evidenceFrame.js';
import { dedupSorted, sanitizeName, sha256Hex } from './util.js';

export {
  effectiveRequireProofs,
  requireSignerAllowlistFromEnv,
  signerAllowlistEnvName,
  SIGNER_ALLOWLIST_ENV_PREFIX,
  type ArbiterConfig,
} from './config.js';
export { validateCase, CaseValidationError } from './pipeline/validate.js';
export {
  verifyEvidenceCommitments,
  EvidenceIntegrityError,
  ORDER_MANDATE_TAMPERED,
  type VerifiedEvidence,
} from './pipeline/evidenceIntegrity.js';
export {
  analyzeDeterministic,
  type DeterministicAnalysis,
  type DeterministicShortCircuit,
  type ParsedMandate,
  type ShortCircuitRule,
} from './pipeline/deterministic.js';
export {
  buildJudicialInstructions,
  renderJudicialInstructionsSection,
  JUDICIAL_INSTRUCTIONS_TITLE,
  WITHHELD_MANDATE_TEXT_PLACEHOLDER,
  type InstructionMandateView,
  type JudicialInstructionsResult,
} from './pipeline/judicialInstructions.js';
export {
  aggregateDecision,
  fallbackOutcome,
  injectionEscalationReasons,
  SWAP_FLIP_ESCALATION_THRESHOLD,
  MEAN_CONFIDENCE_FLOOR,
  SPLIT_SWAP_TOLERANCE_BPS,
  SCALAR_SWAP_TOLERANCE_FRACTION,
  SCALAR_SPREAD_ESCALATION_FRACTION,
  type AggregateOptions,
  type Decision,
} from './pipeline/aggregate.js';
export {
  runJury,
  parseJurorOutput,
  jurorSystemPrompt,
  computeSwapConsistent,
  JUROR_MAX_TOKENS,
  type JuryRunResult,
  type SeatReasoningRecord,
} from './pipeline/jury.js';
// BENCH-TRIAL MODE (UNATTESTED) — single-judge quality benchmark, explicitly
// separate from the attested jury path: BenchResult is NOT a VerdictObject,
// nothing downstream can settle it, and results never feed the quality gate.
export {
  benchAdjudicate,
  usageFromCompletionRaw,
  BENCH_RESULT_TYPE,
  BENCH_LABEL,
  type BenchOptions,
  type BenchResult,
  type BenchPassRecord,
  type BenchUsage,
} from './bench.js';
export {
  verifyProviderProof,
  proofEnvelope,
  proofEnvelopeBodyHashes,
  ethPersonalBytesDigest,
  ethPersonalMessageDigest,
  recoverEthAddress,
  DEFAULT_PROOF_FRESHNESS_MS,
  type ProofPolicy,
  type ProofVerification,
  type VerifyProofOptions,
} from './pipeline/proofVerify.js';
export {
  renderEvidenceFrame,
  ORIENTATIONS,
  INVALID_OUTCOME_MARKER,
  type Orientation,
  type EvidenceFrameResult,
} from './pipeline/evidenceFrame.js';
// Injection-screen primitives — DOCUMENTED PUBLIC API (consumed by the
// mandate linter and other tooling): screenText neutralizes untrusted text
// and reports severity-classified flags; isAttackFlag / isStylisticNoteFlag
// and the two prefixes classify them. Stable — breaking changes require a
// major version bump.
export {
  screenText,
  isAttackFlag,
  isStylisticNoteFlag,
  ATTACK_FLAG_PREFIX,
  NOTE_FLAG_PREFIX,
  type InjectionScreenResult,
  type InjectionSeverity,
} from './pipeline/injectionScreen.js';
export {
  buildCustomerSettlementExecutionDigest,
  buildCustomerSettlementCanonicalVector,
  canonicalRuling,
  canonicalOutcome,
  type CustomerSettlementExecutionDigestInput,
} from './executionPayload.js';
export {
  OpenAICompatibleProvider,
  type OpenAICompatibleOptions,
  type CompletionCapture,
} from './providers/openaiCompatible.js';
export { NearAiProvider, NEARAI_DEFAULT_BASE_URL, type NearAiProviderOptions } from './providers/nearai.js';
export { PhalaProvider, PHALA_DEFAULT_BASE_URL, type PhalaProviderOptions } from './providers/phala.js';
export {
  EdictNodeProvider,
  EDICT_NODE_PROVIDER_ID,
  EDICT_NODE_REPORT_DATA_CONTEXT,
  type EdictNodeProviderOptions,
} from './providers/edictNode.js';
export { MockProvider, type MockProviderOptions } from './providers/mock.js';
// BENCH-ONLY (unattested — never a jury seat; see providers/anthropic.ts).
export {
  AnthropicProvider,
  ANTHROPIC_DEFAULT_BASE_URL,
  ANTHROPIC_BENCH_PROVIDER_ID,
  type AnthropicProviderOptions,
} from './providers/anthropic.js';

/**
 * Adjudicate one case: returns the VerdictObject and archives (under
 * `${config.archiveDir}/${caseId}/`) every juror output + proof, the full
 * structured reasoning document (parties get plaintext; the registry gets
 * only its sha256), and the verdict itself.
 *
 * @param evidencePlaintext sealed evidence plaintext keyed by the sha256 in
 *   the corresponding EvidenceCommitment. Every entry is verified against the
 *   commitments BEFORE anything else: unknown keys or tampered bytes are hard
 *   errors. A tampered order_mandate is FATAL (EvidenceIntegrityError with
 *   code 'order_mandate_tampered' — the mandate is the contract; no verdict
 *   is ever issued). A mismatched delivery_manifest is instead treated as
 *   forgery evidence — flagged `evidence_hash_mismatch:delivery_manifest`
 *   and fed to the deterministic layer. Missing entries render as "[sealed]"
 *   in the evidence frame.
 */
export async function adjudicate(
  caseObj: CaseObject,
  evidencePlaintext: Record<string, string>,
  config: ArbiterConfig,
): Promise<VerdictObject> {
  // Enforce evidence commitments at the boundary before processing the case.
  const verified = verifyEvidenceCommitments(caseObj, evidencePlaintext);

  validateCase(caseObj, config.seats, config.providers);

  const caseDir = join(config.archiveDir, sanitizeName(caseObj.caseId));
  await mkdir(caseDir, { recursive: true });

  // Run the deterministic machine-check layer before invoking the jury.
  const analysis = analyzeDeterministic(caseObj, verified);

  // Judicial instructions — the tribunal's rules of decision, a deterministic
  // function of the case, parsed mandate, machine report and commitments.
  // Rendered into BOTH orientation frames ahead of the evidence sections.
  // Carries note-level flags from the defensive screen over
  // mandate-originated free text quoted into the instructions.
  const judicial = buildJudicialInstructions(caseObj, analysis.parsedMandate, analysis.report, caseObj.evidence);

  if (analysis.shortCircuit !== undefined) {
    return finalizeDeterministic(
      caseObj,
      verified.plaintext,
      analysis.shortCircuit,
      [...analysis.flags, ...judicial.flags],
      caseDir,
      judicial.blocks,
    );
  }

  const jury = await runJury(caseObj, verified.plaintext, config, analysis.findingsSection, judicial.blocks);
  const allFlags = [...jury.injectionFlags, ...analysis.flags, ...judicial.flags];
  const decision = aggregateDecision(caseObj, jury.votes, jury.passConfidences, allFlags, {
    ...(jury.excludedSeats.length > 0 ? { excludedSeats: jury.excludedSeats } : {}),
  });

  // Structured reasoning document. Deliberately timestamp-free so the
  // reasoning hash obeys the same-case → same-verdict invariant.
  const reasoningDoc = {
    version: 'arbiter-reasoning-v1',
    caseId: caseObj.caseId,
    ruling: decision.ruling,
    final: decision.final,
    quality: decision.quality,
    ...(analysis.report !== undefined ? { machineChecks: analysis.report } : {}),
    ...(analysis.blocked !== undefined ? { blockedDeterministicFinding: analysis.blocked } : {}),
    seats: jury.seatRecords,
  };
  const reasoningJson = JSON.stringify(reasoningDoc, null, 2);
  const reasoningSha256 = sha256Hex(reasoningJson);
  await writeFile(join(caseDir, 'reasoning.json'), reasoningJson, 'utf8');

  const verdict: VerdictObject = {
    caseId: caseObj.caseId,
    ruling: decision.ruling,
    final: decision.final,
    reasoningSha256,
    votes: jury.votes,
    quality: decision.quality,
    legalProfile: caseObj.legalProfile,
    issuedAtUnixMs: Date.now(),
  };
  await writeFile(join(caseDir, 'verdict.json'), JSON.stringify(verdict, null, 2), 'utf8');
  return verdict;
}

/**
 * Build + archive a deterministic (no-jury) verdict for a machine-check
 * short-circuit: votes=[], unanimous. The injection screen still runs over
 * the rendered frames so adversarial submissions are flagged even when no
 * juror ever sees them, and the resulting flags pass
 * through THE SAME escalation/finality gate as jury verdicts
 * (injectionEscalationReasons): a tier-C case with attack-severity flags is
 * escalated (final=false, the machine ruling stays as advisory) exactly as
 * it would be on the jury path; tier A/B attack flags are recorded without
 * escalating, matching the jury path's policy.
 */
async function finalizeDeterministic(
  caseObj: CaseObject,
  plaintext: Record<string, string>,
  sc: DeterministicShortCircuit,
  deterministicFlags: string[],
  caseDir: string,
  judicialInstructions?: string[],
): Promise<VerdictObject> {
  const frames = {} as Record<Orientation, EvidenceFrameResult>;
  for (const o of ORIENTATIONS) {
    frames[o] = renderEvidenceFrame(caseObj, plaintext, o, undefined, judicialInstructions);
  }
  const injectionFlags = dedupSorted([
    ...frames.requester_first.injectionFlags,
    ...frames.worker_first.injectionFlags,
    ...deterministicFlags,
    ...sc.flags,
  ]);

  // THE shared finality gate (same policy as aggregateDecision). A tripped
  // gate NEVER yields an executable verdict: final=false, escalated=true,
  // and the deterministic ruling remains on the verdict as advisory only.
  const gateReasons = injectionEscalationReasons(caseObj.tier, injectionFlags);
  const escalated = gateReasons.length > 0;
  const quality: VerdictObject['quality'] = {
    majority: 'unanimous',
    swapFlipRate: 0,
    injectionFlags,
    escalated,
    ...(escalated ? { escalationReason: gateReasons.join('; ') } : {}),
  };

  const reasoningDoc = {
    version: 'arbiter-reasoning-v1',
    caseId: caseObj.caseId,
    ruling: sc.ruling,
    final: !escalated,
    deterministic: {
      marker: 'DETERMINISTIC_SHORT_CIRCUIT',
      rule: sc.rule,
      detail: sc.detail,
      flags: sc.flags,
    },
    quality,
    seats: [],
  };
  const reasoningJson = JSON.stringify(reasoningDoc, null, 2);
  const reasoningSha256 = sha256Hex(reasoningJson);
  await writeFile(join(caseDir, 'reasoning.json'), reasoningJson, 'utf8');

  const verdict: VerdictObject = {
    caseId: caseObj.caseId,
    ruling: sc.ruling,
    final: !escalated,
    reasoningSha256,
    votes: [],
    quality,
    legalProfile: caseObj.legalProfile,
    issuedAtUnixMs: Date.now(),
  };
  await writeFile(join(caseDir, 'verdict.json'), JSON.stringify(verdict, null, 2), 'utf8');
  return verdict;
}
