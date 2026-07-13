/**
 * Deterministic mock InferenceProvider — the whole pipeline runs offline
 * against these.
 *
 * Behaviour is seeded by sha256(caseId + ":" + modelId): each (case, model)
 * pair gets a stable bias so different mock "models" can disagree on close
 * cases while any single model is perfectly reproducible. The verdict itself
 * comes from toy keyword heuristics over the rendered evidence frame
 * (delivery/conformance words favour the worker; failure/breach words favour
 * the requester).
 *
 * DECISION SPACES: the mock reads the DECISION SPACE section of
 * the frame and answers in the matching outcome shape:
 * - escrow_branches: deterministic keyword and lean heuristics select a
 *   permitted payout branch (split pro-rata on partial milestone records).
 * - categorical: keyword heuristic over the committed outcome labels — each
 *   label is scored by its occurrence count in the party-narrative text
 *   (x10), plus a small per-(seed, label) jitter so mock models can disagree
 *   when no label dominates; the top-scoring label wins (ties break toward
 *   the earlier committed label). Deterministic by seed.
 * - bounded_scalar: findings-derived pro-rata within the bounds — the award
 *   fraction is FAIL/(PASS+FAIL) over the tribunal's deterministic findings
 *   (machine-verified failures favour the claimant); with no findings the
 *   fraction derives from the keyword lean (requester-favouring text raises
 *   the award). value = min + fraction*(max-min), rounded to 2 decimals.
 *   Deterministic by seed.
 *
 * DETERMINISTIC FINDINGS handling: like a real juror following the system
 * prompt, the mock weighs the tribunal-computed machine-check section
 * heavily — each FAIL counts strongly against the worker, and a partial
 * hash_equals milestone record (some PASS, some FAIL) yields a pro-rata
 * split when split is permitted. The findings text itself is EXCLUDED from
 * the free-text keyword scan (it is structured tribunal output, not party
 * narrative). The TRIBUNAL INSTRUCTIONS and DECISION SPACE sections are
 * excluded from the scan for the same reason: tribunal-authored / committed
 * case structure, not evidence, and their wording must not tilt the keyword
 * heuristics.
 *
 * `positionalBias: true` simulates a model with ordering bias: it leans
 * toward whichever party is presented first. This is exactly the failure
 * mode the swap-debias run is designed to catch, so tests can force
 * swap-flips realistically.
 */
import type { InferenceProvider, Outcome, ProviderProof, Ruling } from '@edict/core';
import { clamp, sha256Hex, SEVENTY_TWO_HOURS_MS } from '../util.js';

export interface MockProviderOptions {
  /** Lean toward whichever party is listed first in the frame. */
  positionalBias?: boolean;
  /** How hard positional bias pushes (default 8 — enough to flip verdicts). */
  positionalWeight?: number;
}

interface MockCapture {
  providerId: string;
  modelId: string;
  requestSha256: string;
  responseSha256: string;
}

const WORKER_SIGNALS = [
  'delivered',
  'completed',
  'complete',
  'passed',
  'verified',
  'conforms',
  'confirmed',
  'uploaded',
  'on time',
  'as agreed',
];

const REQUESTER_SIGNALS = [
  'missing',
  'failed',
  'failure',
  'late',
  'broken',
  'incomplete',
  'undelivered',
  'defective',
  'wrong',
  'corrupted',
  'mismatch',
  'breach',
  'unusable',
  'refund',
];

export class MockProvider implements InferenceProvider {
  readonly id: string;
  private readonly opts: MockProviderOptions;

  constructor(id: string, opts: MockProviderOptions = {}) {
    this.id = id;
    this.opts = opts;
  }

  async complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }): Promise<{ text: string; requestSha256: string; responseSha256: string; raw: unknown }> {
    const frame = req.messages
      .filter((m) => m.role === 'user')
      .map((m) => m.content)
      .join('\n');

    const caseId = /^CASE:\s*(.+)$/m.exec(frame)?.[1]?.trim() ?? '';
    const openedAt = Number(/^OPENED AT \(unix ms\):\s*(\d+)/m.exec(frame)?.[1] ?? '0');
    const space = extractDecisionSpace(frame);
    const criterionIds = extractCriterionIds(frame);
    const findings = extractDeterministicFindings(frame);

    // --- keyword heuristics over the frame ------------------------------
    // The DETERMINISTIC FINDINGS, TRIBUNAL INSTRUCTIONS and DECISION SPACE
    // sections are structured tribunal output / committed case structure,
    // not party narrative — excluded from the free-text scan (findings are
    // weighed explicitly below). Normalise negations first so "not
    // delivered" doesn't count as a worker signal.
    const scanText = stripTribunalSections(frame);
    const lower = scanText.toLowerCase().replace(/\b(?:not|never|un)[\s-]?delivered\b/g, 'undelivered');
    const score = countSignals(lower, WORKER_SIGNALS) - countSignals(lower, REQUESTER_SIGNALS);

    // Stable per-(case, model) bias in [-2, +2] so mock models can disagree.
    const seedHash = sha256Hex(`${caseId}:${req.modelId}`);
    const bias = (parseInt(seedHash.slice(0, 2), 16) % 5) - 2;
    let adjusted = score + bias;

    if (this.opts.positionalBias) {
      const w = this.opts.positionalWeight ?? 8;
      adjusted += requesterListedFirst(frame) ? -w : w;
    }

    // Machine-verified failures weigh heavily against the worker — a juror
    // following the system prompt trusts the tribunal's deterministic layer
    // far above party narrative (near-dispositive, same magnitude as the
    // positional-bias default).
    const failedFindings = findings.filter((f) => f.status === 'FAIL');
    adjusted -= 8 * failedFindings.length;

    const { ruling, confidence, finding } =
      space.kind === 'categorical'
        ? this.decideCategorical(space.outcomes, lower, seedHash)
        : space.kind === 'scalar'
          ? this.decideScalar(space, findings, adjusted)
          : this.decideEscrow(space.permitted, adjusted, findings, failedFindings, openedAt);

    const reasons = (criterionIds.length > 0 ? criterionIds : ['general']).map((id) => ({
      criterionId: id,
      finding,
    }));

    const text = JSON.stringify({ ruling, confidence, reasons });

    // Mirror the OpenAI-compatible wire shape so hashes are meaningful.
    const requestBody = JSON.stringify({
      model: req.modelId,
      messages: req.messages,
      temperature: 0,
      ...(req.maxTokens !== undefined ? { max_tokens: req.maxTokens } : {}),
      seed: 0,
    });
    const requestSha256 = sha256Hex(requestBody);
    const responseBody = JSON.stringify({
      id: `mock-${seedHash.slice(0, 12)}`,
      object: 'chat.completion',
      model: req.modelId,
      choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
    });
    const responseSha256 = sha256Hex(responseBody);

    const capture: MockCapture = { providerId: this.id, modelId: req.modelId, requestSha256, responseSha256 };
    return { text, requestSha256, responseSha256, raw: capture };
  }

  /** Deterministic escrow heuristics retained for reproducible fixtures. */
  private decideEscrow(
    permitted: Array<Ruling['kind']>,
    adjusted: number,
    findings: MockFinding[],
    failedFindings: MockFinding[],
    openedAt: number,
  ): { ruling: Outcome; confidence: number; finding: string } {
    const lean: 'worker' | 'requester' | 'middle' =
      adjusted >= 2 ? 'worker' : adjusted <= -2 ? 'requester' : 'middle';

    // Partial milestone delivery: the deterministic record shows some
    // mandated artifacts delivered (hash_equals PASS) and some not (FAIL).
    // When split is permitted, apportion pro-rata to the requester.
    const hashPass = findings.filter((f) => f.kind === 'hash_equals' && f.status === 'PASS').length;
    const hashFail = findings.filter((f) => f.kind === 'hash_equals' && f.status === 'FAIL').length;
    const milestoneSplit =
      hashPass > 0 && hashFail > 0 && failedFindings.every((f) => f.kind === 'hash_equals') && permitted.includes('split');

    const prefs: Array<Ruling['kind']> = milestoneSplit
      ? ['split', 'redo', 'requester_wins', 'worker_wins']
      : lean === 'worker'
        ? ['worker_wins', 'split', 'redo', 'requester_wins']
        : lean === 'requester'
          ? ['requester_wins', 'split', 'redo', 'worker_wins']
          : adjusted >= 0
            ? ['split', 'redo', 'worker_wins', 'requester_wins']
            : ['split', 'redo', 'requester_wins', 'worker_wins'];
    const kind = prefs.find((k) => permitted.includes(k)) ?? permitted[0] ?? 'split';

    const ruling: Ruling =
      kind === 'split'
        ? {
            kind,
            requesterBps: milestoneSplit
              ? Math.round((hashFail / (hashFail + hashPass)) * 10_000)
              : lean === 'worker'
                ? 2500
                : lean === 'requester'
                  ? 7500
                  : 5000,
          }
        : kind === 'redo'
          ? { kind, newDeadlineUnixMs: openedAt + SEVENTY_TWO_HOURS_MS }
          : { kind };

    // A pro-rata milestone split grounded in the machine-verified record is a
    // high-confidence outcome regardless of how noisy the narrative was.
    const confidence = milestoneSplit
      ? 0.8
      : Math.round(clamp(0.5 + 0.07 * Math.abs(adjusted), 0, 0.95) * 100) / 100;
    const finding =
      lean === 'worker'
        ? 'evidence signals support conforming delivery by the worker'
        : lean === 'requester'
          ? 'evidence signals support non-conformance or non-delivery'
          : 'evidence signals are balanced; no clear conformance finding';
    return { ruling, confidence, finding };
  }

  /** Keyword-heuristic pick among the committed outcome labels (seed-jittered). */
  private decideCategorical(
    outcomes: string[],
    lowerScan: string,
    seedHash: string,
  ): { ruling: Outcome; confidence: number; finding: string } {
    let best = outcomes[0] ?? '';
    let bestScore = -1;
    let secondScore = -1;
    for (const label of outcomes) {
      const jitter = parseInt(sha256Hex(`${seedHash}:${label}`).slice(0, 2), 16) % 3;
      const s = countLabel(lowerScan, label) * 10 + jitter;
      if (s > bestScore) {
        secondScore = bestScore;
        bestScore = s;
        best = label;
      } else if (s > secondScore) {
        secondScore = s;
      }
    }
    const margin = Math.max(0, bestScore - Math.max(0, secondScore));
    const confidence = Math.round(clamp(0.5 + 0.02 * margin, 0, 0.95) * 100) / 100;
    return {
      ruling: { kind: 'categorical', outcome: best },
      confidence,
      finding: `evidence record references outcome ${JSON.stringify(best)} most strongly`,
    };
  }

  /** Findings-derived pro-rata quantum within the bounds (keyword lean fallback). */
  private decideScalar(
    space: { min: number; max: number },
    findings: MockFinding[],
    adjusted: number,
  ): { ruling: Outcome; confidence: number; finding: string } {
    const pass = findings.filter((f) => f.status === 'PASS').length;
    const fail = findings.filter((f) => f.status === 'FAIL').length;
    const findingsDerived = pass + fail > 0;
    // Machine-verified failures favour the claimant (requester) pro-rata;
    // absent findings, requester-favouring narrative raises the award.
    const fraction = findingsDerived ? fail / (pass + fail) : clamp(0.5 - 0.1 * adjusted, 0, 1);
    const value = Math.round((space.min + fraction * (space.max - space.min)) * 100) / 100;
    const confidence = findingsDerived
      ? 0.8
      : Math.round(clamp(0.5 + 0.07 * Math.abs(adjusted), 0, 0.95) * 100) / 100;
    return {
      ruling: { kind: 'scalar', value },
      confidence,
      finding: findingsDerived
        ? `quantum apportioned pro-rata from the machine-verified record (${fail} FAIL / ${pass + fail} checked)`
        : 'quantum derived from the weight of the narrative evidence signals',
    };
  }

  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as MockCapture;
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      signatureScheme: 'none_mock',
      fetchedAtUnixMs: Date.now(),
    };
  }
}

function countSignals(lowerText: string, signals: string[]): number {
  let n = 0;
  for (const kw of signals) {
    if (kw.includes(' ')) {
      // multi-word phrase: plain substring count
      n += countSubstring(lowerText, kw);
    } else {
      const re = new RegExp(`\\b${kw}\\b`, 'g');
      n += lowerText.match(re)?.length ?? 0;
    }
  }
  return n;
}

function countSubstring(haystack: string, needle: string): number {
  let n = 0;
  let idx = 0;
  for (;;) {
    idx = haystack.indexOf(needle, idx);
    if (idx === -1) break;
    n++;
    idx += needle.length;
  }
  return n;
}

/** Occurrences of one committed outcome label in the (lowercased) narrative scan. */
function countLabel(lowerScan: string, label: string): number {
  const l = label.toLowerCase();
  if (l.length === 0) return 0;
  if (/^[a-z0-9_]+$/.test(l)) {
    const re = new RegExp(`\\b${l}\\b`, 'g');
    return lowerScan.match(re)?.length ?? 0;
  }
  return countSubstring(lowerScan, l);
}

// --- frame-section extraction -------------------------------------------------

type MockSpace =
  | { kind: 'escrow'; permitted: Array<Ruling['kind']> }
  | { kind: 'categorical'; outcomes: string[] }
  | { kind: 'scalar'; min: number; max: number };

const SPACE_SECTION_RE = /=== DECISION SPACE[^\n]*===\n([\s\S]*?)(?=\n=== |$)/;
const FINDINGS_SECTION_RE = /=== DETERMINISTIC FINDINGS[^\n]*===\n[\s\S]*?(?=\n=== |$)/;
const INSTRUCTIONS_SECTION_RE = /=== TRIBUNAL INSTRUCTIONS[^\n]*===\n[\s\S]*?(?=\n=== |$)/;
const SPACE_SECTION_FULL_RE = /=== DECISION SPACE[^\n]*===\n[\s\S]*?(?=\n=== |$)/;
const INVALID_MARKER_RE = /\s+\[designated invalid\/void outcome\]$/;

function extractDecisionSpace(frame: string): MockSpace {
  const section = SPACE_SECTION_RE.exec(frame)?.[1] ?? '';
  const kind = /^KIND:\s*(escrow_branches|categorical|bounded_scalar)/m.exec(section)?.[1];
  if (kind === 'categorical') {
    const outcomes = [...section.matchAll(/^- (.+)$/gm)].map((m) => m[1]!.replace(INVALID_MARKER_RE, '').trim());
    return { kind: 'categorical', outcomes };
  }
  if (kind === 'bounded_scalar') {
    const m = /^BOUNDS:\s*min=(\S+)\s+max=(\S+)\s+unit=/m.exec(section);
    return { kind: 'scalar', min: Number(m?.[1] ?? '0'), max: Number(m?.[2] ?? '0') };
  }
  const kinds: Array<Ruling['kind']> = [];
  for (const m of section.matchAll(/^- ([a-z_]+)/gm)) {
    const k = m[1];
    if (k === 'requester_wins' || k === 'worker_wins' || k === 'split' || k === 'redo') kinds.push(k);
  }
  return { kind: 'escrow', permitted: kinds };
}

function extractCriterionIds(frame: string): string[] {
  const section = /=== ACCEPTANCE CRITERIA ===\n([\s\S]*?)(?:\n===|$)/.exec(frame)?.[1] ?? '';
  return [...section.matchAll(/^- \[([A-Za-z0-9_.-]+)\]/gm)].map((m) => m[1]!);
}

interface MockFinding {
  id: string;
  kind: string;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
}

function extractDeterministicFindings(frame: string): MockFinding[] {
  const section = FINDINGS_SECTION_RE.exec(frame)?.[0] ?? '';
  return [...section.matchAll(/^- \[([^\]]+)\] ([a-z_]+) → (PASS|FAIL|SKIPPED)/gm)].map((m) => ({
    id: m[1]!,
    kind: m[2]!,
    status: m[3] as MockFinding['status'],
  }));
}

/** Remove tribunal-authored sections (findings + instructions + decision space) from the party-narrative scan. */
function stripTribunalSections(frame: string): string {
  return frame
    .replace(FINDINGS_SECTION_RE, '')
    .replace(INSTRUCTIONS_SECTION_RE, '')
    .replace(SPACE_SECTION_FULL_RE, '');
}

function requesterListedFirst(frame: string): boolean {
  const iReq = frame.indexOf('ROLE: REQUESTER');
  const iWork = frame.indexOf('ROLE: WORKER');
  if (iReq === -1) return false;
  if (iWork === -1) return true;
  return iReq < iWork;
}
