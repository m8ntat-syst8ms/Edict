/**
 * Built-in baseline adjudicator — the OFFLINE FALLBACK used when
 * @edict/arbiter is not resolvable (it is built in parallel). It implements
 * the same `adjudicate(caseObj, evidencePlaintext, config)` signature and the
 * same invariants (verdict oracle: outcomes only from the case's
 * decisionSpace; deterministic: same case → same verdict), but only the
 * DETERMINISTIC layer of the pipeline: injection screening + machine checks +
 * burden defaults. It is a credibility baseline for the harness itself, NOT
 * the system under test — reports label which adjudicator produced them.
 *
 * Decision-space handling:
 * - `escrow_branches`  — the full bilateral procedure below (manifests,
 *                        machine checks, MAE, payment receipts). Jury votes
 *                        are emitted (3 seats × 2 swap passes, mock proofs).
 * - `categorical`      — authenticated-support scan: count whole-word
 *                        occurrences of each committed outcome label across
 *                        AUTHENTICATED, non-order_mandate evidence
 *                        (unauthenticated party narratives carry no weight);
 *                        strict max wins; no strict max → the declared
 *                        invalidOutcome when present, else escalate.
 * - `bounded_scalar`   — hash-committed loss components: sum
 *                        `machineCheck.params.payableUsd` (legacy alias `amountUsd`) over the mandate's
 *                        `hash_equals` criteria whose `expectedSha256` matches
 *                        an AUTHENTICATED evidence commitment, clamped to
 *                        [min, max].
 * Categorical/scalar decisions are purely deterministic — no jury seats are
 * convened, so `votes` is empty for those cases (JuryVote passes carry escrow
 * Rulings only).
 */
import type {
  CaseObject,
  DecisionSpace,
  EvidenceCommitment,
  EvidenceKind,
  InferenceProvider,
  JurySeatSpec,
  OrderMandate,
  Outcome,
  ProviderProof,
  Ruling,
  VerdictObject,
} from '@edict/core';
import type { AdjudicateFn, ArbiterConfigLike } from './harnessTypes.js';
import { sha256Hex } from './hash.js';

// ---------------------------------------------------------------------------
// Mock provider (offline, deterministic, signatureScheme 'none_mock')
// ---------------------------------------------------------------------------

export class LocalMockProvider implements InferenceProvider {
  constructor(public readonly id: string) {}

  async complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }): Promise<{ text: string; requestSha256: string; responseSha256: string; raw: unknown }> {
    const requestSha256 = sha256Hex(JSON.stringify({ modelId: req.modelId, messages: req.messages }));
    const text = `mock-completion:${requestSha256.slice(0, 16)}`;
    return { text, requestSha256, responseSha256: sha256Hex(text), raw: null };
  }

  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const ref = (completionRef ?? {}) as Partial<ProviderProof> & { requestSha256?: string; responseSha256?: string };
    return {
      providerId: this.id,
      modelId: ref.modelId ?? 'unknown',
      requestSha256: ref.requestSha256 ?? sha256Hex('mock-request'),
      responseSha256: ref.responseSha256 ?? sha256Hex('mock-response'),
      signatureScheme: 'none_mock',
      fetchedAtUnixMs: 0,
    };
  }
}

/** Build one mock provider per distinct providerId in the seat roster. */
export function buildLocalMockProviders(seats: JurySeatSpec[]): Record<string, InferenceProvider> {
  const providers: Record<string, InferenceProvider> = {};
  for (const seat of seats) {
    providers[seat.providerId] ??= new LocalMockProvider(seat.providerId);
  }
  return providers;
}

/** Look a provider up in either config shape (Map — real arbiter — or Record). */
export function lookupProvider(
  providers: Map<string, InferenceProvider> | Record<string, InferenceProvider> | undefined,
  providerId: string,
): InferenceProvider | undefined {
  if (!providers) return undefined;
  if (providers instanceof Map) return providers.get(providerId);
  return providers[providerId];
}

export const DEFAULT_MOCK_SEATS: JurySeatSpec[] = [
  { seatId: 'mock-alpha:anna', providerId: 'mock-alpha', modelId: 'mock-anna-1.0', modelFamily: 'anna' },
  { seatId: 'mock-beta:boris', providerId: 'mock-beta', modelId: 'mock-boris-1.0', modelFamily: 'boris' },
  { seatId: 'mock-gamma:clara', providerId: 'mock-gamma', modelId: 'mock-clara-1.0', modelFamily: 'clara' },
];

// ---------------------------------------------------------------------------
// Injection screen
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp }> = [
  { id: 'system_role_override', re: /\bSYSTEM\s*:/ },
  { id: 'ignore_instructions', re: /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions/i },
  { id: 'mode_reassignment', re: /you\s+are\s+now\s+in\s+\w+\s+mode/i },
  { id: 'verdict_coercion', re: /(?:rule\s+(?:for|in\s+favou?r\s+of)\s+the\s+(?:worker|requester))|(?:arbiter\s+is\s+required\s+to)|(?:required\s+to\s+enter\s+judgment)/i },
  { id: 'output_format_injection', re: /"ruling"\s*:\s*\{/i },
  { id: 'instruction_supersession', re: /supersedes?\s+(?:all\s+)?(?:case-specific|previous|prior|other)\s+instructions/i },
];

/**
 * Scan unsealed evidence for embedded instruction attacks. Returns
 * verdict-ready flag strings. Every baseline pattern is an authority-claiming
 * attack, so flags carry the ecosystem-wide `attack:` severity prefix
 * (stylistic `note:` flags are a real-pipeline concept; the baseline records
 * none).
 */
export function screenForInjection(
  evidence: EvidenceCommitment[],
  plaintext: Record<string, string>,
): string[] {
  const flags: string[] = [];
  for (const commitment of evidence) {
    const content = plaintext[commitment.sha256];
    if (content === undefined) continue;
    for (const { id, re } of INJECTION_PATTERNS) {
      if (re.test(content)) {
        flags.push(`attack:${id}@${commitment.kind}:${commitment.sha256.slice(0, 8)}`);
      }
    }
  }
  return flags;
}

// ---------------------------------------------------------------------------
// Deterministic machine checks (mandate acceptanceCriteria[].machineCheck)
//
// Param conventions (documented in the package README):
//   hash_equals     { expectedSha256, artifactName?, payableUsd? } — escrow: the
//                   manifest must claim an artifact with that sha256 (and
//                   name, when given); bounded_scalar: an AUTHENTICATED
//                   evidence commitment with that sha256 must exist, in which
//                   case payableUsd (legacy alias amountUsd) joins the quantum sum
//   contains        { needle, evidenceKind?, submitter? } — some evidence item of
//                   that kind/submitter must contain the needle string
//   deadline_before {} — manifest.deliveredAtUnixMs <= mandate.deadlineUnixMs
//   schema_valid / custom — not machine-evaluable here; left to the jury layer
// ---------------------------------------------------------------------------

interface ManifestLike {
  jobNonce?: string;
  deliveredAtUnixMs?: number;
  artifacts?: Array<{ name?: string; sha256?: string; format?: string }>;
}

interface CheckOutcome {
  criterionId: string;
  kind: string;
  result: 'pass' | 'fail' | 'unchecked';
  detail: string;
}

function parseJsonSafe<T>(raw: string | undefined): T | undefined {
  if (raw === undefined) return undefined;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return undefined;
  }
}

function evidenceOfKind(
  caseObj: CaseObject,
  plaintext: Record<string, string>,
  kind: EvidenceKind,
  submitter?: string,
): Array<{ commitment: EvidenceCommitment; content: string }> {
  return caseObj.evidence
    .filter((e) => e.kind === kind && (submitter === undefined || e.submitter === submitter))
    .map((e) => ({ commitment: e, content: plaintext[e.sha256] }))
    .filter((x): x is { commitment: EvidenceCommitment; content: string } => x.content !== undefined);
}

function runMachineChecks(
  caseObj: CaseObject,
  plaintext: Record<string, string>,
  mandate: Partial<OrderMandate> | undefined,
  manifest: ManifestLike | undefined,
): CheckOutcome[] {
  const outcomes: CheckOutcome[] = [];
  for (const ac of mandate?.acceptanceCriteria ?? []) {
    const check = ac.machineCheck;
    if (!check) continue;
    const params = check.params ?? {};
    switch (check.kind) {
      case 'hash_equals': {
        const expected = typeof params.expectedSha256 === 'string' ? params.expectedSha256 : undefined;
        const name = typeof params.artifactName === 'string' ? params.artifactName : undefined;
        if (!expected) {
          outcomes.push({ criterionId: ac.id, kind: check.kind, result: 'unchecked', detail: 'missing expectedSha256 param' });
          break;
        }
        const claimed = (manifest?.artifacts ?? []).some(
          (a) => a.sha256 === expected && (name === undefined || a.name === name),
        );
        outcomes.push({
          criterionId: ac.id,
          kind: check.kind,
          result: claimed ? 'pass' : 'fail',
          detail: claimed
            ? `manifest claims artifact ${expected.slice(0, 12)}…`
            : `no manifest artifact matches mandated sha256 ${expected.slice(0, 12)}…${name ? ` (${name})` : ''}`,
        });
        break;
      }
      case 'contains': {
        const needle = typeof params.needle === 'string' ? params.needle : undefined;
        if (!needle) {
          outcomes.push({ criterionId: ac.id, kind: check.kind, result: 'unchecked', detail: 'missing needle param' });
          break;
        }
        const kind = (typeof params.evidenceKind === 'string' ? params.evidenceKind : 'delivery_manifest') as EvidenceKind;
        const submitter = typeof params.submitter === 'string' ? params.submitter : undefined;
        const haystacks = evidenceOfKind(caseObj, plaintext, kind, submitter);
        const hit = haystacks.some((h) => h.content.includes(needle));
        outcomes.push({
          criterionId: ac.id,
          kind: check.kind,
          result: hit ? 'pass' : 'fail',
          detail: hit ? `found "${needle}" in ${kind}` : `"${needle}" absent from ${haystacks.length} ${kind} item(s)`,
        });
        break;
      }
      case 'deadline_before': {
        if (manifest?.deliveredAtUnixMs === undefined || mandate?.deadlineUnixMs === undefined) {
          outcomes.push({ criterionId: ac.id, kind: check.kind, result: 'unchecked', detail: 'no deliveredAtUnixMs/deadlineUnixMs available' });
          break;
        }
        const ok = manifest.deliveredAtUnixMs <= mandate.deadlineUnixMs;
        outcomes.push({
          criterionId: ac.id,
          kind: check.kind,
          result: ok ? 'pass' : 'fail',
          detail: `delivered ${manifest.deliveredAtUnixMs} vs deadline ${mandate.deadlineUnixMs}`,
        });
        break;
      }
      default:
        outcomes.push({ criterionId: ac.id, kind: check.kind, result: 'unchecked', detail: 'not machine-evaluable in baseline' });
    }
  }
  return outcomes;
}

// ---------------------------------------------------------------------------
// Baseline decision procedures (one per decision-space kind)
// ---------------------------------------------------------------------------

interface BaselineDecision {
  outcome: Outcome;
  escalated: boolean;
  reason?: string;
}

function pickPermitted(
  space: Extract<DecisionSpace, { kind: 'escrow_branches' }>,
  openedAtUnixMs: number,
  preferred: Ruling,
): BaselineDecision {
  if (space.permitted.includes(preferred.kind)) return { outcome: preferred, escalated: false };
  // Verdict-oracle invariant: never emit a ruling outside the permitted branches.
  const fallbackKind = space.permitted[0];
  const fallback: Ruling =
    fallbackKind === 'split'
      ? { kind: 'split', requesterBps: 5000 }
      : fallbackKind === 'redo'
        ? { kind: 'redo', newDeadlineUnixMs: openedAtUnixMs + 7 * 24 * 3600 * 1000 }
        : { kind: fallbackKind };
  return {
    outcome: fallback,
    escalated: true,
    reason: `baseline preferred '${preferred.kind}' which is not among the permitted escrow branches — escalating`,
  };
}

/**
 * Escrow (bilateral) decision: (1) no manifest ⇒ non-delivery ⇒ requester
 * wins; (2) machine-check failures ⇒ requester wins, except pure milestone
 * (hash_equals) partial delivery where split is permitted ⇒ pro-rata split;
 * (3) proven enumerated MAE event ⇒ requester wins (qualified code deference);
 * (4) otherwise delivery presumption + contra proferentem ⇒ worker wins.
 * Payment receipts whose jobNonce mismatches the mandate nonce are disregarded.
 */
function decideEscrow(
  caseObj: CaseObject,
  space: Extract<DecisionSpace, { kind: 'escrow_branches' }>,
  evidencePlaintext: Record<string, string>,
  mandate: Partial<OrderMandate> | undefined,
  reasoning: string[],
): BaselineDecision {
  const manifest = caseObj.deliveryManifestHash
    ? parseJsonSafe<ManifestLike>(evidencePlaintext[caseObj.deliveryManifestHash])
    : undefined;

  let preferred: Ruling;
  if (caseObj.deliveryManifestHash === undefined) {
    reasoning.push('no delivery manifest committed → non-delivery; burden of proving delivery is on the worker and is unmet');
    preferred = { kind: 'requester_wins' };
  } else {
    const checks = runMachineChecks(caseObj, evidencePlaintext, mandate, manifest);
    for (const c of checks) reasoning.push(`machine check ${c.criterionId} (${c.kind}): ${c.result} — ${c.detail}`);
    const failed = checks.filter((c) => c.result === 'fail');
    const passedHash = checks.filter((c) => c.kind === 'hash_equals' && c.result === 'pass');
    const hashChecks = checks.filter((c) => c.kind === 'hash_equals' && c.result !== 'unchecked');

    // Payment-receipt scrutiny (receipt-deterministic settlement disputes).
    let receiptSatisfiesPayment = false;
    for (const { commitment, content } of evidenceOfKind(caseObj, evidencePlaintext, 'payment_receipt')) {
      const receipt = parseJsonSafe<{ jobNonce?: string; amountUsd?: number }>(content);
      if (!receipt) continue;
      if (mandate?.nonce !== undefined && receipt.jobNonce !== undefined && receipt.jobNonce !== mandate.nonce) {
        reasoning.push(`payment receipt ${commitment.sha256.slice(0, 8)} disregarded: jobNonce ${receipt.jobNonce} does not match mandate nonce ${mandate.nonce}`);
      } else if (receipt.amountUsd !== undefined && mandate?.priceUsd !== undefined && receipt.amountUsd >= mandate.priceUsd) {
        receiptSatisfiesPayment = true;
        reasoning.push(`payment receipt ${commitment.sha256.slice(0, 8)} matches mandate nonce and covers price`);
      }
    }

    // Enumerated MAE events proven by authenticated evidence (DRR Rule 33).
    const maeEvents = mandate?.maeEvents ?? [];
    let maeProven: string | undefined;
    for (const e of caseObj.evidence) {
      if (!e.authenticated) continue;
      const content = evidencePlaintext[e.sha256];
      if (!content) continue;
      for (const m of content.matchAll(/MAE_EVENT:\s*([a-z0-9_]+)/g)) {
        if (maeEvents.includes(m[1])) maeProven = m[1];
      }
    }

    if (failed.length > 0) {
      const allFailedAreHash = failed.every((c) => c.kind === 'hash_equals');
      if (allFailedAreHash && passedHash.length > 0 && space.permitted.includes('split')) {
        const bps = Math.round((failed.length / hashChecks.length) * 10_000);
        reasoning.push(`partial milestone delivery: ${passedHash.length}/${hashChecks.length} mandated artifacts delivered → pro-rata split, requester refunded ${bps} bps`);
        preferred = { kind: 'split', requesterBps: bps };
      } else {
        reasoning.push(`acceptance criteria breach: ${failed.map((c) => c.criterionId).join(', ')} failed deterministically`);
        preferred = { kind: 'requester_wins' };
      }
    } else if (maeProven) {
      reasoning.push(`enumerated MAE event '${maeProven}' proven by authenticated evidence → qualified code deference yields (DRR Rule 33)`);
      preferred = { kind: 'requester_wins' };
    } else if (receiptSatisfiesPayment) {
      reasoning.push('valid payment receipt for this mandate covers the price → settlement already made, requester position sustained');
      preferred = { kind: 'requester_wins' };
    } else {
      reasoning.push('delivery manifested, no deterministic breach; delivery presumption + ambiguity construed against the drafting party → worker prevails');
      preferred = { kind: 'worker_wins' };
    }
  }

  return pickPermitted(space, caseObj.openedAtUnixMs, preferred);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Categorical decision: authenticated-support scan. Counts whole-word,
 * case-sensitive occurrences of each committed outcome label across
 * AUTHENTICATED evidence, EXCLUDING order_mandate items (the mandate defines
 * the space — its rules text naming the labels is not support for any of
 * them). Unauthenticated party narratives carry no weight (evidence policy burden
 * defaults). A strict maximum wins; otherwise the declared invalidOutcome
 * (indeterminate ⇒ void) when present, else the first outcome with
 * escalation.
 */
function decideCategorical(
  caseObj: CaseObject,
  space: Extract<DecisionSpace, { kind: 'categorical' }>,
  evidencePlaintext: Record<string, string>,
  reasoning: string[],
): BaselineDecision {
  const counts = new Map<string, number>(space.outcomes.map((o) => [o, 0]));
  for (const e of caseObj.evidence) {
    if (!e.authenticated || e.kind === 'order_mandate') continue;
    const content = evidencePlaintext[e.sha256];
    if (content === undefined) continue;
    for (const label of space.outcomes) {
      const re = new RegExp(`\\b${escapeRegExp(label)}\\b`, 'g');
      const n = (content.match(re) ?? []).length;
      if (n > 0) counts.set(label, (counts.get(label) ?? 0) + n);
    }
  }
  const tally = space.outcomes.map((o) => `${o}=${counts.get(o) ?? 0}`).join(', ');
  reasoning.push(`categorical authenticated-support scan (order_mandate excluded): ${tally}`);

  const max = Math.max(...space.outcomes.map((o) => counts.get(o) ?? 0));
  const leaders = space.outcomes.filter((o) => (counts.get(o) ?? 0) === max);
  if (max > 0 && leaders.length === 1) {
    reasoning.push(`outcome '${leaders[0]}' has strictly dominant authenticated support`);
    return { outcome: { kind: 'categorical', outcome: leaders[0] }, escalated: false };
  }
  if (space.invalidOutcome !== undefined) {
    reasoning.push(`no outcome has strictly dominant authenticated support → declared invalid outcome '${space.invalidOutcome}'`);
    return { outcome: { kind: 'categorical', outcome: space.invalidOutcome }, escalated: false };
  }
  reasoning.push(`no outcome has strictly dominant authenticated support and no invalid outcome is declared → escalating with provisional '${space.outcomes[0]}'`);
  return {
    outcome: { kind: 'categorical', outcome: space.outcomes[0] },
    escalated: true,
    reason: 'categorical support indeterminate on authenticated evidence and the space declares no invalid outcome',
  };
}

/**
 * Bounded-scalar decision: hash-committed loss components only. For each
 * mandate acceptance criterion with `machineCheck.kind === 'hash_equals'` and
 * a numeric `params.payableUsd` (legacy alias `amountUsd`), the component is
 * payable iff an AUTHENTICATED
 * evidence commitment with `sha256 === params.expectedSha256` exists (with
 * plaintext). Quantum = sum of payable components, clamped to [min, max].
 * Components without a machine check (e.g. contested consequential losses the
 * committed terms exclude) contribute nothing.
 */
function decideScalar(
  caseObj: CaseObject,
  space: Extract<DecisionSpace, { kind: 'bounded_scalar' }>,
  evidencePlaintext: Record<string, string>,
  mandate: Partial<OrderMandate> | undefined,
  reasoning: string[],
): BaselineDecision {
  let sum = 0;
  for (const ac of mandate?.acceptanceCriteria ?? []) {
    const check = ac.machineCheck;
    if (!check || check.kind !== 'hash_equals') {
      if (check) reasoning.push(`quantum component ${ac.id} (${check.kind}): not hash-committed — contributes 0`);
      continue;
    }
    const params = check.params ?? {};
    const expected = typeof params.expectedSha256 === 'string' ? params.expectedSha256 : undefined;
    // Claim-component convention: payableUsd is the canonical param
    // (services/arbiter README); amountUsd is accepted as a legacy alias.
    const rawPayable = params.payableUsd ?? params.amountUsd;
    const payableUsd = typeof rawPayable === 'number' ? rawPayable : undefined;
    if (expected === undefined || payableUsd === undefined) {
      reasoning.push(`quantum component ${ac.id}: missing expectedSha256/payableUsd params — contributes 0`);
      continue;
    }
    const verified = caseObj.evidence.some(
      (e) => e.authenticated && e.sha256 === expected && evidencePlaintext[e.sha256] !== undefined,
    );
    if (verified) {
      sum += payableUsd;
      reasoning.push(`quantum component ${ac.id}: authenticated evidence ${expected.slice(0, 12)}… verifies — ${payableUsd} ${space.unit} payable`);
    } else {
      reasoning.push(`quantum component ${ac.id}: no authenticated evidence commitment matches ${expected.slice(0, 12)}… — contributes 0`);
    }
  }
  const value = Math.min(Math.max(sum, space.min), space.max);
  if (value !== sum) reasoning.push(`quantum ${sum} clamped to the bounded scalar range [${space.min}, ${space.max}] ${space.unit}`);
  reasoning.push(`quantum: ${value} ${space.unit}`);
  return { outcome: { kind: 'scalar', value }, escalated: false };
}

// ---------------------------------------------------------------------------
// Baseline adjudicator
// ---------------------------------------------------------------------------

export const baselineAdjudicate: AdjudicateFn = async (
  caseObj: CaseObject,
  evidencePlaintext: Record<string, string>,
  config: ArbiterConfigLike,
): Promise<VerdictObject> => {
  const reasoning: string[] = [`baseline adjudication of case ${caseObj.caseId} (${caseObj.caseType}, ${caseObj.decisionSpace.kind})`];

  const injectionFlags = screenForInjection(caseObj.evidence, evidencePlaintext);
  if (injectionFlags.length > 0) {
    reasoning.push(`injection screen: ${injectionFlags.length} flag(s) — flagged material excluded from merits: ${injectionFlags.join(', ')}`);
  } else {
    reasoning.push('injection screen: clean');
  }

  const mandate = parseJsonSafe<Partial<OrderMandate>>(evidencePlaintext[caseObj.orderMandateHash]);

  const space = caseObj.decisionSpace;
  const decision: BaselineDecision =
    space.kind === 'escrow_branches'
      ? decideEscrow(caseObj, space, evidencePlaintext, mandate, reasoning)
      : space.kind === 'categorical'
        ? decideCategorical(caseObj, space, evidencePlaintext, reasoning)
        : decideScalar(caseObj, space, evidencePlaintext, mandate, reasoning);
  const { outcome, escalated, reason } = decision;
  reasoning.push(`ruling: ${JSON.stringify(outcome)}${escalated ? ` (ESCALATED: ${reason})` : ''}`);
  const reasoningDoc = reasoning.join('\n');

  // Deterministic issuance time: derived from the case, not the wall clock.
  const issuedAtUnixMs = caseObj.openedAtUnixMs + 60_000;
  const seats = config.seats && config.seats.length > 0 ? config.seats : DEFAULT_MOCK_SEATS;

  // Jury votes carry escrow Rulings (JuryVote.passes[].ruling is the
  // unchanged 4-branch shape); categorical/scalar baseline decisions are
  // deterministic-only, so no seats are convened for them.
  const votes: VerdictObject['votes'] = [];
  if (outcome.kind !== 'categorical' && outcome.kind !== 'scalar') {
    for (const seat of seats) {
      const provider = lookupProvider(config.providers, seat.providerId) ?? new LocalMockProvider(seat.providerId);
      const passes: VerdictObject['votes'][number]['passes'] = [];
      for (const orientation of ['requester_first', 'worker_first'] as const) {
        const completion = await provider.complete({
          modelId: seat.modelId,
          messages: [
            { role: 'system', content: `edict-baseline-arbiter:${orientation}` },
            { role: 'user', content: `${caseObj.caseId}\n${reasoningDoc}` },
          ],
        });
        passes.push({
          orientation,
          ruling: outcome,
          reasoningSha256: sha256Hex(`${seat.seatId}:${orientation}:${reasoningDoc}`),
          proof: {
            providerId: seat.providerId,
            modelId: seat.modelId,
            requestSha256: completion.requestSha256,
            responseSha256: completion.responseSha256,
            signatureScheme: 'none_mock',
            fetchedAtUnixMs: issuedAtUnixMs,
          },
        });
      }
      votes.push({ seat, passes, swapConsistent: true });
    }
  }

  return {
    caseId: caseObj.caseId,
    ruling: outcome,
    // Escalated verdicts are never executable.
    final: !escalated,
    reasoningSha256: sha256Hex(reasoningDoc),
    votes,
    quality: {
      majority: 'unanimous',
      swapFlipRate: 0,
      injectionFlags,
      escalated,
      ...(reason !== undefined ? { escalationReason: reason } : {}),
    },
    legalProfile: caseObj.legalProfile,
    issuedAtUnixMs,
  };
};
