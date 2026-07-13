/**
 * Mandate-side tool implementations: `edict_draft_mandate`,
 * `edict_lint_mandate`, `edict_sandbox_dispute`, `edict_resolve_review`.
 *
 * Mandates conform to the current @edict/core schema and are canonical
 * objects hashed with the canonical evidence hasher, lint reports come from
 * the @edict/linter, and sandbox disputes run the @edict/arbiter
 * pipeline through the @edict/sdk sandbox (deterministic mock jury seats,
 * full escrow + bond settlement math).
 */

import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  AcceptanceCriterion,
  DecisionSpace,
  LegalProfile,
  OrderMandate,
  Outcome,
  PartyRef,
  VerdictObject,
} from '@edict/core';
import { validateDecisionSpace } from '@edict/core';
import { canonicalOrderMandateHash, canonicalize, sha256Canonical, sha256Hex } from '@edict/evidence';
import { canonicalOutcome } from '@edict/arbiter';
import { lintMandate, type LintReport } from '@edict/linter';
import {
  createEdict,
  defaultProfile,
  ExecutableVerdictError,
  isFinalVerdict,
  PendingReviewError,
  ProtectionStateError,
  ReviewOutcomeError,
  UnsupportedRulingError,
  type EscalationDisposition,
  type EscrowSettlement,
  type ProtectOrderInput,
  type ReviewState,
} from '@edict/sdk';
import { ToolInputError } from './errors.js';
import { compactReasoning, tribunalInstructionsFor, type TribunalInstructions } from './explain.js';
import { SLUG_RE, readJsonContained } from './safeRead.js';
import type { SessionStore } from './session.js';

// ---------------------------------------------------------------------------
// Shared parsing helpers
// ---------------------------------------------------------------------------

const MACHINE_CHECK_KINDS = ['hash_equals', 'schema_valid', 'deadline_before', 'contains', 'custom'] as const;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Strings become AC-n criteria; objects may pin id/machineCheck. */
export function normalizeCriteria(input: unknown, problems: string[]): AcceptanceCriterion[] {
  if (!Array.isArray(input) || input.length === 0) {
    problems.push('acceptanceCriteria: must be a non-empty array of strings or {id?, statement, machineCheck?} objects');
    return [];
  }
  const out: AcceptanceCriterion[] = [];
  input.forEach((entry, i) => {
    if (typeof entry === 'string' && entry.trim().length > 0) {
      out.push({ id: `AC-${i + 1}`, statement: entry.trim() });
      return;
    }
    if (!isRecord(entry) || typeof entry['statement'] !== 'string' || entry['statement'].trim().length === 0) {
      problems.push(`acceptanceCriteria[${i}]: must be a non-empty string or an object with a non-empty "statement"`);
      return;
    }
    const criterion: AcceptanceCriterion = {
      id: typeof entry['id'] === 'string' && entry['id'].length > 0 ? entry['id'] : `AC-${i + 1}`,
      statement: entry['statement'],
    };
    const mc = entry['machineCheck'];
    if (mc !== undefined) {
      if (
        !isRecord(mc) ||
        typeof mc['kind'] !== 'string' ||
        !(MACHINE_CHECK_KINDS as readonly string[]).includes(mc['kind']) ||
        !isRecord(mc['params'])
      ) {
        problems.push(
          `acceptanceCriteria[${i}].machineCheck: must be { kind: ${MACHINE_CHECK_KINDS.join('|')}, params: object }`,
        );
      } else {
        criterion.machineCheck = {
          kind: mc['kind'] as (typeof MACHINE_CHECK_KINDS)[number],
          params: mc['params'] as Record<string, unknown>,
        };
      }
    }
    out.push(criterion);
  });
  return out;
}

function requireNumber(v: unknown, path: string, problems: string[]): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) {
    problems.push(`${path}: must be a finite number`);
    return 0;
  }
  return v;
}

function requireString(v: unknown, path: string, problems: string[]): string {
  if (typeof v !== 'string' || v.trim().length === 0) {
    problems.push(`${path}: must be a non-empty string`);
    return '';
  }
  return v;
}

/** Wallet-native placeholders: the signing key is the protocol identity. */
const PLACEHOLDER_REQUESTER: PartyRef = { agentId: 'sandbox:requester' };
const PLACEHOLDER_WORKER: PartyRef = { agentId: 'sandbox:worker' };

function normalizeParty(v: unknown, fallback: PartyRef): PartyRef {
  if (isRecord(v) && typeof v['agentId'] === 'string' && v['agentId'].length > 0) {
    const p: PartyRef = { agentId: v['agentId'] };
    if (typeof v['principalKybRef'] === 'string' && v['principalKybRef'].length > 0) {
      p.principalKybRef = v['principalKybRef'];
    }
    if (typeof v['erc8004Ref'] === 'string') p.erc8004Ref = v['erc8004Ref'];
    const authority = v['authorityCredentialRef'];
    if (
      isRecord(authority) &&
      typeof authority['credentialId'] === 'string' &&
      typeof authority['sha256'] === 'string' &&
      typeof authority['issuer'] === 'string' &&
      typeof authority['revocationRegistry'] === 'string'
    ) {
      p.authorityCredentialRef = {
        credentialId: authority['credentialId'],
        sha256: authority['sha256'],
        issuer: authority['issuer'],
        revocationRegistry: authority['revocationRegistry'],
      };
    }
    return p;
  }
  return { ...fallback };
}

// ---------------------------------------------------------------------------
// edict_draft_mandate
// ---------------------------------------------------------------------------

export interface DraftMandateResult {
  mandate: OrderMandate;
  mandateHash: string;
  lint: LintReport;
  notes: string[];
}

/**
 * Build a complete OrderMandate from the bundled default ProtectionProfile's
 * defaults + the drafted terms, hash it canonically, and lint it.
 * Deterministic: the nonce derives from the drafted content, so the same
 * draft always yields the same mandateHash.
 */
export function draftMandate(args: Record<string, unknown>): DraftMandateResult {
  const problems: string[] = [];
  const description = requireString(args['description'], 'description', problems);
  const acceptanceCriteria = normalizeCriteria(args['acceptanceCriteria'], problems);
  const priceUsd = requireNumber(args['priceUsd'], 'priceUsd', problems);
  const deadlineUnixMs = requireNumber(args['deadlineUnixMs'], 'deadlineUnixMs', problems);
  if (typeof args['priceUsd'] === 'number' && (priceUsd <= 0 || priceUsd > 100_000)) {
    problems.push(`priceUsd: must be in (0, 100000] (tier C cap), got ${priceUsd}`);
  }

  const profile = defaultProfile();
  const d = profile.defaults;
  let decisionSpace: DecisionSpace = d.decisionSpace;
  if (args['decisionSpace'] !== undefined) {
    const errs = validateDecisionSpace(args['decisionSpace'], 'decisionSpace');
    if (errs.length > 0) problems.push(...errs);
    else decisionSpace = args['decisionSpace'] as DecisionSpace;
  }
  let legalProfile: LegalProfile = d.legalProfile;
  if (args['legalProfile'] !== undefined) {
    if (!isRecord(args['legalProfile'])) problems.push('legalProfile: must be an object (LegalProfile)');
    else legalProfile = args['legalProfile'] as unknown as LegalProfile;
  }
  if (legalProfile.enforcementTier !== 'E0') {
    problems.push('legalProfile.enforcementTier: this wallet-native draft tool supports E0; use an enterprise SDK profile for E1/E2/E3');
  }
  let maeEvents: string[] = d.maeEvents ?? [];
  if (args['maeEvents'] !== undefined) {
    if (!Array.isArray(args['maeEvents']) || args['maeEvents'].some((e) => typeof e !== 'string')) {
      problems.push('maeEvents: must be an array of strings');
    } else maeEvents = args['maeEvents'] as string[];
  }
  if (problems.length > 0) throw new ToolInputError(problems);

  const nonce = `draft-${sha256Canonical({ description, acceptanceCriteria, priceUsd, deadlineUnixMs }).slice(0, 16)}`;
  const mandate: OrderMandate = {
    version: 'edict-om-2',
    requester: { ...PLACEHOLDER_REQUESTER },
    worker: { ...PLACEHOLDER_WORKER },
    description,
    acceptanceCriteria,
    priceUsd,
    currency: { asset: 'USDC', rail: 'sdk-sandbox' },
    deadlineUnixMs,
    acceptanceWindowMs: d.acceptanceWindowMs,
    legalProfile: { ...legalProfile, ...(priceUsd < 10 ? { enforcementTier: 'E0' as const } : {}) },
    legalPolicy: structuredClone(profile.legalPolicy),
    decisionSpace: structuredClone(decisionSpace),
    settlement: {
      custodyMode: 'M2_external_escrow',
      fundsController: 'payment_rail',
      adapterRef: 'rail:sdk-sandbox',
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'controller_resolution',
    },
    maeEvents: [...maeEvents],
    nonce,
  };

  return {
    mandate,
    mandateHash: canonicalOrderMandateHash(mandate),
    lint: lintMandate(mandate),
    notes: [
      'requester/worker use wallet-native self-authority; no Edict KYB or delegated credential is required for this E0 draft.',
      'funds remain with the customer-hosted payment rail; Edict can publish a directive but cannot transfer them.',
      'defaults (decision space, E0 Legal Profile, Legal Policy and 24h acceptance window) come from the bundled sandbox profile.',
      'the nonce is derived from the drafted content, so an identical draft yields an identical mandateHash.',
    ],
  };
}

// ---------------------------------------------------------------------------
// edict_lint_mandate
// ---------------------------------------------------------------------------

export function lintMandateTool(args: Record<string, unknown>): { lint: LintReport } {
  if (!isRecord(args['mandate'])) throw new ToolInputError(['mandate: must be an OrderMandate object']);
  // lintMandate is tolerant by design (pre-commitment analysis): structural
  // problems come back as findings, not throws.
  return { lint: lintMandate(args['mandate'] as unknown as OrderMandate) };
}

// ---------------------------------------------------------------------------
// edict_sandbox_dispute
// ---------------------------------------------------------------------------

export interface SandboxDisputeResult {
  caseId: string;
  mandateHash: string;
  verdict: {
    ruling: VerdictObject['ruling'];
    final: boolean;
    quality: VerdictObject['quality'];
  };
  reasoning: { summary: string; document?: Record<string, unknown> };
  tribunalInstructions: TribunalInstructions;
  /** Escrow payout + bond math when the verdict was final; null when escalated. */
  settlement: EscrowSettlement | null;
  /** Why no settlement executed despite a final verdict or supported sandbox path. */
  settlementNote?: string;
  escalation?: { reason: string };
  /** Human escalation policy routing (review policy) under the sandbox profile. */
  disposition: EscalationDisposition;
  /** Present when the case is held for human review ('queued') — resolve with edict_resolve_review. */
  reviewState?: ReviewState;
  sandbox: {
    requesterAgentId: string;
    workerAgentId: string;
    requesterBalanceUsd: number;
    workerBalanceUsd: number;
    burnedTotalUsd: number;
  };
  notes: string[];
}

/**
 * Run a full protect → (deliver) → dispute → settle round through the
 * @edict/sdk sandbox: real arbiter pipeline, deterministic mock jury,
 * real escrow/bond settlement math. Never touches live rails.
 */
export async function sandboxDispute(
  args: Record<string, unknown>,
  session: SessionStore,
): Promise<SandboxDisputeResult> {
  const problems: string[] = [];
  const m = args['mandate'];
  if (!isRecord(m)) throw new ToolInputError(['mandate: must be an OrderMandate object']);
  const description = requireString(m['description'], 'mandate.description', problems);
  const acceptanceCriteria = normalizeCriteria(m['acceptanceCriteria'], problems);
  const priceUsd = requireNumber(m['priceUsd'], 'mandate.priceUsd', problems);
  const deadlineUnixMs = requireNumber(m['deadlineUnixMs'], 'mandate.deadlineUnixMs', problems);

  const submissionsRaw = args['submissions'];
  if (!isRecord(submissionsRaw)) problems.push('submissions: must be an object { requester?, worker? }');
  const submissions: { requester?: string; worker?: string } = {};
  if (isRecord(submissionsRaw)) {
    for (const side of ['requester', 'worker'] as const) {
      const v = submissionsRaw[side];
      if (v === undefined) continue;
      if (typeof v !== 'string') problems.push(`submissions.${side}: must be a string pleading`);
      else if (v.length > 0) submissions[side] = v;
    }
  }

  // Optional per-order overrides lifted from the provided mandate object.
  const overrides: NonNullable<ProtectOrderInput['overrides']> = {};
  const currency = m['currency'];
  if (isRecord(currency) && typeof currency['asset'] === 'string' && typeof currency['rail'] === 'string') {
    overrides.currency = { asset: currency['asset'], rail: currency['rail'] };
  }
  if (typeof m['acceptanceWindowMs'] === 'number') overrides.acceptanceWindowMs = m['acceptanceWindowMs'];
  if (m['legalProfile'] !== undefined) {
    if (!isRecord(m['legalProfile'])) problems.push('mandate.legalProfile: must be an object (LegalProfile)');
    else overrides.legalProfile = m['legalProfile'] as unknown as LegalProfile;
  }
  if (m['decisionSpace'] !== undefined) {
    const errs = validateDecisionSpace(m['decisionSpace'], 'mandate.decisionSpace');
    if (errs.length > 0) problems.push(...errs);
    else overrides.decisionSpace = m['decisionSpace'] as DecisionSpace;
  }
  if (Array.isArray(m['maeEvents']) && m['maeEvents'].every((e) => typeof e === 'string')) {
    overrides.maeEvents = m['maeEvents'] as string[];
  }
  if (typeof m['nonce'] === 'string' && m['nonce'].length > 0) overrides.nonce = m['nonce'];

  // Optional delivery manifest (worker's side of the record).
  const dm = args['deliveryManifest'];
  let deliverInput: { artifactHashes: Array<{ path: string; sha256: string; mediaType: string }>; formatClaims?: string[]; deliveredAtUnixMs?: number } | undefined;
  if (dm !== undefined) {
    if (!isRecord(dm)) {
      problems.push('deliveryManifest: must be an object { artifactHashes, formatClaims?, deliveredAtUnixMs? }');
    } else {
      const artifacts: Array<{ path: string; sha256: string; mediaType: string }> = [];
      const ah = dm['artifactHashes'];
      if (!Array.isArray(ah)) {
        problems.push('deliveryManifest.artifactHashes: must be an array of { path, sha256, mediaType? }');
      } else {
        ah.forEach((a, i) => {
          if (!isRecord(a) || typeof a['path'] !== 'string' || typeof a['sha256'] !== 'string' || !/^[0-9a-fA-F]{64}$/.test(a['sha256'])) {
            problems.push(`deliveryManifest.artifactHashes[${i}]: must be { path: string, sha256: 64-hex, mediaType? }`);
            return;
          }
          artifacts.push({
            path: a['path'],
            sha256: a['sha256'].toLowerCase(),
            mediaType: typeof a['mediaType'] === 'string' ? a['mediaType'] : 'application/octet-stream',
          });
        });
      }
      deliverInput = { artifactHashes: artifacts };
      if (Array.isArray(dm['formatClaims']) && dm['formatClaims'].every((f) => typeof f === 'string')) {
        deliverInput.formatClaims = dm['formatClaims'] as string[];
      }
      if (typeof dm['deliveredAtUnixMs'] === 'number') deliverInput.deliveredAtUnixMs = dm['deliveredAtUnixMs'];
    }
  }
  if (problems.length > 0) throw new ToolInputError(problems);

  const requester = normalizeParty(m['requester'], PLACEHOLDER_REQUESTER);
  const worker = normalizeParty(m['worker'], PLACEHOLDER_WORKER);

  // Sandbox client: lint gate wide open (this tool adjudicates, it does not
  // gate drafting — use edict_lint_mandate / edict_draft_mandate for that).
  const profile = defaultProfile();
  profile.lintGate = { minScore: 0, blockOnError: false };
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-mcp-'));
  const client = createEdict({ mode: 'sandbox', profile, archiveDir });

  // protect() auto-funds from the requester's sandbox balance; cover the
  // escrow amount plus dispute-bond headroom for either party.
  client.escrow.deposit(requester.agentId, priceUsd * 2);
  client.escrow.deposit(worker.agentId, priceUsd);

  const protect = await client.protect({
    requester,
    worker,
    description,
    acceptanceCriteria,
    priceUsd,
    deadlineUnixMs,
    ...(Object.keys(overrides).length > 0 ? { overrides } : {}),
  });
  if (deliverInput !== undefined) await client.deliver(protect, deliverInput);

  const verdict = await client.dispute(protect, { submissions });
  const record = client.getRecord(protect);
  const disposition = record.disposition!; // dispute() always computes it
  const reviewState = record.reviewState;

  let settlement: EscrowSettlement | null = null;
  let settlementNote: string | undefined;
  if (reviewState === 'queued') {
    // Held for human review (review policy): nothing settles until
    // edict_resolve_review produces the human-reviewed verdict.
    settlementNote =
      `held for human review (mode ${disposition.mode}` +
      `${disposition.trigger !== undefined ? `, trigger ${disposition.trigger}` : ''}) — ` +
      'call edict_resolve_review with this caseId, a ruling within the decision space, and a reviewerRef';
  } else if (isFinalVerdict(verdict)) {
    try {
      settlement = client.settle(verdict).settlement ?? null;
    } catch (e) {
      if (e instanceof UnsupportedRulingError || e instanceof ExecutableVerdictError || e instanceof PendingReviewError) {
        settlementNote = e.message;
      } else throw e;
    }
  }

  // Archived reasoning (written by the real arbiter during dispute()).
  // Containment-checked like every other file read in this server: the
  // caseId must be a safe path segment and the file must realpath-resolve
  // inside the sandbox archive dir.
  let reasoning: Record<string, unknown> | undefined;
  if (SLUG_RE.test(verdict.caseId)) {
    const parsed = readJsonContained(archiveDir, join(archiveDir, verdict.caseId, 'reasoning.json'));
    if (isRecord(parsed)) reasoning = parsed;
  }

  // Which tribunal-instruction blocks applied (recomputed deterministically).
  const rec = client.getRecord(protect);
  const plaintext: Record<string, string> = { [rec.mandateHash]: canonicalize(rec.mandate) };
  if (rec.manifest !== undefined && rec.manifestHash !== undefined) {
    plaintext[rec.manifestHash] = canonicalize(rec.manifest);
  }
  for (const text of [submissions.requester, submissions.worker]) {
    if (text !== undefined) plaintext[sha256Hex(text)] = text;
  }
  const caseObj = rec.caseObject!;
  const tribunalInstructions = tribunalInstructionsFor(caseObj, plaintext);
  const compact = reasoning !== undefined ? compactReasoning(reasoning) : undefined;

  const result: SandboxDisputeResult = {
    caseId: verdict.caseId,
    mandateHash: rec.mandateHash,
    verdict: { ruling: verdict.ruling, final: verdict.final, quality: verdict.quality },
    reasoning: { summary: summarizeVerdict(verdict, reasoning), ...(compact !== undefined ? { document: compact } : {}) },
    tribunalInstructions,
    settlement,
    ...(settlementNote !== undefined ? { settlementNote } : {}),
    ...(verdict.quality.escalated
      ? { escalation: { reason: verdict.quality.escalationReason ?? 'unspecified' } }
      : {}),
    disposition,
    ...(reviewState !== undefined ? { reviewState } : {}),
    sandbox: {
      requesterAgentId: requester.agentId,
      workerAgentId: worker.agentId,
      requesterBalanceUsd: client.escrow.balanceOf(requester.agentId),
      workerBalanceUsd: client.escrow.balanceOf(worker.agentId),
      burnedTotalUsd: client.escrow.burnedTotalUsd(),
    },
    notes: [
      'sandbox only: deterministic mock jury (3 disjoint-family seats), in-memory escrow, no live rails.',
      `sandbox balances started at ${priceUsd * 2} (requester) / ${priceUsd} (worker) USD to cover escrow + dispute bond.`,
      ...(reviewState === 'queued'
        ? ['case is HELD for human review — resolve with edict_resolve_review { caseRef, ruling, reviewerRef }.']
        : []),
    ],
  };

  session.set(verdict.caseId, {
    caseId: verdict.caseId,
    mandateHash: rec.mandateHash,
    caseObj,
    verdict,
    ...(compact !== undefined ? { reasoning: compact } : {}),
    tribunalInstructions,
    settlement,
    disposition,
    ...(reviewState !== undefined ? { reviewState } : {}),
    client, // kept alive for edict_resolve_review
  });
  return result;
}

// ---------------------------------------------------------------------------
// edict_resolve_review
// ---------------------------------------------------------------------------

export interface ResolveReviewResult {
  caseId: string;
  mandateHash: string;
  verdict: {
    ruling: VerdictObject['ruling'];
    final: boolean;
    quality: VerdictObject['quality'];
    humanReview: VerdictObject['humanReview'];
  };
  reviewState: ReviewState;
  disposition?: EscalationDisposition;
  /** Settlement math of the human-reviewed verdict (null only when it could not execute). */
  settlement: EscrowSettlement | null;
  settlementNote?: string;
  sandbox: {
    requesterAgentId: string;
    workerAgentId: string;
    requesterBalanceUsd: number;
    workerBalanceUsd: number;
    burnedTotalUsd: number;
  };
  notes: string[];
}

/**
 * Resolve a sandbox case held for human review (review policy): validates the
 * ruling against the case's PRE-COMMITTED decision space, produces the
 * human-reviewed final verdict via the real `EdictClient.resolveHumanReview`
 * (AI votes preserved, `humanReview` audit marker set), then settles it on
 * the run's escrow. Sandbox-scoped: only cases adjudicated by
 * `edict_sandbox_dispute` in THIS server session resolve here.
 */
export function resolveReview(args: Record<string, unknown>, session: SessionStore): ResolveReviewResult {
  const problems: string[] = [];
  const caseRef = requireString(args['caseRef'], 'caseRef', problems);
  const reviewerRef = requireString(args['reviewerRef'], 'reviewerRef', problems);
  if (!isRecord(args['ruling'])) problems.push('ruling: must be an outcome object within the case decision space');
  if (problems.length > 0) throw new ToolInputError(problems);

  let entry = session.get(caseRef);
  if (entry === undefined) {
    for (const candidate of session.values()) {
      if (candidate.mandateHash === caseRef) {
        entry = candidate;
        break;
      }
    }
  }
  if (entry === undefined || entry.client === undefined) {
    throw new ToolInputError([
      `caseRef: no sandbox case "${caseRef}" in this session — run edict_sandbox_dispute first (session cases reset on restart)`,
    ]);
  }
  const client = entry.client;

  let reviewed: VerdictObject;
  try {
    reviewed = client.resolveHumanReview(entry.mandateHash, {
      ruling: args['ruling'] as unknown as Outcome,
      reviewerRef,
    });
  } catch (e) {
    if (e instanceof ReviewOutcomeError) throw new ToolInputError(e.problems);
    if (e instanceof ProtectionStateError) throw new ToolInputError([`caseRef: ${e.message}`]);
    throw e;
  }

  let settlement: EscrowSettlement | null = null;
  let settlementNote: string | undefined;
  if (isFinalVerdict(reviewed)) {
    try {
      settlement = client.settle(reviewed).settlement ?? null;
    } catch (e) {
      if (e instanceof UnsupportedRulingError || e instanceof ExecutableVerdictError) settlementNote = e.message;
      else throw e;
    }
  }

  const rec = client.getRecord(entry.mandateHash);
  // Keep the session's view of the case current for edict_case_status /
  // edict_explain_ruling.
  entry.verdict = reviewed;
  entry.settlement = settlement;
  entry.reviewState = rec.reviewState;
  entry.disposition = rec.disposition;

  const requesterAgentId = rec.mandate.requester.agentId;
  const workerAgentId = rec.mandate.worker.agentId;
  return {
    caseId: entry.caseId,
    mandateHash: entry.mandateHash,
    verdict: {
      ruling: reviewed.ruling,
      final: reviewed.final,
      quality: reviewed.quality,
      humanReview: reviewed.humanReview,
    },
    reviewState: rec.reviewState ?? 'resolved',
    ...(rec.disposition !== undefined ? { disposition: rec.disposition } : {}),
    settlement,
    ...(settlementNote !== undefined ? { settlementNote } : {}),
    sandbox: {
      requesterAgentId,
      workerAgentId,
      requesterBalanceUsd: client.escrow.balanceOf(requesterAgentId),
      workerBalanceUsd: client.escrow.balanceOf(workerAgentId),
      burnedTotalUsd: client.escrow.burnedTotalUsd(),
    },
    notes: [
      'human-reviewed verdict: the AI jury record (votes, injection flags) is preserved for audit; humanReview marks the bench resolution.',
      'the superseded AI verdict remains non-executable forever — only this human-reviewed verdict settles.',
    ],
  };
}

function summarizeVerdict(verdict: VerdictObject, reasoning: Record<string, unknown> | undefined): string {
  const q = verdict.quality;
  let rulingText: string;
  try {
    rulingText = canonicalOutcome(verdict.ruling);
  } catch {
    rulingText = JSON.stringify(verdict.ruling);
  }
  const parts: string[] = [];
  const det = reasoning !== undefined && isRecord(reasoning['deterministic']) ? (reasoning['deterministic'] as Record<string, unknown>) : undefined;
  if (det !== undefined) {
    parts.push(`Deterministic short-circuit [${String(det['rule'])}] → ${rulingText}: ${String(det['detail'])}`);
  } else {
    parts.push(`Jury ruling (${q.majority}) → ${rulingText}; swap-flip rate ${q.swapFlipRate}.`);
  }
  const mc = reasoning !== undefined && isRecord(reasoning['machineChecks']) ? (reasoning['machineChecks'] as Record<string, unknown>) : undefined;
  if (mc !== undefined) {
    parts.push(`Machine checks: ${String(mc['passed'] ?? 0)} passed, ${String(mc['failed'] ?? 0)} failed, ${String(mc['skipped'] ?? 0)} skipped.`);
  }
  if (q.escalated) {
    parts.push(`ESCALATED (${q.escalationReason ?? 'unspecified'}): advisory ruling only — final=false, never settleable; route up a tier.`);
  } else {
    parts.push(verdict.final ? 'Verdict is final and executable.' : 'Verdict is not final.');
  }
  if (q.injectionFlags.length > 0) parts.push(`Injection flags: ${q.injectionFlags.join(', ')}.`);
  return parts.join(' ');
}
