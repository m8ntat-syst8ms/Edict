/**
 * POST /api/sandbox/run backend — drives the @edict/sdk sandbox
 * end-to-end: protect (lint gate + escrow funding) → optional deliver →
 * dispute (real @edict/arbiter jury over deterministic mock seats) →
 * settle when the verdict is final and escrow-executable.
 *
 * Input is either a shadow-docket case TEMPLATE (replayed through the SDK —
 * a reconstruction, not a byte-replay: the SDK recomputes hashes, so e.g.
 * forged-manifest templates lose their forgery) or the policy editor's
 * current mandate DRAFT plus optional evidence. Each run uses a fresh client
 * and a fresh in-memory escrow, so runs never interfere — EXCEPT that runs
 * whose disposition routes to human review (review policy) park their client in
 * the {@link ReviewQueueStore} so POST /api/sandbox/review can resolve them
 * later through the real `EdictClient.resolveHumanReview` + settle flow.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { AcceptanceCriterion, DecisionSpace, LegalProfile, Outcome, VerdictObject } from '@edict/core';
import { EVIDENCE_KINDS, EVIDENCE_SUBMITTERS, validateDecisionSpace } from '@edict/core';
import { canonicalize, sha256Hex, type ArtifactHash } from '@edict/evidence';
import {
  analyzeDeterministic,
  buildJudicialInstructions,
  renderJudicialInstructionsSection,
  verifyEvidenceCommitments,
} from '@edict/arbiter';
import {
  createEdict,
  defaultProfile,
  isFinalVerdict,
  profileHash as computeProfileHash,
  DEFAULT_DISPUTE_BOND_FRACTION,
  LintGateError,
  PendingReviewError,
  ProfileValidationError,
  ProtectionStateError,
  EvidenceMismatchError,
  ExecutableVerdictError,
  ReviewOutcomeError,
  UnsupportedRulingError,
  type DisputeInput,
  type EdictClient,
  type EscrowRecord,
  type ExtraEvidenceInput,
  type ProtectOrderInput,
  type ProtectionProfile,
  type ProtectResult,
} from '@edict/sdk';
import { loadTemplate, type CaseTemplate } from './docket.js';
import { completeDraft, type MandateDraft } from './lintDraft.js';
import type { ProfileStore } from './profiles.js';

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

export interface SandboxRunRequest {
  /** 'default' (or absent) → defaultProfile(); 'name@version' or {name,version} → saved profile. */
  profileRef?: unknown;
  /** Shadow-docket case slug or caseId. Mutually exclusive with mandateDraft. */
  caseTemplate?: unknown;
  /** The policy editor's current draft (same shape POST /api/lint accepts). */
  mandateDraft?: unknown;
  /** Draft-run evidence: submissions, an optional delivery, extra commitments. */
  evidence?: unknown;
  /** Which party opens the dispute (posts the bond). Default 'requester'. */
  by?: unknown;
}

export type SandboxRunOutcome =
  | { kind: 'ok'; body: Record<string, unknown> }
  | { kind: 'lint_blocked'; body: Record<string, unknown> }
  | { kind: 'not_found'; message: string }
  | { kind: 'bad_request'; message: string; problems?: string[] };

// ---------------------------------------------------------------------------
// Review queue (review policy): sandbox runs whose disposition routed to
// human_review keep their (in-memory) client alive so a later
// POST /api/sandbox/review can resolve them. Local single-user tool —
// bounded FIFO, evaporates on restart like every other sandbox artifact.
// ---------------------------------------------------------------------------

interface ReviewEntry {
  caseId: string;
  mandateHash: string;
  client: EdictClient;
  profile: { name: string; version: string; profileHash: string; ref: string };
  source: RunPlan['source'];
  createdAtUnixMs: number;
}

const REVIEW_QUEUE_CAP = 100;

/** In-memory queue of sandbox cases awaiting (or resolved by) human review. */
export class ReviewQueueStore {
  private readonly entries = new Map<string, ReviewEntry>(); // caseId -> entry

  add(entry: ReviewEntry): void {
    this.entries.set(entry.caseId, entry);
    while (this.entries.size > REVIEW_QUEUE_CAP) {
      const oldest = this.entries.keys().next().value as string;
      this.entries.delete(oldest);
    }
  }

  /** Resolve by caseId or mandateHash. */
  get(caseRef: string): ReviewEntry | undefined {
    const byId = this.entries.get(caseRef);
    if (byId !== undefined) return byId;
    for (const entry of this.entries.values()) {
      if (entry.mandateHash === caseRef) return entry;
    }
    return undefined;
  }

  /** Queue listing with LIVE review state read back off each client record. */
  list(): Array<Record<string, unknown>> {
    return [...this.entries.values()].map((entry) => {
      const rec = entry.client.getRecord(entry.mandateHash);
      return {
        caseId: entry.caseId,
        mandateHash: entry.mandateHash,
        profile: entry.profile,
        source: entry.source,
        tier: rec.caseObject?.tier,
        valueUsd: rec.caseObject?.valueUsd,
        decisionSpace: rec.caseObject?.decisionSpace,
        disposition: rec.disposition,
        reviewState: rec.reviewState,
        /** The AI verdict's (advisory or held-final) ruling + quality signals. */
        ruling: rec.verdict?.ruling,
        escalated: rec.verdict?.quality.escalated,
        ...(rec.verdict?.quality.escalationReason !== undefined
          ? { escalationReason: rec.verdict.quality.escalationReason }
          : {}),
        humanReview: rec.verdict?.humanReview ?? null,
        status: rec.status,
        createdAtUnixMs: entry.createdAtUnixMs,
      };
    });
  }
}

export interface ReviewResolveRequest {
  /** caseId (or mandateHash) of a queued/appealed sandbox case. */
  caseRef?: unknown;
  /** The reviewer's ruling — must lie within the case's decision space. */
  ruling?: unknown;
  /** Bench member / reviewer identity ref. */
  reviewerRef?: unknown;
}

/**
 * POST /api/sandbox/review backend: resolve a queued/appealed sandbox case
 * through `EdictClient.resolveHumanReview`, then settle the
 * human-reviewed verdict on the run's escrow.
 */
export function resolveSandboxReview(req: ReviewResolveRequest, reviews: ReviewQueueStore): SandboxRunOutcome {
  if (typeof req.caseRef !== 'string' || req.caseRef.length === 0) {
    return { kind: 'bad_request', message: 'caseRef must be a sandbox caseId (or mandateHash) from a queued run' };
  }
  if (!isRecord(req.ruling)) {
    return { kind: 'bad_request', message: 'ruling must be an outcome object within the case decision space' };
  }
  if (typeof req.reviewerRef !== 'string' || req.reviewerRef.length === 0) {
    return { kind: 'bad_request', message: 'reviewerRef must be a non-empty reviewer identity ref' };
  }
  const entry = reviews.get(req.caseRef);
  if (entry === undefined) {
    return { kind: 'not_found', message: `no sandbox case "${req.caseRef}" is awaiting review (runs reset on restart)` };
  }
  const { client, mandateHash } = entry;

  let reviewed;
  try {
    reviewed = client.resolveHumanReview(mandateHash, {
      ruling: req.ruling as unknown as Outcome,
      reviewerRef: req.reviewerRef,
    });
  } catch (e) {
    if (e instanceof ReviewOutcomeError) {
      return { kind: 'bad_request', message: 'ruling is outside the case decision space', problems: e.problems };
    }
    if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
    throw e;
  }

  // Settle the human-reviewed verdict (the attack-flag guard is satisfied by
  // the humanReview marker — no opt-outs).
  let escrow: EscrowRecord | undefined;
  let settlementNote: string | undefined;
  if (isFinalVerdict(reviewed)) {
    try {
      escrow = client.settle(reviewed);
    } catch (e) {
      if (e instanceof UnsupportedRulingError || e instanceof ExecutableVerdictError || e instanceof PendingReviewError) {
        settlementNote = e.message;
      } else throw e;
    }
  }

  const rec = client.getRecord(mandateHash);
  const requesterId = rec.mandate.requester.agentId;
  const workerId = rec.mandate.worker.agentId;
  return {
    kind: 'ok',
    body: {
      caseId: entry.caseId,
      mandateHash,
      profile: entry.profile,
      verdict: reviewed,
      disposition: rec.disposition,
      reviewState: rec.reviewState,
      settlement: escrow?.settlement ?? null,
      escrow: escrow ?? null,
      ...(settlementNote !== undefined ? { settlementNote } : {}),
      balances: {
        [requesterId]: client.escrow.balanceOf(requesterId),
        [workerId]: client.escrow.balanceOf(workerId),
      },
      burnedTotalUsd: client.escrow.burnedTotalUsd(),
    },
  };
}

interface RunPlan {
  source: { kind: 'template'; slug: string } | { kind: 'draft' };
  order: ProtectOrderInput;
  deliver?: { artifactHashes: ArtifactHash[]; formatClaims?: string[]; deliveredAtUnixMs?: number };
  dispute: DisputeInput;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Profile resolution
// ---------------------------------------------------------------------------

async function resolveProfile(
  ref: unknown,
  store: ProfileStore,
): Promise<{ profile: ProtectionProfile; label: string } | { error: 'not_found' | 'bad_ref'; message: string }> {
  if (ref === undefined || ref === null || ref === 'default' || ref === '') {
    return { profile: defaultProfile(), label: 'default' };
  }
  let name: string | undefined;
  let version: string | undefined;
  if (typeof ref === 'string' && ref.includes('@')) {
    const at = ref.lastIndexOf('@');
    name = ref.slice(0, at);
    version = ref.slice(at + 1);
  } else if (isRecord(ref) && typeof ref.name === 'string' && typeof ref.version === 'string') {
    name = ref.name;
    version = ref.version;
  }
  if (name === undefined || version === undefined || name.length === 0 || version.length === 0) {
    return { error: 'bad_ref', message: 'profileRef must be "default", "name@version", or { name, version }' };
  }
  const stored = await store.get(name, version);
  if (stored === undefined) return { error: 'not_found', message: `no saved profile ${name}@${version}` };
  return { profile: stored.profile, label: `${name}@${version}` };
}

// ---------------------------------------------------------------------------
// Plans: template / draft → SDK inputs
// ---------------------------------------------------------------------------

function templatePlan(template: CaseTemplate): RunPlan | { error: string } {
  const om = template.orderMandate;
  const c = template.caseObj;
  const priceUsd = typeof om.priceUsd === 'number' ? om.priceUsd : c.valueUsd;
  if (typeof om.description !== 'string' || !Array.isArray(om.acceptanceCriteria) || typeof om.deadlineUnixMs !== 'number') {
    return { error: `template ${template.slug}: evidence order mandate is missing description/acceptanceCriteria/deadlineUnixMs` };
  }
  // v0.1 evidence mandates carry permittedRulings; the canonical space lives on case.json.
  const decisionSpace: DecisionSpace =
    om.decisionSpace !== undefined && validateDecisionSpace(om.decisionSpace).length === 0
      ? (om.decisionSpace as DecisionSpace)
      : c.decisionSpace;
  const currency =
    isRecord(om.currency) && typeof om.currency.asset === 'string' && typeof om.currency.rail === 'string'
      ? { asset: om.currency.asset, rail: om.currency.rail }
      : undefined;
  const order: ProtectOrderInput = {
    requester: { ...c.requester },
    worker: { ...c.worker },
    description: om.description,
    acceptanceCriteria: om.acceptanceCriteria as AcceptanceCriterion[],
    priceUsd,
    deadlineUnixMs: om.deadlineUnixMs,
    overrides: {
      ...(currency !== undefined ? { currency } : {}),
      ...(typeof om.acceptanceWindowMs === 'number' ? { acceptanceWindowMs: om.acceptanceWindowMs } : {}),
      legalProfile: (isRecord(om.legalProfile) ? om.legalProfile : c.legalProfile) as LegalProfile,
      decisionSpace,
      maeEvents: Array.isArray(om.maeEvents) ? om.maeEvents.filter((e): e is string => typeof e === 'string') : [],
      ...(typeof om.nonce === 'string' ? { nonce: om.nonce } : {}),
    },
  };

  const plan: RunPlan = {
    source: { kind: 'template', slug: template.slug },
    order,
    dispute: {
      submissions: template.submissions,
      extraEvidence: template.extraEvidence,
      caseType: c.caseType,
      publicity: c.publicity,
      openedAtUnixMs: c.openedAtUnixMs,
    },
  };
  const m = template.deliveryManifest;
  if (m !== undefined && Array.isArray(m.artifactHashes)) {
    plan.deliver = {
      artifactHashes: m.artifactHashes as ArtifactHash[],
      ...(Array.isArray(m.formatClaims)
        ? { formatClaims: m.formatClaims.filter((f): f is string => typeof f === 'string') }
        : {}),
      ...(typeof m.deliveredAtUnixMs === 'number' ? { deliveredAtUnixMs: m.deliveredAtUnixMs } : {}),
    };
  }
  return plan;
}

function draftEvidence(evidence: unknown): {
  submissions: { requester?: string; worker?: string };
  deliver?: RunPlan['deliver'];
  extraEvidence: ExtraEvidenceInput[];
  problems: string[];
} {
  const problems: string[] = [];
  const out: ReturnType<typeof draftEvidence> = { submissions: {}, extraEvidence: [], problems };
  if (evidence === undefined) return out;
  if (!isRecord(evidence)) {
    problems.push('evidence: must be an object { submissions?, deliver?, extraEvidence? }');
    return out;
  }
  if (isRecord(evidence.submissions)) {
    if (typeof evidence.submissions.requester === 'string') out.submissions.requester = evidence.submissions.requester;
    if (typeof evidence.submissions.worker === 'string') out.submissions.worker = evidence.submissions.worker;
  }
  if (isRecord(evidence.deliver)) {
    const d = evidence.deliver;
    if (
      Array.isArray(d.artifactHashes) &&
      d.artifactHashes.every(
        (a): a is ArtifactHash =>
          isRecord(a) && typeof a.path === 'string' && typeof a.sha256 === 'string' && typeof a.mediaType === 'string',
      )
    ) {
      out.deliver = {
        artifactHashes: d.artifactHashes,
        ...(Array.isArray(d.formatClaims)
          ? { formatClaims: d.formatClaims.filter((f): f is string => typeof f === 'string') }
          : {}),
        ...(typeof d.deliveredAtUnixMs === 'number' ? { deliveredAtUnixMs: d.deliveredAtUnixMs } : {}),
      };
    } else {
      problems.push('evidence.deliver.artifactHashes: must be [{ path, sha256, mediaType }]');
    }
  }
  if (Array.isArray(evidence.extraEvidence)) {
    for (const [i, e] of evidence.extraEvidence.entries()) {
      if (
        isRecord(e) &&
        typeof e.kind === 'string' &&
        (EVIDENCE_KINDS as readonly string[]).includes(e.kind) &&
        typeof e.plaintext === 'string' &&
        typeof e.submitter === 'string' &&
        (EVIDENCE_SUBMITTERS as readonly string[]).includes(e.submitter)
      ) {
        out.extraEvidence.push({
          kind: e.kind as ExtraEvidenceInput['kind'],
          plaintext: e.plaintext,
          submitter: e.submitter as ExtraEvidenceInput['submitter'],
          ...(typeof e.authenticated === 'boolean' ? { authenticated: e.authenticated } : {}),
          ...(typeof e.uri === 'string' ? { uri: e.uri } : {}),
        });
      } else {
        problems.push(`evidence.extraEvidence[${i}]: needs { kind (EvidenceKind), plaintext, submitter }`);
      }
    }
  }
  return out;
}

function draftPlan(mandateDraft: MandateDraft, evidence: unknown): RunPlan | { error: string; problems?: string[] } {
  const { mandate } = completeDraft(mandateDraft);
  const ev = draftEvidence(evidence);
  if (ev.problems.length > 0) return { error: 'invalid evidence', problems: ev.problems };
  const plan: RunPlan = {
    source: { kind: 'draft' },
    order: {
      requester: { ...mandate.requester },
      worker: { ...mandate.worker },
      description: mandate.description,
      acceptanceCriteria: mandate.acceptanceCriteria,
      priceUsd: mandate.priceUsd,
      deadlineUnixMs: mandate.deadlineUnixMs,
      overrides: {
        currency: mandate.currency,
        acceptanceWindowMs: mandate.acceptanceWindowMs,
        legalProfile: mandate.legalProfile,
        decisionSpace: mandate.decisionSpace,
        maeEvents: mandate.maeEvents,
        nonce: mandate.nonce,
      },
    },
    dispute: { submissions: ev.submissions, extraEvidence: ev.extraEvidence },
  };
  if (ev.deliver !== undefined) plan.deliver = ev.deliver;
  return plan;
}

// ---------------------------------------------------------------------------
// Frames: rebuild the sealed plaintext and recompute the instruction section
// ---------------------------------------------------------------------------

function instructionFrames(client: EdictClient, protect: ProtectResult, plan: RunPlan): Record<string, unknown> | undefined {
  try {
    const rec = client.getRecord(protect.mandateHash);
    if (rec.caseObject === undefined) return undefined;
    const plaintext: Record<string, string> = { [rec.mandateHash]: canonicalize(rec.mandate) };
    if (rec.manifest !== undefined && rec.manifestHash !== undefined) {
      plaintext[rec.manifestHash] = canonicalize(rec.manifest);
    }
    for (const text of [plan.dispute.submissions.requester, plan.dispute.submissions.worker]) {
      if (typeof text === 'string' && text.length > 0) plaintext[sha256Hex(text)] = text;
    }
    for (const extra of plan.dispute.extraEvidence ?? []) {
      plaintext[sha256Hex(extra.plaintext)] = extra.plaintext;
    }
    const verified = verifyEvidenceCommitments(rec.caseObject, plaintext);
    const analysis = analyzeDeterministic(rec.caseObject, verified);
    const judicial = buildJudicialInstructions(rec.caseObject, analysis.parsedMandate, analysis.report, rec.caseObject.evidence);
    return {
      instructionBlocks: judicial.blocks,
      rendered: renderJudicialInstructionsSection(judicial.blocks),
    };
  } catch {
    return undefined; // frames are best-effort decoration
  }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export async function runSandbox(
  req: SandboxRunRequest,
  deps: { profiles: ProfileStore; docketDir: string; archiveRoot: string; reviews?: ReviewQueueStore },
): Promise<SandboxRunOutcome> {
  const resolved = await resolveProfile(req.profileRef, deps.profiles);
  if ('error' in resolved) {
    return resolved.error === 'not_found'
      ? { kind: 'not_found', message: resolved.message }
      : { kind: 'bad_request', message: resolved.message };
  }

  // --- build the plan ---------------------------------------------------------
  let plan: RunPlan;
  if (req.caseTemplate !== undefined) {
    if (typeof req.caseTemplate !== 'string' || req.caseTemplate.length === 0) {
      return { kind: 'bad_request', message: 'caseTemplate must be a docket case slug or caseId' };
    }
    const template = await loadTemplate(deps.docketDir, req.caseTemplate);
    if (template === undefined) {
      return { kind: 'not_found', message: `no shadow-docket case template "${req.caseTemplate}"` };
    }
    const built = templatePlan(template);
    if ('error' in built) return { kind: 'bad_request', message: built.error };
    plan = built;
  } else if (req.mandateDraft !== undefined) {
    if (!isRecord(req.mandateDraft)) {
      return { kind: 'bad_request', message: 'mandateDraft must be an object (the editor draft)' };
    }
    const built = draftPlan(req.mandateDraft, req.evidence);
    if ('error' in built) {
      return { kind: 'bad_request', message: built.error, ...(built.problems ? { problems: built.problems } : {}) };
    }
    plan = built;
  } else {
    return { kind: 'bad_request', message: 'body needs either caseTemplate or mandateDraft' };
  }
  const by: 'requester' | 'worker' = req.by === 'worker' ? 'worker' : 'requester';
  plan.dispute.by = by;

  // --- fresh client + funded balances ------------------------------------------
  const archiveDir = join(deps.archiveRoot, randomUUID());
  let client: EdictClient;
  try {
    client = createEdict({ mode: 'sandbox', profile: resolved.profile, archiveDir });
  } catch (e) {
    if (e instanceof ProfileValidationError) return { kind: 'bad_request', message: e.message, problems: e.problems };
    throw e;
  }
  const requesterId = plan.order.requester.agentId;
  const workerId = plan.order.worker.agentId;
  const bondUsd = plan.order.priceUsd * DEFAULT_DISPUTE_BOND_FRACTION;
  client.escrow.deposit(requesterId, plan.order.priceUsd + bondUsd);
  client.escrow.deposit(workerId, bondUsd);

  // --- protect (lint gate) ------------------------------------------------------
  let protect: ProtectResult;
  try {
    protect = await client.protect(plan.order);
  } catch (e) {
    if (e instanceof LintGateError) {
      return {
        kind: 'lint_blocked',
        body: { lintBlocked: true, reasons: e.reasons, report: e.report, source: plan.source },
      };
    }
    if (e instanceof RangeError) return { kind: 'bad_request', message: e.message };
    throw e;
  }

  // --- deliver / dispute ----------------------------------------------------------
  try {
    if (plan.deliver !== undefined) await client.deliver(protect, plan.deliver);
    const verdict: VerdictObject = await client.dispute(protect, plan.dispute);
    const record = client.getRecord(protect.mandateHash);
    const disposition = record.disposition;
    const reviewState = record.reviewState;

    // --- settle (final + escrow-executable rulings only) -------------------------
    let escrow: EscrowRecord | undefined;
    let settlementNote: string | undefined;
    if (reviewState === 'queued') {
      settlementNote =
        `held for human review (${disposition?.mode ?? 'policy'}` +
        `${disposition?.trigger !== undefined ? `, trigger ${disposition.trigger}` : ''}) — ` +
        'resolve it in the Review queue (POST /api/sandbox/review) to settle';
    } else if (isFinalVerdict(verdict)) {
      try {
        escrow = client.settle(verdict);
      } catch (e) {
        if (e instanceof UnsupportedRulingError || e instanceof ExecutableVerdictError || e instanceof PendingReviewError) {
          settlementNote = e.message;
        } else throw e;
      }
    } else {
      settlementNote =
        `verdict escalated (final=false) — never executable; disposition '${disposition?.route ?? 'unknown'}'` +
        (disposition?.route === 'programmatic_fallback'
          ? ': the advisory ruling is a recommendation for the pre-committed fallback policy'
          : '');
    }

    // Cases routed to human review stay resolvable across requests.
    if (deps.reviews !== undefined && reviewState === 'queued') {
      deps.reviews.add({
        caseId: verdict.caseId,
        mandateHash: protect.mandateHash,
        client,
        profile: {
          name: resolved.profile.name,
          version: resolved.profile.version,
          profileHash: computeProfileHash(resolved.profile),
          ref: resolved.label,
        },
        source: plan.source,
        createdAtUnixMs: Date.now(),
      });
    }

    // --- archived reasoning document ---------------------------------------------
    let reasoning: unknown;
    try {
      const caseId = client.getRecord(protect.mandateHash).caseObject?.caseId;
      if (caseId !== undefined) {
        reasoning = JSON.parse(await readFile(join(archiveDir, caseId, 'reasoning.json'), 'utf8'));
      }
    } catch {
      reasoning = undefined;
    }

    const frames = instructionFrames(client, protect, plan);
    const body: Record<string, unknown> = {
      profile: {
        name: resolved.profile.name,
        version: resolved.profile.version,
        profileHash: computeProfileHash(resolved.profile),
        ref: resolved.label,
      },
      source: plan.source,
      mandateHash: protect.mandateHash,
      lint: protect.lint,
      verdict,
      escalated: !verdict.final,
      ...(verdict.quality.escalationReason !== undefined ? { escalationReason: verdict.quality.escalationReason } : {}),
      // Human escalation policy routing (review policy).
      disposition: disposition ?? null,
      ...(reviewState !== undefined ? { reviewState } : {}),
      reasoning,
      ...(frames !== undefined ? { frames } : {}),
      settlement: escrow?.settlement ?? null,
      escrow: escrow ?? null,
      ...(settlementNote !== undefined ? { settlementNote } : {}),
      deposits: { [requesterId]: plan.order.priceUsd + bondUsd, [workerId]: bondUsd },
      balances: {
        [requesterId]: client.escrow.balanceOf(requesterId),
        [workerId]: client.escrow.balanceOf(workerId),
      },
      burnedTotalUsd: client.escrow.burnedTotalUsd(),
    };
    return { kind: 'ok', body };
  } catch (e) {
    if (e instanceof EvidenceMismatchError) {
      return { kind: 'bad_request', message: e.message, problems: e.problems };
    }
    throw e;
  }
}
