/**
 * The protect-app workspace: sandbox transactions and hash-committed
 * protection policies over the @edict/sdk.
 *
 * Every "transaction" is a real sandbox protection: its own EdictClient
 * (fresh in-memory escrow), the elected policy applied, funds locked at
 * protect() time, the real arbiter pipeline on dispute(), the real
 * human-review resolution flow. NOTHING here is a mock of Edict — only the
 * money and the counterparty are simulated.
 *
 * Every user-facing string leaving this module passes through the shared
 * @edict/sdk terminology module (canonical user-facing terminology).
 * Protocol vocabulary appears ONLY in the audit bundle.
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { EscalationTrigger, Outcome } from '@edict/core';
import { sha256Hex } from '@edict/evidence';
import {
  DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD,
  LintGateError,
  PRESETS,
  PendingReviewError,
  ProtectionStateError,
  ReviewOutcomeError,
  UnsupportedRulingError,
  ExecutableVerdictError,
  createEdict,
  isFinalVerdict,
  lifecycleState,
  plainOutcome,
  presetByKey,
  profileHash,
  statusColor,
  validateProfile,
  type EdictClient,
  type EscrowSettlement,
  type LifecycleState,
  type PresetKey,
  type ProtectionProfile,
  type ProtectionRecord,
} from '@edict/sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TxEvent {
  atUnixMs: number;
  /** Lifecycle rail state this event moved the transaction to (or stayed in). */
  state: LifecycleState;
  label: string;
  detail?: string;
}

interface TxEntry {
  /** Public transaction id = the mandate content hash. */
  id: string;
  title: string;
  counterparty: string;
  amountUsd: number;
  presetKey: PresetKey | 'custom';
  policy: { name: string; version: string; hash: string; title: string };
  client: EdictClient;
  archiveDir: string;
  /** Pinned content of the expected deliverable (drives the demo delivery outcomes). */
  expectedArtifact: { path: string; content: string; sha256: string };
  createdAtUnixMs: number;
  disputedAtUnixMs?: number;
  settledAtUnixMs?: number;
  disputeReason?: string;
  disputedBy?: 'requester' | 'worker';
  submissions?: { requester?: string; worker?: string };
  settlement?: EscrowSettlement;
  settlementError?: string;
  events: TxEvent[];
}

export interface CreateTxInput {
  preset?: unknown;
  policyRef?: unknown;
  title?: unknown;
  description?: unknown;
  amountUsd?: unknown;
  counterparty?: unknown;
  deadlineUnixMs?: unknown;
  criteria?: unknown;
}

export type StoreOutcome =
  | { kind: 'ok'; body: Record<string, unknown> }
  | { kind: 'blocked'; body: Record<string, unknown> }
  | { kind: 'not_found'; message: string }
  | { kind: 'bad_request'; message: string; problems?: string[] };

const BUYER = { agentId: 'you:buyer-agent' };

// ---------------------------------------------------------------------------
// Plain-English helpers (server-side rendering of internal vocabulary)
// ---------------------------------------------------------------------------

/** product interface — the human-review toggle's four plainly-worded options. */
export function humanReviewCopy(profile: ProtectionProfile): string {
  const he = profile.humanEscalation;
  const threshold = he?.thresholdUsd ?? DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD;
  switch (he?.mode) {
    case 'off':
      return 'Off — the automated decision is final when quality gates pass.';
    case 'optional_appeal':
      return 'Optional appeal — either party may request human review before the decision settles.';
    case 'required_above_value':
      return `Required for high value — decisions at or above $${threshold.toLocaleString('en-US')} always get human review.`;
    case 'quality_gate':
      return 'Automatic safety valve — human review starts automatically when Edict cannot issue a final decision.';
    default:
      return 'Default — human review is available automatically on higher-value transactions when a decision needs it.';
  }
}

function reviewTypeCopy(profile: ProtectionProfile): string {
  return profile.juryPolicy.requireProofs === true
    ? 'Automated checks first, then a verified AI review panel (only verified votes count)'
    : 'Automated checks first, then an AI review panel';
}

function assuranceCopy(profile: ProtectionProfile): string {
  switch (profile.legalPolicy.assuranceMode) {
    case 'wallet_native':
      return 'Wallet-native — signing keys identify the parties; no Edict KYB required';
    case 'rail_verified':
      return 'Rail-verified — Edict relies on your payment rail’s authenticated party references';
    case 'enterprise_legal':
      return 'Enterprise legal — verified principals and delegated agent authority';
  }
}

const TRIGGER_COPY: Record<EscalationTrigger, string> = {
  no_majority: 'The review panel could not agree on an outcome',
  insufficient_attested_seats: 'Not enough review-panel votes passed verification',
  swap_inconsistency: 'The review panel changed its answer when the sides were swapped',
  low_confidence: 'The review panel was not confident enough to decide',
  injection_attack: 'A submission tried to manipulate the review',
  out_of_policy_evidence: 'Part of the evidence record failed verification',
  party_appeal: 'A party asked for human review',
};

function confidenceCopy(rec: ProtectionRecord): 'High' | 'Medium' | 'Low' {
  const q = rec.verdict?.quality;
  if (q === undefined || q.escalated) return 'Low';
  if (q.majority === 'unanimous' && q.swapFlipRate === 0) return 'High';
  return 'Medium';
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}
function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined;
}
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ---------------------------------------------------------------------------
// Policy store — hash-committed, immutable versions (console ProfileStore
// semantics: identical re-save is idempotent, different content conflicts)
// ---------------------------------------------------------------------------

export interface StoredPolicy {
  name: string;
  version: string;
  profileHash: string;
  savedAtUnixMs: number;
  /** UX metadata: which preset the builder started from. */
  basePreset?: string;
  profile: ProtectionProfile;
}

export type PolicySaveResult =
  | { status: 'created'; stored: StoredPolicy }
  | { status: 'unchanged'; stored: StoredPolicy }
  | { status: 'conflict'; name: string; version: string; existingHash: string; incomingHash: string }
  | { status: 'invalid'; problems: string[] };

export class PolicyStore {
  private readonly policies = new Map<string, StoredPolicy>(); // `${name}@${version}`

  save(candidate: unknown, basePreset?: string): PolicySaveResult {
    const problems = validateProfile(candidate);
    if (problems.length > 0) return { status: 'invalid', problems };
    const profile = candidate as ProtectionProfile;
    const key = `${profile.name}@${profile.version}`;
    const incomingHash = profileHash(profile);
    const existing = this.policies.get(key);
    if (existing !== undefined) {
      if (existing.profileHash === incomingHash) return { status: 'unchanged', stored: existing };
      return {
        status: 'conflict',
        name: profile.name,
        version: profile.version,
        existingHash: existing.profileHash,
        incomingHash,
      };
    }
    const stored: StoredPolicy = {
      name: profile.name,
      version: profile.version,
      profileHash: incomingHash,
      savedAtUnixMs: Date.now(),
      ...(basePreset !== undefined ? { basePreset } : {}),
      profile,
    };
    this.policies.set(key, stored);
    return { status: 'created', stored };
  }

  get(ref: string): StoredPolicy | undefined {
    return this.policies.get(ref);
  }

  list(): StoredPolicy[] {
    return [...this.policies.values()];
  }
}

// ---------------------------------------------------------------------------
// Transaction store
// ---------------------------------------------------------------------------

export class TransactionStore {
  private readonly txs = new Map<string, TxEntry>();
  private readonly archiveRoot: string;
  readonly policies = new PolicyStore();

  constructor(archiveRoot: string) {
    this.archiveRoot = archiveRoot;
  }

  // --- create (guided "Create test transaction") ------------------------------

  async create(input: CreateTxInput): Promise<StoreOutcome> {
    const amountUsd = num(input.amountUsd);
    if (amountUsd === undefined || amountUsd <= 0 || amountUsd > 100_000) {
      return { kind: 'bad_request', message: 'Amount must be a number between $0 and $100,000.' };
    }
    const resolved = this.resolvePolicy(input.preset, input.policyRef);
    if ('error' in resolved) return { kind: 'bad_request', message: resolved.error };

    const title = str(input.title) ?? 'Test transaction';
    const counterparty = str(input.counterparty) ?? 'worker:sandbox-agent';
    const deadlineUnixMs = num(input.deadlineUnixMs) ?? Date.now() + 7 * 86_400_000;
    const artifactPath = 'deliverable.bin';
    const artifactContent = `deliverable for "${title}" (${randomUUID()})`;
    const artifactSha = sha256Hex(artifactContent);

    const extraCriteria = Array.isArray(input.criteria)
      ? input.criteria.filter((c): c is string => typeof c === 'string' && c.trim().length > 0)
      : [];
    const description =
      str(input.description) ??
      `${title}: the worker delivers ${artifactPath}, byte-identical to the agreed reference committed in these terms, before the deadline.`;

    const archiveDir = join(this.archiveRoot, randomUUID());
    const client = createEdict({ mode: 'sandbox', profile: resolved.profile, archiveDir });
    // Sandbox funding: buyer covers the amount + dispute-bond headroom for
    // either side (this is test money — the sandbox banner says so).
    client.escrow.deposit(BUYER.agentId, amountUsd * 2);
    client.escrow.deposit(counterparty, amountUsd);

    let protect;
    try {
      protect = await client.protectPayment({
        paymentId: randomUUID(),
        requester: BUYER.agentId,
        worker: counterparty,
        promise: description,
        acceptanceCriteria: [
          {
            id: 'AC-1',
            statement: `${artifactPath} is byte-identical to the agreed reference (pinned checksum).`,
            machineCheck: { kind: 'hash_equals', params: { path: artifactPath, sha256: artifactSha } },
          },
          ...extraCriteria.map((statement, i) => ({ id: `AC-${i + 2}`, statement })),
        ],
        amountUsd,
        deadlineUnixMs,
      });
    } catch (e) {
      if (e instanceof LintGateError) {
        return {
          kind: 'blocked',
          body: {
            blocked: true,
            message:
              'The policy blocked this transaction: the terms are not specific enough to protect yet. ' +
              'Add clearer acceptance criteria or lower the policy strictness.',
            reasons: e.reasons,
          },
        };
      }
      if (e instanceof RangeError) return { kind: 'bad_request', message: e.message };
      throw e;
    }

    const entry: TxEntry = {
      id: protect.mandateHash,
      title,
      counterparty,
      amountUsd,
      presetKey: resolved.presetKey,
      policy: resolved.policy,
      client,
      archiveDir,
      expectedArtifact: { path: artifactPath, content: artifactContent, sha256: artifactSha },
      createdAtUnixMs: Date.now(),
      events: [
        {
          atUnixMs: Date.now(),
          state: 'Protected',
          label: 'Transaction protected',
          detail: `$${amountUsd.toLocaleString('en-US')} locked under the "${resolved.policy.title}" policy`,
        },
      ],
    };
    this.txs.set(entry.id, entry);
    return { kind: 'ok', body: this.row(entry) };
  }

  private resolvePolicy(
    preset: unknown,
    policyRef: unknown,
  ):
    | { profile: ProtectionProfile; presetKey: PresetKey | 'custom'; policy: TxEntry['policy'] }
    | { error: string } {
    if (typeof policyRef === 'string' && policyRef.length > 0) {
      const stored = this.policies.get(policyRef);
      if (stored === undefined) return { error: `No saved policy "${policyRef}".` };
      return {
        profile: stored.profile,
        presetKey: 'custom',
        policy: { name: stored.name, version: stored.version, hash: stored.profileHash, title: stored.name },
      };
    }
    const key = typeof preset === 'string' && preset.length > 0 ? preset : 'standard';
    const def = presetByKey(key);
    if (def === undefined) return { error: `Unknown preset "${key}" — pick basic, standard or high_assurance.` };
    return {
      profile: def.profile,
      presetKey: def.key,
      policy: { name: def.profile.name, version: def.profile.version, hash: def.profileHash, title: def.title },
    };
  }

  // --- lifecycle actions -----------------------------------------------------

  async deliver(id: string, quality: unknown): Promise<StoreOutcome> {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    if (quality !== 'as_agreed' && quality !== 'incomplete') {
      return { kind: 'bad_request', message: 'Delivery quality must be "as_agreed" or "incomplete".' };
    }
    const asAgreed = quality !== 'incomplete';
    const sha256 = asAgreed ? tx.expectedArtifact.sha256 : sha256Hex(`${tx.expectedArtifact.content} [truncated]`);
    try {
      await tx.client.deliver(tx.id, {
        artifactHashes: [{ path: tx.expectedArtifact.path, sha256, mediaType: 'application/octet-stream' }],
        formatClaims: asAgreed ? ['matches agreed reference'] : [],
      });
    } catch (e) {
      if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
      throw e;
    }
    tx.events.push({
      atUnixMs: Date.now(),
      state: 'Delivered',
      label: 'Work delivered',
      detail: asAgreed
        ? 'The delivered file matches the agreed reference'
        : 'The delivered file does NOT match the agreed reference (simulated incomplete work)',
    });
    return { kind: 'ok', body: this.row(tx) };
  }

  async accept(id: string): Promise<StoreOutcome> {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    try {
      await tx.client.accept(tx.id);
    } catch (e) {
      if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
      throw e;
    }
    tx.events.push({
      atUnixMs: Date.now(),
      state: 'Accepted',
      label: 'Delivery accepted',
      detail: `$${tx.amountUsd.toLocaleString('en-US')} released to ${tx.counterparty}`,
    });
    return { kind: 'ok', body: this.row(tx) };
  }

  async dispute(
    id: string,
    input: { reason?: unknown; buyerStatement?: unknown; workerStatement?: unknown; by?: unknown },
  ): Promise<StoreOutcome> {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const reason = str(input.reason) ?? 'Delivered work does not match the agreed terms';
    const by: 'requester' | 'worker' = input.by === 'worker' ? 'worker' : 'requester';
    const submissions: { requester?: string; worker?: string } = {};
    const buyer = str(input.buyerStatement);
    const worker = str(input.workerStatement);
    if (buyer !== undefined) submissions.requester = buyer;
    if (worker !== undefined) submissions.worker = worker;
    try {
      await tx.client.dispute(tx.id, { submissions, by });
    } catch (e) {
      if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
      throw e;
    }
    tx.disputeReason = reason;
    tx.disputedBy = by;
    tx.submissions = submissions;
    tx.disputedAtUnixMs = Date.now();
    const rec = tx.client.getRecord(tx.id);
    tx.events.push({ atUnixMs: Date.now(), state: 'Disputed', label: 'Dispute raised', detail: reason });
    const state = lifecycleState(rec);
    if (state === 'Under Review') {
      tx.events.push({
        atUnixMs: Date.now(),
        state,
        label: 'Human review started',
        detail: this.reviewReason(rec),
      });
    } else if (state === 'Escalated') {
      tx.events.push({
        atUnixMs: Date.now(),
        state,
        label: 'Escalated',
        detail: 'Edict could not issue a final decision and no human review is enabled on this policy',
      });
    } else if (rec.verdict !== undefined) {
      tx.events.push({
        atUnixMs: Date.now(),
        state: 'Decided',
        label: 'Decision issued',
        detail: plainOutcome(rec.verdict.ruling, rec.caseObject?.caseType),
      });
    }
    return { kind: 'ok', body: await this.disputeDetail(tx) };
  }

  settle(id: string): StoreOutcome {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const rec = tx.client.getRecord(tx.id);
    const verdict = rec.verdict;
    if (verdict === undefined || !isFinalVerdict(verdict)) {
      return { kind: 'bad_request', message: 'No final decision to settle yet.' };
    }
    try {
      const escrow = tx.client.settle(verdict);
      tx.settlement = escrow.settlement;
      delete tx.settlementError;
      tx.settledAtUnixMs = Date.now();
      tx.events.push({
        atUnixMs: Date.now(),
        state: 'Settled',
        label: 'Rail settlement simulated',
        detail: plainOutcome(verdict.ruling, rec.caseObject?.caseType),
      });
      return { kind: 'ok', body: this.row(tx) };
    } catch (e) {
      if (e instanceof PendingReviewError) {
        return { kind: 'bad_request', message: 'This decision is waiting for human review — it cannot settle yet.' };
      }
      if (
        e instanceof ProtectionStateError ||
        e instanceof UnsupportedRulingError ||
        e instanceof ExecutableVerdictError
      ) {
        return { kind: 'bad_request', message: e.message };
      }
      throw e;
    }
  }

  async appeal(id: string, by: unknown): Promise<StoreOutcome> {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const party: 'requester' | 'worker' = by === 'worker' ? 'worker' : 'requester';
    try {
      await tx.client.appeal(tx.id, party);
    } catch (e) {
      if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
      throw e;
    }
    tx.events.push({
      atUnixMs: Date.now(),
      state: 'Under Review',
      label: 'Appeal filed',
      detail: `${party === 'requester' ? 'Buyer' : 'Worker'} requested human review of the decision`,
    });
    return { kind: 'ok', body: await this.disputeDetail(tx) };
  }

  resolveReview(id: string, input: { outcome?: unknown; reviewerRef?: unknown }): StoreOutcome {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const reviewerRef = str(input.reviewerRef);
    if (reviewerRef === undefined) return { kind: 'bad_request', message: 'A reviewer name/reference is required.' };
    if (!isRecord(input.outcome)) {
      return { kind: 'bad_request', message: 'Pick one of the possible outcomes for this dispute.' };
    }
    let reviewed;
    try {
      reviewed = tx.client.resolveHumanReview(tx.id, { ruling: input.outcome as unknown as Outcome, reviewerRef });
    } catch (e) {
      if (e instanceof ReviewOutcomeError) {
        return {
          kind: 'bad_request',
          message: 'That outcome is not among the possible outcomes agreed for this transaction.',
          problems: e.problems,
        };
      }
      if (e instanceof ProtectionStateError) return { kind: 'bad_request', message: e.message };
      throw e;
    }
    const rec = tx.client.getRecord(tx.id);
    tx.events.push({
      atUnixMs: Date.now(),
      state: 'Decided',
      label: 'Human review decided',
      detail: `${plainOutcome(reviewed.ruling, rec.caseObject?.caseType)} (reviewed by ${reviewerRef})`,
    });
    // Settle the reviewed decision immediately (mirrors the SDK review flow).
    if (isFinalVerdict(reviewed)) {
      try {
        const escrow = tx.client.settle(reviewed);
        tx.settlement = escrow.settlement;
        delete tx.settlementError;
        tx.settledAtUnixMs = Date.now();
        tx.events.push({
          atUnixMs: Date.now(),
          state: 'Settled',
          label: 'Rail settlement simulated',
          detail: plainOutcome(reviewed.ruling, rec.caseObject?.caseType),
        });
      } catch (e) {
        if (
          e instanceof UnsupportedRulingError ||
          e instanceof ExecutableVerdictError ||
          e instanceof ProtectionStateError
        ) {
          tx.settlementError = e.message;
          tx.events.push({
            atUnixMs: Date.now(),
            state: 'Decided',
            label: 'Settlement held',
            detail: e.message,
          });
        } else throw e;
      }
    }
    return { kind: 'ok', body: this.row(tx) };
  }

  // --- readers -----------------------------------------------------------------

  /** One table row (product interface): Transaction | Amount | Status | Counterparty | Protection | Deadline | Action. */
  private row(tx: TxEntry): Record<string, unknown> {
    const rec = tx.client.getRecord(tx.id);
    const state = lifecycleState(rec);
    return {
      id: tx.id,
      title: tx.title,
      amountUsd: tx.amountUsd,
      state,
      stateColor: statusColor(state),
      counterparty: tx.counterparty,
      protection: tx.policy.title,
      deadline: this.deadlineFor(tx, rec, state),
      actions: this.actionsFor(rec, state),
      createdAtUnixMs: tx.createdAtUnixMs,
    };
  }

  private deadlineFor(
    tx: TxEntry,
    rec: ProtectionRecord,
    state: LifecycleState,
  ): { label: string; atUnixMs: number } | null {
    if (state === 'Protected') return { label: 'Delivery due', atUnixMs: rec.mandate.deadlineUnixMs };
    if (state === 'Delivered') {
      return { label: 'Auto-accepts', atUnixMs: tx.client.autoAcceptDeadline(tx.id) };
    }
    return null;
  }

  /** State-gated actions (product interface: View / Accept / Dispute / Settle / Appeal only when available). */
  private actionsFor(rec: ProtectionRecord, state: LifecycleState): string[] {
    switch (state) {
      case 'Protected':
        return ['view', 'deliver', 'dispute'];
      case 'Delivered':
        return ['view', 'accept', 'dispute'];
      case 'Decided': {
        const actions = ['view', 'settle'];
        if (rec.disposition?.route === 'appealable') actions.push('appeal');
        return actions;
      }
      case 'Under Review':
        return ['view', 'review'];
      default:
        return ['view'];
    }
  }

  listRows(): Array<Record<string, unknown>> {
    return [...this.txs.values()].sort((a, b) => b.createdAtUnixMs - a.createdAtUnixMs).map((tx) => this.row(tx));
  }

  /** Operational summary for the customer activity surface. */
  summary(): Record<string, unknown> {
    const all = [...this.txs.values()];
    const states = all.map((tx) => ({ tx, state: lifecycleState(tx.client.getRecord(tx.id)) }));
    const disputes = states.filter(({ state }) =>
      state === 'Disputed' || state === 'Under Review' || state === 'Escalated' || state === 'Decided',
    );
    const resolutionTimes = all
      .filter((tx) => tx.disputedAtUnixMs !== undefined && tx.settledAtUnixMs !== undefined)
      .map((tx) => tx.settledAtUnixMs! - tx.disputedAtUnixMs!);
    const outcomes = { buyerWins: 0, workerWins: 0, split: 0, redo: 0 };
    for (const tx of all) {
      const ruling = tx.client.getRecord(tx.id).verdict?.ruling;
      if (ruling === undefined) continue;
      if (ruling.kind === 'requester_wins') outcomes.buyerWins += 1;
      else if (ruling.kind === 'worker_wins') outcomes.workerWins += 1;
      else if (ruling.kind === 'split') outcomes.split += 1;
      else if (ruling.kind === 'redo') outcomes.redo += 1;
    }
    return {
      protectedVolumeUsd: all.reduce((sum, tx) => sum + tx.amountUsd, 0),
      transactionCount: all.length,
      activeDisputes: disputes.filter(({ state }) => state !== 'Decided').length,
      decisionsPendingSettlement: states.filter(({ state }) => state === 'Decided').length,
      escalatedOrReview: states.filter(({ state }) => state === 'Under Review' || state === 'Escalated').length,
      avgResolutionMs:
        resolutionTimes.length > 0
          ? Math.round(resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length)
          : null,
      outcomes,
    };
  }

  /** Transaction detail (product interface — the most important screen). */
  detail(id: string): StoreOutcome {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const rec = tx.client.getRecord(tx.id);
    const state = lifecycleState(rec);
    const profile = tx.client.profile;
    const space = rec.mandate.decisionSpace;
    const possibleOutcomes =
      space.kind === 'escrow_branches'
        ? space.permitted.map((kind) =>
            plainOutcome(
              kind === 'split'
                ? { kind: 'split', requesterBps: 5_000 }
                : kind === 'redo'
                  ? { kind: 'redo', newDeadlineUnixMs: rec.mandate.deadlineUnixMs }
                  : { kind },
              rec.caseObject?.caseType,
            ),
          )
        : space.kind === 'categorical'
          ? space.outcomes
          : [`An amount between ${space.min} and ${space.max} ${space.unit}`];
    // Split/redo previews read oddly with concrete numbers — keep the generic phrases.
    const outcomesPlain =
      space.kind === 'escrow_branches'
        ? space.permitted.map(
            (kind) =>
              ({
                requester_wins: 'Buyer wins',
                worker_wins: 'Worker wins',
                split: 'Split payment',
                redo: 'Redo work',
              })[kind],
          )
        : possibleOutcomes;

    return {
      kind: 'ok',
      body: {
        ...this.row(tx),
        header: {
          title: tx.title,
          amountProtectedUsd: tx.amountUsd,
          state,
          stateColor: statusColor(state),
          deadlineUnixMs: rec.mandate.deadlineUnixMs,
          protectionLevel: tx.policy.title,
        },
        terms: {
          description: rec.mandate.description,
          acceptanceCriteria: rec.mandate.acceptanceCriteria.map((c) => ({
            id: c.id,
            statement: c.statement,
            automated: c.machineCheck !== undefined,
          })),
          deadlineUnixMs: rec.mandate.deadlineUnixMs,
          possibleOutcomes: outcomesPlain,
        },
        delivery:
          rec.manifest !== undefined
            ? {
                deliveredAtUnixMs: rec.manifest.deliveredAtUnixMs,
                files: rec.manifest.artifactHashes.map((a) => ({ name: a.path })),
                notes: rec.manifest.formatClaims,
              }
            : null,
        protection: {
          custody:
            'Your wallet, contract or payment rail controls the funds. Edict cannot move or freeze them and is not ' +
            'the settlement signer ' +
            '(this sandbox uses a simulated test ledger).',
          identity: assuranceCopy(profile),
          reviewType: reviewTypeCopy(profile),
          humanReview: humanReviewCopy(profile),
          autoAcceptWindowMs: rec.mandate.acceptanceWindowMs,
          policy: tx.policy.title,
          policyVersion: tx.policy.version,
        },
        timeline: tx.events.map((e) => ({ ...e, stateColor: statusColor(e.state) })),
        dispute:
          rec.status === 'disputed' || rec.status === 'settled'
            ? tx.disputeReason !== undefined
              ? { reason: tx.disputeReason, state }
              : null
            : null,
        auditUrl: `/api/audit/${tx.id}`,
      },
    };
  }

  private reviewReason(rec: ProtectionRecord): string {
    const trigger = rec.disposition?.trigger;
    if (trigger !== undefined) return TRIGGER_COPY[trigger];
    return 'This policy requires human review before high-value decisions settle';
  }

  /** Disputes list (screen: Disputes tab). */
  async listDisputes(): Promise<Array<Record<string, unknown>>> {
    const out: Array<Record<string, unknown>> = [];
    for (const tx of [...this.txs.values()].sort((a, b) => b.createdAtUnixMs - a.createdAtUnixMs)) {
      const rec = tx.client.getRecord(tx.id);
      if (rec.caseObject === undefined) continue;
      const state = lifecycleState(rec);
      out.push({
        id: tx.id,
        title: tx.title,
        amountUsd: tx.amountUsd,
        reason: tx.disputeReason ?? 'Dispute',
        state,
        stateColor: statusColor(state),
        decision: rec.verdict !== undefined ? plainOutcome(rec.verdict.ruling, rec.caseObject.caseType) : null,
        needsReview: rec.reviewState === 'queued' || rec.reviewState === 'appealed',
      });
    }
    return out;
  }

  /** Dispute detail — the claim tracker (product interface). */
  async disputeDetail(ref: string | TxEntry): Promise<Record<string, unknown>> {
    const tx = typeof ref === 'string' ? this.txs.get(ref) : ref;
    if (tx === undefined) throw new Error('unknown dispute');
    const rec = tx.client.getRecord(tx.id);
    const state = lifecycleState(rec);
    const caseType = rec.caseObject?.caseType;
    const reasoning = await this.readReasoning(tx);
    const pendingReview = rec.reviewState === 'queued' || rec.reviewState === 'appealed';

    // Automated checks in plain English.
    const checks: Array<{ name: string; result: string; detail: string }> = [];
    const det = isRecord(reasoning?.deterministic) ? (reasoning!.deterministic as Record<string, unknown>) : undefined;
    if (det !== undefined) {
      const rule = String(det.rule ?? '');
      const plain: Record<string, { name: string; result: string; detail: string }> = {
        non_delivery_after_deadline: {
          name: 'Delivery check',
          result: 'failed',
          detail: 'Nothing was delivered before the agreed deadline.',
        },
        forged_delivery_manifest: {
          name: 'Content verification',
          result: 'failed',
          detail: 'The delivered file does not match the reference agreed in the transaction terms.',
        },
        deterministic_conformance: {
          name: 'Content verification',
          result: 'passed',
          detail: 'Every agreed check passed: the delivery matches the transaction terms exactly.',
        },
        deterministic_claim_quantum: {
          name: 'Claim calculation',
          result: 'passed',
          detail: 'The payable amount was calculated directly from the agreed claim components.',
        },
      };
      checks.push(
        plain[rule] ?? { name: 'Automated check', result: 'decisive', detail: String(det.detail ?? 'Decided automatically.') },
      );
    }
    const mc = isRecord(reasoning?.machineChecks) ? (reasoning!.machineChecks as Record<string, unknown>) : undefined;
    if (mc !== undefined && Array.isArray(mc.results)) {
      for (const r of mc.results as Array<Record<string, unknown>>) {
        checks.push({
          name: `${String(r.criterionId)} — ${String(r.statement)}`,
          result: String(r.status),
          detail: String(r.detail ?? ''),
        });
      }
    }

    // Review decision card: Decision / Confidence / Status / Settlement.
    const decision =
      rec.verdict !== undefined
        ? {
            decision: plainOutcome(rec.verdict.ruling, caseType),
            confidence: confidenceCopy(rec),
            status: pendingReview
              ? 'Waiting for human review'
              : state === 'Escalated'
                ? 'Escalated — not final'
                : rec.verdict.humanReview !== undefined
                  ? 'Final (human-reviewed)'
                  : rec.verdict.final
                    ? 'Final'
                    : 'Not final',
            settlement:
              tx.settlement !== undefined
                ? {
                    outcome: plainOutcome(tx.settlement.ruling, caseType),
                    buyerReceivesUsd: tx.settlement.requesterPayoutUsd,
                    workerReceivesUsd: tx.settlement.workerPayoutUsd,
                  }
                : null,
            settlementIssue: tx.settlementError ?? null,
          }
        : null;

    // Escalation card (plain copy per product interface).
    const escalation =
      pendingReview || state === 'Escalated'
        ? {
            title: pendingReview ? 'Decision needs review' : 'Decision escalated',
            reason: this.reviewReason(rec),
            nextStep: pendingReview
              ? 'Human review — a reviewer picks the outcome, then payment settles'
              : 'This policy has no human review: the case falls back to the pre-agreed fallback handling',
            estimatedTime: pendingReview ? 'Usually within 24 hours' : null,
          }
        : null;

    const space = rec.mandate.decisionSpace;
    return {
      id: tx.id,
      caseId: rec.caseObject?.caseId ?? null,
      title: tx.title,
      amountUsd: tx.amountUsd,
      state,
      stateColor: statusColor(state),
      header: {
        reason: tx.disputeReason ?? 'Dispute',
        reviewType: reviewTypeCopy(tx.client.profile),
        expectedTime: pendingReview ? 'Waiting on a human reviewer' : 'Decided in seconds',
      },
      sides: {
        buyer: tx.submissions?.requester ?? null,
        worker: tx.submissions?.worker ?? null,
      },
      evidence: (rec.caseObject?.evidence ?? []).map((c) => ({
        item: {
          order_mandate: 'Transaction terms',
          legal_policy: 'Protection settings',
          customer_policy_pack: 'Customer terms policy',
          authority_credential: 'Agent authority',
          delivery_manifest: 'Delivery record',
          delivery_receipt: 'Delivery receipt',
          interaction_log_head: 'Interaction log',
          payment_receipt: 'Payment receipt',
          party_submission: 'Statement',
          zktls_proof: 'Web evidence',
          tee_runtime_attestation: 'Runtime verification',
          c2pa_manifest: 'Content credentials',
        }[c.kind],
        submittedBy: { requester: 'Buyer', worker: 'Worker', venue: 'Venue', system: 'Edict', third_party: 'Third party' }[
          c.submitter
        ],
        verified: c.authenticated,
      })),
      automatedChecks: checks,
      decision,
      escalation,
      review: pendingReview
        ? {
            available: true,
            prompt: 'Resolve as the human reviewer (sandbox): pick the outcome and sign with your reviewer name.',
            possibleOutcomes:
              space.kind === 'escrow_branches'
                ? space.permitted.map((kind) => ({
                    outcome:
                      kind === 'split'
                        ? { kind: 'split', requesterBps: 5_000 }
                        : kind === 'redo'
                          ? { kind: 'redo', newDeadlineUnixMs: Date.now() + 7 * 86_400_000 }
                          : { kind },
                    label: { requester_wins: 'Buyer wins', worker_wins: 'Worker wins', split: 'Split payment 50/50', redo: 'Redo work' }[
                      kind
                    ],
                  }))
                : [],
          }
        : null,
      auditUrl: `/api/audit/${tx.id}`,
    };
  }

  // --- audit drawer -------------------------------------------------------------

  /** The ONLY surface where protocol vocabulary appears (product interface). */
  async auditBundle(id: string): Promise<StoreOutcome> {
    const tx = this.txs.get(id);
    if (tx === undefined) return { kind: 'not_found', message: `No transaction ${id}.` };
    const rec = tx.client.getRecord(tx.id);
    const reasoning = await this.readReasoning(tx);
    const verdict = rec.verdict;
    const captures =
      verdict?.votes.flatMap((vote) =>
        vote.passes.map((pass) => ({
          seatId: vote.seat.seatId,
          providerId: vote.seat.providerId,
          modelId: vote.seat.modelId,
          orientation: pass.orientation,
          requestSha256: pass.proof.requestSha256,
          responseSha256: pass.proof.responseSha256,
          reasoningSha256: pass.reasoningSha256,
        })),
      ) ?? [];
    const proofs =
      verdict?.votes.flatMap((vote) =>
        vote.passes.map((pass) => ({
          seatId: vote.seat.seatId,
          providerId: pass.proof.providerId,
          modelId: pass.proof.modelId,
          signatureScheme: pass.proof.signatureScheme ?? null,
          signingAddress: pass.proof.signingAddress ?? null,
          attestationRef: pass.proof.attestationRef ?? null,
          fetchedAtUnixMs: pass.proof.fetchedAtUnixMs,
          /** Signer recovery outcome under the policy's verification gate. */
          verification:
            tx.client.profile.juryPolicy.requireProofs === true
              ? (verdict.quality.excludedSeats ?? []).some((x) => x.seatId === vote.seat.seatId)
                ? 'failed'
                : 'verified'
              : 'not_required',
        })),
      ) ?? [];
    let archiveFiles: string[] = [];
    if (rec.caseObject !== undefined) {
      try {
        archiveFiles = (await readdir(join(tx.archiveDir, rec.caseObject.caseId))).sort();
      } catch {
        archiveFiles = [];
      }
    }
    return {
      kind: 'ok',
      body: {
        bundleVersion: 'edict-audit-bundle-v1',
        transactionId: tx.id,
        caseObject: rec.caseObject ?? null,
        orderMandate: rec.mandate,
        mandateHash: rec.mandateHash,
        deliveryManifest: rec.manifest ?? null,
        deliveryManifestHash: rec.manifestHash ?? null,
        evidenceCommitments: (rec.caseObject?.evidence ?? rec.protect.evidenceCommitments).map((c) => ({
          kind: c.kind,
          sha256: c.sha256,
          submitter: c.submitter,
          authenticated: c.authenticated,
        })),
        profileHash: tx.client.profileHash,
        protectionProfile: tx.client.profile,
        verdict: verdict ?? null,
        reasoningSha256: verdict?.reasoningSha256 ?? null,
        reasoningDocument: reasoning ?? null,
        requestResponseCaptures: captures,
        providerProofs: proofs,
        excludedSeats: verdict?.quality.excludedSeats ?? [],
        injectionFlags: verdict?.quality.injectionFlags ?? [],
        disposition: rec.disposition ?? null,
        reviewState: rec.reviewState ?? null,
        humanReview: verdict?.humanReview ?? null,
        settlementDirective: rec.rounds.at(-1)?.settlementDirective ?? null,
        settlement: tx.settlement ?? null,
        archiveFiles,
      },
    };
  }

  private async readReasoning(tx: TxEntry): Promise<Record<string, unknown> | undefined> {
    const caseId = tx.client.getRecord(tx.id).caseObject?.caseId;
    if (caseId === undefined) return undefined;
    try {
      const raw = await readFile(join(tx.archiveDir, caseId, 'reasoning.json'), 'utf8');
      const parsed: unknown = JSON.parse(raw);
      return isRecord(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  has(id: string): boolean {
    return this.txs.has(id);
  }
}

/** The three step-1 presets with builder copy (served to the Policies screen). */
export function presetCards(): Array<Record<string, unknown>> {
  return PRESETS().map((def) => ({
    key: def.key,
    title: def.title,
    copy: def.copy,
    humanReview: def.humanReviewCopy,
    profileHash: def.profileHash,
    profile: def.profile,
  }));
}
