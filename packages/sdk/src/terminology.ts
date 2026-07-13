/**
 * Canonical user-facing terminology shared by every product surface.
 *
 * Edict protects transactions. Users must never be asked to understand
 * courts, mandates, juries, attestations, or verdict internals unless they
 * explicitly open audit mode. This module is the ONE source of user-facing
 * words consumed by every surface (customer app, console UI, MCP tool
 * descriptions, SDK error messages, and reports.
 *
 * Nothing here changes protocol semantics: it maps internal vocabulary to
 * the words a customer sees.
 */

import type { CaseType, Outcome } from '@edict/core';
import type { EscalationRoute } from './escalation.js';
import type { ProtectionStatus, ReviewState } from './client.js';

// ---------------------------------------------------------------------------
// The translation table (verbatim from the product interface)
// ---------------------------------------------------------------------------

/** Internal term → user-facing term. Keys are matched case-insensitively by {@link userFacing}. */
export const TERMINOLOGY: Readonly<Record<string, string>> = Object.freeze({
  caseobject: 'Dispute',
  case: 'Dispute',
  ordermandate: 'Transaction terms',
  'order mandate': 'Transaction terms',
  mandate: 'Transaction terms',
  protectionprofile: 'Protection policy',
  profile: 'Protection policy',
  verdictobject: 'Decision',
  verdict: 'Decision',
  'jury seats': 'Review panel',
  jury: 'Review panel',
  'provider proofs': 'Verification',
  proofs: 'Verification',
  escalation: 'Appeal / human review',
  'decision space': 'Possible outcomes',
  decisionspace: 'Possible outcomes',
  'evidence commitments': 'Evidence record',
  'evidence commitment': 'Evidence record',
});

/**
 * The user-facing word for an internal term (case-insensitive; interior
 * whitespace collapsed). Unknown terms pass through unchanged so callers can
 * template freely: `userFacing('OrderMandate')` → `'Transaction terms'`.
 */
export function userFacing(internalTerm: string): string {
  const key = internalTerm.trim().toLowerCase().replace(/\s+/g, ' ');
  return TERMINOLOGY[key] ?? internalTerm;
}

// ---------------------------------------------------------------------------
// Lifecycle rail (canonical lifecycle — the status rail, used everywhere)
// ---------------------------------------------------------------------------

/** `Draft → Protected → Delivered → Accepted / Disputed → Under Review → Decided → Settled` (+ `Escalated`). */
export type LifecycleState =
  | 'Draft'
  | 'Protected'
  | 'Delivered'
  | 'Accepted'
  | 'Disputed'
  | 'Changes Requested'
  | 'Under Review'
  | 'Decided'
  | 'Settled'
  | 'Escalated';

/** Rail order for rendering the timeline (Escalated is the off-rail branch). */
export const LIFECYCLE_STATES: readonly LifecycleState[] = [
  'Draft',
  'Protected',
  'Delivered',
  'Accepted',
  'Disputed',
  'Changes Requested',
  'Under Review',
  'Decided',
  'Settled',
  'Escalated',
];

/**
 * The slice of a ProtectionRecord the lifecycle mapping reads — a
 * ProtectionRecord is assignable as-is; partial shapes (e.g. a wizard draft
 * with no status yet) map to 'Draft'.
 */
export interface LifecycleRecordLike {
  status?: ProtectionStatus;
  reviewState?: ReviewState;
  disposition?: { route: EscalationRoute } | undefined;
  verdict?: { final: boolean; quality?: { escalated: boolean } } | undefined;
}

/**
 * Map a protection record's internal state (status + disposition +
 * reviewState) onto the user-facing lifecycle rail:
 *
 * - no record / no status yet             → 'Draft'
 * - 'protected' / 'delivered' / 'accepted' / 'settled' → the rail state
 * - 'disputed' refines by what happened next:
 *     · reviewState 'queued' | 'appealed'  → 'Under Review' (a human has it)
 *     · escalated verdict routed to the programmatic fallback (no human
 *       elected)                           → 'Escalated'
 *     · a decision exists (final, or human-review 'resolved')
 *                                          → 'Decided' (awaiting settlement)
 *     · otherwise                          → 'Disputed'
 */
export function lifecycleState(record: LifecycleRecordLike | undefined): LifecycleState {
  if (record === undefined || record.status === undefined) return 'Draft';
  switch (record.status) {
    case 'protected':
      return 'Protected';
    case 'delivered':
      return 'Delivered';
    case 'accepted':
      return 'Accepted';
    case 'settled':
      return 'Settled';
    case 'disputed': {
      if (record.reviewState === 'queued' || record.reviewState === 'appealed') return 'Under Review';
      if (record.verdict?.quality?.escalated === true && record.disposition?.route === 'programmatic_fallback') {
        return 'Escalated';
      }
      if (record.verdict?.final === true || record.reviewState === 'resolved') return 'Decided';
      return 'Disputed';
    }
    case 'redo':
      return 'Changes Requested';
  }
}

// ---------------------------------------------------------------------------
// Status colors (status palette)
// ---------------------------------------------------------------------------

/**
 * user-facing status palette: Protected blue · Delivered neutral · Disputed
 * amber · Under review indigo · Final/settled green · Escalated orange ·
 * Failed/blocked red. Draft renders neutral; Accepted/Decided/Settled are
 * final/settled green. Returns a CSS hex color.
 */
export function statusColor(state: LifecycleState | 'Failed'): string {
  switch (state) {
    case 'Protected':
      return '#1d4ed8'; // blue
    case 'Draft':
    case 'Delivered':
      return '#64748b'; // neutral
    case 'Disputed':
    case 'Changes Requested':
      return '#b45309'; // amber
    case 'Under Review':
      return '#4f46e5'; // indigo
    case 'Accepted':
    case 'Decided':
    case 'Settled':
      return '#15803d'; // final/settled green
    case 'Escalated':
      return '#ea580c'; // orange
    case 'Failed':
      return '#b91c1c'; // failed/blocked red
  }
}

// ---------------------------------------------------------------------------
// Plain-English outcomes (product interface key rule: every advanced field gets a
// plain-English wrapper — never `escrow_branches`, always "Buyer wins · …")
// ---------------------------------------------------------------------------

/** Who "requester" and "worker" are, per case shape (core role mapping). */
const PARTY_LABELS: Record<CaseType, { requester: string; worker: string }> = {
  bilateral: { requester: 'Buyer', worker: 'Worker' },
  public_resolution: { requester: 'Challenger', worker: 'Proposer' },
  claim: { requester: 'Claimant', worker: 'Underwriter' },
};

/**
 * The plain-English phrase for a decided outcome:
 *
 * - escrow branches: "Buyer wins" / "Worker wins" / "Split payment (25% / 75%)"
 *   / "Redo work (new deadline …)" — party words follow the case shape
 *   ("Challenger/Proposer" on public resolutions, "Claimant/Underwriter" on
 *   claims).
 * - categorical: the label itself (e.g. "YES").
 * - scalar: the quantum phrasing "Amount awarded: 1200".
 */
export function plainOutcome(outcome: Outcome, caseType: CaseType = 'bilateral'): string {
  const who = PARTY_LABELS[caseType] ?? PARTY_LABELS.bilateral;
  switch (outcome.kind) {
    case 'requester_wins':
      return `${who.requester} wins`;
    case 'worker_wins':
      return `${who.worker} wins`;
    case 'split': {
      const requesterPct = outcome.requesterBps / 100;
      const workerPct = 100 - requesterPct;
      return `Split payment (${formatPct(requesterPct)}% to ${who.requester.toLowerCase()} / ${formatPct(workerPct)}% to ${who.worker.toLowerCase()})`;
    }
    case 'redo':
      return `Redo work (new deadline ${new Date(outcome.newDeadlineUnixMs).toISOString().slice(0, 10)})`;
    case 'categorical':
      return outcome.outcome;
    case 'scalar':
      return `Amount awarded: ${outcome.value}`;
  }
}

function formatPct(x: number): string {
  return Number.isInteger(x) ? String(x) : String(Math.round(x * 100) / 100);
}
