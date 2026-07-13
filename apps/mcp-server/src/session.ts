/**
 * In-memory record of sandbox disputes adjudicated during THIS server session,
 * so `edict_case_status` / `edict_explain_ruling` can resolve the case ids
 * returned by `edict_sandbox_dispute` alongside the shadow-docket corpus.
 */

import type { CaseObject, VerdictObject } from '@edict/core';
import type { EdictClient, EscalationDisposition, EscrowSettlement, ReviewState } from '@edict/sdk';
import type { TribunalInstructions } from './explain.js';

export interface SessionCase {
  caseId: string;
  mandateHash: string;
  caseObj: CaseObject;
  verdict: VerdictObject;
  /** Archived arbiter reasoning document (already compacted). */
  reasoning?: Record<string, unknown>;
  tribunalInstructions: TribunalInstructions;
  /** null when the verdict escalated (nothing settleable). */
  settlement: EscrowSettlement | null;
  /** Human escalation policy routing (review policy). */
  disposition?: EscalationDisposition;
  /** Human-review lifecycle state ('queued' | 'appealed' | 'resolved'). */
  reviewState?: ReviewState;
  /**
   * The run's sandbox client, kept alive so `edict_resolve_review` can
   * resolve a queued case through the resolveHumanReview and settle flow.
   */
  client?: EdictClient;
}

export type SessionStore = Map<string, SessionCase>;
