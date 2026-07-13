/**
 * POST /api/lint backend: complete a PARTIAL order-mandate draft from the
 * policy editor into a complete, lintable OrderMandate using neutral
 * placeholders, then run the real @edict/linter over it.
 *
 * The completion is deliberately forgiving — the editor calls this on every
 * debounced keystroke, so half-typed fields fall back to neutral defaults and
 * are reported in `draftProblems` instead of failing the request. Placeholders
 * are chosen to be lint-neutral (fixed nonce and wallet-native placeholder
 * parties) so the score reflects the DRAFT, not the scaffolding.
 */

import type { AcceptanceCriterion, DecisionSpace, LegalProfile, OrderMandate } from '@edict/core';
import { ENFORCEMENT_TIERS, GOVERNING_LAWS, SEATS, validateDecisionSpace } from '@edict/core';
import { lintMandate, type LintReport } from '@edict/linter';
import { defaultProfile } from '@edict/sdk';

/** The partial mandate shape the policy editor sends. All fields optional. */
export interface MandateDraft {
  description?: unknown;
  acceptanceCriteria?: unknown;
  priceUsd?: unknown;
  deadlineUnixMs?: unknown;
  decisionSpace?: unknown;
  maeEvents?: unknown;
  legalProfile?: unknown;
  acceptanceWindowMs?: unknown;
}

export interface LintDraftResult {
  report: LintReport;
  /** The completed mandate that was actually linted (placeholders included). */
  mandate: OrderMandate;
  /** Draft fields that were unusable and replaced by neutral defaults. */
  draftProblems: string[];
}

const NEUTRAL_LEGAL: LegalProfile = {
  governingLaw: 'england_wales',
  seat: 'london',
  rules: 'edict-drr-v0.1',
  enforcementTier: 'E0',
};

const NEUTRAL_DECISION_SPACE: DecisionSpace = {
  kind: 'escrow_branches',
  permitted: ['requester_wins', 'worker_wins', 'split', 'redo'],
};

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asPositiveNumber(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : undefined;
}

/** Coerce the draft's criteria into AcceptanceCriterion[], assigning AC-n ids. */
function completeCriteria(v: unknown, problems: string[]): AcceptanceCriterion[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) {
    problems.push('acceptanceCriteria: not an array — linting with no criteria');
    return [];
  }
  const out: AcceptanceCriterion[] = [];
  for (const item of v) {
    if (!isRecord(item) || typeof item.statement !== 'string' || item.statement.trim().length === 0) continue;
    const criterion: AcceptanceCriterion = {
      id: typeof item.id === 'string' && item.id.trim().length > 0 ? item.id.trim() : `AC-${out.length + 1}`,
      statement: item.statement,
    };
    const mc = item.machineCheck;
    if (
      isRecord(mc) &&
      typeof mc.kind === 'string' &&
      ['hash_equals', 'schema_valid', 'deadline_before', 'contains', 'custom'].includes(mc.kind) &&
      isRecord(mc.params)
    ) {
      criterion.machineCheck = {
        kind: mc.kind as NonNullable<AcceptanceCriterion['machineCheck']>['kind'],
        params: mc.params,
      };
    }
    out.push(criterion);
  }
  return out;
}

function completeLegalProfile(v: unknown, problems: string[]): LegalProfile {
  if (v === undefined) return { ...NEUTRAL_LEGAL };
  if (
    isRecord(v) &&
    typeof v.governingLaw === 'string' &&
    (GOVERNING_LAWS as readonly string[]).includes(v.governingLaw) &&
    typeof v.seat === 'string' &&
    (SEATS as readonly string[]).includes(v.seat) &&
    typeof v.rules === 'string' &&
    v.rules.length > 0 &&
    typeof v.enforcementTier === 'string' &&
    (ENFORCEMENT_TIERS as readonly string[]).includes(v.enforcementTier)
  ) {
    return {
      governingLaw: v.governingLaw as LegalProfile['governingLaw'],
      seat: v.seat as LegalProfile['seat'],
      rules: v.rules,
      enforcementTier: v.enforcementTier as LegalProfile['enforcementTier'],
    };
  }
  problems.push('legalProfile: invalid — linting under the neutral wallet-native default (england_wales/london/E0)');
  return { ...NEUTRAL_LEGAL };
}

function completeDecisionSpace(v: unknown, problems: string[]): DecisionSpace {
  if (v === undefined) return structuredClone(NEUTRAL_DECISION_SPACE);
  const errors = validateDecisionSpace(v, 'decisionSpace');
  if (errors.length > 0) {
    problems.push(...errors.map((e) => `${e} — linting with the full escrow-branch default`));
    return structuredClone(NEUTRAL_DECISION_SPACE);
  }
  return structuredClone(v) as DecisionSpace;
}

/** Complete a partial draft into a lintable OrderMandate with neutral placeholders. */
export function completeDraft(draft: MandateDraft): { mandate: OrderMandate; draftProblems: string[] } {
  const problems: string[] = [];
  const priceUsd = asPositiveNumber(draft.priceUsd) ?? 100;
  if (draft.priceUsd !== undefined && asPositiveNumber(draft.priceUsd) === undefined) {
    problems.push('priceUsd: not a positive number — linting with the $100 placeholder');
  }
  const deadlineUnixMs = asPositiveNumber(draft.deadlineUnixMs) ?? Date.now() + 7 * 86_400_000;
  if (draft.deadlineUnixMs !== undefined && asPositiveNumber(draft.deadlineUnixMs) === undefined) {
    problems.push('deadlineUnixMs: not a positive number — linting with a +7d placeholder');
  }
  const maeEvents = Array.isArray(draft.maeEvents)
    ? draft.maeEvents.filter((e): e is string => typeof e === 'string' && e.trim().length > 0)
    : [];
  const profile = defaultProfile();
  const requestedLegal = completeLegalProfile(draft.legalProfile, problems);
  const legalProfile: LegalProfile = {
    ...requestedLegal,
    ...(priceUsd < 10 ? { enforcementTier: 'E0' as const } : {}),
  };

  const mandate: OrderMandate = {
    version: 'edict-om-2',
    requester: { agentId: 'console:requester' },
    worker: { agentId: 'console:worker' },
    description: typeof draft.description === 'string' ? draft.description : '',
    acceptanceCriteria: completeCriteria(draft.acceptanceCriteria, problems),
    priceUsd,
    currency: { asset: 'USDC', rail: 'console-draft' },
    deadlineUnixMs,
    acceptanceWindowMs: asPositiveNumber(draft.acceptanceWindowMs) ?? 86_400_000,
    legalProfile,
    legalPolicy: structuredClone(profile.legalPolicy),
    decisionSpace: completeDecisionSpace(draft.decisionSpace, problems),
    settlement: {
      custodyMode: 'M2_external_escrow',
      fundsController: 'payment_rail',
      adapterRef: 'rail:console-draft',
      edictOperatorCanTransfer: false,
      edictOperatorCanFreeze: false,
      edictOperatorIsRequiredSigner: false,
      resolutionTimeoutMs: 259_200_000,
      livenessFallback: 'controller_resolution',
    },
    maeEvents,
    nonce: 'console-draft-nonce', // fixed → same draft always lints identically
  };
  return { mandate, draftProblems: problems };
}

/** Complete + lint a draft. Never throws on malformed drafts. */
export function lintDraft(draft: MandateDraft): LintDraftResult {
  const { mandate, draftProblems } = completeDraft(draft);
  const report = lintMandate(mandate);
  return { report, mandate, draftProblems };
}
