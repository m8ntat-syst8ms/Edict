/**
 * The Edict tool surface — seven agent-callable tools over the court
 * (MCP tool interface), each with a JSON Schema inputSchema and pretty-JSON text
 * content results.
 */

import { userFacing } from '@edict/sdk';
import type { ToolCallResult, ToolDefinition, ToolRegistry } from './protocol.js';
import { ToolInputError } from './errors.js';
import { DocketStore } from './docket.js';
import type { SessionStore } from './session.js';
import { draftMandate, lintMandateTool, resolveReview, sandboxDispute } from './mandateTools.js';
import { caseStatus, explainRuling, queryPrecedent } from './docketTools.js';

// ---------------------------------------------------------------------------
// Definitions
//
// User-facing wording comes from the shared @edict/sdk terminology module
// (canonical user-facing terminology). Internal type names appear only
// as parenthetical technical identifiers where a schema needs them.
// ---------------------------------------------------------------------------

/** Shared user-facing vocabulary (never hand-write these words here). */
const T = {
  dispute: userFacing('CaseObject'), // 'Dispute'
  terms: userFacing('OrderMandate'), // 'Transaction terms'
  policy: userFacing('ProtectionProfile'), // 'Protection policy'
  decision: userFacing('VerdictObject'), // 'Decision'
  panel: userFacing('jury seats'), // 'Review panel'
  verification: userFacing('provider proofs'), // 'Verification'
  outcomes: userFacing('decision space'), // 'Possible outcomes'
  evidence: userFacing('evidence commitments'), // 'Evidence record'
  escalation: userFacing('escalation'), // 'Appeal / human review'
} as const;

const CASE_ID_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['caseId'],
  properties: {
    caseId: {
      type: 'string',
      minLength: 1,
      description:
        `${T.dispute} id (uuid) or a shadow-docket case slug like "c01-minerals-attestation". ` +
        'Ids returned by edict_sandbox_dispute in this session also resolve.',
    },
  },
} as const;

export const TOOL_DEFINITIONS: ToolDefinition[] = [
  {
    name: 'edict_draft_mandate',
    description:
      `Draft the full ${T.terms} for an order (technical shape: OrderMandate, edict-om-2): fills defaults ` +
      `(${T.outcomes.toLowerCase()}, legal profile, auto-accept window) from the bundled default ${T.policy.toLowerCase()}, ` +
      'computes the canonical content hash, and returns the full pre-commitment lint report. ' +
      'Draft BEFORE funding: fix error/warn findings while they are still cheap.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['description', 'acceptanceCriteria', 'priceUsd', 'deadlineUnixMs'],
      properties: {
        description: { type: 'string', minLength: 1, description: 'What is being ordered.' },
        acceptanceCriteria: {
          type: 'array',
          minItems: 1,
          description:
            'Acceptance criteria. Plain strings become AC-n criteria; objects may pin an id and a deterministic machineCheck.',
          items: {
            anyOf: [
              { type: 'string', minLength: 1 },
              {
                type: 'object',
                additionalProperties: false,
                required: ['statement'],
                properties: {
                  id: { type: 'string', description: 'Stable criterion id, e.g. "AC-1".' },
                  statement: { type: 'string', minLength: 1 },
                  machineCheck: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['kind', 'params'],
                    properties: {
                      kind: {
                        type: 'string',
                        enum: ['hash_equals', 'schema_valid', 'deadline_before', 'contains', 'custom'],
                      },
                      params: { type: 'object' },
                    },
                  },
                },
              },
            ],
          },
        },
        priceUsd: { type: 'number', exclusiveMinimum: 0, maximum: 100000, description: 'Order price in USD (tier C caps at $100k).' },
        deadlineUnixMs: { type: 'integer', description: 'Delivery deadline (unix epoch milliseconds).' },
        decisionSpace: {
          type: 'object',
          description:
            'Optional DecisionSpace override, e.g. { "kind": "escrow_branches", "permitted": ["requester_wins","worker_wins","split","redo"] }. Default: the profile\'s full escrow-branches space.',
        },
        legalProfile: {
          type: 'object',
          description:
            'Optional LegalProfile override { governingLaw, seat, rules, enforcementTier }. Default: wallet-native E0 (england_wales / london / edict-drr-v0.1 / E0). E1-E3 require an enterprise profile through the full SDK.',
        },
        maeEvents: {
          type: 'array',
          items: { type: 'string' },
          description: 'Enumerated Material Adverse Exception events for qualified code deference (DRR Rule 33).',
        },
      },
    },
  },
  {
    name: 'edict_lint_mandate',
    description:
      `Lint existing ${T.terms.toLowerCase()} (technical shape: OrderMandate, edict-om-1 or edict-om-2) with the @edict/linter: ` +
      `ambiguity lexicon, machine-check coverage, structural sanity over the ${T.outcomes.toLowerCase()}, injection screening. ` +
      'Returns the lint report (score 0-100, findings, machineCoverage).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['mandate'],
      properties: {
        mandate: { type: 'object', description: `The ${T.terms.toLowerCase()} object to lint (technical shape: OrderMandate; edict-om-2 for new orders).` },
      },
    },
  },
  {
    name: 'edict_sandbox_dispute',
    description:
      `Run a ${T.dispute.toLowerCase()} offline through the Edict pipeline via the SDK sandbox: protect the ` +
      `${T.terms.toLowerCase()}, (optionally) record the delivery, run automated checks + a 3-seat ${T.panel.toLowerCase()} ` +
      `with swap-debias, then settle when the ${T.decision.toLowerCase()} is final. Returns the ${T.decision.toLowerCase()} ` +
      'summary (outcome, finality, quality gates, escalation reason), reasoning, instruction blocks, and the full ' +
      'settlement math (payouts + dispute-bond economics). Sandbox only — no live rails, no real funds.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['mandate', 'submissions'],
      properties: {
        mandate: {
          type: 'object',
          description:
            `The ${T.terms.toLowerCase()} under dispute (as returned by edict_draft_mandate). Missing parties get sandbox placeholders.`,
        },
        deliveryManifest: {
          type: 'object',
          additionalProperties: false,
          description:
            "The worker's delivery manifest. Omit entirely for a non-delivery dispute. workerAgentId/orderMandateHash are derived from the mandate.",
          properties: {
            artifactHashes: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['path', 'sha256'],
                properties: {
                  path: { type: 'string' },
                  sha256: { type: 'string', pattern: '^[0-9a-fA-F]{64}$' },
                  mediaType: { type: 'string', description: 'IANA media type; default application/octet-stream.' },
                },
              },
            },
            formatClaims: { type: 'array', items: { type: 'string' } },
            deliveredAtUnixMs: { type: 'integer' },
          },
        },
        submissions: {
          type: 'object',
          additionalProperties: false,
          description: 'Free-form party pleadings (adversarial by construction; screened for injection).',
          properties: {
            requester: { type: 'string' },
            worker: { type: 'string' },
          },
        },
      },
    },
  },
  {
    name: 'edict_resolve_review',
    description:
      `Resolve a sandbox ${T.dispute.toLowerCase()} HELD FOR HUMAN REVIEW (profile-elected ` +
      `${T.escalation.toLowerCase()}): supply an outcome within the pre-committed ${T.outcomes.toLowerCase()} plus a ` +
      `reviewerRef; the real SDK produces a human-reviewed FINAL ${T.decision.toLowerCase()} (the automated ` +
      `${T.panel.toLowerCase()} record is preserved for audit, humanReview marker set) and settles it on the run's ` +
      'escrow. Sandbox-scoped: works only on ids returned by edict_sandbox_dispute in this session whose result said ' +
      `"held for human review" (reviewState "queued"). The superseded automated ${T.decision.toLowerCase()} remains non-executable forever.`,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['caseRef', 'ruling', 'reviewerRef'],
      properties: {
        caseRef: {
          type: 'string',
          minLength: 1,
          description: 'id returned by edict_sandbox_dispute in this session (the content hash of the terms also resolves).',
        },
        ruling: {
          type: 'object',
          description:
            `The reviewer's outcome — MUST lie within the ${T.dispute.toLowerCase()}'s ${T.outcomes.toLowerCase()}, ` +
            'e.g. { "kind": "requester_wins" }, { "kind": "split", "requesterBps": 2500 }, ' +
            '{ "kind": "categorical", "outcome": "YES" }, { "kind": "scalar", "value": 1200 }.',
        },
        reviewerRef: {
          type: 'string',
          minLength: 1,
          description: `Reviewer identity ref recorded on the ${T.decision.toLowerCase()}'s humanReview audit marker (never inline PII).`,
        },
      },
    },
  },
  {
    name: 'edict_query_precedent',
    description:
      `Keyword search over the illustrative public Edict docket (bilateral, public_resolution and claim shapes) — ` +
      `${T.dispute.toLowerCase()} examples, public rationales and local ` +
      `${T.decision.toLowerCase()}s. Returns ranked refs with the outcome, a one-line holding, and a matching snippet. ` +
      'These examples are not production qualification evidence. Optional tags filter requires every requested tag.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['query'],
      properties: {
        query: { type: 'string', minLength: 1, description: 'Free-text keywords, e.g. "forged manifest settlement receipt".' },
        tags: { type: 'array', items: { type: 'string' }, description: `Groundtruth tags the ${T.dispute.toLowerCase()} must ALL carry.` },
      },
    },
  },
  {
    name: 'edict_case_status',
    description:
      `Status of a ${T.dispute.toLowerCase()} from local data: shadow-docket entries (${T.decision.toLowerCase()} ` +
      'outcome, finality, escalation, quality gates, groundtruth agreement when reports exist) and sandbox ' +
      `${T.dispute.toLowerCase()}s adjudicated in this session. Degrades gracefully when docket reports have not been generated.`,
    inputSchema: CASE_ID_SCHEMA,
  },
  {
    name: 'edict_explain_ruling',
    description:
      `Explain a ${T.decision.toLowerCase()}: the archived reasoning (automated checks, per-seat ${T.panel.toLowerCase()} ` +
      'votes and confidences, deterministic short-circuits) plus WHICH instruction blocks applied — recomputed ' +
      "deterministically through the real pipeline's judicial-instructions layer.",
    inputSchema: CASE_ID_SCHEMA,
  },
];

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export interface EdictToolsOptions {
  docket?: DocketStore;
}

/** Build the tool registry served over MCP. */
export function createEdictTools(opts: EdictToolsOptions = {}): ToolRegistry {
  const docket = opts.docket ?? new DocketStore();
  const session: SessionStore = new Map();

  const handlers: Record<string, (args: Record<string, unknown>) => unknown | Promise<unknown>> = {
    edict_draft_mandate: (args) => draftMandate(args),
    edict_lint_mandate: (args) => lintMandateTool(args),
    edict_sandbox_dispute: (args) => sandboxDispute(args, session),
    edict_resolve_review: (args) => resolveReview(args, session),
    edict_query_precedent: (args) => queryPrecedent(args, docket),
    edict_case_status: (args) => caseStatus(args, docket, session),
    edict_explain_ruling: (args) => explainRuling(args, docket, session),
  };

  return {
    list: () => TOOL_DEFINITIONS,
    call: (name, args) => {
      const handler = handlers[name];
      if (handler === undefined) return undefined;
      return run(handler, args);
    },
  };
}

async function run(
  handler: (args: Record<string, unknown>) => unknown | Promise<unknown>,
  args: Record<string, unknown>,
): Promise<ToolCallResult> {
  try {
    const result = await handler(args);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    const text =
      err instanceof ToolInputError
        ? err.message
        : err instanceof Error
          ? `${err.name}: ${err.message}`
          : `Error: ${String(err)}`;
    return { content: [{ type: 'text', text }], isError: true };
  }
}
