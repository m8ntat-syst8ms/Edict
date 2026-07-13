/**
 * Typed errors for the @edict/sdk developer surface. Every gate in the SDK
 * fails with one of these — callers can catch by class instead of parsing
 * message strings.
 */

import type { LintReport } from '@edict/linter';

/** `validateProfile` problems, raised by `createEdict` / `assertValidProfile`. */
export class ProfileValidationError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`protection profile invalid:\n- ${problems.join('\n- ')}`);
    this.name = 'ProfileValidationError';
    this.problems = problems;
  }
}

/**
 * The lint gate blocked `protect()`: the mandate has error-severity findings
 * (with `lintGate.blockOnError`) and/or scored below `lintGate.minScore`.
 * The full {@link LintReport} is attached so callers can render the findings.
 */
export class LintGateError extends Error {
  readonly report: LintReport;
  readonly reasons: string[];
  constructor(report: LintReport, reasons: string[]) {
    super(
      `lint gate blocked the order mandate (score ${report.score}):\n- ${reasons.join('\n- ')}\n` +
        `findings:\n${report.findings.map((f) => `  [${f.severity}] ${f.code}: ${f.message}`).join('\n')}`,
    );
    this.name = 'LintGateError';
    this.report = report;
    this.reasons = reasons;
  }
}

/** A `protectRef` that matches no protection created by this client. */
export class UnknownProtectionError extends Error {
  readonly ref: string;
  constructor(ref: string) {
    super(`unknown protection ref "${ref}" — protect() the order with this client first`);
    this.name = 'UnknownProtectionError';
    this.ref = ref;
  }
}

/** A protection is in the wrong lifecycle state for the requested operation. */
export class ProtectionStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtectionStateError';
  }
}

/** Evidence plaintext does not hash to its declared/committed sha256. */
export class EvidenceMismatchError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`evidence plaintext hash mismatch:\n- ${problems.join('\n- ')}`);
    this.name = 'EvidenceMismatchError';
    this.problems = problems;
  }
}

/** Direct live adjudication/settlement belongs to ProtectionRuntime or the customer rail. */
export class LiveModeError extends Error {
  constructor(feature: string) {
    super(
      `${feature} is not a direct @edict/sdk operation in mode 'live'; use ` +
        `@edict/protection-runtime for observation/adjudication and the customer rail or contract for settlement ` +
        `(see the "Sandbox vs live" section of @edict/sdk README.md)`,
    );
    this.name = 'LiveModeError';
  }
}

/** A mandate/case would place funds or transfer authority inside Edict. */
export class CustodyBoundaryError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`self-custody boundary rejected the settlement:\n- ${problems.join('\n- ')}`);
    this.name = 'CustodyBoundaryError';
    this.problems = problems;
  }
}

/** Sandbox ledger: a party's balance cannot cover a funding / bond posting. */
export class InsufficientFundsError extends Error {
  readonly agentId: string;
  readonly requiredUsd: number;
  readonly availableUsd: number;
  constructor(agentId: string, requiredUsd: number, availableUsd: number) {
    super(
      `insufficient sandbox funds for ${agentId}: need $${requiredUsd}, ` +
        `have $${availableUsd} — deposit() first`,
    );
    this.name = 'InsufficientFundsError';
    this.agentId = agentId;
    this.requiredUsd = requiredUsd;
    this.availableUsd = availableUsd;
  }
}

/** Sandbox escrow: unknown escrow id or an invalid state transition. */
export class EscrowStateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EscrowStateError';
  }
}

/**
 * `settle()` was handed a verdict whose runtime `final` flag is not `true`
 * (an escalated / advisory verdict smuggled past the `FinalVerdict` type via
 * a cast). Escalated verdicts are NEVER executable — they route up a tier.
 */
export class EscalatedVerdictError extends Error {
  readonly caseId: string;
  constructor(caseId: string, reason?: string) {
    super(
      `verdict for case ${caseId} is not final${reason ? ` (${reason})` : ''} — ` +
        'escalated verdicts are never executable; route the case up a tier instead of settling',
    );
    this.name = 'EscalatedVerdictError';
    this.caseId = caseId;
  }
}

/**
 * `settle()` received a structurally executable verdict that is not the exact
 * verdict issued (or later adopted by human review) for this client record.
 * This prevents callers from swapping in another in-space ruling after the
 * adjudication boundary.
 */
export class VerdictMismatchError extends Error {
  readonly caseId: string;
  readonly expectedSha256: string;
  readonly receivedSha256: string;

  constructor(caseId: string, expectedSha256: string, receivedSha256: string) {
    super(
      `verdict for case ${caseId} does not match the decision recorded by this client ` +
        `(expected sha256 ${expectedSha256}, received ${receivedSha256})`,
    );
    this.name = 'VerdictMismatchError';
    this.caseId = caseId;
    this.expectedSha256 = expectedSha256;
    this.receivedSha256 = receivedSha256;
  }
}

/**
 * `settle()` was called while the case is held for human review (review policy):
 * the disposition routed to 'human_review' (reviewState 'queued' — including
 * clean above-threshold finals under 'required_above_value') or a party appealed
 * (reviewState 'appealed'). Resolve the review first — `resolveHumanReview`
 * produces the settle-able, human-reviewed verdict.
 */
export class PendingReviewError extends Error {
  readonly caseId: string;
  readonly reviewState: 'queued' | 'appealed';
  constructor(caseId: string, reviewState: 'queued' | 'appealed') {
    super(
      `case ${caseId} is held for human review (reviewState '${reviewState}') — ` +
        'settle() is blocked until resolveHumanReview() produces the human-reviewed verdict',
    );
    this.name = 'PendingReviewError';
    this.caseId = caseId;
    this.reviewState = reviewState;
  }
}

/**
 * `resolveHumanReview()` was handed a ruling outside the case's pre-committed
 * decision space (or an otherwise invalid resolution). The human bench is
 * bound by the SAME verdict-oracle invariant as the AI jury: it selects
 * WITHIN the committed decision space only.
 */
export class ReviewOutcomeError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(
      `human review resolution rejected:\n- ${problems.join('\n- ')}\n` +
        'the human bench selects within the pre-committed decision space only',
    );
    this.name = 'ReviewOutcomeError';
    this.problems = problems;
  }
}

/** The sandbox escrow only executes escrow payout branches (Ruling shapes). */
export class UnsupportedRulingError extends Error {
  constructor(kind: string) {
    super(
      `sandbox escrow cannot execute ruling kind '${kind}' — only the pre-committed escrow ` +
        'payout branches (requester_wins | worker_wins | split | redo) settle here',
    );
    this.name = 'UnsupportedRulingError';
  }
}
