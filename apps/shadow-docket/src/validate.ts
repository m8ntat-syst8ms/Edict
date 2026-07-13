/**
 * Validators for docket inputs. Structural CaseObject validation is DELEGATED
 * to @edict/core's `validateCaseObject`; the docket only keeps
 * its harness-specific checks (groundtruth shape, seat rosters, evidence-uri
 * conventions enforced in loadCases.ts).
 */
import type { CaseObject, JurySeatSpec } from '@edict/core';
import { RULING_KINDS, validateCaseObject as coreValidateCaseObject } from '@edict/core';
import type {
  Difficulty,
  ExpectedOutcome,
  ExpectedRuling,
  GroundTruth,
  ValidationIssue,
} from './harnessTypes.js';
import { UUID_V4_RE } from './hash.js';

export { tierForValueUsd } from '@edict/core';

const DIFFICULTIES: ReadonlyArray<Difficulty> = ['deterministic', 'easy', 'medium', 'hard'];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function err(path: string, message: string): ValidationIssue {
  return { level: 'error', path, message };
}
function warn(path: string, message: string): ValidationIssue {
  return { level: 'warn', path, message };
}

function checkString(out: ValidationIssue[], v: unknown, path: string, opts?: { re?: RegExp; hint?: string }): v is string {
  if (typeof v !== 'string' || v.length === 0) {
    out.push(err(path, 'must be a non-empty string'));
    return false;
  }
  if (opts?.re && !opts.re.test(v)) {
    out.push(err(path, `does not match expected format${opts.hint ? ` (${opts.hint})` : ''}`));
    return false;
  }
  return true;
}

function checkEnum<T extends string>(out: ValidationIssue[], v: unknown, path: string, allowed: ReadonlyArray<T>): v is T {
  if (typeof v !== 'string' || !(allowed as ReadonlyArray<string>).includes(v)) {
    out.push(err(path, `must be one of: ${allowed.join(', ')}`));
    return false;
  }
  return true;
}

/**
 * Split a core `<path>: <message>` error string back into an issue. Core
 * reports SHOULD-level rules in the same array prefixed `warn:` — those map
 * to warn-level issues (they never fail a case).
 */
function coreErrorToIssue(e: string): ValidationIssue {
  const level: ValidationIssue['level'] = e.startsWith('warn:') ? 'warn' : 'error';
  const body = level === 'warn' ? e.slice('warn:'.length) : e;
  const idx = body.indexOf(': ');
  if (idx === -1) return { level, path: 'case', message: body };
  return { level, path: body.slice(0, idx), message: body.slice(idx + 2) };
}

/**
 * Validate an unknown value against the canonical CaseObject shape.
 * Structural checks are delegated to @edict/core's validateCaseObject; only
 * harness-specific extras live here (evidence-uri conventions are enforced
 * when the bundle is loaded, see loadCases.ts).
 */
export function validateCaseObject(v: unknown): ValidationIssue[] {
  return coreValidateCaseObject(v).errors.map(coreErrorToIssue);
}

const OUTCOME_KINDS = [...RULING_KINDS, 'categorical', 'scalar'] as const;

/**
 * Validate a groundtruth expected outcome, cross-checked (when the case is
 * available) against the case's pre-committed decisionSpace: the arbiter is a
 * verdict oracle and could never return an outcome outside the space.
 */
function validateExpectedOutcome(v: unknown, path: string, caseObj?: CaseObject): ValidationIssue[] {
  const out: ValidationIssue[] = [];
  if (!isRecord(v)) return [err(path, 'must be an object { kind, ... }')];
  if (!checkEnum(out, v.kind, `${path}.kind`, OUTCOME_KINDS)) return out;
  const space = caseObj?.decisionSpace;

  if (v.kind === 'categorical') {
    if (checkString(out, v.outcome, `${path}.outcome`) && space) {
      if (space.kind !== 'categorical') {
        out.push(err(`${path}.kind`, `expects a categorical outcome but the case decisionSpace kind is '${space.kind}'`));
      } else if (!space.outcomes.includes(v.outcome as string)) {
        out.push(err(`${path}.outcome`, `'${String(v.outcome)}' is not among the case's committed outcomes [${space.outcomes.join(', ')}]`));
      }
    }
    return out;
  }

  if (v.kind === 'scalar') {
    if (typeof v.value !== 'number' || !Number.isFinite(v.value)) {
      out.push(err(`${path}.value`, 'scalar expectations need a finite numeric value'));
    } else if (space) {
      if (space.kind !== 'bounded_scalar') {
        out.push(err(`${path}.kind`, `expects a scalar outcome but the case decisionSpace kind is '${space.kind}'`));
      } else if (v.value < space.min || v.value > space.max) {
        out.push(err(`${path}.value`, `${v.value} is outside the case's bounded scalar range [${space.min}, ${space.max}] ${space.unit}`));
      }
    }
    return out;
  }

  // Escrow ruling expectation.
  if (space) {
    if (space.kind !== 'escrow_branches') {
      out.push(err(`${path}.kind`, `expects an escrow ruling but the case decisionSpace kind is '${space.kind}'`));
    } else if (!space.permitted.includes(v.kind as ExpectedRuling['kind'])) {
      out.push(err(`${path}.kind`, `'${String(v.kind)}' is not in the case's permitted escrow branches — the arbiter is a verdict oracle and could never return it`));
    }
  }
  if (v.kind === 'split') {
    if (typeof v.requesterBps !== 'number' || v.requesterBps < 0 || v.requesterBps > 10_000) {
      out.push(err(`${path}.requesterBps`, 'split expectations need requesterBps in 0..10000'));
    }
  } else if (v.requesterBps !== undefined) {
    out.push(warn(`${path}.requesterBps`, 'requesterBps is only meaningful for split rulings'));
  }
  return out;
}

/** Validate a groundtruth.json payload (optionally cross-checked against its case). */
export function validateGroundTruth(v: unknown, caseObj?: CaseObject): ValidationIssue[] {
  const out: ValidationIssue[] = [];
  if (!isRecord(v)) return [err('groundtruth', 'groundtruth.json must be a JSON object')];

  checkString(out, v.caseId, 'groundtruth.caseId', { re: UUID_V4_RE, hint: 'uuid v4' });
  if (caseObj && typeof v.caseId === 'string' && v.caseId !== caseObj.caseId) {
    out.push(err('groundtruth.caseId', `does not match case.json caseId (${caseObj.caseId})`));
  }
  checkString(out, v.title, 'groundtruth.title');
  out.push(...validateExpectedOutcome(v.expected, 'groundtruth.expected', caseObj));
  if (v.acceptableAlternatives !== undefined) {
    if (!Array.isArray(v.acceptableAlternatives)) out.push(err('groundtruth.acceptableAlternatives', 'must be an array'));
    else v.acceptableAlternatives.forEach((a, i) =>
      out.push(...validateExpectedOutcome(a, `groundtruth.acceptableAlternatives[${i}]`, caseObj)));
  }
  for (const tol of ['splitToleranceBps', 'scalarToleranceBps'] as const) {
    if (v[tol] !== undefined && (typeof v[tol] !== 'number' || v[tol] < 0 || v[tol] > 10_000)) {
      out.push(err(`groundtruth.${tol}`, 'must be a number in 0..10000'));
    }
  }
  checkString(out, v.rationale, 'groundtruth.rationale');
  checkEnum(out, v.difficulty, 'groundtruth.difficulty', DIFFICULTIES);
  if (!Array.isArray(v.tags) || v.tags.length === 0 || !v.tags.every((t) => typeof t === 'string' && t.length > 0)) {
    out.push(err('groundtruth.tags', 'must be a non-empty array of strings'));
  } else {
    const buckets = ['real_dispute', 'synthetic', 'adversarial', 'edge'];
    if (!v.tags.some((t) => buckets.includes(t as string))) {
      out.push(warn('groundtruth.tags', `should include a bucket tag (${buckets.join(' | ')})`));
    }
  }
  for (const flag of ['expectInjectionFlag', 'allowEscalation'] as const) {
    if (v[flag] !== undefined && typeof v[flag] !== 'boolean') out.push(err(`groundtruth.${flag}`, 'must be a boolean'));
  }
  if (v.historicalDivergence !== undefined) checkString(out, v.historicalDivergence, 'groundtruth.historicalDivergence');
  return out;
}

/**
 * Validate a jury seat roster. Enforces the ROSTER-level placement
 * invariants : >= 2 distinct providerIds (the tier-A/B floor — a
 * single-operator roster can seat nothing) and pairwise-disjoint model
 * families. A provider MAJORITY is only a warning: it is legal at tiers A/B,
 * and tier-C cases are skipped per case by the runner's placement precheck
 * (placementSkipReason in report.ts), which also requires >= 3 operators.
 */
export function validateSeats(v: unknown): ValidationIssue[] {
  const out: ValidationIssue[] = [];
  if (!Array.isArray(v) || v.length === 0) return [err('seats', 'must be a non-empty array of JurySeatSpec')];
  const byProvider = new Map<string, number>();
  const families = new Map<string, string>();
  v.forEach((s, i) => {
    const p = `seats[${i}]`;
    if (!isRecord(s)) {
      out.push(err(p, 'must be an object (JurySeatSpec)'));
      return;
    }
    for (const field of ['seatId', 'providerId', 'modelId', 'modelFamily'] as const) {
      checkString(out, s[field], `${p}.${field}`);
    }
    if (typeof s.providerId === 'string') byProvider.set(s.providerId, (byProvider.get(s.providerId) ?? 0) + 1);
    if (typeof s.modelFamily === 'string') {
      const prev = families.get(s.modelFamily);
      if (prev !== undefined) out.push(err(`${p}.modelFamily`, `model family '${s.modelFamily}' already used by ${prev} — families must be disjoint across seats`));
      else if (typeof s.seatId === 'string') families.set(s.modelFamily, s.seatId);
    }
  });
  if (byProvider.size > 0 && byProvider.size < 2) {
    out.push(err('seats', `roster spans ${byProvider.size} distinct provider(s) — tiers A/B require >= 2 , so a single-operator roster can seat nothing`));
  }
  for (const [providerId, count] of byProvider) {
    if (count * 2 > v.length) {
      out.push(warn('seats', `provider '${providerId}' holds ${count}/${v.length} seats — legal at tiers A/B, but tier-C cases will be skipped (tier C forbids a provider majority and needs >= 3 operators)`));
    }
  }
  return out;
}

/** Convenience: keep only error-level issues. */
export function errorsOf(issues: ValidationIssue[]): ValidationIssue[] {
  return issues.filter((i) => i.level === 'error');
}

/** Typed casts after validation (call only when errorsOf(...) is empty). */
export function asCaseObject(v: unknown): CaseObject {
  return v as CaseObject;
}
export function asGroundTruth(v: unknown): GroundTruth {
  return v as GroundTruth;
}
export function asSeats(v: unknown): JurySeatSpec[] {
  return v as JurySeatSpec[];
}
export type { ExpectedOutcome, ExpectedRuling };
