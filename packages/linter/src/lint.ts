/**
 * @edict/linter — pre-commitment analysis of an OrderMandate (pre-funding lint policy).
 *
 * Ambiguity is the largest preventable dispute class (43% of Polymarket
 * disputes are wording). This linter runs BEFORE funds lock, entirely
 * deterministic — no LLM, no network — and reports every wording / structure
 * defect that historically turns into a dispute, each with a concrete fix.
 *
 * Passes (all deterministic):
 *  1. machine-coverage      — criteria lacking a machineCheck (warn each;
 *                             info summary with the coverage pct when
 *                             coverage is incomplete).
 *  2. vague-term lexicon    — "reasonable", "professional", "should", … over
 *                             criterion statements + description (warn each,
 *                             with a bind-to-a-threshold suggestion).
 *  3. missing parameters    — translation/language tasks without an explicit
 *                             locale/variant,
 *                             numeric thresholds without units, missing or
 *                             epoch-implausible deadline (unix-seconds
 *                             detection included), absurd acceptanceWindowMs
 *                             (<1 min or >90 days).
 *  4. structural            — empty acceptanceCriteria (error), duplicate
 *                             criterion ids (error), decision-space sanity
 *                             via the core validators (error) plus
 *                             linter-level advisories: split permitted with
 *                             no milestone-priced criteria (warn),
 *                             categorical outcome unreachable from the
 *                             committed text (info), scalar unit vs priceUsd
 *                             semantics (info), bounded_scalar components
 *                             lacking machineCheck.params.payableUsd — the
 *                             claim-component convention (info).
 *  5. injection screening   — the arbiter's exported injection screen over
 *                             every piece of mandate-originated free text
 *                             (description, criterion statements, maeEvents).
 *                             Attack-level detections are ERRORS: this is the
 *                             pre-commitment defence for the known
 *                             MAE-verbatim channel — the arbiter withholds
 *                             screened mandate text from the tribunal, so an
 *                             attack-bearing mandate cannot even rely on its
 *                             own words. Stylistic detections are info.
 *
 * Scoring rubric (documented contract): score = 100 − Σ deductions, floored
 * at 0, where each finding deducts by severity: error 15, warn 5, info 1
 * (see SEVERITY_DEDUCTION). A mandate that is not even a JSON object scores
 * 0. The machine-coverage summary is emitted only when coverage is
 * incomplete, so a fully clean mandate scores exactly 100.
 */

import type { AcceptanceCriterion, DecisionSpace, OrderMandate } from '@edict/core';
import { validateDecisionSpace } from '@edict/core';
import { isAttackFlag, isStylisticNoteFlag, screenText } from '@edict/arbiter';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type LintSeverity = 'error' | 'warn' | 'info';

export interface LintFinding {
  severity: LintSeverity;
  /** Stable machine-readable code, e.g. 'vague-term', 'missing-locale'. */
  code: string;
  /** Set when the finding anchors to one acceptance criterion. */
  criterionId?: string;
  message: string;
  suggestion?: string;
}

export interface LintReport {
  /** 0–100; see the scoring rubric in the module doc. */
  score: number;
  /** Deterministic machine-checkability of the acceptance criteria. */
  machineCoverage: { checked: number; total: number; pct: number };
  /** Sorted most-severe first (error → warn → info), stable within severity. */
  findings: LintFinding[];
}

export interface LintOptions {
  /**
   * Run the injection screen over mandate-originated text (pass 5).
   * Default true; set false only for trusted-template workflows.
   */
  screen?: boolean;
}

/** Per-finding score deductions (the documented rubric). */
export const SEVERITY_DEDUCTION: Readonly<Record<LintSeverity, number>> = {
  error: 15,
  warn: 5,
  info: 1,
};

// ---------------------------------------------------------------------------
// Lexicons & heuristic patterns
// ---------------------------------------------------------------------------

/**
 * Vague-term lexicon (pass 2). Every entry is unenforceable as written:
 * juries improvise a meaning at dispute time, and the two parties will have
 * assumed different ones. One finding per (term, text unit).
 */
const VAGUE_TERMS: ReadonlyArray<{ label: string; re: RegExp }> = [
  { label: 'reasonable', re: /\breasonabl[ey]\b/i },
  { label: 'appropriate', re: /\bappropriate(?:ly)?\b/i },
  { label: 'high quality', re: /\bhigh[-\s]quality\b/i },
  { label: 'promptly', re: /\bpromptly\b/i },
  { label: 'timely', re: /\btimely\b/i },
  { label: 'best efforts', re: /\bbest[-\s]efforts?\b/i },
  { label: 'industry standard', re: /\bindustry[-\s]standards?\b/i },
  { label: 'etc.', re: /\betc\b\.?/i },
  { label: 'substantially', re: /\bsubstantial(?:ly)?\b/i },
  { label: 'satisfactory', re: /\bsatisfactor(?:y|ily)\b/i },
  { label: 'professional', re: /\bprofessional(?:ly)?\b/i },
  { label: 'as needed', re: /\bas\s+needed\b/i },
  { label: 'may', re: /\bmay\b/i },
  { label: 'should', re: /\bshould\b/i },
  { label: 'adequate', re: /\badequate(?:ly)?\b/i },
  { label: 'sufficient', re: /\bsufficient(?:ly)?\b/i },
  { label: 'good faith', re: /\bgood[-\s]faith\b/i },
  { label: 'workmanlike', re: /\bworkmanlike\b/i },
  { label: 'state of the art', re: /\bstate[-\s]of[-\s]the[-\s]art\b/i },
  { label: 'user-friendly', re: /\buser[-\s]friendly\b/i },
];

/** Language/translation task trigger (pass 3). */
const LANGUAGE_TASK_RE = /\btranslat(?:e|es|ed|ing|ion|ions|or)\b|\blocali[sz](?:e|es|ed|ing|ation)\b|\blanguages?\b|\blocales?\b/i;
/** An explicit BCP-47-ish locale tag: fr-FR, en_US, zh-Hans, es-419. */
const LOCALE_TAG_RE = /\b[A-Za-z]{2,3}[-_](?:[A-Z]{2}|\d{3}|[A-Z][a-z]{3})\b/;
/** A region-qualified language name: "Canadian French", "Simplified Chinese". */
const LANGUAGE_VARIANT_RE =
  /\b(?:european|canadian|brazilian|latin[-\s]american|mexican|castilian|iberian|simplified|traditional|mandarin|cantonese|british|american|australian|swiss|austrian|flemish|quebec|québec)\s+(?:french|portuguese|spanish|chinese|english|german|dutch|arabic)\b/i;
/** A parenthesised region qualifier: "French (France)". */
const REGION_PAREN_RE = /\((?:france|canada|quebec|québec|brazil|portugal|spain|mexico|uk|us|usa|prc|taiwan)\)/i;

/**
 * A threshold-context number with no unit after it ("at least 90." but not
 * "at least 90%" / "at least 90 words" / "at least $90" / "at least 90-day").
 */
const UNITLESS_THRESHOLD_RE =
  /\b(?:at (?:least|most)|no (?:more|less|fewer) than|minimum(?: of)?|maximum(?: of)?|greater than|less than|score of|threshold of|up to)\s+(\d[\d,]*(?:\.\d+)?)(?![.,]?\d)(?!\s*(?:%|[A-Za-z$€£¥])|-)/gi;

/** Evidence of milestone-priced partial performance (pass 4 split advisory). */
const MILESTONE_PRICING_RE =
  /\bmilestones?\b|\bphases?\s*\d|\b\d{1,3}(?:\.\d+)?\s*(?:%|percent|bps)\b|\bpro[-\s]?rata\b|\bper\s+(?:module|section|item|unit|milestone|deliverable)\b|\bseparately\s+priced\b/i;

/** USD-denominated units (matching the OrderMandate priceUsd semantics). */
const USD_UNIT_RE = /^(?:usd[ct]?|us\s*dollars?|\$)$/i;

/** Sane unix-ms bounds: 2000-01-01T00:00:00Z .. 3000-01-01T00:00:00Z (mirrors core). */
const UNIX_MS_MIN = 946_684_800_000;
const UNIX_MS_MAX = 32_503_680_000_000;
const MS_MINUTE = 60_000;
const MS_90_DAYS = 90 * 86_400_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** One screenable/scannable piece of mandate-originated free text. */
interface TextUnit {
  /** Deterministic source label, e.g. 'description', 'criterion:AC-1', 'maeEvents[0]'. */
  label: string;
  text: string;
  criterionId?: string;
}

const SEVERITY_RANK: Readonly<Record<LintSeverity, number>> = { error: 0, warn: 1, info: 2 };

// ---------------------------------------------------------------------------
// lintMandate
// ---------------------------------------------------------------------------

/**
 * Lint an OrderMandate before commitment/funds-lock. Pure, deterministic,
 * never throws — malformed input surfaces as error-severity findings.
 */
export function lintMandate(om: OrderMandate, opts: LintOptions = {}): LintReport {
  const m: unknown = om;
  if (!isRecord(m)) {
    return {
      score: 0,
      machineCoverage: { checked: 0, total: 0, pct: 0 },
      findings: [
        {
          severity: 'error',
          code: 'not-an-object',
          message: 'mandate: must be a JSON object (OrderMandate)',
        },
      ],
    };
  }

  const findings: LintFinding[] = [];
  const push = (f: LintFinding): void => {
    findings.push(f);
  };

  // --- well-formed criteria (malformed entries become structural errors) ----
  const rawCriteria = m.acceptanceCriteria;
  const criteria: AcceptanceCriterion[] = [];
  if (!Array.isArray(rawCriteria) || rawCriteria.length === 0) {
    push({
      severity: 'error',
      code: 'no-acceptance-criteria',
      message: 'acceptanceCriteria: empty or missing — there is nothing committed to adjudicate against',
      suggestion: 'add at least one acceptance criterion; make each machine-checkable where possible',
    });
  } else {
    rawCriteria.forEach((c, i) => {
      if (isRecord(c) && typeof c.id === 'string' && c.id.length > 0 && typeof c.statement === 'string' && c.statement.length > 0) {
        criteria.push(c as unknown as AcceptanceCriterion);
      } else {
        push({
          severity: 'error',
          code: 'malformed-criterion',
          message: `acceptanceCriteria[${i}]: must be an object with non-empty string id and statement`,
        });
      }
    });
  }

  // --- text units (pass 2/3 scan statements + description; pass 5 adds maeEvents)
  const description = typeof m.description === 'string' ? m.description : '';
  const proseUnits: TextUnit[] = [];
  if (description.length > 0) proseUnits.push({ label: 'description', text: description });
  for (const c of criteria) {
    proseUnits.push({ label: `criterion:${c.id}`, text: c.statement, criterionId: c.id });
  }
  const maeUnits: TextUnit[] = [];
  if (Array.isArray(m.maeEvents)) {
    m.maeEvents.forEach((e, i) => {
      if (typeof e === 'string' && e.length > 0) maeUnits.push({ label: `maeEvents[${i}]`, text: e });
    });
  }
  const combinedProse = proseUnits.map((u) => u.text).join('\n');

  // --- pass 1: machine coverage ---------------------------------------------
  const total = criteria.length;
  let checked = 0;
  for (const c of criteria) {
    if (c.machineCheck !== undefined) {
      checked += 1;
    } else {
      push({
        severity: 'warn',
        code: 'machine-check-missing',
        criterionId: c.id,
        message: `criterion ${c.id}: no machineCheck — satisfaction rests entirely on jury interpretation`,
        suggestion:
          'bind the criterion to a deterministic check (hash_equals | schema_valid | deadline_before | contains | custom) so the machine layer can settle it',
      });
    }
  }
  const pct = total === 0 ? 0 : Math.round((checked / total) * 100);
  if (total > 0 && checked < total) {
    push({
      severity: 'info',
      code: 'machine-coverage',
      message: `machine coverage: ${checked}/${total} criteria machine-checkable (${pct}%)`,
      suggestion: 'every non-machine-checkable criterion is a jury judgment call — raise coverage before locking funds',
    });
  }

  // --- pass 2: vague-term lexicon --------------------------------------------
  for (const unit of proseUnits) {
    for (const term of VAGUE_TERMS) {
      if (term.re.test(unit.text)) {
        push({
          severity: 'warn',
          code: 'vague-term',
          ...(unit.criterionId !== undefined ? { criterionId: unit.criterionId } : {}),
          message: `${unit.label}: vague term "${term.label}" — the parties will assume different meanings and a jury will improvise one`,
          suggestion: `replace "${term.label}" with a measurable threshold (number + unit, an enumerated list, or a machineCheck)`,
        });
      }
    }
  }

  // --- pass 3: missing-parameter heuristics ----------------------------------
  // 3a. language/translation task without an explicit locale/variant.
  if (
    LANGUAGE_TASK_RE.test(combinedProse) &&
    !LOCALE_TAG_RE.test(combinedProse) &&
    !LANGUAGE_VARIANT_RE.test(combinedProse) &&
    !REGION_PAREN_RE.test(combinedProse)
  ) {
    push({
      severity: 'warn',
      code: 'missing-locale',
      message:
        'language/translation task with no explicit locale or variant — an unqualified language name ("French") is the classic wording dispute (fr-FR vs fr-CA)',
      suggestion: 'name the exact locale in the description AND a criterion, e.g. a BCP-47 tag (fr-FR) or "Canadian French"',
    });
  }

  // 3b. numeric thresholds without units.
  for (const unit of proseUnits) {
    UNITLESS_THRESHOLD_RE.lastIndex = 0;
    for (const match of unit.text.matchAll(UNITLESS_THRESHOLD_RE)) {
      push({
        severity: 'warn',
        code: 'unitless-threshold',
        ...(unit.criterionId !== undefined ? { criterionId: unit.criterionId } : {}),
        message: `${unit.label}: numeric threshold "${match[0].trim()}" has no unit — 90 what?`,
        suggestion: 'attach an explicit unit (%, words, ms, USD, …) so the threshold is checkable',
      });
    }
  }

  // 3c. deadline missing / epoch-implausible.
  const deadline = m.deadlineUnixMs;
  if (typeof deadline !== 'number' || !Number.isSafeInteger(deadline)) {
    push({
      severity: 'warn',
      code: 'deadline-missing',
      message: 'deadlineUnixMs: missing or not an integer — "late" becomes a jury judgment call',
      suggestion: 'set an explicit unix-ms deadline (deadline_before machine checks depend on it)',
    });
  } else if (deadline < UNIX_MS_MIN || deadline > UNIX_MS_MAX) {
    const looksLikeSeconds = deadline * 1000 >= UNIX_MS_MIN && deadline * 1000 <= UNIX_MS_MAX;
    push({
      severity: 'warn',
      code: 'deadline-implausible',
      message:
        `deadlineUnixMs: ${deadline} is outside the plausible epoch bounds [${UNIX_MS_MIN}, ${UNIX_MS_MAX}] (unix ms, 2000–3000 AD)` +
        (looksLikeSeconds ? ' — value looks like unix SECONDS; multiply by 1000' : ''),
      suggestion: 'use unix milliseconds for deadlineUnixMs',
    });
  }

  // 3d. acceptanceWindowMs absurdity (0 / <1min / >90d).
  const win = m.acceptanceWindowMs;
  if (typeof win !== 'number' || !Number.isFinite(win)) {
    push({
      severity: 'warn',
      code: 'acceptance-window-missing',
      message: 'acceptanceWindowMs: missing or not a number — auto-release timing is undefined',
      suggestion: 'set the post-delivery review window explicitly (e.g. 172800000 for 48h)',
    });
  } else if (win < MS_MINUTE) {
    push({
      severity: 'warn',
      code: 'acceptance-window-implausible',
      message: `acceptanceWindowMs: ${win} ms (< 1 minute) — the requester gets no real review window before auto-release`,
      suggestion: 'use a window the requester can actually review within (typically 24–72h)',
    });
  } else if (win > MS_90_DAYS) {
    push({
      severity: 'warn',
      code: 'acceptance-window-implausible',
      message: `acceptanceWindowMs: ${win} ms (> 90 days) — worker payout is locked for an absurdly long acceptance window`,
      suggestion: 'shorten the window; long review periods belong in milestones, not one auto-release timer',
    });
  }

  // --- pass 4: structural -----------------------------------------------------
  // duplicate criterion ids.
  const idCounts = new Map<string, number>();
  for (const c of criteria) idCounts.set(c.id, (idCounts.get(c.id) ?? 0) + 1);
  for (const [id, n] of idCounts) {
    if (n > 1) {
      push({
        severity: 'error',
        code: 'duplicate-criterion-id',
        criterionId: id,
        message: `acceptanceCriteria: id '${id}' appears ${n} times — machine checks and verdict reasoning cannot reference it unambiguously`,
        suggestion: 'give every criterion a unique id',
      });
    }
  }

  // decision-space sanity via the core validators.
  const space = m.decisionSpace;
  const legacy = m.permittedRulings;
  if (space === undefined && legacy !== undefined) {
    push({
      severity: 'error',
      code: 'decision-space-invalid',
      message: "mandate carries the retired v0.1 'permittedRulings' field and no decisionSpace",
      suggestion: "use decisionSpace: { kind: 'escrow_branches', permitted: [...] }",
    });
  } else {
    const spaceErrors = validateDecisionSpace(space, 'decisionSpace');
    for (const err of spaceErrors) {
      push({ severity: 'error', code: 'decision-space-invalid', message: err });
    }
    if (spaceErrors.length === 0) {
      const ds = space as DecisionSpace;
      if (ds.kind === 'escrow_branches') {
        if (ds.permitted.includes('split') && !MILESTONE_PRICING_RE.test(combinedProse)) {
          push({
            severity: 'warn',
            code: 'split-without-milestones',
            message:
              "decisionSpace: 'split' is a permitted branch but neither the description nor any criterion prices partial performance — a split basis will be improvised at dispute time",
            suggestion: "price milestones explicitly (e.g. 'module N = 25% of escrow') or drop 'split' from the permitted branches",
          });
        }
      } else if (ds.kind === 'categorical') {
        for (const label of ds.outcomes) {
          if (label === ds.invalidOutcome) continue; // the void branch needs no textual route
          const reach = new RegExp(`\\b${escapeRegExp(label)}\\b`, 'i');
          if (!reach.test(combinedProse)) {
            push({
              severity: 'info',
              code: 'unreachable-outcome',
              message: `decisionSpace: categorical outcome '${label}' never appears in the description or criteria — the committed text gives a jury no route to it`,
              suggestion: 'add a criterion stating exactly when this outcome applies (or remove it)',
            });
          }
        }
      } else {
        // bounded_scalar — claim-component convention awareness: a criterion
        // with a machineCheck but no numeric payableUsd cannot join the
        // deterministic quantum sum (see the claim-component convention in
        // services/arbiter/README.md), so the whole quantum falls to the jury.
        for (const c of criteria) {
          if (c.machineCheck === undefined) continue; // already warned (machine-check-missing)
          const payable = c.machineCheck.params?.payableUsd;
          if (typeof payable !== 'number' || !Number.isFinite(payable) || payable < 0) {
            push({
              severity: 'info',
              code: 'claim-component-missing-payable',
              criterionId: c.id,
              message: `criterion ${c.id}: bounded_scalar mandate component has no machineCheck.params.payableUsd — it cannot join the deterministic quantum and leaves the quantum to the jury`,
              suggestion:
                'declare payableUsd on each loss component (payableUsd > 0 with a hash_equals expectedSha256 for payable components; payableUsd: 0 for committed exclusions)',
            });
          }
        }
        // unit vs priceUsd semantics.
        if (!USD_UNIT_RE.test(ds.unit.trim())) {
          push({
            severity: 'info',
            code: 'scalar-unit-mismatch',
            message: `decisionSpace: scalar unit '${ds.unit}' does not match the mandate's USD price semantics (priceUsd) — settlement conversion is unstated`,
            suggestion: 'denominate the scalar in USD, or state the conversion rule in a criterion',
          });
        } else if (typeof m.priceUsd === 'number' && Number.isFinite(m.priceUsd) && ds.max > m.priceUsd) {
          push({
            severity: 'info',
            code: 'scalar-exceeds-price',
            message: `decisionSpace: scalar max ${ds.max} ${ds.unit} exceeds priceUsd ${m.priceUsd} — confirm the award may exceed the order price (insurance-style coverage), otherwise lower max`,
          });
        }
      }
    }
  }

  // --- pass 5: injection screening over mandate-originated text ---------------
  if (opts.screen !== false) {
    for (const unit of [...proseUnits, ...maeUnits]) {
      const screened = screenText(unit.text, unit.label);
      for (const flag of screened.flags) {
        if (isAttackFlag(flag)) {
          push({
            severity: 'error',
            code: 'injection-attack',
            ...(unit.criterionId !== undefined ? { criterionId: unit.criterionId } : {}),
            message: `${unit.label}: mandate text trips the injection screen (${flag}) — the arbiter withholds screened mandate text from the tribunal`,
            suggestion:
              'remove instruction-like or payload-like content; screened text renders as "[withheld: screened mandate text]" and cannot support your own criteria at dispute time',
          });
        } else if (isStylisticNoteFlag(flag)) {
          push({
            severity: 'info',
            code: 'injection-note',
            ...(unit.criterionId !== undefined ? { criterionId: unit.criterionId } : {}),
            message: `${unit.label}: advocacy-style phrasing noted by the injection screen (${flag})`,
            suggestion: 'state criteria as neutral conditions, not requests to the tribunal',
          });
        }
      }
    }
  }

  // --- score (documented rubric) ----------------------------------------------
  const deductions = findings.reduce((sum, f) => sum + SEVERITY_DEDUCTION[f.severity], 0);
  const score = Math.max(0, 100 - deductions);

  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  return { score, machineCoverage: { checked, total, pct }, findings: sorted };
}
