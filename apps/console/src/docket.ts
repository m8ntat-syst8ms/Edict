/**
 * Shadow-docket reader — the console consumes docket OUTPUTS from disk
 * (apps/shadow-docket/cases/** for inputs; reports/report.json +
 * reports/verdicts/*.json + reports/archive/<caseId>/reasoning.json when
 * present). It never imports the harness: file reads only, resilient to the
 * reports directory being absent (a regenerate hint is included instead).
 *
 * The case detail additionally recomputes the tribunal's judicial instruction
 * blocks with the @edict/arbiter primitives (deterministic and offline) so
 * the verdict viewer can show the rules of decision next to the ruling.
 */

import { readdir, readFile, realpath } from 'node:fs/promises';
import { join, sep } from 'node:path';
import type { CaseObject, VerdictObject } from '@edict/core';
import {
  analyzeDeterministic,
  buildJudicialInstructions,
  verifyEvidenceCommitments,
} from '@edict/arbiter';
import { sha256Hex } from '@edict/evidence';

export const REGENERATE_HINT =
  'reports not generated — run `npm run docket -w @edict/shadow-docket` to (re)generate reports/report.json and reports/verdicts/';

/** One row of the CASES tab. */
export interface CaseSummary {
  slug: string;
  caseId?: string;
  title?: string;
  caseType?: string;
  tier?: string;
  valueUsd?: number;
  tags?: string[];
  difficulty?: string;
  decisionSpaceKind?: string;
  /** From reports/verdicts when available. */
  ruling?: unknown;
  final?: boolean;
  escalated?: boolean;
  injectionFlags?: string[];
  /** From report.json results when available. */
  agreed?: boolean;
  /** Set when case.json could not be read/parsed. */
  error?: string;
}

export interface CaseListing {
  reportsAvailable: boolean;
  hint?: string;
  cases: CaseSummary[];
}

export interface CaseDetail {
  slug: string;
  case: CaseObject;
  groundTruth?: unknown;
  verdict?: VerdictObject;
  /** The archived structured reasoning document (arbiter-reasoning-v1). */
  reasoning?: unknown;
  /** The per-case row from report.json (agreement, rationale, flags). */
  result?: unknown;
  /** Recomputed tribunal instruction blocks (deterministic; absent on failure). */
  instructionBlocks?: string[];
  reportsAvailable: boolean;
  hint?: string;
}

/** Everything the sandbox runner needs to replay a docket case through the SDK. */
export interface CaseTemplate {
  slug: string;
  caseObj: CaseObject;
  /** Parsed evidence/order_mandate.json (may be v0.1-shaped with permittedRulings). */
  orderMandate: Record<string, unknown>;
  /** Parsed delivery manifest plaintext, when the case has one. */
  deliveryManifest?: Record<string, unknown>;
  /** Party pleadings joined per submitter. */
  submissions: { requester?: string; worker?: string };
  /** Every other evidence commitment with its verified plaintext. */
  extraEvidence: Array<{
    kind: CaseObject['evidence'][number]['kind'];
    plaintext: string;
    submitter: CaseObject['evidence'][number]['submitter'];
    authenticated: boolean;
    uri?: string;
  }>;
}

const EVIDENCE_URI_RE = /^evidence\/[A-Za-z0-9][A-Za-z0-9._-]*$/;
const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

async function containedRealpath(rootDir: string, candidate: string): Promise<string | undefined> {
  try {
    const root = await realpath(rootDir);
    const resolved = await realpath(candidate);
    return resolved.startsWith(`${root}${sep}`) ? resolved : undefined;
  } catch {
    return undefined;
  }
}

async function readFileContained(rootDir: string, candidate: string): Promise<string | undefined> {
  const resolved = await containedRealpath(rootDir, candidate);
  if (resolved === undefined) return undefined;
  try {
    return await readFile(resolved, 'utf8');
  } catch {
    return undefined;
  }
}

async function readJsonContained(rootDir: string, candidate: string): Promise<unknown | undefined> {
  const raw = await readFileContained(rootDir, candidate);
  if (raw === undefined) return undefined;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

async function caseDirs(docketDir: string): Promise<string[]> {
  try {
    return (await readdir(join(docketDir, 'cases'), { withFileTypes: true }))
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .filter((name) => SLUG_RE.test(name))
      .sort();
  } catch {
    return [];
  }
}

/** Load verified evidence plaintext for a case dir, keyed by committed sha256. */
async function loadEvidencePlaintext(dir: string, caseObj: CaseObject): Promise<Record<string, string>> {
  const plaintext: Record<string, string> = {};
  for (const commitment of caseObj.evidence) {
    if (commitment.uri === undefined || !EVIDENCE_URI_RE.test(commitment.uri)) continue;
    const raw = await readFileContained(dir, join(dir, commitment.uri));
    if (raw === undefined) continue;
    if (sha256Hex(raw) !== commitment.sha256) continue; // tampered/edited — treat as sealed
    plaintext[commitment.sha256] = raw;
  }
  return plaintext;
}

/** report.json results keyed by caseId (empty map when reports are absent). */
async function loadReportIndex(
  docketDir: string,
): Promise<{ reportsAvailable: boolean; results: Map<string, Record<string, unknown>> }> {
  const reportsDir = join(docketDir, 'reports');
  const report = await readJsonContained(reportsDir, join(reportsDir, 'report.json'));
  const results = new Map<string, Record<string, unknown>>();
  if (!isRecord(report) || !Array.isArray(report.results)) {
    return { reportsAvailable: false, results };
  }
  for (const row of report.results) {
    if (isRecord(row) && typeof row.caseId === 'string') results.set(row.caseId, row);
  }
  return { reportsAvailable: true, results };
}

async function loadVerdict(docketDir: string, caseId: string): Promise<VerdictObject | undefined> {
  if (!SLUG_RE.test(caseId)) return undefined;
  const verdictsDir = join(docketDir, 'reports', 'verdicts');
  const v = await readJsonContained(verdictsDir, join(verdictsDir, `${caseId}.json`));
  return isRecord(v) && typeof v.caseId === 'string' ? (v as unknown as VerdictObject) : undefined;
}

/** GET /api/cases — table rows, resilient to absent reports. */
export async function listCases(docketDir: string): Promise<CaseListing> {
  const { reportsAvailable, results } = await loadReportIndex(docketDir);
  const cases: CaseSummary[] = [];
  for (const slug of await caseDirs(docketDir)) {
    const dir = join(docketDir, 'cases', slug);
    const caseObj = await readJsonContained(dir, join(dir, 'case.json'));
    if (!isRecord(caseObj) || typeof caseObj.caseId !== 'string') {
      cases.push({ slug, error: 'case.json missing or unparseable' });
      continue;
    }
    const gt = await readJsonContained(dir, join(dir, 'groundtruth.json'));
    const summary: CaseSummary = {
      slug,
      caseId: caseObj.caseId,
      caseType: typeof caseObj.caseType === 'string' ? caseObj.caseType : undefined,
      tier: typeof caseObj.tier === 'string' ? caseObj.tier : undefined,
      valueUsd: typeof caseObj.valueUsd === 'number' ? caseObj.valueUsd : undefined,
      decisionSpaceKind:
        isRecord(caseObj.decisionSpace) && typeof caseObj.decisionSpace.kind === 'string'
          ? caseObj.decisionSpace.kind
          : undefined,
    };
    if (isRecord(gt)) {
      if (typeof gt.title === 'string') summary.title = gt.title;
      if (Array.isArray(gt.tags)) summary.tags = gt.tags.filter((t): t is string => typeof t === 'string');
      if (typeof gt.difficulty === 'string') summary.difficulty = gt.difficulty;
    }
    const verdict = await loadVerdict(docketDir, caseObj.caseId);
    if (verdict !== undefined) {
      summary.ruling = verdict.ruling;
      summary.final = verdict.final;
      summary.escalated = verdict.quality?.escalated;
      summary.injectionFlags = verdict.quality?.injectionFlags ?? [];
    }
    const row = results.get(caseObj.caseId);
    if (row !== undefined && typeof row.agreed === 'boolean') summary.agreed = row.agreed;
    cases.push(summary);
  }
  return reportsAvailable ? { reportsAvailable, cases } : { reportsAvailable, hint: REGENERATE_HINT, cases };
}

/** Resolve an id (slug or caseId) to its case directory slug. */
async function resolveSlug(docketDir: string, idOrSlug: string): Promise<string | undefined> {
  if (!SLUG_RE.test(idOrSlug)) return undefined;
  const dirs = await caseDirs(docketDir);
  if (dirs.includes(idOrSlug)) return idOrSlug;
  for (const slug of dirs) {
    const dir = join(docketDir, 'cases', slug);
    const caseObj = await readJsonContained(dir, join(dir, 'case.json'));
    if (isRecord(caseObj) && caseObj.caseId === idOrSlug) return slug;
  }
  return undefined;
}

/** GET /api/cases/:id — full detail incl. recomputed instruction blocks. */
export async function getCase(docketDir: string, idOrSlug: string): Promise<CaseDetail | undefined> {
  const slug = await resolveSlug(docketDir, idOrSlug);
  if (slug === undefined) return undefined;
  const dir = join(docketDir, 'cases', slug);
  const caseRaw = await readJsonContained(dir, join(dir, 'case.json'));
  if (!isRecord(caseRaw) || typeof caseRaw.caseId !== 'string') return undefined;
  const caseObj = caseRaw as unknown as CaseObject;

  const { reportsAvailable, results } = await loadReportIndex(docketDir);
  const detail: CaseDetail = { slug, case: caseObj, reportsAvailable };
  if (!reportsAvailable) detail.hint = REGENERATE_HINT;
  detail.groundTruth = await readJsonContained(dir, join(dir, 'groundtruth.json'));
  detail.verdict = await loadVerdict(docketDir, caseObj.caseId);
  if (SLUG_RE.test(caseObj.caseId)) {
    const archiveDir = join(docketDir, 'reports', 'archive');
    detail.reasoning = await readJsonContained(archiveDir, join(archiveDir, caseObj.caseId, 'reasoning.json'));
  }
  detail.result = results.get(caseObj.caseId);

  // Recompute the tribunal's instruction blocks (deterministic, offline).
  try {
    const plaintext = await loadEvidencePlaintext(dir, caseObj);
    const verified = verifyEvidenceCommitments(caseObj, plaintext);
    const analysis = analyzeDeterministic(caseObj, verified);
    const judicial = buildJudicialInstructions(caseObj, analysis.parsedMandate, analysis.report, caseObj.evidence);
    detail.instructionBlocks = judicial.blocks;
  } catch {
    /* viewer degrades gracefully — blocks stay absent */
  }
  return detail;
}

/** Load a docket case as an SDK-replayable template (sandbox runner input). */
export async function loadTemplate(docketDir: string, idOrSlug: string): Promise<CaseTemplate | undefined> {
  const slug = await resolveSlug(docketDir, idOrSlug);
  if (slug === undefined) return undefined;
  const dir = join(docketDir, 'cases', slug);
  const caseRaw = await readJsonContained(dir, join(dir, 'case.json'));
  if (!isRecord(caseRaw) || typeof caseRaw.caseId !== 'string') return undefined;
  const caseObj = caseRaw as unknown as CaseObject;
  const plaintext = await loadEvidencePlaintext(dir, caseObj);

  let orderMandate: Record<string, unknown> | undefined;
  let deliveryManifest: Record<string, unknown> | undefined;
  const submissions: { requester?: string; worker?: string } = {};
  const extraEvidence: CaseTemplate['extraEvidence'] = [];

  for (const commitment of caseObj.evidence) {
    const text = plaintext[commitment.sha256];
    if (text === undefined) continue; // sealed / mismatched (e.g. forged manifests) — skip
    if (commitment.kind === 'order_mandate') {
      try {
        const parsed = JSON.parse(text) as unknown;
        if (isRecord(parsed)) orderMandate = parsed;
      } catch {
        /* unparseable mandate → template unusable, caught below */
      }
    } else if (commitment.kind === 'delivery_manifest') {
      try {
        const parsed = JSON.parse(text) as unknown;
        if (isRecord(parsed)) deliveryManifest = parsed;
      } catch {
        /* reconstructed run proceeds without the manifest */
      }
    } else if (commitment.kind === 'party_submission' && (commitment.submitter === 'requester' || commitment.submitter === 'worker')) {
      const prior = submissions[commitment.submitter];
      submissions[commitment.submitter] = prior === undefined ? text : `${prior}\n\n${text}`;
    } else {
      const entry: CaseTemplate['extraEvidence'][number] = {
        kind: commitment.kind,
        plaintext: text,
        submitter: commitment.submitter,
        authenticated: commitment.authenticated,
      };
      if (commitment.uri !== undefined) entry.uri = commitment.uri;
      extraEvidence.push(entry);
    }
  }
  if (orderMandate === undefined) return undefined;
  const template: CaseTemplate = { slug, caseObj, orderMandate, submissions, extraEvidence };
  if (deliveryManifest !== undefined) template.deliveryManifest = deliveryManifest;
  return template;
}
