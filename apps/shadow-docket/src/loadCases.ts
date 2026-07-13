/**
 * Case loader. A docket case is a directory:
 *
 *   cases/<slug>/
 *     case.json          — canonical CaseObject (hashes cross-checked below)
 *     groundtruth.json   — expected outcome + rationale + tags (never shown to the arbiter)
 *     evidence/<files>   — plaintext for every EvidenceCommitment; commitment.uri
 *                          is the dir-relative path ("evidence/<name>") and
 *                          commitment.sha256 MUST equal sha256(file bytes).
 */
import { readdir, readFile } from 'node:fs/promises';
import * as path from 'node:path';
import { asCaseObject, asGroundTruth, errorsOf, validateCaseObject, validateGroundTruth } from './validate.js';
import { sha256Hex } from './hash.js';
import type { CaseBundle, ValidationIssue } from './harnessTypes.js';

async function readJson(file: string): Promise<{ value?: unknown; issue?: ValidationIssue }> {
  let raw: string;
  try {
    raw = await readFile(file, 'utf8');
  } catch (e) {
    return { issue: { level: 'error', path: file, message: `cannot read file: ${(e as Error).message}` } };
  }
  try {
    return { value: JSON.parse(raw) };
  } catch (e) {
    return { issue: { level: 'error', path: file, message: `invalid JSON: ${(e as Error).message}` } };
  }
}

/** Load and fully validate a single case directory. Never throws; issues are collected. */
export async function loadCaseDir(dir: string): Promise<CaseBundle> {
  const issues: ValidationIssue[] = [];
  const bundle: CaseBundle = {
    dir,
    caseObj: undefined as unknown as CaseBundle['caseObj'],
    groundTruth: undefined as unknown as CaseBundle['groundTruth'],
    evidencePlaintext: {},
    issues,
  };

  const caseRead = await readJson(path.join(dir, 'case.json'));
  if (caseRead.issue) issues.push(caseRead.issue);
  const gtRead = await readJson(path.join(dir, 'groundtruth.json'));
  if (gtRead.issue) issues.push(gtRead.issue);

  if (caseRead.value !== undefined) {
    const caseIssues = validateCaseObject(caseRead.value);
    issues.push(...caseIssues);
    if (errorsOf(caseIssues).length === 0) bundle.caseObj = asCaseObject(caseRead.value);
  }
  if (gtRead.value !== undefined) {
    const gtIssues = validateGroundTruth(gtRead.value, bundle.caseObj);
    issues.push(...gtIssues);
    if (errorsOf(gtIssues).length === 0) bundle.groundTruth = asGroundTruth(gtRead.value);
  }
  if (!bundle.caseObj) return bundle;

  // Unseal evidence: read each commitment's file, verify hash, key plaintext by sha256.
  const referenced = new Set<string>();
  for (const [i, commitment] of bundle.caseObj.evidence.entries()) {
    const p = `case.evidence[${i}]`;
    if (!commitment.uri || !commitment.uri.startsWith('evidence/')) {
      issues.push({ level: 'error', path: `${p}.uri`, message: 'docket cases must set uri to a dir-relative "evidence/<file>" path' });
      continue;
    }
    referenced.add(commitment.uri);
    let raw: string;
    try {
      raw = await readFile(path.join(dir, commitment.uri), 'utf8');
    } catch (e) {
      issues.push({ level: 'error', path: `${p}.uri`, message: `evidence file missing: ${(e as Error).message}` });
      continue;
    }
    const actual = sha256Hex(raw);
    if (actual !== commitment.sha256) {
      issues.push({
        level: 'error',
        path: `${p}.sha256`,
        message: `commitment hash mismatch for ${commitment.uri}: committed ${commitment.sha256.slice(0, 12)}…, file hashes to ${actual.slice(0, 12)}… (run \`shadow-docket rehash\` after editing evidence)`,
      });
      continue;
    }
    bundle.evidencePlaintext[commitment.sha256] = raw;
  }

  // Unreferenced files under evidence/ are probably authoring mistakes.
  try {
    const files = await readdir(path.join(dir, 'evidence'));
    for (const f of files) {
      if (!referenced.has(`evidence/${f}`)) {
        issues.push({ level: 'warn', path: `evidence/${f}`, message: 'file present but not referenced by any evidence commitment' });
      }
    }
  } catch {
    issues.push({ level: 'error', path: 'evidence/', message: 'evidence directory missing' });
  }

  return bundle;
}

/** Load every case directory under a root (sorted by directory name for stable ordering). */
export async function loadAllCases(root: string): Promise<CaseBundle[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const dirs = entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
  const bundles: CaseBundle[] = [];
  for (const name of dirs) {
    bundles.push(await loadCaseDir(path.join(root, name)));
  }
  return bundles;
}
