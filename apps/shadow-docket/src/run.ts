#!/usr/bin/env node
/**
 * Shadow-docket CLI.
 *
 *   shadow-docket run      [--seats <file>] [--cases <dir>] [--out <dir>]
 *                          [--providers mock|env] [--strict]
 *   shadow-docket validate [--cases <dir>] [--seats <file>]
 *   shadow-docket rehash   [--cases <dir>]
 *
 * `run` replays every case through the arbiter and writes per-case verdicts
 * plus report.md / report.json. Offline by default (mock providers).
 * `validate` checks cases + seats without adjudicating. `rehash` recomputes
 * evidence hashes into case.json after evidence files are edited.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadAllCases } from './loadCases.js';
import { asSeats, errorsOf, validateSeats } from './validate.js';
import { resolveArbiter, type ProviderMode } from './arbiterBridge.js';
import {
  aggregate,
  errorResult,
  evaluateCase,
  placementSkipReason,
  renderMarkdown,
  skippedResult,
  type CaseResult,
} from './report.js';
import { sha256Hex } from './hash.js';
import type { CaseBundle, ValidationIssue } from './harnessTypes.js';

const PKG_ROOT = fileURLToPath(new URL('..', import.meta.url));

interface CliArgs {
  command: 'run' | 'validate' | 'rehash';
  seats: string;
  cases: string;
  out: string;
  providers: ProviderMode;
  strict: boolean;
}

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    command: 'run',
    seats: path.join(PKG_ROOT, 'seats', 'mock-seats.json'),
    cases: path.join(PKG_ROOT, 'cases'),
    out: path.join(PKG_ROOT, 'reports'),
    providers: 'mock',
    strict: false,
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--seats': args.seats = argv[++i] ?? args.seats; break;
      case '--cases': args.cases = argv[++i] ?? args.cases; break;
      case '--out': args.out = argv[++i] ?? args.out; break;
      case '--providers': {
        const v = argv[++i];
        if (v !== 'mock' && v !== 'env') throw new Error(`--providers must be mock|env, got '${v}'`);
        args.providers = v;
        break;
      }
      case '--strict': args.strict = true; break;
      default:
        if (a.startsWith('--')) throw new Error(`unknown flag: ${a}`);
        positional.push(a);
    }
  }
  const cmd = positional[0] ?? 'run';
  if (cmd !== 'run' && cmd !== 'validate' && cmd !== 'rehash') {
    throw new Error(`unknown command: ${cmd} (expected run | validate | rehash)`);
  }
  args.command = cmd;
  return args;
}

function printIssues(prefix: string, issues: ValidationIssue[]): void {
  for (const i of issues) {
    console.error(`  [${i.level}] ${prefix}${i.path}: ${i.message}`);
  }
}

async function loadSeatsFile(file: string): Promise<ReturnType<typeof asSeats>> {
  const raw = JSON.parse(await readFile(file, 'utf8')) as unknown;
  const issues = validateSeats(raw);
  if (errorsOf(issues).length > 0) {
    printIssues(`${file} `, issues);
    throw new Error(`invalid seats file: ${file}`);
  }
  return asSeats(raw);
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------

export async function runDocket(args: CliArgs): Promise<{ results: CaseResult[]; gatePass: boolean }> {
  const seats = await loadSeatsFile(args.seats);
  const archiveDir = path.join(args.out, 'archive');
  await mkdir(archiveDir, { recursive: true });
  const arbiter = resolveArbiter(seats, args.providers, archiveDir);
  console.log(`shadow-docket: adjudicator = ${arbiter.source}`);

  const bundles = await loadAllCases(args.cases);
  if (bundles.length === 0) throw new Error(`no case directories found under ${args.cases}`);

  const verdictsDir = path.join(args.out, 'verdicts');
  await mkdir(verdictsDir, { recursive: true });

  const results: CaseResult[] = [];
  for (const bundle of bundles) {
    const name = path.basename(bundle.dir);
    const errors = errorsOf(bundle.issues);
    const warns = bundle.issues.filter((i) => i.level === 'warn');
    if (warns.length > 0) printIssues(`${name}/`, warns);
    if (errors.length > 0 || !bundle.caseObj || !bundle.groundTruth) {
      printIssues(`${name}/`, errors);
      results.push(
        errorResult(
          bundle.groundTruth ?? { caseId: bundle.caseObj?.caseId ?? name },
          `case failed validation (${errors.length} error(s))`,
          bundle.caseObj?.caseType,
        ),
      );
      continue;
    }
    // Per-tier placement precheck : a case this roster cannot seat
    // (e.g. tier C under a 2-operator roster) is SKIPPED gracefully and
    // reported, never crashed into an adjudication error.
    const skipReason = placementSkipReason(bundle.caseObj.tier, seats);
    if (skipReason !== undefined) {
      console.log(`  skipped ${name} — ${skipReason}`);
      results.push(skippedResult(bundle.groundTruth, skipReason, bundle.caseObj.caseType));
      continue;
    }
    try {
      const verdict = await arbiter.adjudicate(bundle.caseObj, bundle.evidencePlaintext, arbiter.config);
      await writeFile(
        path.join(verdictsDir, `${bundle.caseObj.caseId}.json`),
        JSON.stringify(verdict, null, 2) + '\n',
        'utf8',
      );
      results.push(evaluateCase(bundle.groundTruth, verdict, bundle.caseObj));
      console.log(`  adjudicated ${name} → ${JSON.stringify(verdict.ruling)}`);
    } catch (e) {
      console.error(`  adjudication error in ${name}: ${(e as Error).message}`);
      results.push(errorResult(bundle.groundTruth, `adjudication threw: ${(e as Error).message}`, bundle.caseObj.caseType));
    }
  }

  const agg = aggregate(results);
  const md = renderMarkdown(results, agg, {
    arbiterSource: arbiter.source,
    seats,
    casesDir: args.cases,
    generatedAtIso: new Date().toISOString(),
  });
  await writeFile(path.join(args.out, 'report.md'), md, 'utf8');
  await writeFile(
    path.join(args.out, 'report.json'),
    JSON.stringify({ aggregates: agg, results }, null, 2) + '\n',
    'utf8',
  );

  console.log('');
  console.log(`agreement ${agg.agreed}/${agg.totalCases} (${(agg.agreementRate * 100).toFixed(1)}%), ` +
    (agg.skipped > 0
      ? `eligible-subset agreement ${agg.agreed}/${agg.eligibleCases} (${(agg.eligibleAgreementRate * 100).toFixed(1)}%), ` +
        `skipped by placement ${agg.skipped}, `
      : '') +
    `injection catch ${agg.injectionCaught}/${agg.injectionCases}, ` +
    `injection flips ${agg.injectionFlips}/${agg.injectionCases}, ` +
    `screen FP ${agg.screenFalsePositives}/${agg.screenFalsePositiveEligible}, ` +
    `mean swap-flip ${(agg.meanSwapFlipRate * 100).toFixed(1)}%, ` +
    `escalations ${agg.escalated}/${agg.totalCases}`);
  console.log(`Quality gate: ${agg.gate.pass ? 'PASS' : 'FAIL'}`);
  console.log(`report: ${path.join(args.out, 'report.md')}`);
  return { results, gatePass: agg.gate.pass };
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

export async function validateDocket(args: CliArgs): Promise<boolean> {
  let ok = true;
  try {
    await loadSeatsFile(args.seats);
    console.log(`seats OK: ${args.seats}`);
  } catch {
    ok = false;
  }
  const bundles = await loadAllCases(args.cases);
  for (const bundle of bundles) {
    const name = path.basename(bundle.dir);
    const errors = errorsOf(bundle.issues);
    if (bundle.issues.length > 0) printIssues(`${name}/`, bundle.issues);
    if (errors.length > 0) ok = false;
    else console.log(`case OK: ${name} (${Object.keys(bundle.evidencePlaintext).length} evidence items)`);
  }
  console.log(ok ? 'validation PASSED' : 'validation FAILED');
  return ok;
}

// ---------------------------------------------------------------------------
// rehash — recompute evidence hashes into case.json after editing evidence
// ---------------------------------------------------------------------------

export async function rehashCases(casesRoot: string): Promise<void> {
  const { readdir } = await import('node:fs/promises');
  const entries = await readdir(casesRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(casesRoot, entry.name);
    const caseFile = path.join(dir, 'case.json');
    let caseJson: Record<string, unknown>;
    try {
      caseJson = JSON.parse(await readFile(caseFile, 'utf8')) as Record<string, unknown>;
    } catch {
      console.error(`  skipping ${entry.name}: no readable case.json`);
      continue;
    }
    const evidence = Array.isArray(caseJson.evidence) ? (caseJson.evidence as Array<Record<string, unknown>>) : [];
    let mandateHash: string | undefined;
    let manifestHash: string | undefined;
    for (const commitment of evidence) {
      const uri = commitment.uri;
      if (typeof uri !== 'string' || !uri.startsWith('evidence/')) continue;
      const raw = await readFile(path.join(dir, uri), 'utf8');
      const h = sha256Hex(raw);
      commitment.sha256 = h;
      if (commitment.kind === 'order_mandate' && mandateHash === undefined) mandateHash = h;
      if (commitment.kind === 'delivery_manifest' && manifestHash === undefined) manifestHash = h;
    }
    if (mandateHash !== undefined) caseJson.orderMandateHash = mandateHash;
    if (caseJson.deliveryManifestHash !== undefined && manifestHash !== undefined) {
      caseJson.deliveryManifestHash = manifestHash;
    }
    await writeFile(caseFile, JSON.stringify(caseJson, null, 2) + '\n', 'utf8');
    console.log(`  rehashed ${entry.name}`);
  }
}

// ---------------------------------------------------------------------------

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  switch (args.command) {
    case 'run': {
      const { gatePass } = await runDocket(args);
      return gatePass || !args.strict ? 0 : 2;
    }
    case 'validate':
      return (await validateDocket(args)) ? 0 : 1;
    case 'rehash':
      await rehashCases(args.cases);
      return 0;
  }
}

const invokedDirectly =
  typeof process.argv[1] === 'string' && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedDirectly) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((e) => {
      console.error(`shadow-docket: ${(e as Error).message}`);
      process.exitCode = 1;
    });
}
