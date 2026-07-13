#!/usr/bin/env node
/**
 * edict-lint — pre-commitment OrderMandate linter.
 *
 *   edict-lint <mandate.json> [--json] [--no-screen]
 *
 *   --json       print the LintReport as JSON instead of the readable report
 *   --no-screen  skip the injection screen pass (trusted-template workflows)
 *
 * Exit codes: 0 clean-or-advisory, 1 at least one error-severity finding,
 * 2 usage / unreadable / unparseable input.
 */
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import type { OrderMandate } from '@edict/core';
import { canonicalOrderMandateHash } from '@edict/evidence';
import { lintMandate, type LintFinding, type LintSeverity } from './lint.js';

function usage(): never {
  console.error('usage: edict-lint <mandate.json> [--json] [--no-screen]');
  process.exit(2);
}

function renderFinding(f: LintFinding): string {
  const sev = f.severity.toUpperCase().padEnd(5);
  const crit = f.criterionId !== undefined ? ` [${f.criterionId}]` : '';
  const lines = [`${sev} ${f.code}${crit}: ${f.message}`];
  if (f.suggestion !== undefined) lines.push(`      ↳ ${f.suggestion}`);
  return lines.join('\n');
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    options: {
      json: { type: 'boolean', default: false },
      'no-screen': { type: 'boolean', default: false },
    },
    allowPositionals: true,
  });
  if (positionals.length !== 1) usage();
  const path = positionals[0] as string;

  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (e) {
    console.error(`edict-lint: cannot read ${path}: ${(e as Error).message}`);
    process.exit(2);
  }
  let mandate: unknown;
  try {
    mandate = JSON.parse(raw);
  } catch (e) {
    console.error(`edict-lint: ${path} is not valid JSON: ${(e as Error).message}`);
    process.exit(2);
  }

  const report = lintMandate(mandate as OrderMandate, { screen: values['no-screen'] !== true });

  if (values.json === true) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    let hashLine: string;
    try {
      hashLine = canonicalOrderMandateHash(mandate as OrderMandate);
    } catch {
      hashLine = 'unavailable (mandate not canonically hashable)';
    }
    const counts: Record<LintSeverity, number> = { error: 0, warn: 0, info: 0 };
    for (const f of report.findings) counts[f.severity] += 1;

    const lines = [
      `edict-lint: ${path}`,
      `mandate hash (canonical): ${hashLine}`,
      `score: ${report.score}/100`,
      `machine coverage: ${report.machineCoverage.checked}/${report.machineCoverage.total} criteria machine-checkable (${report.machineCoverage.pct}%)`,
      '',
    ];
    if (report.findings.length === 0) {
      lines.push('no findings — mandate is lint-clean.');
    } else {
      for (const f of report.findings) lines.push(renderFinding(f));
      lines.push('', `${counts.error} error(s), ${counts.warn} warning(s), ${counts.info} info`);
    }
    console.log(lines.join('\n'));
  }

  process.exit(report.findings.some((f) => f.severity === 'error') ? 1 : 0);
}

main().catch((e) => {
  console.error(`edict-lint: unexpected failure: ${(e as Error).stack ?? String(e)}`);
  process.exit(2);
});
