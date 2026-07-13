/**
 * Integration: lint the mandates from apps/shadow-docket/cases.
 *
 * The public examples intentionally retain hash-committed `edict-om-1` evidence to
 * exercise ingestion compatibility. The loader normalizes `permittedRulings`
 * to an escrow DecisionSpace before linting. Current-schema mandates pass
 * through unchanged.
 *
 * Pinned expectation:
 *  - c01 (minerals attestation) must score high on machine coverage
 *    (100% machine-checkable) and lint free of error-severity findings.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { OrderMandate } from '@edict/core';
import { lintMandate, type LintReport } from './index.js';

const CASES_DIR = fileURLToPath(new URL('../../../apps/shadow-docket/cases', import.meta.url));

/** Normalize a compatibility fixture without changing its committed bytes. */
function upgradeMandate(raw: Record<string, unknown>): OrderMandate {
  if (raw.decisionSpace === undefined && Array.isArray(raw.permittedRulings)) {
    const { permittedRulings, ...rest } = raw;
    return { ...rest, decisionSpace: { kind: 'escrow_branches', permitted: permittedRulings } } as unknown as OrderMandate;
  }
  return raw as unknown as OrderMandate;
}

/** Every evidence/*.json across the docket whose bytes parse to an OrderMandate. */
function loadDocketMandates(): Map<string, OrderMandate> {
  const mandates = new Map<string, OrderMandate>();
  for (const caseDir of readdirSync(CASES_DIR).sort()) {
    const evidenceDir = join(CASES_DIR, caseDir, 'evidence');
    let files: string[];
    try {
      files = readdirSync(evidenceDir);
    } catch {
      continue;
    }
    for (const f of files) {
      if (!f.endsWith('.json')) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(join(evidenceDir, f), 'utf8'));
      } catch {
        continue;
      }
      if (typeof parsed === 'object' && parsed !== null && (parsed as Record<string, unknown>).version === 'edict-om-1') {
        mandates.set(caseDir, upgradeMandate(parsed as Record<string, unknown>));
      }
    }
  }
  return mandates;
}

const mandates = loadDocketMandates();
const reports = new Map<string, LintReport>();
for (const [caseDir, om] of mandates) reports.set(caseDir, lintMandate(om));

function reportFor(prefix: string): LintReport {
  for (const [caseDir, report] of reports) {
    if (caseDir.startsWith(prefix)) return report;
  }
  throw new Error(`no docket mandate found for ${prefix}`);
}

describe('shadow-docket mandates', () => {
  it('finds and lints every docket mandate without throwing', () => {
    assert.equal(mandates.size, 5, `expected 5 public example mandates, found ${mandates.size}`);
    for (const [caseDir, report] of reports) {
      assert.ok(Number.isInteger(report.score) && report.score >= 0 && report.score <= 100, caseDir);
      assert.ok(report.machineCoverage.total >= 1, `${caseDir}: mandate has no criteria`);
      for (const f of report.findings) {
        assert.ok(['error', 'warn', 'info'].includes(f.severity), caseDir);
        assert.ok(f.code.length > 0 && f.message.length > 0, caseDir);
      }
    }
  });

  it('c01 (minerals attestation) scores high on machine coverage and has no errors', () => {
    const report = reportFor('c01');
    assert.deepEqual(report.machineCoverage, { checked: 2, total: 2, pct: 100 });
    assert.equal(report.findings.filter((f) => f.severity === 'error').length, 0);
    assert.ok(report.score >= 90, `c01 score ${report.score} — expected a high-scoring mandate`);
  });

  it('c13 categorical mandate has a structurally valid decision space', () => {
    const report = reportFor('c13');
    assert.equal(report.findings.filter((f) => f.code === 'decision-space-invalid').length, 0);
  });

  it('c14 bounded-scalar mandate matches the USD price semantics', () => {
    const report = reportFor('c14');
    assert.equal(report.findings.filter((f) => f.code === 'scalar-unit-mismatch').length, 0);
    assert.equal(report.findings.filter((f) => f.code === 'decision-space-invalid').length, 0);
  });

  it('no docket mandate carries attack-level injection content', () => {
    for (const [caseDir, report] of reports) {
      assert.equal(
        report.findings.filter((f) => f.code === 'injection-attack').length,
        0,
        `${caseDir}: docket mandates are drafted clean — attacks live in the pleadings, not the mandates`,
      );
    }
  });
});
