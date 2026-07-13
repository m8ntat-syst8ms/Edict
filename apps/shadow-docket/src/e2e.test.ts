/** End-to-end replay over the public illustrative docket. */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { loadAllCases } from './loadCases.js';
import { baselineAdjudicate, DEFAULT_MOCK_SEATS, buildLocalMockProviders, screenForInjection } from './baselineArbiter.js';
import { aggregate, evaluateCase, renderMarkdown, type CaseResult } from './report.js';
import type { CaseBundle } from './harnessTypes.js';
import type { VerdictObject } from '@edict/core';
import { validateOutcome } from '@edict/core';

const CASES_DIR = fileURLToPath(new URL('../cases/', import.meta.url));
const config = { seats: DEFAULT_MOCK_SEATS, providers: buildLocalMockProviders(DEFAULT_MOCK_SEATS) };

describe('public docket e2e (offline baseline)', () => {
  let bundles: CaseBundle[];
  const verdicts = new Map<string, VerdictObject>();
  const results: CaseResult[] = [];

  before(async () => {
    bundles = await loadAllCases(CASES_DIR);
    for (const bundle of bundles) {
      const verdict = await baselineAdjudicate(bundle.caseObj, bundle.evidencePlaintext, config);
      verdicts.set(bundle.dir, verdict);
      results.push(evaluateCase(bundle.groundTruth, verdict, bundle.caseObj));
    }
  });

  it('keeps every outcome inside its committed Decision Space', () => {
    for (const bundle of bundles) {
      const verdict = verdicts.get(bundle.dir)!;
      assert.deepEqual(
        validateOutcome(verdict.ruling, bundle.caseObj.decisionSpace),
        [],
        `${bundle.dir}: ${JSON.stringify(verdict.ruling)}`,
      );
    }
    for (const result of results) assert.deepEqual(result.invariantViolations, [], result.caseId);
  });

  it('runs the full mock jury structure for escrow decisions', () => {
    for (const bundle of bundles.filter((item) => item.caseObj.decisionSpace.kind === 'escrow_branches')) {
      const verdict = verdicts.get(bundle.dir)!;
      assert.equal(verdict.votes.length, 3, bundle.dir);
      for (const vote of verdict.votes) {
        assert.deepEqual(vote.passes.map((pass) => pass.orientation).sort(), ['requester_first', 'worker_first']);
        for (const pass of vote.passes) {
          assert.match(pass.proof.requestSha256, /^[0-9a-f]{64}$/);
          assert.equal(pass.proof.signatureScheme, 'none_mock');
        }
      }
    }
  });

  it('is deterministic across repeated runs', async () => {
    for (const bundle of bundles) {
      const repeated = await baselineAdjudicate(bundle.caseObj, bundle.evidencePlaintext, config);
      assert.deepEqual(repeated, verdicts.get(bundle.dir), bundle.dir);
    }
  });

  it('decides the illustrative archetypes as expected', () => {
    const bySlug = (fragment: string) => {
      const bundle = bundles.find((item) => item.dir.includes(fragment))!;
      return verdicts.get(bundle.dir)!;
    };
    assert.equal(bySlug('c05-clean-non-delivery').ruling.kind, 'requester_wins');
    const split = bySlug('c12-milestone-split').ruling;
    assert.equal(split.kind, 'split');
    assert.equal(split.kind === 'split' ? split.requesterBps : -1, 5000);
    assert.deepEqual(bySlug('c13-ufo-declassification-challenge').ruling, { kind: 'categorical', outcome: 'NO' });
    assert.deepEqual(bySlug('c14-agent-liability-quantum').ruling, { kind: 'scalar', value: 30_000 });
  });

  it('has no attack-level flags in the public examples', () => {
    for (const bundle of bundles) {
      assert.deepEqual(
        screenForInjection(bundle.caseObj.evidence, bundle.evidencePlaintext),
        [],
        `${bundle.dir} false-positive injection flags`,
      );
    }
  });

  it('passes the illustrative replay gate without claiming qualification', () => {
    const aggregates = aggregate(results);
    assert.equal(aggregates.totalCases, 5);
    assert.equal(aggregates.agreed, 5);
    assert.equal(aggregates.injectionCases, 0);
    assert.equal(aggregates.screenFalsePositives, 0);
    assert.equal(aggregates.gate.pass, true);
  });

  it('reports all public case shapes', () => {
    const aggregates = aggregate(results);
    const byType = Object.fromEntries(aggregates.byCaseType.map((entry) => [entry.caseType, entry]));
    assert.equal(byType.bilateral?.total, 3);
    assert.equal(byType.public_resolution?.total, 1);
    assert.equal(byType.claim?.total, 1);
  });

  it('renders a complete public replay report', () => {
    const markdown = renderMarkdown(results, aggregate(results), {
      arbiterSource: 'builtin-baseline',
      seats: DEFAULT_MOCK_SEATS,
      casesDir: CASES_DIR,
      generatedAtIso: '2026-07-08T00:00:00.000Z',
    });
    for (const bundle of bundles) assert.ok(markdown.includes(bundle.groundTruth.title));
    assert.ok(markdown.includes('## Quality gate'));
    assert.ok(markdown.includes('outcome:NO'));
    assert.ok(markdown.includes('quantum:30000'));
  });
});
