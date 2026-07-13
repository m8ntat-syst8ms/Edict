/** Validate the public illustrative fixtures against the canonical shapes. */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadAllCases } from './loadCases.js';
import { errorsOf } from './validate.js';
import type { CaseBundle } from './harnessTypes.js';

const CASES_DIR = fileURLToPath(new URL('../cases/', import.meta.url));
const MANIFEST = fileURLToPath(new URL('../PUBLIC_FIXTURES.json', import.meta.url));

describe('public illustrative cases', () => {
  let bundles: CaseBundle[];
  let declaredCases: string[];

  before(async () => {
    bundles = await loadAllCases(CASES_DIR);
    const manifest = JSON.parse(await readFile(MANIFEST, 'utf8')) as {
      classification: string;
      qualificationEligible: boolean;
      cases: string[];
    };
    assert.equal(manifest.classification, 'illustrative_only');
    assert.equal(manifest.qualificationEligible, false);
    declaredCases = manifest.cases;
  });

  it('matches the committed public-fixture allowlist', () => {
    const loaded = bundles.map((bundle) => bundle.dir.split('/').at(-1)).sort();
    assert.deepEqual(loaded, [...declaredCases].sort());
    assert.equal(bundles.length, 5);
  });

  it('validates with no errors or warnings', () => {
    for (const bundle of bundles) {
      const errors = errorsOf(bundle.issues);
      assert.deepEqual(errors, [], `${bundle.dir}: ${errors.map((issue) => issue.message).join('; ')}`);
      assert.deepEqual(bundle.issues, [], `${bundle.dir} has validation issues`);
      assert.ok(bundle.caseObj);
      assert.ok(bundle.groundTruth);
    }
  });

  it('uses unique matching case identifiers', () => {
    const ids = new Set(bundles.map((bundle) => bundle.caseObj.caseId));
    assert.equal(ids.size, bundles.length);
    for (const bundle of bundles) {
      assert.equal(bundle.groundTruth.caseId, bundle.caseObj.caseId);
    }
  });

  it('contains no qualification or adversarial markers', () => {
    const privateTags = new Set(['adversarial', 'prompt_injection', 'qualification', 'holdout']);
    for (const bundle of bundles) {
      assert.equal(bundle.groundTruth.expectInjectionFlag, undefined, bundle.dir);
      assert.deepEqual(bundle.groundTruth.tags.filter((tag) => privateTags.has(tag)), [], bundle.dir);
    }
  });

  it('demonstrates all three case shapes and escrow outcomes', () => {
    const caseTypes = new Set(bundles.map((bundle) => bundle.caseObj.caseType));
    assert.deepEqual([...caseTypes].sort(), ['bilateral', 'claim', 'public_resolution']);

    const escrowOutcomes = bundles
      .filter((bundle) => bundle.caseObj.decisionSpace.kind === 'escrow_branches')
      .map((bundle) => bundle.groundTruth.expected.kind);
    assert.ok(escrowOutcomes.includes('requester_wins'));
    assert.ok(escrowOutcomes.includes('split'));
  });

  it('keeps evidence plaintext keyed by its SHA-256 commitment', async () => {
    const { sha256Hex } = await import('./hash.js');
    for (const bundle of bundles) {
      for (const [hash, content] of Object.entries(bundle.evidencePlaintext)) {
        assert.equal(sha256Hex(content), hash, `${bundle.dir}: plaintext key/hash mismatch`);
      }
    }
  });

  it('demonstrates categorical and scalar decision spaces', () => {
    const categorical = bundles.find((bundle) => bundle.caseObj.caseType === 'public_resolution');
    assert.ok(categorical);
    assert.equal(categorical.caseObj.publicity, 'public');
    assert.deepEqual(categorical.groundTruth.expected, { kind: 'categorical', outcome: 'NO' });

    const scalar = bundles.find((bundle) => bundle.caseObj.caseType === 'claim');
    assert.ok(scalar);
    assert.equal(scalar.caseObj.decisionSpace.kind, 'bounded_scalar');
    assert.deepEqual(scalar.groundTruth.expected, { kind: 'scalar', value: 30_000 });
  });
});
