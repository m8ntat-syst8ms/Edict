/**
 * Bench-trial mode tests — OFFLINE (MockProvider / throwing stub only; no
 * API key, no network).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InferenceProvider } from '@edict/core';
import { benchAdjudicate, usageFromCompletionRaw, BENCH_RESULT_TYPE } from './bench.js';
import { MockProvider } from './providers/mock.js';
import { sanitizeName } from './util.js';
import { makeFixture, WORKER_FAVORING_SUBMISSION, NEUTRAL_REQUESTER_SUBMISSION } from './fixtures.js';

function tempArchive(): string {
  return mkdtempSync(join(tmpdir(), 'edict-bench-test-'));
}

/** A provider that MUST NOT be called — proves the model is unused on short-circuits. */
class ThrowingProvider implements InferenceProvider {
  readonly id = 'never-called';
  complete(): never {
    throw new Error('bench called the model on a deterministic short-circuit case');
  }
  getProof(): never {
    throw new Error('bench fetched a proof on a deterministic short-circuit case');
  }
}

test('jury-path case: BenchResult shape — one judge, both orientations, no settlement path', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({
    workerSubmission: WORKER_FAVORING_SUBMISSION,
    requesterSubmission: NEUTRAL_REQUESTER_SUBMISSION,
  });
  const archiveDir = tempArchive();
  const result = await benchAdjudicate(caseObj, evidencePlaintext, {
    provider: new MockProvider('bench-mock'),
    modelId: 'mock-judge-1',
    archiveDir,
  });

  assert.equal(result.benchType, BENCH_RESULT_TYPE);
  assert.equal(result.caseId, caseObj.caseId);
  assert.equal(result.providerId, 'bench-mock');
  assert.equal(result.modelId, 'mock-judge-1');
  assert.equal(result.deterministicShortCircuit, false);
  assert.equal(result.passes.length, 2);
  assert.deepEqual(
    result.passes.map((p) => p.orientation).sort(),
    ['requester_first', 'worker_first'],
  );
  assert.ok(result.outcomes.requester_first !== undefined);
  assert.ok(result.outcomes.worker_first !== undefined);
  assert.equal(result.parsedOk, true);
  assert.equal(typeof result.swapConsistent, 'boolean');
  assert.equal(result.escalatedByGate, false);
  assert.deepEqual(result.escalationReasons, []);

  // A BenchResult is NOT a VerdictObject: nothing downstream can settle it.
  // No execution gate, no jury votes, no ruling field, no award reference.
  const r = result as unknown as Record<string, unknown>;
  assert.equal('final' in r, false, 'BenchResult must not carry the execution gate field');
  assert.equal('votes' in r, false, 'BenchResult must not carry jury votes');
  assert.equal('ruling' in r, false, 'BenchResult must not carry a settleable ruling');
  assert.equal('reasoningSha256' in r, false);
  assert.equal('awardRef' in r, false);
  // And it never writes the settlement artifacts the real pipeline writes.
  const caseDir = join(archiveDir, sanitizeName(caseObj.caseId));
  assert.equal(existsSync(join(caseDir, 'verdict.json')), false, 'bench must never archive a verdict.json');
  // The judge outputs and the bench summary ARE archived, clearly labeled.
  assert.equal(existsSync(join(caseDir, 'bench_mock-judge-1_requester_first.json')), true);
  assert.equal(existsSync(join(caseDir, 'bench_mock-judge-1_worker_first.json')), true);
  assert.equal(existsSync(join(caseDir, 'bench_mock-judge-1_result.json')), true);
});

test('jury-path bench is deterministic with the deterministic mock judge', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({});
  const run = () =>
    benchAdjudicate(caseObj, evidencePlaintext, {
      provider: new MockProvider('bench-mock'),
      modelId: 'mock-judge-1',
      archiveDir: tempArchive(),
    });
  const [a, b] = [await run(), await run()];
  assert.deepEqual(a.outcomes, b.outcomes);
  assert.equal(a.swapConsistent, b.swapConsistent);
  assert.equal(a.parsedOk, b.parsedOk);
});

test('deterministic short-circuit: model unused, reported as such, gate still applied', async () => {
  // A delivery manifest whose mandate binding contradicts the case fires the
  // forged_delivery_manifest short-circuit (rule b) before any model call.
  const { caseObj, evidencePlaintext } = makeFixture({
    manifestText: JSON.stringify({
      version: 'edict-dm-1',
      artifacts: [],
      jobNonce: 'a-different-engagement',
      orderMandateHash: 'ab'.repeat(32),
    }),
  });
  const result = await benchAdjudicate(caseObj, evidencePlaintext, {
    provider: new ThrowingProvider(), // throws if the judge is ever exercised
    modelId: 'claude-sonnet-5',
    archiveDir: tempArchive(),
  });

  assert.equal(result.deterministicShortCircuit, true);
  assert.equal(result.shortCircuitRule, 'forged_delivery_manifest');
  assert.equal(result.passes.length, 0, 'no judge passes on a short-circuit');
  assert.deepEqual(result.outcomes.requester_first, { kind: 'requester_wins' });
  assert.deepEqual(result.outcomes.worker_first, { kind: 'requester_wins' });
  assert.equal(result.swapConsistent, true);
  assert.equal(result.parsedOk, true);
  // Shared gate ran over the flags (deterministic:* flags never escalate).
  assert.equal(result.escalatedByGate, false);
  assert.ok(result.injectionFlags.includes('deterministic:manifest_binding_mismatch'));
  assert.equal(result.usage, undefined);
});

test('usageFromCompletionRaw understands Anthropic and OpenAI shapes, rejects the rest', () => {
  assert.deepEqual(
    usageFromCompletionRaw({ parsed: { usage: { input_tokens: 10, output_tokens: 3 } } }),
    { inputTokens: 10, outputTokens: 3 },
  );
  assert.deepEqual(
    usageFromCompletionRaw({ parsed: { usage: { prompt_tokens: 7, completion_tokens: 2 } } }),
    { inputTokens: 7, outputTokens: 2 },
  );
  assert.equal(usageFromCompletionRaw({ parsed: { usage: {} } }), undefined);
  assert.equal(usageFromCompletionRaw({ parsed: null }), undefined);
  assert.equal(usageFromCompletionRaw({}), undefined);
  assert.equal(usageFromCompletionRaw(null), undefined);
  // MockProvider raw captures carry no parsed body → no usage.
  assert.equal(
    usageFromCompletionRaw({ providerId: 'mock', modelId: 'm', requestSha256: 'x', responseSha256: 'y' }),
    undefined,
  );
});

test('bench sums usage across both passes when the capture reports it', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({});
  // Wrap the mock so each completion carries an Anthropic-shaped usage block.
  const inner = new MockProvider('bench-mock');
  const provider: InferenceProvider = {
    id: 'bench-usage-mock',
    async complete(req) {
      const c = await inner.complete(req);
      return { ...c, raw: { parsed: { usage: { input_tokens: 100, output_tokens: 10 } } } };
    },
    getProof: (ref) => inner.getProof(ref),
  };
  const result = await benchAdjudicate(caseObj, evidencePlaintext, {
    provider,
    modelId: 'mock-judge-1',
    archiveDir: tempArchive(),
  });
  assert.deepEqual(result.usage, { inputTokens: 200, outputTokens: 20 });
});
