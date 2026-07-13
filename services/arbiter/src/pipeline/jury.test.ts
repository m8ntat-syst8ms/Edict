/**
 * Reasoning-seat accommodations:
 * - parseJurorOutput strips closed <think>/<reasoning> blocks and any prose
 *   outside the outermost JSON object BEFORE strict parsing — and never
 *   mistakes JSON *inside* a think block for the verdict;
 * - the per-pass completion budget (ArbiterConfig.jurorMaxTokens /
 *   BenchOptions.maxTokens) is plumbed through to provider.complete().
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InferenceProvider, ProviderProof } from '@edict/core';
import { parseJurorOutput, runJury, JUROR_MAX_TOKENS } from './jury.js';
import { benchAdjudicate } from '../bench.js';
import type { ArbiterConfig } from '../config.js';
import { makeFixture } from '../fixtures.js';
import { sha256Hex } from '../util.js';

const VERDICT = JSON.stringify({
  ruling: { kind: 'worker_wins' },
  confidence: 0.8,
  reasons: [{ criterionId: 'AC-1', finding: 'delivered' }],
});

// ---------------------------------------------------------------------------
// parseJurorOutput — think/reasoning stripping
// ---------------------------------------------------------------------------

test('parse: a <think> preamble before the verdict JSON is stripped, parsing stays strict', () => {
  const { caseObj } = makeFixture({ caseId: 'jury-think-1' });
  const text = `<think>\nThe worker delivered. Let me weigh AC-1…\n</think>\n${VERDICT}`;
  const parsed = parseJurorOutput(text, caseObj);
  assert.equal(parsed.parseError, undefined);
  assert.deepEqual(parsed.ruling, { kind: 'worker_wins' });
  assert.equal(parsed.confidence, 0.8);
});

test('parse: <reasoning> blocks (any case) and surrounding prose are stripped', () => {
  const { caseObj } = makeFixture({ caseId: 'jury-think-2' });
  const text = `Sure — here is my verdict.\n<REASONING>step 1… step 2…</REASONING>\n${VERDICT}\nHope this helps!`;
  const parsed = parseJurorOutput(text, caseObj);
  assert.equal(parsed.parseError, undefined);
  assert.deepEqual(parsed.ruling, { kind: 'worker_wins' });
});

test('parse: JSON inside a think block is NEVER taken as the verdict', () => {
  const { caseObj } = makeFixture({ caseId: 'jury-think-3' });
  // The model *considered* requester_wins inside its think block, then ruled
  // worker_wins. Without stripping-before-slicing, the outermost {…} span
  // would swallow the think block's JSON.
  const considered = JSON.stringify({ ruling: { kind: 'requester_wins' }, confidence: 0.9, reasons: [] });
  const withVerdict = parseJurorOutput(`<think>maybe ${considered} ?</think>\n${VERDICT}`, caseObj);
  assert.equal(withVerdict.parseError, undefined);
  assert.deepEqual(withVerdict.ruling, { kind: 'worker_wins' });

  // Think-block-only output (no verdict outside) is a parse failure — the
  // JSON inside the block must not be rescued.
  const thinkOnly = parseJurorOutput(`<think>maybe ${considered} ?</think>`, caseObj);
  assert.notEqual(thinkOnly.parseError, undefined);
  assert.equal(thinkOnly.confidence, 0);
});

test('parse: an unclosed <think> block (budget exhausted mid-think) degrades to a parse failure', () => {
  const { caseObj } = makeFixture({ caseId: 'jury-think-4' });
  const parsed = parseJurorOutput('<think>\nFirst, consider the mandate. The deadline was', caseObj);
  assert.notEqual(parsed.parseError, undefined);
  assert.equal(parsed.confidence, 0);
});

test('parse: fenced verdict after a think block still parses', () => {
  const { caseObj } = makeFixture({ caseId: 'jury-think-5' });
  const parsed = parseJurorOutput(`<think>ok</think>\n\`\`\`json\n${VERDICT}\n\`\`\``, caseObj);
  assert.equal(parsed.parseError, undefined);
  assert.deepEqual(parsed.ruling, { kind: 'worker_wins' });
});

// ---------------------------------------------------------------------------
// Budget plumbing — jurorMaxTokens / BenchOptions.maxTokens
// ---------------------------------------------------------------------------

/** Minimal provider that records the maxTokens of every complete() call. */
class CapturingProvider implements InferenceProvider {
  readonly id: string;
  readonly seenMaxTokens: Array<number | undefined> = [];
  constructor(id: string) {
    this.id = id;
  }
  async complete(req: { modelId: string; messages: Array<{ role: 'system' | 'user'; content: string }>; maxTokens?: number }) {
    this.seenMaxTokens.push(req.maxTokens);
    const requestSha256 = sha256Hex(JSON.stringify(req));
    const responseSha256 = sha256Hex(VERDICT);
    return { text: VERDICT, requestSha256, responseSha256, raw: { modelId: req.modelId, requestSha256, responseSha256 } };
  }
  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as { modelId: string; requestSha256: string; responseSha256: string };
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      fetchedAtUnixMs: 0,
    };
  }
}

class AuditedProvider implements InferenceProvider {
  readonly id = 'cap-audit';

  async complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }) {
    const requestBody = JSON.stringify({
      model: req.modelId,
      messages: req.messages,
      ...(req.maxTokens !== undefined ? { max_tokens: req.maxTokens } : {}),
    });
    const responseBody = JSON.stringify({
      id: 'audit-completion-1',
      choices: [{ message: { content: VERDICT } }],
    });
    const requestSha256 = sha256Hex(requestBody);
    const responseSha256 = sha256Hex(responseBody);
    return {
      text: VERDICT,
      requestSha256,
      responseSha256,
      raw: {
        providerId: this.id,
        modelId: req.modelId,
        requestBody,
        responseBody,
        requestSha256,
        responseSha256,
        status: 200,
        headers: { 'x-receipt-id': 'receipt-1' },
        parsed: JSON.parse(responseBody),
      },
    };
  }

  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as { modelId: string; requestSha256: string; responseSha256: string };
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      fetchedAtUnixMs: 0,
    };
  }
}

function capturingConfig(provider: CapturingProvider, jurorMaxTokens?: number): ArbiterConfig {
  return {
    seats: [{ seatId: `${provider.id}:m`, providerId: provider.id, modelId: 'reasoning-model-1', modelFamily: 'fam' }],
    providers: new Map<string, InferenceProvider>([[provider.id, provider]]),
    archiveDir: mkdtempSync(join(tmpdir(), 'edict-jury-budget-')),
    requireProofs: false,
    ...(jurorMaxTokens !== undefined ? { jurorMaxTokens } : {}),
  };
}

test('jury archive: byte-exact completion capture is archived when provider exposes it', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({ caseId: 'jury-audit-capture' });
  const provider = new AuditedProvider();
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-jury-audit-'));
  await runJury(caseObj, evidencePlaintext, {
    seats: [{ seatId: `${provider.id}:m`, providerId: provider.id, modelId: 'audit-model', modelFamily: 'audit-fam' }],
    providers: new Map<string, InferenceProvider>([[provider.id, provider]]),
    archiveDir,
    requireProofs: false,
  });

  const caseDir = join(archiveDir, caseObj.caseId);
  const archiveFiles = readdirSync(caseDir).filter((f) => f.endsWith('_requester_first.json'));
  assert.equal(archiveFiles.length, 1);
  const archived = JSON.parse(readFileSync(join(caseDir, archiveFiles[0]!), 'utf8')) as {
    completion?: {
      providerId: string;
      modelId: string;
      requestBody: string;
      responseBody: string;
      requestSha256: string;
      responseSha256: string;
      status: number;
      headers: Record<string, string>;
    };
  };
  assert.ok(archived.completion);
  assert.equal(archived.completion.providerId, provider.id);
  assert.equal(archived.completion.modelId, 'audit-model');
  assert.equal(archived.completion.status, 200);
  assert.equal(archived.completion.headers['x-receipt-id'], 'receipt-1');
  assert.equal(archived.completion.requestSha256, sha256Hex(archived.completion.requestBody));
  assert.equal(archived.completion.responseSha256, sha256Hex(archived.completion.responseBody));
});

test('jury budget: config.jurorMaxTokens reaches provider.complete on every pass', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({ caseId: 'jury-budget-1' });
  const provider = new CapturingProvider('cap-a');
  await runJury(caseObj, evidencePlaintext, capturingConfig(provider, 4096));
  assert.deepEqual(provider.seenMaxTokens, [4096, 4096], 'both orientations get the configured budget');
});

test('jury budget: defaults to JUROR_MAX_TOKENS when jurorMaxTokens is unset', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({ caseId: 'jury-budget-2' });
  const provider = new CapturingProvider('cap-b');
  await runJury(caseObj, evidencePlaintext, capturingConfig(provider));
  assert.deepEqual(provider.seenMaxTokens, [JUROR_MAX_TOKENS, JUROR_MAX_TOKENS]);
});

test('bench budget: BenchOptions.maxTokens reaches the judge (default JUROR_MAX_TOKENS)', async () => {
  const { caseObj, evidencePlaintext } = makeFixture({ caseId: 'jury-budget-bench' });
  const custom = new CapturingProvider('cap-c');
  await benchAdjudicate(caseObj, evidencePlaintext, {
    provider: custom,
    modelId: 'reasoning-model-1',
    archiveDir: mkdtempSync(join(tmpdir(), 'edict-bench-budget-')),
    maxTokens: 8192,
  });
  assert.deepEqual(custom.seenMaxTokens, [8192, 8192]);

  const dflt = new CapturingProvider('cap-d');
  await benchAdjudicate(caseObj, evidencePlaintext, {
    provider: dflt,
    modelId: 'reasoning-model-1',
    archiveDir: mkdtempSync(join(tmpdir(), 'edict-bench-budget-')),
  });
  assert.deepEqual(dflt.seenMaxTokens, [JUROR_MAX_TOKENS, JUROR_MAX_TOKENS]);
});
