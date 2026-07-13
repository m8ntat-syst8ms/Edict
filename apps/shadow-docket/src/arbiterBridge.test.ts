import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MockProvider, signerAllowlistEnvName } from '@edict/arbiter';
import { resolveArbiter } from './arbiterBridge.js';

const NEARAI_SEAT = {
  seatId: 'nearai:test',
  providerId: 'nearai',
  modelId: 'test-model',
  modelFamily: 'test-family',
};

function withEnv(vars: Record<string, string | undefined>, fn: () => void): void {
  const prior = new Map<string, string | undefined>();
  for (const k of Object.keys(vars)) prior.set(k, process.env[k]);
  try {
    for (const [k, v] of Object.entries(vars)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fn();
  } finally {
    for (const [k, v] of prior) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('resolveArbiter env mode requires a signer allowlist for real attested providers', () => {
  const allowlistEnv = signerAllowlistEnvName('nearai');
  withEnv({ NEARAI_API_KEY: 'test-key', [allowlistEnv]: undefined }, () => {
    assert.throws(
      () => resolveArbiter([NEARAI_SEAT], 'env', mkdtempSync(join(tmpdir(), 'edict-arbiter-env-'))),
      new RegExp(allowlistEnv),
    );
  });
});

test('resolveArbiter env mode passes signer allowlists into proofPolicy', () => {
  const allowlistEnv = signerAllowlistEnvName('nearai');
  withEnv({ NEARAI_API_KEY: 'test-key', [allowlistEnv]: '0xabc, 0xdef' }, () => {
    const resolved = resolveArbiter([NEARAI_SEAT], 'env', mkdtempSync(join(tmpdir(), 'edict-arbiter-env-')));
    assert.equal(resolved.config.requireProofs, true);
    assert.deepEqual(resolved.config.proofPolicy?.signerAllowlist?.nearai, ['0xabc', '0xdef']);
    assert.equal(typeof resolved.config.proofPolicy?.nowUnixMs, 'number');
  });
});

test('resolveArbiter env mode still permits mock substitution without an allowlist', () => {
  const allowlistEnv = signerAllowlistEnvName('nearai');
  withEnv({ NEARAI_API_KEY: undefined, [allowlistEnv]: undefined }, () => {
    const resolved = resolveArbiter([NEARAI_SEAT], 'env', mkdtempSync(join(tmpdir(), 'edict-arbiter-env-')));
    assert.ok(resolved.config.providers.get('nearai') instanceof MockProvider);
    assert.equal(resolved.config.proofPolicy?.signerAllowlist, undefined);
  });
});
