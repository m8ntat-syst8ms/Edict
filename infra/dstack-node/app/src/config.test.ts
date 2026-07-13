import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from './config.js';

test('dev config stays lightweight but validates numeric and URL inputs', () => {
  const config = loadConfig({ EDICT_NODE_MODE: 'dev' });
  assert.equal(config.modelIdPin, undefined);
  assert.equal(config.apiKey, undefined);
  assert.equal(config.maxBodyBytes, 10 * 1024 * 1024);
  assert.equal(config.upstreamTimeoutMs, 180_000);
  assert.throws(
    () => loadConfig({ EDICT_NODE_MODE: 'dev', EDICT_NODE_MAX_BODY_BYTES: 'NaN' }),
    /positive integer/,
  );
  assert.throws(
    () => loadConfig({ EDICT_NODE_MODE: 'dev', LOCAL_MODEL_URL: 'file:///tmp/model' }),
    /http: or https:/,
  );
});

test('dstack mode fails closed without a model pin and strong bearer token', () => {
  assert.throws(() => loadConfig({ EDICT_NODE_MODE: 'dstack' }), /EDICT_NODE_MODEL_ID/);
  assert.throws(
    () => loadConfig({ EDICT_NODE_MODE: 'dstack', EDICT_NODE_MODEL_ID: 'gpt-oss-20b' }),
    /EDICT_NODE_API_KEY/,
  );
  assert.throws(
    () => loadConfig({ EDICT_NODE_MODE: 'dstack', EDICT_NODE_MODEL_ID: 'gpt-oss-20b', EDICT_NODE_API_KEY: 'short' }),
    /at least 32/,
  );
});

test('dstack config accepts explicit production requirements', () => {
  const config = loadConfig({
    EDICT_NODE_MODE: 'dstack',
    EDICT_NODE_MODEL_ID: 'gpt-oss-20b',
    EDICT_NODE_API_KEY: 'a'.repeat(64),
    EDICT_NODE_UPSTREAM_TIMEOUT_MS: '240000',
  });
  assert.equal(config.modelIdPin, 'gpt-oss-20b');
  assert.equal(config.apiKey, 'a'.repeat(64));
  assert.equal(config.upstreamTimeoutMs, 240_000);
});
