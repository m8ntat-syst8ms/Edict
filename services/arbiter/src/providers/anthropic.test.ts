/**
 * AnthropicProvider unit tests — OFFLINE. The fetch implementation is a stub
 * injected via opts.fetchImpl; the real Anthropic API is NEVER called and no
 * API key is required by these tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AnthropicProvider,
  ANTHROPIC_BENCH_PROVIDER_ID,
  ANTHROPIC_VERSION,
} from './anthropic.js';
import { sha256Hex } from '../util.js';

interface CapturedRequest {
  url: string;
  method: string | undefined;
  headers: Record<string, string>;
  body: string;
}

/** Build a stub fetch returning a canned Messages-API response. */
function stubFetch(
  captured: CapturedRequest[],
  responseJson: unknown,
  status = 200,
): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    captured.push({
      url: String(input),
      method: init?.method,
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [
          k.toLowerCase(),
          v,
        ]),
      ),
      body: String(init?.body),
    });
    return new Response(JSON.stringify(responseJson), {
      status,
      headers: { 'content-type': 'application/json', 'request-id': 'req_test_1' },
    });
  }) as typeof fetch;
}

const OK_RESPONSE = {
  id: 'msg_test',
  type: 'message',
  model: 'claude-sonnet-5',
  content: [
    // A thinking block must be filtered out of the extracted text.
    { type: 'thinking', thinking: 'internal reasoning', signature: 'sig' },
    { type: 'text', text: '{"ruling":{"kind":"worker_wins"},' },
    { type: 'text', text: '"confidence":0.9,"reasons":[]}' },
  ],
  stop_reason: 'end_turn',
  usage: { input_tokens: 1234, output_tokens: 56 },
};

const MESSAGES: Array<{ role: 'system' | 'user'; content: string }> = [
  { role: 'system', content: 'You are one seat on a multi-model jury.' },
  { role: 'user', content: '=== CASE FILE ===\nCASE: test' },
];

test('maps {system,user} messages to the Messages API shape with exact headers', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({ apiKey: 'test-key', fetchImpl: stubFetch(captured, OK_RESPONSE) });

  const completion = await provider.complete({
    modelId: 'claude-sonnet-5',
    messages: MESSAGES,
    maxTokens: 1024,
  });

  assert.equal(captured.length, 1);
  const req = captured[0]!;
  assert.equal(req.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(req.method, 'POST');
  assert.equal(req.headers['x-api-key'], 'test-key');
  assert.equal(req.headers['anthropic-version'], ANTHROPIC_VERSION);
  assert.equal(req.headers['content-type'], 'application/json');

  const body = JSON.parse(req.body) as Record<string, unknown>;
  assert.equal(body.model, 'claude-sonnet-5');
  assert.equal(body.max_tokens, 1024);
  assert.equal(body.system, 'You are one seat on a multi-model jury.');
  assert.deepEqual(body.messages, [{ role: 'user', content: '=== CASE FILE ===\nCASE: test' }]);
  // Sonnet 5 rejects non-default sampling params — temperature must be OMITTED.
  assert.equal('temperature' in body, false);
  // …and omitting `thinking` on Sonnet 5 would silently enable adaptive
  // thinking, so the explicit disable must be present.
  assert.deepEqual(body.thinking, { type: 'disabled' });

  // Byte-exact capture: hashes cover exactly the bytes sent/received.
  assert.equal(completion.requestSha256, sha256Hex(req.body));
  assert.equal(completion.responseSha256, sha256Hex(JSON.stringify(OK_RESPONSE)));
  // Text extraction joins text blocks and drops the thinking block.
  assert.equal(completion.text, '{"ruling":{"kind":"worker_wins"},"confidence":0.9,"reasons":[]}');
});

test('sends temperature 0 to models that still accept sampling params', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({ apiKey: 'k', fetchImpl: stubFetch(captured, OK_RESPONSE) });
  await provider.complete({ modelId: 'claude-sonnet-4-6', messages: MESSAGES, maxTokens: 512 });
  const body = JSON.parse(captured[0]!.body) as Record<string, unknown>;
  assert.equal(body.temperature, 0);
  assert.deepEqual(body.thinking, { type: 'disabled' });
});

test('omits both temperature and thinking for always-on-thinking models (fable)', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({ apiKey: 'k', fetchImpl: stubFetch(captured, OK_RESPONSE) });
  await provider.complete({ modelId: 'claude-fable-5', messages: MESSAGES });
  const body = JSON.parse(captured[0]!.body) as Record<string, unknown>;
  assert.equal('temperature' in body, false);
  assert.equal('thinking' in body, false);
  // max_tokens is required by the Messages API — defaulted when unset.
  assert.equal(body.max_tokens, 1024);
});

test('getProof returns the UNATTESTED bench proof (none_mock, anthropic-bench)', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({ apiKey: 'k', fetchImpl: stubFetch(captured, OK_RESPONSE) });
  const completion = await provider.complete({ modelId: 'claude-sonnet-5', messages: MESSAGES, maxTokens: 64 });
  const proof = await provider.getProof(completion.raw);
  assert.equal(proof.providerId, ANTHROPIC_BENCH_PROVIDER_ID);
  assert.equal(provider.id, ANTHROPIC_BENCH_PROVIDER_ID);
  assert.equal(proof.signatureScheme, 'none_mock');
  assert.equal(proof.modelId, 'claude-sonnet-5');
  assert.equal(proof.requestSha256, completion.requestSha256);
  assert.equal(proof.responseSha256, completion.responseSha256);
  // No attestation exists on the bench path — it must never pass the gate.
  assert.equal(proof.attestationRef, undefined);
  assert.equal(proof.signature, undefined);
});

test('non-2xx responses throw with the response body excerpt', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({
    apiKey: 'k',
    fetchImpl: stubFetch(captured, { type: 'error', error: { type: 'invalid_request_error', message: 'bad' } }, 400),
  });
  await assert.rejects(
    provider.complete({ modelId: 'claude-sonnet-5', messages: MESSAGES, maxTokens: 64 }),
    /HTTP 400/,
  );
});

test('missing API key fails fast without any network call', async () => {
  const captured: CapturedRequest[] = [];
  const provider = new AnthropicProvider({ apiKey: '', fetchImpl: stubFetch(captured, OK_RESPONSE) });
  await assert.rejects(
    provider.complete({ modelId: 'claude-sonnet-5', messages: MESSAGES, maxTokens: 64 }),
    /ANTHROPIC_API_KEY/,
  );
  assert.equal(captured.length, 0);
});
