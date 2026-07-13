/**
 * AnthropicProvider — InferenceProvider over the Anthropic Messages API
 * (`POST https://api.anthropic.com/v1/messages`).
 *
 * ⚠️ BENCH-ONLY (UNATTESTED). This provider exists for bench-trial mode
 * (../bench.ts) — a single-judge QUALITY INSTRUMENT — and must NEVER be used
 * in jury seats:
 * - The Anthropic API returns no TEE attestation and no provider-native
 *   signature over the request/response bytes, so `getProof()` can only
 *   return an unattested `signatureScheme: 'none_mock'` proof. Under the
 *   attestation gate (requireProofs) such a seat would always be excluded;
 *   without the gate it would silently weaken the attested-jury guarantee.
 * - The placement validator's model-family disjointness rule (see
 *   pipeline/validate.ts — families must be disjoint across seats) makes a
 *   3-seat all-Claude jury impossible anyway; this comment is belt and
 *   braces on top of that structural rule.
 * Bench results are labeled UNATTESTED BENCH and never feed the quality gate.
 *
 * Wire mapping from our `{system, user}` message shape:
 * - system messages are joined into the top-level `system` string;
 * - user messages map to `messages: [{role:'user', content}]`;
 * - `max_tokens` from the request (the Messages API requires it);
 * - determinism posture: `temperature: 0` where the model still accepts
 *   sampling parameters. Claude Sonnet 5 / Opus 4.7 / Opus 4.8 / Fable 5 /
 *   Mythos reject non-default sampling params with a 400, so temperature is
 *   OMITTED for those model families (full API-level determinism is not
 *   available there; the bench records this caveat);
 * - thinking is explicitly DISABLED (`thinking: {type:'disabled'}`) so the
 *   judge answers in one shot inside the juror token budget. On Claude
 *   Sonnet 5 omitting `thinking` silently enables adaptive thinking, which
 *   would eat the 1024-token juror budget and truncate the strict-JSON
 *   answer — the explicit disable is load-bearing. Fable/Mythos models
 *   reject an explicit disable (thinking is always on there), so for those
 *   the parameter is omitted entirely.
 *
 * The exact request body bytes sent and the exact response body bytes
 * received are captured and sha256-hashed (same discipline as
 * OpenAICompatibleProvider) so bench outputs stay byte-auditable even
 * though they are unattested.
 */
import type { InferenceProvider, ProviderProof } from '@edict/core';
import { sha256Hex } from '../util.js';
import type { CompletionCapture } from './openaiCompatible.js';

export const ANTHROPIC_DEFAULT_BASE_URL = 'https://api.anthropic.com';
export const ANTHROPIC_VERSION = '2023-06-01';
export const ANTHROPIC_BENCH_PROVIDER_ID = 'anthropic-bench';

/**
 * Model families where non-default sampling parameters (temperature/top_p/
 * top_k) are removed and return a 400: Sonnet 5, Opus 4.7/4.8, Fable 5,
 * Mythos. For these, `temperature: 0` must be omitted.
 */
const SAMPLING_PARAMS_REMOVED_RE = /claude-(sonnet-5|opus-4-[78]|fable|mythos)/;

/**
 * Model families where thinking is always on and an explicit
 * `thinking: {type:'disabled'}` returns a 400 (omit the parameter entirely).
 */
const THINKING_ALWAYS_ON_RE = /claude-(fable|mythos)/;

export interface AnthropicProviderOptions {
  /** Defaults to process.env.ANTHROPIC_API_KEY. */
  apiKey?: string;
  /** Defaults to https://api.anthropic.com — `/v1/messages` is appended. */
  baseUrl?: string;
  /** Injectable for tests. NEVER call the real API from tests. */
  fetchImpl?: typeof fetch;
}

export class AnthropicProvider implements InferenceProvider {
  /** Fixed bench identity — the id itself says "not a jury provider". */
  readonly id = ANTHROPIC_BENCH_PROVIDER_ID;
  private readonly apiKey: string | undefined;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: AnthropicProviderOptions = {}) {
    this.apiKey = opts.apiKey ?? process.env.ANTHROPIC_API_KEY;
    this.baseUrl = (opts.baseUrl ?? ANTHROPIC_DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  async complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }): Promise<{ text: string; requestSha256: string; responseSha256: string; raw: unknown }> {
    if (this.apiKey === undefined || this.apiKey.length === 0) {
      throw new Error(
        `${this.id}: no Anthropic API key — set ANTHROPIC_API_KEY (or pass opts.apiKey)`,
      );
    }

    const system = req.messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    const userMessages = req.messages
      .filter((m) => m.role === 'user')
      .map((m) => ({ role: 'user' as const, content: m.content }));

    const body: Record<string, unknown> = {
      model: req.modelId,
      // The Messages API requires max_tokens; the juror budget is the caller's.
      max_tokens: req.maxTokens ?? 1024,
      ...(system.length > 0 ? { system } : {}),
      messages: userMessages,
      // Determinism posture — see module doc for the per-family gating.
      ...(SAMPLING_PARAMS_REMOVED_RE.test(req.modelId) ? {} : { temperature: 0 }),
      ...(THINKING_ALWAYS_ON_RE.test(req.modelId) ? {} : { thinking: { type: 'disabled' } }),
    };
    // The stringified body IS the wire bytes — hash exactly what is sent.
    const requestBody = JSON.stringify(body);
    const requestSha256 = sha256Hex(requestBody);

    const res = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': this.apiKey,
        'anthropic-version': ANTHROPIC_VERSION,
      },
      body: requestBody,
    });

    // Capture the raw response bytes before any parsing so the hash is exact.
    const bytes = Buffer.from(await res.arrayBuffer());
    const responseSha256 = sha256Hex(bytes);
    const responseBody = bytes.toString('utf8');
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });

    if (!res.ok) {
      throw new Error(`${this.id}: /v1/messages HTTP ${res.status} — ${responseBody.slice(0, 300)}`);
    }

    let parsed: unknown = null;
    try {
      parsed = JSON.parse(responseBody);
    } catch {
      // leave parsed null; caller sees empty text and treats it as parse failure
    }
    const text = extractText(parsed);

    const capture: CompletionCapture = {
      providerId: this.id,
      modelId: req.modelId,
      requestBody,
      responseBody,
      requestSha256,
      responseSha256,
      status: res.status,
      headers,
      parsed,
    };
    return { text, requestSha256, responseSha256, raw: capture };
  }

  /**
   * BENCH-ONLY, UNATTESTED proof: hashes over the captured bytes with
   * `signatureScheme: 'none_mock'` — there is no provider-native signature or
   * TEE attestation to fetch. A seat backed by this proof can never pass the
   * attestation gate; that is by design (this provider must never sit on a
   * jury — see the module doc).
   */
  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as CompletionCapture;
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      signatureScheme: 'none_mock',
      fetchedAtUnixMs: Date.now(),
    };
  }
}

/**
 * Join the response's `text` content blocks. Non-text blocks (`thinking`,
 * tool blocks) are ignored; refusals / empty content yield '' which the
 * juror parser degrades to a parse failure — the correct bench semantics.
 */
function extractText(parsed: unknown): string {
  if (parsed === null || typeof parsed !== 'object') return '';
  const content = (parsed as { content?: unknown }).content;
  if (!Array.isArray(content)) return '';
  return content
    .filter(
      (b): b is { type: string; text: string } =>
        b !== null &&
        typeof b === 'object' &&
        (b as { type?: unknown }).type === 'text' &&
        typeof (b as { text?: unknown }).text === 'string',
    )
    .map((b) => b.text)
    .join('');
}
