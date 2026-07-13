/**
 * Base InferenceProvider over any OpenAI-compatible `/chat/completions`
 * endpoint (provider abstraction).
 *
 * Determinism: temperature 0 always; a pinned seed is sent where the endpoint
 * supports it. The exact request body bytes we send and the exact response
 * body bytes we receive are captured and hashed (sha256) so a verdict can be
 * re-verified against provider-side signatures later.
 */
import type { InferenceProvider, ProviderProof } from '@edict/core';
import { sha256Hex } from '../util.js';

/**
 * Byte-exact capture of one completion round-trip. Returned as the opaque
 * `raw` field from `complete()` and consumed by `getProof()`.
 */
export interface CompletionCapture {
  providerId: string;
  modelId: string;
  /** Exact UTF-8 request body string sent over the wire. */
  requestBody: string;
  /** Exact response body bytes as received (decoded to UTF-8 for storage). */
  responseBody: string;
  requestSha256: string;
  responseSha256: string;
  status: number;
  /** Lower-cased response headers (e.g. Phala's `x-receipt-id`). */
  headers: Record<string, string>;
  /** Parsed response JSON, or null when the body was not valid JSON. */
  parsed: unknown;
}

export interface OpenAICompatibleOptions {
  id: string;
  /** e.g. "https://cloud-api.near.ai/v1" — `/chat/completions` is appended. */
  baseUrl: string;
  apiKey?: string;
  /** Send `"seed"` in the request body (some endpoints reject unknown params). */
  supportsSeed?: boolean;
  /** Pinned seed for determinism; default 0. */
  seed?: number;
  extraHeaders?: Record<string, string>;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
}

export class OpenAICompatibleProvider implements InferenceProvider {
  readonly id: string;
  protected readonly baseUrl: string;
  protected readonly apiKey: string | undefined;
  protected readonly supportsSeed: boolean;
  protected readonly seed: number;
  protected readonly extraHeaders: Record<string, string>;
  protected readonly fetchImpl: typeof fetch;

  constructor(opts: OpenAICompatibleOptions) {
    this.id = opts.id;
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.apiKey = opts.apiKey;
    this.supportsSeed = opts.supportsSeed ?? true;
    this.seed = opts.seed ?? 0;
    this.extraHeaders = opts.extraHeaders ?? {};
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  protected authHeaders(): Record<string, string> {
    return this.apiKey ? { authorization: `Bearer ${this.apiKey}` } : {};
  }

  async complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }): Promise<{ text: string; requestSha256: string; responseSha256: string; raw: unknown }> {
    const body: Record<string, unknown> = {
      model: req.modelId,
      messages: req.messages,
      temperature: 0,
      ...(req.maxTokens !== undefined ? { max_tokens: req.maxTokens } : {}),
      ...(this.supportsSeed ? { seed: this.seed } : {}),
    };
    // The stringified body IS the wire bytes — hash exactly what is sent.
    const requestBody = JSON.stringify(body);
    const requestSha256 = sha256Hex(requestBody);

    const res = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...this.authHeaders(),
        ...this.extraHeaders,
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
      throw new Error(
        `${this.id}: chat/completions HTTP ${res.status} — ${responseBody.slice(0, 300)}`,
      );
    }

    let parsed: unknown = null;
    try {
      parsed = JSON.parse(responseBody);
    } catch {
      // leave parsed null; caller sees empty text and treats as parse failure
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
   * Base implementation: an unsigned proof from the captured hashes.
   * Attested providers (NEAR AI, Phala) override this to fetch and archive
   * provider-native signatures/attestations IMMEDIATELY (caches expire).
   */
  async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as CompletionCapture;
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      fetchedAtUnixMs: Date.now(),
    };
  }
}

function extractText(parsed: unknown): string {
  if (parsed === null || typeof parsed !== 'object') return '';
  const choices = (parsed as { choices?: unknown }).choices;
  if (!Array.isArray(choices) || choices.length === 0) return '';
  const first = choices[0] as { message?: { content?: unknown } };
  const content = first?.message?.content;
  return typeof content === 'string' ? content : '';
}
