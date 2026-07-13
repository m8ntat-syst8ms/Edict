/**
 * NEAR AI Cloud attested inference provider.
 *
 * - OpenAI-compatible completions at https://cloud-api.near.ai/v1
 * - Per-completion ECDSA (secp256k1, eth-style) signature fetched from
 *   GET /v1/signature/{chat_id}
 * - TEE attestation report fetched from GET /v1/attestation/report
 *
 * Both proof documents are archived to `archiveDir` IMMEDIATELY inside
 * `getProof()` — NEAR AI's signature cache expires, so deferring the fetch
 * loses the proof forever.
 */
import type { ProviderProof } from '@edict/core';
import { OpenAICompatibleProvider, type CompletionCapture } from './openaiCompatible.js';
import { archiveWriteImmutable, sanitizeName } from '../util.js';

export const NEARAI_DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';

export interface NearAiProviderOptions {
  /** Where signature + attestation documents are archived at proof time. */
  archiveDir: string;
  apiKey?: string; // default: env NEARAI_API_KEY
  baseUrl?: string; // default: env NEARAI_BASE_URL or NEARAI_DEFAULT_BASE_URL
  fetchImpl?: typeof fetch;
}

export class NearAiProvider extends OpenAICompatibleProvider {
  private readonly archiveDir: string;

  constructor(opts: NearAiProviderOptions) {
    super({
      id: 'nearai',
      baseUrl: opts.baseUrl ?? process.env.NEARAI_BASE_URL ?? NEARAI_DEFAULT_BASE_URL,
      apiKey: opts.apiKey ?? process.env.NEARAI_API_KEY,
      supportsSeed: true,
      fetchImpl: opts.fetchImpl,
    });
    this.archiveDir = opts.archiveDir;
  }

  override async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as CompletionCapture;
    const chatId = extractChatId(c.parsed);
    if (!chatId) {
      throw new Error('nearai: completion response has no chat id; cannot fetch signature');
    }
    const safeId = sanitizeName(chatId);

    // 1. Per-chat signature — fetch and archive immediately (cache expires).
    const sigRes = await this.fetchImpl(`${this.baseUrl}/signature/${encodeURIComponent(chatId)}`, {
      headers: this.authHeaders(),
    });
    const sigBody = await sigRes.text();
    await archiveWriteImmutable(this.archiveDir, `nearai_signature_${safeId}.json`, sigBody);
    if (!sigRes.ok) {
      throw new Error(`nearai: GET /signature/${chatId} HTTP ${sigRes.status} — ${sigBody.slice(0, 200)}`);
    }

    // 2. Attestation report for the serving TEE — archive alongside.
    const attRes = await this.fetchImpl(`${this.baseUrl}/attestation/report`, {
      headers: this.authHeaders(),
    });
    const attBody = await attRes.text();
    const attPath = await archiveWriteImmutable(this.archiveDir, `nearai_attestation_${safeId}.json`, attBody);
    if (!attRes.ok) {
      throw new Error(`nearai: GET /attestation/report HTTP ${attRes.status} — ${attBody.slice(0, 200)}`);
    }

    const sig = parseSignatureDoc(sigBody);
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      signature: sig.signature,
      signatureScheme: 'ecdsa_secp256k1_eth',
      signingAddress: sig.signingAddress,
      attestationRef: attPath,
      fetchedAtUnixMs: Date.now(),
    };
  }
}

function extractChatId(parsed: unknown): string | undefined {
  if (parsed === null || typeof parsed !== 'object') return undefined;
  const id = (parsed as { id?: unknown }).id;
  return typeof id === 'string' && id.length > 0 ? id : undefined;
}

/** Defensive parse — field names per NEAR AI Cloud verification API. */
function parseSignatureDoc(body: string): { signature?: string; signingAddress?: string } {
  try {
    const j = JSON.parse(body) as Record<string, unknown>;
    const signature =
      typeof j.signature === 'string' ? j.signature : typeof j.sig === 'string' ? j.sig : undefined;
    const signingAddress =
      typeof j.signing_address === 'string'
        ? j.signing_address
        : typeof j.address === 'string'
          ? j.address
          : typeof j.signer === 'string'
            ? j.signer
            : undefined;
    return { signature, signingAddress };
  } catch {
    return {};
  }
}
