/**
 * Edict's self-hosted dstack/TDX inference node. The node speaks the same
 * OpenAI + persistent-signature surface as NEAR AI, with an attestation report
 * whose report_data binds the signer and this completion's response hash.
 *
 * Quote/DCAP verification and compose-measurement approval remain registry
 * admission duties. This provider verifies the online binding and signature
 * document before returning a proof; the jury gate then verifies signature
 * recovery and the configured signer allowlist.
 */
import type { ProviderProof } from '@edict/core';
import { archiveWriteImmutable, sanitizeName, sha256Hex } from '../util.js';
import { OpenAICompatibleProvider, type CompletionCapture } from './openaiCompatible.js';

export const EDICT_NODE_PROVIDER_ID = 'edict-node';
export const EDICT_NODE_REPORT_DATA_CONTEXT = 'edict-node-signing-key-v1';

export interface EdictNodeProviderOptions {
  archiveDir: string;
  /** OpenAI-compatible base URL ending in /v1. Defaults to EDICT_NODE_BASE_URL. */
  baseUrl?: string;
  apiKey?: string;
  /** Tests/local tooling only. Production provider construction leaves this false. */
  allowDevAttestation?: boolean;
  fetchImpl?: typeof fetch;
}

export class EdictNodeProvider extends OpenAICompatibleProvider {
  private readonly archiveDir: string;
  private readonly allowDevAttestation: boolean;

  constructor(opts: EdictNodeProviderOptions) {
    const baseUrl = opts.baseUrl ?? process.env.EDICT_NODE_BASE_URL;
    if (baseUrl === undefined || baseUrl.trim().length === 0) {
      throw new Error('EdictNodeProvider requires baseUrl or EDICT_NODE_BASE_URL');
    }
    super({
      id: EDICT_NODE_PROVIDER_ID,
      baseUrl,
      apiKey: opts.apiKey ?? process.env.EDICT_NODE_API_KEY,
      supportsSeed: true,
      fetchImpl: opts.fetchImpl,
    });
    this.archiveDir = opts.archiveDir;
    this.allowDevAttestation = opts.allowDevAttestation ?? false;
  }

  override async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as CompletionCapture;
    const chatId = extractChatId(c.parsed);
    if (chatId === undefined) throw new Error('edict-node: completion response has no chat id; cannot fetch signature');
    const safeId = sanitizeName(chatId);

    const sigRes = await this.fetchImpl(`${this.baseUrl}/signature/${encodeURIComponent(chatId)}`, {
      headers: this.authHeaders(),
    });
    const sigBody = await sigRes.text();
    await archiveWriteImmutable(this.archiveDir, `edict_node_signature_${safeId}.json`, sigBody);
    if (!sigRes.ok) {
      throw new Error(`edict-node: GET /signature/${chatId} HTTP ${sigRes.status} — ${sigBody.slice(0, 200)}`);
    }
    const sig = parseObject(sigBody, 'signature');
    requireEqual(sig.api_version, 'edict-node/1', 'signature.api_version');
    requireEqual(sig.chat_id, chatId, 'signature.chat_id');
    requireEqual(sig.model_id, c.modelId, 'signature.model_id');
    requireEqual(sig.request_sha256, c.requestSha256, 'signature.request_sha256');
    requireEqual(sig.response_sha256, c.responseSha256, 'signature.response_sha256');
    requireEqual(sig.signature_scheme, 'ecdsa_secp256k1_eth', 'signature.signature_scheme');
    const signingAddress = requireString(sig.signing_address, 'signature.signing_address');
    const signature = requireString(sig.signature, 'signature.signature');
    const expectedEnvelope = `${c.modelId}:${c.requestSha256}:${c.responseSha256}`;
    requireEqual(sig.text, expectedEnvelope, 'signature.text');

    const attRes = await this.fetchImpl(
      `${this.baseUrl}/attestation/report?nonce=${encodeURIComponent(c.responseSha256)}`,
      { headers: this.authHeaders() },
    );
    const attBody = await attRes.text();
    const attPath = await archiveWriteImmutable(this.archiveDir, `edict_node_attestation_${safeId}.json`, attBody);
    if (!attRes.ok) {
      throw new Error(`edict-node: GET /attestation/report HTTP ${attRes.status} — ${attBody.slice(0, 200)}`);
    }
    const att = parseObject(attBody, 'attestation');
    requireEqual(att.provider, EDICT_NODE_PROVIDER_ID, 'attestation.provider');
    requireEqual(att.api_version, 'edict-node/1', 'attestation.api_version');
    requireEqual(String(att.signing_address).toLowerCase(), signingAddress.toLowerCase(), 'attestation.signing_address');

    if (att.dev_mode === true) {
      if (!this.allowDevAttestation) {
        throw new Error('edict-node: dev_mode attestation is never accepted by the production provider');
      }
    } else {
      requireEqual(att.dev_mode, false, 'attestation.dev_mode');
      requireEqual(att.nonce, c.responseSha256, 'attestation.nonce');
      const expectedReportData = sha256Hex(
        `${EDICT_NODE_REPORT_DATA_CONTEXT}:${signingAddress}:${c.responseSha256}`,
      );
      requireEqual(att.report_data, expectedReportData, 'attestation.report_data');
      requireString(att.quote, 'attestation.quote');
    }

    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      signature,
      signatureScheme: 'ecdsa_secp256k1_eth',
      signingAddress,
      attestationRef: attPath,
      fetchedAtUnixMs: Date.now(),
    };
  }
}

function extractChatId(parsed: unknown): string | undefined {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
  const id = (parsed as { id?: unknown }).id;
  return typeof id === 'string' && id.length > 0 ? id : undefined;
}

function parseObject(body: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // handled below
  }
  throw new Error(`edict-node: ${label} response is not a JSON object`);
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`edict-node: ${label} must be a non-empty string`);
  }
  return value;
}

function requireEqual(actual: unknown, expected: unknown, label: string): void {
  if (actual !== expected) {
    throw new Error(`edict-node: ${label} mismatch (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`);
  }
}
