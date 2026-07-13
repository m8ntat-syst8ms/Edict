/**
 * Phala Cloud Confidential AI provider — served through the ACI
 * (Attested Confidential Inference) gateway that fronts both
 * https://api.redpill.ai/v1 and https://inference.phala.com/v1.
 *
 * EVIDENCE NOTE (2026-07-09) — verification mechanism, empirically pinned:
 * - Base URL: https://api.redpill.ai/v1 (RedPill is Phala's confidential-AI
 *   router). https://api.phala.network is unreachable;
 *   cloud-api.phala.network/v1 is the CVM management API, not inference.
 *   The catalog (`GET /v1/models`) carries an `is_tee` flag — ONLY
 *   `is_tee: true` models run inside TEEs; the same catalog proxies non-TEE
 *   frontier models, so a jury seat MUST pin an is_tee model.
 * - Every inference response carries `x-receipt-id` / `x-aci-identity` /
 *   `x-aci-keyset-digest` headers (observed live on this gateway).
 * - Per-inference proof: `GET {base}/signature/{chat_id}` (the ACI legacy
 *   signature profile; also embeds the full canonical receipt) returns
 *   `{ text, signature, signing_address, signing_algo, receipt }` where
 *   `text` = `"<sha256(request body)>:<sha256(response wire bytes)>"` and the
 *   default `signing_algo` is `ecdsa`: an Ethereum personal-message
 *   secp256k1 signature (r||s||v, v = recid+27) whose signer address is
 *   `signing_address`. Pinned by the gateway source named in the LIVE
 *   attestation's `source_provenance`
 *   (Dstack-TEE/private-ai-gateway@58b027d17b582de6b7b2e5c60a04393901d9b31d:
 *   `sign_legacy_message` in src/dstack.rs, `legacy_signature_text` in
 *   src/aggregator/service/helpers.rs) and mapped to our
 *   `ecdsa_secp256k1_eth_bodyhashes` scheme in pipeline/proofVerify.ts.
 * - Attestation: `GET {base}/aci/attestation?model=…&nonce=…` (fetched live
 *   2026-07-09, archived under
 *   services/arbiter/evidence/redpill-aci-2026-07-09/): Intel TDX quote,
 *   `workload_keyset.receipt_signing_keys` = ecdsa-secp256k1 + ed25519 (NOT
 *   P-256 — the earlier `ecdsa_p256` assumption is disproven), keyset
 *   endorsement algo `ecdsa-secp256k1`.
 * - CAVEAT: end-to-end recovery against a LIVE completion is still pending —
 *   the on-disk PHALA_API_KEY (`phak_…`) is a Phala Cloud *management* key
 *   (authenticates cloud-api.phala.network/api/v1, workspace-scoped) that
 *   the inference gateway rejects with HTTP 401; an inference API key must
 *   be provisioned via the Phala dashboard (Confidential AI API → Enable) or
 *   `POST cloud-api.phala.network/api/v1/redpill/api-keys`. Until a live
 *   proof verifies, requireProofs juries fail closed: the signature fetch
 *   errors and the seat is excluded ('proof fetch failed').
 *
 * Signatures are cached server-side for ~5 minutes only, so the proof and
 * attestation documents are archived to `archiveDir` IMMEDIATELY inside
 * `getProof()`.
 */
import type { ProviderProof } from '@edict/core';
import { OpenAICompatibleProvider, type CompletionCapture } from './openaiCompatible.js';
import { archiveWriteImmutable, sanitizeName } from '../util.js';

export const PHALA_DEFAULT_BASE_URL = 'https://api.redpill.ai/v1';

export interface PhalaProviderOptions {
  /** Where receipts + attestation documents are archived at proof time. */
  archiveDir: string;
  apiKey?: string; // default: env PHALA_API_KEY
  baseUrl?: string; // default: env PHALA_BASE_URL or PHALA_DEFAULT_BASE_URL
  fetchImpl?: typeof fetch;
}

export class PhalaProvider extends OpenAICompatibleProvider {
  private readonly archiveDir: string;

  constructor(opts: PhalaProviderOptions) {
    super({
      id: 'phala',
      baseUrl: opts.baseUrl ?? process.env.PHALA_BASE_URL ?? PHALA_DEFAULT_BASE_URL,
      apiKey: opts.apiKey ?? process.env.PHALA_API_KEY,
      // Conservative: do not send "seed" until the ACI gateway is confirmed
      // to accept it (some gateways reject unknown params). temperature 0
      // is still always sent.
      supportsSeed: false,
      fetchImpl: opts.fetchImpl,
    });
    this.archiveDir = opts.archiveDir;
  }

  override async getProof(completionRef: unknown): Promise<ProviderProof> {
    const c = completionRef as CompletionCapture;
    const chatId = extractChatId(c.parsed);
    const receiptId = c.headers['x-receipt-id'];
    const refId = sanitizeName(receiptId ?? chatId ?? c.responseSha256.slice(0, 16));

    if (chatId === undefined) {
      // Preserve what we can (the receipt id lives in the headers) before
      // failing — under requireProofs this seat is excluded.
      await archiveWriteImmutable(
        this.archiveDir,
        `phala_receipt_${refId}.json`,
        JSON.stringify(
          {
            provider: 'phala',
            error: 'completion response carried no chat id; signature not fetchable',
            receiptId: receiptId ?? null,
            responseHeaders: c.headers,
            requestSha256: c.requestSha256,
            responseSha256: c.responseSha256,
            capturedAtUnixMs: Date.now(),
          },
          null,
          2,
        ),
      );
      throw new Error('phala: completion response has no chat id; cannot fetch signature');
    }

    // 1. Per-inference legacy signature + embedded canonical ACI receipt —
    //    fetch and archive immediately (server cache expires in ~5 minutes).
    const sigRes = await this.fetchImpl(`${this.baseUrl}/signature/${encodeURIComponent(chatId)}`, {
      headers: this.authHeaders(),
    });
    const sigBody = await sigRes.text();
    await archiveWriteImmutable(this.archiveDir, `phala_receipt_${refId}.json`, sigBody);
    if (!sigRes.ok) {
      throw new Error(`phala: GET /signature/${chatId} HTTP ${sigRes.status} — ${sigBody.slice(0, 200)}`);
    }

    // 2. Attestation report for the serving ACI gateway. The nonce (bound
    //    into the quote's report_data) ties the report to THIS completion.
    const attUrl =
      `${this.baseUrl}/aci/attestation?model=${encodeURIComponent(c.modelId)}` +
      `&nonce=${encodeURIComponent(c.responseSha256)}`;
    const attRes = await this.fetchImpl(attUrl, { headers: this.authHeaders() });
    const attBody = await attRes.text();
    const attPath = await archiveWriteImmutable(this.archiveDir, `phala_attestation_${refId}.json`, attBody);
    if (!attRes.ok) {
      throw new Error(`phala: GET /aci/attestation HTTP ${attRes.status} — ${attBody.slice(0, 200)}`);
    }

    const sig = parseLegacySignatureDoc(sigBody);
    // Only the ecdsa profile maps onto our recoverable-signature scheme; an
    // unexpected signing_algo degrades to attestationRef-only (fails closed
    // under requireProofs — never mislabel a signature we cannot verify).
    const ecdsa = sig.signingAlgo === undefined || sig.signingAlgo === 'ecdsa';
    return {
      providerId: this.id,
      modelId: c.modelId,
      requestSha256: c.requestSha256,
      responseSha256: c.responseSha256,
      ...(ecdsa && sig.signature !== undefined ? { signature: sig.signature } : {}),
      ...(ecdsa && sig.signature !== undefined
        ? { signatureScheme: 'ecdsa_secp256k1_eth_bodyhashes' as const }
        : {}),
      ...(sig.signingAddress !== undefined ? { signingAddress: sig.signingAddress } : {}),
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

/**
 * Defensive parse of the ACI legacy signature document:
 * `{ api_version, text, signature, signing_address, signing_algo, receipt }`.
 */
function parseLegacySignatureDoc(body: string): {
  signature?: string;
  signingAddress?: string;
  signingAlgo?: string;
} {
  try {
    const j = JSON.parse(body) as Record<string, unknown>;
    return {
      ...(typeof j.signature === 'string' ? { signature: j.signature } : {}),
      ...(typeof j.signing_address === 'string' ? { signingAddress: j.signing_address } : {}),
      ...(typeof j.signing_algo === 'string' ? { signingAlgo: j.signing_algo } : {}),
    };
  } catch {
    return {};
  }
}
