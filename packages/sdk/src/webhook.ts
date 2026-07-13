/**
 * Verdict webhooks — signed delivery of VerdictObjects to integrator
 * endpoints. This module provides the SDK/sandbox format; the live
 * ProtectionRuntime provides durable, retrying delivery.
 *
 * The payload is the CANONICAL JSON of the verdict (sorted keys, no
 * whitespace — @edict/evidence `canonicalize`), so the signature binds the
 * verdict byte-for-byte and any two conforming implementations produce the
 * identical payload for the same verdict. The signature is
 * `sha256=<hex(HMAC-SHA256(secret, payload))>`, verified with a
 * constant-time compare (node:crypto `timingSafeEqual`).
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { VerdictObject } from '@edict/core';
import { canonicalize } from '@edict/evidence';

/** Signature header prefix (GitHub-webhook style). */
export const WEBHOOK_SIGNATURE_PREFIX = 'sha256=';

export interface SignedVerdictWebhook {
  /** Canonical JSON of the verdict — send these exact bytes. */
  payload: string;
  /** `sha256=<hex hmac>` — send as e.g. an `X-Edict-Signature` header. */
  signature: string;
}

const HMAC_HEX_RE = /^[0-9a-f]{64}$/;

/** Sign a verdict for webhook delivery. Throws on an empty secret. */
export function signVerdictWebhook(verdict: VerdictObject, secret: string): SignedVerdictWebhook {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new TypeError('webhook secret must be a non-empty string');
  }
  const payload = canonicalize(verdict);
  const signature = WEBHOOK_SIGNATURE_PREFIX + createHmac('sha256', secret).update(payload).digest('hex');
  return { payload, signature };
}

/**
 * Verify a received webhook: recompute the HMAC over the RAW payload bytes
 * and constant-time-compare against the signature header (with or without
 * the `sha256=` prefix, case-insensitive hex). Never throws — malformed
 * input returns false.
 */
export function verifyVerdictWebhook(payloadRaw: string, signatureHeader: string, secret: string): boolean {
  if (
    typeof payloadRaw !== 'string' ||
    typeof signatureHeader !== 'string' ||
    typeof secret !== 'string' ||
    secret.length === 0
  ) {
    return false;
  }
  let hex = signatureHeader.trim().toLowerCase();
  if (hex.startsWith(WEBHOOK_SIGNATURE_PREFIX)) hex = hex.slice(WEBHOOK_SIGNATURE_PREFIX.length);
  if (!HMAC_HEX_RE.test(hex)) return false;
  const expected = createHmac('sha256', secret).update(payloadRaw).digest();
  const given = Buffer.from(hex, 'hex');
  return timingSafeEqual(expected, given);
}
