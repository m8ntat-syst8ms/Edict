import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonicalize } from '@edict/evidence';
import type { ProtectionEvent, VerdictWebhookTarget } from './types.js';

export const RUNTIME_WEBHOOK_SIGNATURE_PREFIX = 'sha256=' as const;

export function signRuntimeWebhook(payload: string, secret: string): string {
  if (secret.length < 16) throw new TypeError('webhook secret must contain at least 16 characters');
  return `${RUNTIME_WEBHOOK_SIGNATURE_PREFIX}${createHmac('sha256', secret).update(payload).digest('hex')}`;
}

export function verifyRuntimeWebhook(payload: string, signature: string, secret: string): boolean {
  let expected: string;
  try {
    expected = signRuntimeWebhook(payload, secret);
  } catch {
    return false;
  }
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface WebhookDeliveryResult {
  targetId: string;
  verdictEventId: string;
  delivered: boolean;
  attempts: number;
  status?: number;
  error?: string;
}

export async function deliverRuntimeWebhook(
  target: VerdictWebhookTarget,
  event: ProtectionEvent<'verdict_issued'>,
  options: {
    fetchImpl?: typeof fetch;
    attempts?: number;
    timeoutMs?: number;
  } = {},
): Promise<WebhookDeliveryResult> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maximumAttempts = options.attempts ?? 3;
  const timeoutMs = options.timeoutMs ?? 5_000;
  const payload = canonicalize(event);
  const signature = signRuntimeWebhook(payload, target.secret);
  let lastStatus: number | undefined;
  let lastError: string | undefined;
  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(target.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-edict-event-id': event.eventId,
          'x-edict-event-type': event.type,
          'x-edict-signature': signature,
        },
        body: payload,
        signal: controller.signal,
      });
      lastStatus = response.status;
      if (response.ok) {
        return {
          targetId: target.id,
          verdictEventId: event.eventId,
          delivered: true,
          attempts: attempt,
          status: response.status,
        };
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    } finally {
      clearTimeout(timeout);
    }
    if (attempt < maximumAttempts) await new Promise((resolve) => setTimeout(resolve, 20 * 2 ** (attempt - 1)));
  }
  return {
    targetId: target.id,
    verdictEventId: event.eventId,
    delivered: false,
    attempts: maximumAttempts,
    ...(lastStatus !== undefined ? { status: lastStatus } : {}),
    ...(lastError !== undefined ? { error: lastError } : {}),
  };
}
