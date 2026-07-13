import type { PermissionlessRelayer, RelayPlan, RelayResult } from './types.js';

/** Delegates gas-only submission to a relayer that never receives customer keys. */
export class HttpPermissionlessRelayer implements PermissionlessRelayer {
  constructor(
    readonly endpoint: string,
    readonly bearerToken?: string,
    readonly fetchImpl: typeof fetch = fetch,
    readonly timeoutMs = 15_000,
  ) {
    const url = new URL(endpoint);
    const loopbackHttp = url.protocol === 'http:' && url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !loopbackHttp) {
      throw new TypeError('relayer endpoint must be HTTPS (or loopback for local development)');
    }
    if (url.username !== '' || url.password !== '') {
      throw new TypeError('relayer endpoint must not contain credentials');
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('relayer timeout must be a positive integer');
    }
  }

  async relay(plan: RelayPlan): Promise<RelayResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.bearerToken !== undefined ? { authorization: `Bearer ${this.bearerToken}` } : {}),
        },
        body: JSON.stringify({ plan }),
        signal: controller.signal,
      });
      const body = await response.json() as { transactionHash?: unknown; error?: unknown };
      if (!response.ok) throw new Error(`relayer rejected plan (${response.status}): ${String(body.error ?? 'unknown error')}`);
      if (typeof body.transactionHash !== 'string' || body.transactionHash.length === 0) {
        throw new Error('relayer response has no transactionHash');
      }
      return { transactionHash: body.transactionHash };
    } finally {
      clearTimeout(timeout);
    }
  }
}
