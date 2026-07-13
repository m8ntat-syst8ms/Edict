/**
 * Minimal dstack guest-agent client — HTTP over the unix socket the agent
 * exposes inside every dstack CVM (`/var/run/dstack.sock`, mounted into the
 * container by docker-compose).
 *
 * API shapes per Dstack-TEE/dstack `sdk/curl/api.md` (fetched 2026-07-09):
 *
 * - `POST http://dstack/GetKey`   body `{ "path": "...", "purpose": "...",
 *   "algorithm": "secp256k1" }` → `{ "key": "<hex>", "signature_chain":
 *   ["<hex>", ...] }`. Deterministic per (app, path, purpose, algorithm) —
 *   the same CVM app always derives the same key.
 * - `POST http://dstack/GetQuote` body `{ "report_data": "<hex, ≤64 bytes,
 *   zero-padded>" }` → `{ "quote": "<hex>", "event_log": "<json>",
 *   "report_data": "<hex>", "vm_config": "<json>" }` — a genuine Intel TDX
 *   quote whose report_data we bind to the signing key.
 * - `GET  http://dstack/Info` → `{ app_id, instance_id, tcb_info, app_name,
 *   compose_hash, key_provider_info, ... }`.
 *
 * node:http only — no SDK dependency.
 */
import { request } from 'node:http';

export interface DstackGetKeyResponse {
  /** Hex-encoded derived key material. */
  key: string;
  /** Hex signatures chaining the derived key to the app's KMS root. */
  signature_chain: string[];
}

export interface DstackGetQuoteResponse {
  quote: string;
  event_log: string;
  report_data?: string;
  vm_config?: string;
}

export type DstackInfoResponse = Record<string, unknown>;

export class DstackClient {
  constructor(readonly socketPath: string = '/var/run/dstack.sock') {}

  async getKey(
    path: string,
    purpose: string,
    algorithm: 'secp256k1' | 'ed25519' = 'secp256k1',
  ): Promise<DstackGetKeyResponse> {
    const res = (await this.rpc('/GetKey', 'POST', { path, purpose, algorithm })) as Partial<DstackGetKeyResponse>;
    if (typeof res.key !== 'string' || res.key.length === 0) {
      throw new Error('dstack GetKey: response has no "key"');
    }
    return { key: res.key, signature_chain: Array.isArray(res.signature_chain) ? res.signature_chain : [] };
  }

  /** `reportDataHex`: ≤64 bytes of hex; the agent zero-pads shorter values. */
  async getQuote(reportDataHex: string): Promise<DstackGetQuoteResponse> {
    if (!/^[0-9a-fA-F]+$/.test(reportDataHex) || reportDataHex.length % 2 !== 0 || reportDataHex.length > 128) {
      throw new Error('dstack GetQuote: report_data must be ≤64 bytes of even-length hex');
    }
    const res = (await this.rpc('/GetQuote', 'POST', { report_data: reportDataHex })) as Partial<DstackGetQuoteResponse>;
    if (typeof res.quote !== 'string' || res.quote.length === 0) {
      throw new Error('dstack GetQuote: response has no "quote"');
    }
    return {
      quote: res.quote,
      event_log: typeof res.event_log === 'string' ? res.event_log : '',
      ...(typeof res.report_data === 'string' ? { report_data: res.report_data } : {}),
      ...(typeof res.vm_config === 'string' ? { vm_config: res.vm_config } : {}),
    };
  }

  async info(): Promise<DstackInfoResponse> {
    return (await this.rpc('/Info', 'GET')) as DstackInfoResponse;
  }

  private rpc(path: string, method: 'GET' | 'POST', body?: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const req = request(
        {
          socketPath: this.socketPath,
          path,
          method,
          headers: {
            host: 'dstack',
            ...(payload !== undefined
              ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
              : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let parsed: unknown = null;
            try {
              parsed = JSON.parse(text);
            } catch {
              // fall through — handled below
            }
            const errField =
              parsed !== null && typeof parsed === 'object' ? (parsed as { error?: unknown }).error : undefined;
            if (res.statusCode !== 200 || typeof errField === 'string') {
              reject(
                new Error(
                  `dstack guest agent ${method} ${path}: HTTP ${res.statusCode} — ${typeof errField === 'string' ? errField : text.slice(0, 200)}`,
                ),
              );
              return;
            }
            if (parsed === null) {
              reject(new Error(`dstack guest agent ${method} ${path}: non-JSON response`));
              return;
            }
            resolve(parsed);
          });
        },
      );
      req.on('error', (err) =>
        reject(new Error(`dstack guest agent unreachable at ${this.socketPath}: ${(err as Error).message}`)),
      );
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }
}
