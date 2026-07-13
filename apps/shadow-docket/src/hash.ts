import { createHash } from 'node:crypto';

/** sha256 of a string / bytes as lowercase hex — the canonical hash everywhere in Edict. */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
export const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
