/**
 * Shared helpers for the edict-node service. node:crypto only — the node
 * must stay dependency-minimal (see package.json: @noble/* are the ONLY
 * runtime dependencies, mirroring services/arbiter).
 */
import { createHash } from 'node:crypto';

/** sha256 hex digest over exact bytes (strings hashed as UTF-8). */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Make a string safe to use as a filename component (mirrors arbiter util). */
export function sanitizeName(s: string): string {
  const out = s.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
  return out.length > 0 ? out : '_';
}

export function strip0x(s: string): string {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
}

/** Strict hex → bytes; null when not even-length hex. */
export function hexToBytes(s: string): Uint8Array | null {
  const h = strip0x(s.trim());
  if (h.length === 0 || h.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(h)) return null;
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

export function bytesToHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}
