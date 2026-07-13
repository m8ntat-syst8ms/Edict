/**
 * Small shared helpers for the arbiter pipeline. No runtime dependencies —
 * node:crypto / node:fs only.
 */
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

/** sha256 hex digest over exact bytes (strings hashed as UTF-8). */
export function sha256Hex(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Make a string safe to use as a filename component. */
export function sanitizeName(s: string): string {
  const out = s.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120);
  return out.length > 0 ? out : '_';
}

/** Deterministic flag list: deduplicated + sorted. */
export function dedupSorted(xs: string[]): string[] {
  return [...new Set(xs)].sort();
}

/** Write a file into an archive dir (created if needed); returns the path written. */
export async function archiveWrite(dir: string, filename: string, content: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  const p = join(dir, sanitizeName(filename));
  await writeFile(p, content, 'utf8');
  return p;
}

/**
 * Content-addressed archive write for proof material. The digest suffix makes
 * the path immutable: a reused provider/chat id cannot overwrite an older
 * signature or attestation document.
 */
export async function archiveWriteImmutable(dir: string, filename: string, content: string): Promise<string> {
  await mkdir(dir, { recursive: true });
  const safe = sanitizeName(filename);
  const dot = safe.lastIndexOf('.');
  const stem = dot > 0 ? safe.slice(0, dot) : safe;
  const ext = dot > 0 ? safe.slice(dot) : '';
  const p = join(dir, `${stem}_${sha256Hex(content)}${ext}`);
  try {
    await writeFile(p, content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
  }
  return p;
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, n));
}

/** Deterministic median (even-length lists round to nearest integer). */
export function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  return n % 2 === 1 ? s[(n - 1) / 2]! : Math.round((s[n / 2 - 1]! + s[n / 2]!) / 2);
}

export const SEVENTY_TWO_HOURS_MS = 72 * 60 * 60 * 1000;
