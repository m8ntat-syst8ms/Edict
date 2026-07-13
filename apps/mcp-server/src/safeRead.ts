/**
 * Hardened filesystem-read helpers for the MCP server's docket/report access.
 *
 * Mirrors the semantics of the console's docket reader
 * (apps/console/src/docket.ts): identifier/uri allowlist patterns first, then
 * realpath containment so even a symlink planted inside an allowed directory
 * cannot read files outside it. Kept as a local copy on purpose — app
 * packages do not import across each other; if a third consumer appears this
 * belongs in a shared package.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { sep } from 'node:path';

/** Safe path-segment ids (case slugs, caseIds): no separators, no dot-prefix. */
export const SLUG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Readable evidence uris: exactly one filename segment under `evidence/`.
 * Rejects URL schemes (vault://, ipfs://), absolute paths, `..` segments and
 * nested directories by construction.
 */
export const EVIDENCE_URI_RE = /^evidence\/[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Resolve `candidate` with realpath and return it only when it lies STRICTLY
 * inside `rootDir` (also realpath-resolved) — symlink-escape proof. Returns
 * undefined when the file is missing, unresolvable, or escapes the root.
 */
export function containedRealpath(rootDir: string, candidate: string): string | undefined {
  try {
    const realRoot = realpathSync(rootDir);
    const real = realpathSync(candidate);
    return real.startsWith(realRoot + sep) ? real : undefined;
  } catch {
    return undefined;
  }
}

/** Read a utf8 file only if it realpath-resolves inside `rootDir`. */
export function readFileContained(rootDir: string, candidate: string): string | undefined {
  const real = containedRealpath(rootDir, candidate);
  if (real === undefined) return undefined;
  try {
    // Read the RESOLVED path: a symlink swapped in after resolution is not followed.
    return readFileSync(real, 'utf8');
  } catch {
    return undefined;
  }
}

/** JSON.parse a contained read; undefined on any failure (missing/escape/unparseable). */
export function readJsonContained(rootDir: string, candidate: string): unknown {
  const raw = readFileContained(rootDir, candidate);
  if (raw === undefined) return undefined;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return undefined;
  }
}
