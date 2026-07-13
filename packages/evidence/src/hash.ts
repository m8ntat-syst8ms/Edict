/**
 * Hashing primitives for the evidence-mandate SDK (spec C5).
 *
 * Everything in Edict that is hashed is hashed over *canonical* bytes:
 * either raw artifact bytes, or the canonical JSON encoding produced by
 * {@link canonicalize}. Canonical JSON guarantees that two semantically
 * identical objects (same keys/values, any insertion order) always produce
 * the same bytes, and therefore the same sha256 — a prerequisite for
 * deterministic verdicts (same case → same verdict).
 */

import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/**
 * Deterministic JSON serialisation:
 *
 * - Object keys are sorted lexicographically by UTF-16 code unit (recursively).
 * - Object properties whose value is `undefined` are omitted (matching
 *   `JSON.stringify` semantics).
 * - Array element order is preserved; `undefined` elements serialise as
 *   `null` (matching `JSON.stringify` semantics).
 * - Strings/numbers use `JSON.stringify`'s ES2015+ shortest-round-trip
 *   number formatting (stable across conforming engines).
 * - No whitespace.
 *
 * Throws on values that cannot be canonicalised deterministically:
 * non-finite numbers (NaN/Infinity), bigint, function, symbol, and
 * non-plain objects (class instances, Map, Date, ...). Reject rather than
 * guess — a mandate that cannot be canonicalised must not be hashed.
 */
export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`canonicalize: non-finite number ${value}`);
      }
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new TypeError(`canonicalize: cannot canonicalize a ${typeof value}`);
  }

  if (Array.isArray(value)) {
    const parts = value.map((el) => canonicalize(el === undefined ? null : el));
    return `[${parts.join(',')}]`;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError('canonicalize: only plain objects are canonicalizable');
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const parts: string[] = [];
  for (const key of keys) {
    const v = record[key];
    if (v === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${canonicalize(v)}`);
  }
  return `{${parts.join(',')}}`;
}

// ---------------------------------------------------------------------------
// sha256 helpers
// ---------------------------------------------------------------------------

/** sha256 over raw bytes (or the UTF-8 encoding of a string), lowercase hex. */
export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/** sha256 over the canonical JSON encoding of `obj`, lowercase hex. */
export function sha256Canonical(obj: unknown): string {
  return sha256Hex(canonicalize(obj));
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Normalise a sha256 hex string: trims, lowercases, strips an optional `0x`
 * prefix. Returns `null` if the result is not exactly 64 hex chars.
 */
export function normalizeSha256(value: string): string | null {
  let s = value.trim().toLowerCase();
  if (s.startsWith('0x')) s = s.slice(2);
  return HEX64.test(s) ? s : null;
}

function requireSha256(value: string, label: string): string {
  const normalized = normalizeSha256(value);
  if (normalized === null) {
    throw new TypeError(`${label} must be a 64-char sha256 hex string, got: ${JSON.stringify(value)}`);
  }
  return normalized;
}

// ---------------------------------------------------------------------------
// Hash chain
// ---------------------------------------------------------------------------

/**
 * The chain head before any entry has been appended: 64 zero nibbles.
 * A well-known constant so independent verifiers agree on the genesis.
 */
export const GENESIS_HEAD = '0'.repeat(64);

/**
 * Append one entry to a hash chain:
 *
 *   newHead = sha256Hex( prevHeadHex + entrySha256Hex )
 *
 * i.e. sha256 over the UTF-8 bytes of the two lowercase hex strings
 * concatenated (128 ASCII chars). Both inputs are normalised (lowercased,
 * optional `0x` stripped) and validated; invalid hex throws.
 */
export function appendToChain(prevHead: string, entrySha256: string): string {
  const head = requireSha256(prevHead, 'prevHead');
  const entry = requireSha256(entrySha256, 'entrySha256');
  return sha256Hex(head + entry);
}

/**
 * An append-only sha256 hash chain (interaction logs, evidence journals).
 * Anchoring the head commits to every entry and their exact order.
 */
export class HashChain {
  private readonly entries: string[] = [];
  private currentHead: string = GENESIS_HEAD;

  /** Optionally replay an existing entry sequence into the chain. */
  constructor(entries: Iterable<string> = []) {
    for (const entry of entries) this.append(entry);
  }

  /** Append an entry hash; returns the new head. */
  append(entrySha256: string): string {
    const normalized = requireSha256(entrySha256, 'entrySha256');
    this.currentHead = appendToChain(this.currentHead, normalized);
    this.entries.push(normalized);
    return this.currentHead;
  }

  /** Current chain head (GENESIS_HEAD when empty). */
  head(): string {
    return this.currentHead;
  }

  /** Number of entries appended so far. */
  length(): number {
    return this.entries.length;
  }

  /**
   * Verify that `entries`, replayed from GENESIS_HEAD, reproduce exactly this
   * chain's current head. Any tampered, missing, reordered, or extra entry
   * makes this return false.
   */
  verify(entries: readonly string[]): boolean {
    let replayed: string;
    try {
      replayed = HashChain.computeHead(entries);
    } catch {
      return false;
    }
    return replayed === this.currentHead;
  }

  /** Replay a full entry sequence from genesis and return the resulting head. */
  static computeHead(entries: readonly string[]): string {
    let head = GENESIS_HEAD;
    for (const entry of entries) head = appendToChain(head, entry);
    return head;
  }
}
