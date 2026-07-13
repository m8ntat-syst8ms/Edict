/**
 * Evidence-commitment enforcement at the arbiter boundary.
 *
 * The sealed-evidence contract: `evidencePlaintext` maps a commitment sha256
 * to the plaintext it unseals. NOTHING may enter the evidence frame unless
 * its bytes actually hash to a commitment in the case object:
 *
 * - key not matching any commitment sha256  → hard error (unknown evidence);
 * - plaintext whose sha256 ≠ its key        → hard error (tampered evidence),
 *   EXCEPT when the commitment kind is delivery_manifest: a mismatched
 *   manifest is itself evidence of forgery, so instead of crashing we drop
 *   the unverified plaintext (it renders as [sealed]), raise an
 *   `evidence_hash_mismatch:delivery_manifest` flag, and let the
 *   deterministic machine-check layer treat it as a forged-document finding.
 *
 * An order-mandate mismatch is fatal because the mandate defines the contract.
 * Without a hash-valid mandate there is no adjudicable case, so a mismatched
 * `order_mandate` plaintext is NEVER downgraded to a forgery finding. It
 * throws {@link EvidenceIntegrityError} with the distinct code
 * `'order_mandate_tampered'` and no verdict of any kind is issued.
 */
import type { CaseObject, EvidenceKind } from '@edict/core';
import { sha256Hex } from '../util.js';

/** Kinds whose hash mismatch is forgery EVIDENCE (finding), not a hard error. */
const FORGERY_EVIDENCE_KINDS: ReadonlySet<EvidenceKind> = new Set([
  'delivery_manifest',
] as EvidenceKind[]);

/** Distinct error code for a substituted/tampered order mandate (fatal). */
export const ORDER_MANDATE_TAMPERED = 'order_mandate_tampered';

export class EvidenceIntegrityError extends Error {
  readonly problems: string[];
  /**
   * Machine-readable failure class. `'order_mandate_tampered'` when any
   * committed order-mandate plaintext failed hash verification (the mandate
   * is the contract — the case is not adjudicable); undefined for the
   * generic unknown-key / tampered-evidence failures.
   */
  readonly code?: string;
  constructor(problems: string[], code?: string) {
    super(`evidence integrity check failed:\n- ${problems.join('\n- ')}`);
    this.name = 'EvidenceIntegrityError';
    this.problems = problems;
    if (code !== undefined) this.code = code;
  }
}

export interface VerifiedEvidence {
  /** Only entries whose bytes hash to their committed sha256. */
  plaintext: Record<string, string>;
  /** `evidence_hash_mismatch:<kind>` flags (delivery_manifest forgeries). */
  flags: string[];
  /** Kinds whose committed plaintext failed hash verification. */
  mismatchedKinds: Set<EvidenceKind>;
}

/**
 * Verify every plaintext entry against the case's evidence commitments.
 * Throws {@link EvidenceIntegrityError} on unknown keys, on any tampered
 * order_mandate (code `'order_mandate_tampered'` — fatal, never a verdict)
 * and on non-forgery-kind mismatches; returns the verified subset plus
 * forgery flags otherwise.
 */
export function verifyEvidenceCommitments(
  caseObj: CaseObject,
  evidencePlaintext: Record<string, string>,
): VerifiedEvidence {
  const kindsByHash = new Map<string, EvidenceKind[]>();
  for (const c of caseObj.evidence) {
    const kinds = kindsByHash.get(c.sha256) ?? [];
    kinds.push(c.kind);
    kindsByHash.set(c.sha256, kinds);
  }

  const problems: string[] = [];
  const flags: string[] = [];
  const mismatchedKinds = new Set<EvidenceKind>();
  const plaintext: Record<string, string> = {};
  let mandateTampered = false;

  for (const [key, text] of Object.entries(evidencePlaintext)) {
    const kinds = kindsByHash.get(key);
    if (kinds === undefined) {
      problems.push(
        `evidence key ${key.slice(0, 12)}… matches no commitment sha256 in the case object (unknown evidence rejected)`,
      );
      continue;
    }
    const actual = sha256Hex(text);
    if (actual === key) {
      plaintext[key] = text;
      continue;
    }
    // Hash mismatch: the provided plaintext is NOT the committed content.
    if (kinds.includes('order_mandate')) {
      // The mandate IS the contract: a substituted mandate makes the case
      // non-adjudicable. FATAL — never a finding, never a verdict.
      mandateTampered = true;
      problems.push(
        `order_mandate plaintext for commitment ${key.slice(0, 12)}… hashes to ${actual.slice(0, 12)}… — ` +
          'the order mandate is the contract; a tampered/substituted mandate is fatal (no adjudicable case)',
      );
      continue;
    }
    const forgeryKinds = kinds.filter((k) => FORGERY_EVIDENCE_KINDS.has(k));
    if (forgeryKinds.length === kinds.length && forgeryKinds.length > 0) {
      // Manifest forgery: flag it, drop the unverified plaintext.
      for (const k of forgeryKinds) {
        flags.push(`evidence_hash_mismatch:${k}`);
        mismatchedKinds.add(k);
      }
    } else {
      problems.push(
        `plaintext for commitment ${key.slice(0, 12)}… (kind ${kinds.join('+')}) hashes to ${actual.slice(0, 12)}… — evidence bytes do not match the commitment`,
      );
    }
  }

  if (problems.length > 0) {
    throw new EvidenceIntegrityError(problems, mandateTampered ? ORDER_MANDATE_TAMPERED : undefined);
  }
  return { plaintext, flags, mismatchedKinds };
}
