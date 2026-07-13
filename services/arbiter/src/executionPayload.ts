/** Canonical outcome and customer-settlement execution digest helpers. */
import { createHash } from 'node:crypto';
import type { Outcome, Ruling } from '@edict/core';

/**
 * Canonical string form of a ruling for the execution digest. Closed
 * vocabulary; throws on anything outside it (never sign an unknown ruling).
 */
export function canonicalRuling(ruling: Ruling): string {
  switch (ruling.kind) {
    case 'requester_wins':
      return 'requester_wins';
    case 'worker_wins':
      return 'worker_wins';
    case 'split': {
      const bps = ruling.requesterBps;
      if (!Number.isInteger(bps) || bps < 0 || bps > 10_000) {
        throw new RangeError(`split requesterBps must be an integer in 0..10000, got ${bps}`);
      }
      return `split:${bps}`;
    }
    case 'redo': {
      const t = ruling.newDeadlineUnixMs;
      if (!Number.isSafeInteger(t) || t <= 0) {
        throw new RangeError(`redo newDeadlineUnixMs must be a positive safe integer, got ${t}`);
      }
      return `redo:${t}`;
    }
    default: {
      const k = (ruling as { kind: string }).kind;
      throw new RangeError(`unknown ruling kind "${k}" — refusing to canonicalise`);
    }
  }
}

/**
 * Canonical string form of an Outcome used by execution digests:
 *
 * - escrow (as today):  `"requester_wins" | "worker_wins" | "split:<bps>" | "redo:<newDeadlineUnixMs>"`
 * - categorical:        `"outcome:<label>"`
 * - scalar:             `"quantum:<value>"` where `<value>` is the canonical
 *                       JSON number encoding (`JSON.stringify(value)`,
 *                       ES2015+ shortest round-trip).
 *
 * Closed vocabulary; throws on anything outside it (never sign an unknown
 * outcome).
 *
 * The current on-chain contracts implement only the four escrow forms.
 */
export function canonicalOutcome(outcome: Outcome): string {
  switch (outcome.kind) {
    case 'requester_wins':
    case 'worker_wins':
    case 'split':
    case 'redo':
      return canonicalRuling(outcome);
    case 'categorical': {
      const label = outcome.outcome;
      if (typeof label !== 'string' || label.length === 0) {
        throw new TypeError('categorical outcome label must be a non-empty string — refusing to canonicalise');
      }
      return `outcome:${label}`;
    }
    case 'scalar': {
      const value = outcome.value;
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new RangeError(`scalar outcome value must be a finite number, got ${String(value)}`);
      }
      return `quantum:${JSON.stringify(value)}`;
    }
    default: {
      const k = (outcome as { kind: string }).kind;
      throw new RangeError(`unknown outcome kind "${k}" — refusing to canonicalise`);
    }
  }
}

function utf8z(s: string, label: string): Buffer {
  if (typeof s !== 'string' || s.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  const bytes = Buffer.from(s, 'utf8');
  if (bytes.includes(0)) {
    throw new TypeError(`${label} must not contain NUL bytes (0x00 is the field separator)`);
  }
  return Buffer.concat([bytes, Buffer.from([0])]);
}

// Customer settlement digest.

export interface CustomerSettlementExecutionDigestInput {
  /** Keyless customer settlement account executing the branch. */
  settlementAccountId: string;
  /** Canonical edict-om-2 mandate hash and immutable on-chain order id. */
  orderMandateSha256Hex: string;
  /** sha256 of the exact CaseObject caseId string. */
  caseIdSha256Hex: string;
  /** One-based dispute round; v1 permits exactly 1 or 2. */
  round: number;
  /** Output of {@link canonicalRuling}. */
  rulingCanonical: string;
  /** sha256 of the exact executable FinalVerdict JSON. */
  verdictSha256Hex: string;
  /** Signed FinalVerdict issuedAtUnixMs. */
  issuedAtUnixMs: number;
  /** Immutable verifier-policy hash returned by the settlement contract. */
  verifierPolicySha256Hex: string;
  /** One-time 32-byte execution nonce. */
  nonce: Uint8Array;
}

function rawHex32(value: string, label: string): Buffer {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new TypeError(`${label} must be exactly 64 hex characters`);
  }
  return Buffer.from(normalized, 'hex');
}

/**
 * Build `EDICT_SETTLEMENT_V1`, the digest verified directly by the keyless
 * customer contract. It binds the account, order, case, round, ruling,
 * verdict, challenge-clock timestamp, verifier policy, and nonce.
 */
export function buildCustomerSettlementExecutionDigest(
  input: CustomerSettlementExecutionDigestInput,
): string {
  if (input.round !== 1 && input.round !== 2) {
    throw new RangeError(`round must be 1 or 2, got ${String(input.round)}`);
  }
  if (!Number.isSafeInteger(input.issuedAtUnixMs) || input.issuedAtUnixMs <= 0) {
    throw new RangeError('issuedAtUnixMs must be a positive safe integer');
  }
  if (!/^(requester_wins|worker_wins|split:\d{1,5}|redo:\d+)$/.test(input.rulingCanonical)) {
    throw new TypeError(`rulingCanonical "${input.rulingCanonical}" is not executable`);
  }
  if (!(input.nonce instanceof Uint8Array) || input.nonce.length !== 32) {
    throw new TypeError('nonce must be exactly 32 bytes');
  }

  const roundLe = Buffer.alloc(4);
  roundLe.writeUInt32LE(input.round);
  const issuedAtLe = Buffer.alloc(8);
  issuedAtLe.writeBigUInt64LE(BigInt(input.issuedAtUnixMs));
  const preimage = Buffer.concat([
    Buffer.from('EDICT_SETTLEMENT_V1', 'utf8'),
    utf8z(input.settlementAccountId, 'settlementAccountId'),
    rawHex32(input.orderMandateSha256Hex, 'orderMandateSha256Hex'),
    rawHex32(input.caseIdSha256Hex, 'caseIdSha256Hex'),
    roundLe,
    utf8z(input.rulingCanonical, 'rulingCanonical'),
    rawHex32(input.verdictSha256Hex, 'verdictSha256Hex'),
    issuedAtLe,
    rawHex32(input.verifierPolicySha256Hex, 'verifierPolicySha256Hex'),
    Buffer.from(input.nonce),
  ]);
  return createHash('sha256').update(preimage).digest('hex');
}

export function buildCustomerSettlementCanonicalVector(): {
  input: CustomerSettlementExecutionDigestInput;
  digestHex: string;
} {
  const input: CustomerSettlementExecutionDigestInput = {
    settlementAccountId: 'locked.customer-settlement.near',
    orderMandateSha256Hex: '01'.repeat(32),
    caseIdSha256Hex: '02'.repeat(32),
    round: 1,
    rulingCanonical: 'split:2500',
    verdictSha256Hex: '03'.repeat(32),
    issuedAtUnixMs: 1_800_000_000_000,
    verifierPolicySha256Hex: '04'.repeat(32),
    nonce: new Uint8Array(32).fill(0x05),
  };
  return { input, digestHex: buildCustomerSettlementExecutionDigest(input) };
}
