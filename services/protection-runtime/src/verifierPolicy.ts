import { createHash } from 'node:crypto';
import type { RuntimeVerifierPolicy } from './types.js';

const SHA256 = /^[0-9a-f]{64}$/;
const ETH_ADDRESS = /^0x[0-9a-f]{40}$/;
const POLICY_KEYS = ['scheme', 'quorum', 'signers'] as const;
const SIGNER_KEYS = ['signingAddress', 'operatorId', 'edictControlled', 'attestationSha256Hex'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  problems: string[],
  value: Record<string, unknown>,
  path: string,
  allowed: readonly string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) problems.push(`${path}.${key} is not supported`);
  }
}

/** Closed-schema verifier policy validation shared by registration and signer nodes. */
export function validateRuntimeVerifierPolicy(policy: unknown, path = 'verifierPolicy'): string[] {
  const problems: string[] = [];
  if (!isRecord(policy)) return [`${path} must be an object`];
  rejectUnknownKeys(problems, policy, path, POLICY_KEYS);
  if (policy['scheme'] !== 'ecdsa_secp256k1_eth') {
    problems.push(`${path}.scheme must be ecdsa_secp256k1_eth`);
  }
  const quorum = policy['quorum'];
  if (!Number.isInteger(quorum) || (quorum as number) < 2) {
    problems.push(`${path}.quorum must be at least 2`);
  }
  const signers = policy['signers'];
  if (!Array.isArray(signers) || signers.length < 2 || signers.length > 16) {
    problems.push(`${path}.signers must contain 2..16 entries`);
    return problems;
  }

  const addresses = new Set<string>();
  const operators = new Set<string>();
  let previous = '';
  let edictControlled = 0;
  for (const [index, signer] of signers.entries()) {
    const signerPath = `${path}.signers[${index}]`;
    if (!isRecord(signer)) {
      problems.push(`${signerPath} must be an object`);
      continue;
    }
    rejectUnknownKeys(problems, signer, signerPath, SIGNER_KEYS);
    const address = signer['signingAddress'];
    const operatorId = signer['operatorId'];
    const controlled = signer['edictControlled'];
    const attestation = signer['attestationSha256Hex'];
    if (typeof address !== 'string' || !ETH_ADDRESS.test(address)) {
      problems.push(`${signerPath}.signingAddress must be normalized lowercase hex`);
    } else if (addresses.has(address)) {
      problems.push(`${signerPath}.signingAddress is duplicated`);
    } else {
      addresses.add(address);
    }
    if (typeof operatorId !== 'string' || !/^[A-Za-z0-9._:/-]{1,64}$/.test(operatorId)) {
      problems.push(`${signerPath}.operatorId is invalid`);
    } else {
      if (operators.has(operatorId)) problems.push(`${signerPath}.operatorId is duplicated`);
      operators.add(operatorId);
      if (previous !== '' && operatorId <= previous) {
        problems.push(`${path}.signers must be strictly sorted by operatorId`);
      }
      previous = operatorId;
    }
    if (typeof controlled !== 'boolean') {
      problems.push(`${signerPath}.edictControlled must be a boolean`);
    } else if (controlled) {
      edictControlled += 1;
    }
    if (typeof attestation !== 'string' || !SHA256.test(attestation) || /^0+$/.test(attestation)) {
      problems.push(`${signerPath}.attestationSha256Hex must be non-zero sha256 hex`);
    }
  }
  if (Number.isInteger(quorum) && (quorum as number) > signers.length) {
    problems.push(`${path}.quorum exceeds signer count`);
  }
  if (Number.isInteger(quorum) && signers.length - edictControlled < (quorum as number)) {
    problems.push(`${path} quorum cannot be satisfied without Edict-controlled signers`);
  }
  if (Number.isInteger(quorum) && edictControlled >= (quorum as number)) {
    problems.push(`${path} permits Edict-controlled signers to satisfy quorum alone`);
  }
  return problems;
}

export function assertValidRuntimeVerifierPolicy(
  policy: unknown,
): asserts policy is RuntimeVerifierPolicy {
  const problems = validateRuntimeVerifierPolicy(policy);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
}

function u16(value: number): Buffer {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
}

function u32(value: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

function borshString(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([u32(bytes.length), bytes]);
}

/** Byte-identical to edict_settlement_common::verifier_policy_sha256. */
export function runtimeVerifierPolicySha256(policy: RuntimeVerifierPolicy): string {
  assertValidRuntimeVerifierPolicy(policy);
  const signers = policy.signers.map((signer) => Buffer.concat([
    borshString(signer.signingAddress),
    borshString(signer.operatorId),
    Buffer.from([signer.edictControlled ? 1 : 0]),
    Buffer.from(signer.attestationSha256Hex, 'hex'),
  ]));
  const bytes = Buffer.concat([
    borshString(policy.scheme),
    u16(policy.quorum),
    u32(signers.length),
    ...signers,
  ]);
  return createHash('sha256').update(bytes).digest('hex');
}
