/**
 * Signing-identity resolution.
 *
 * dstack mode — the key NEVER leaves the CVM and is NEVER persisted by us:
 *   1. `POST http://dstack/GetKey {path, purpose, algorithm: "secp256k1"}`
 *      over /var/run/dstack.sock — deterministic per (app, path, purpose),
 *      rooted in the dstack KMS (itself a TEE; `signature_chain` proves the
 *      derivation).
 *   2. secret key = sha256(GetKey.key bytes) — the SAME hardening the
 *      official dstack SDK applies (`toViemAccountSecure` "hashes the
 *      derived key with SHA-256 before passing it to privateKeyToAccount"),
 *      so the node's address is reproducible with the upstream SDK.
 *
 * dev mode — a locally persisted random key (dataDir/dev-signing-key.hex,
 * chmod 600) or EDICT_NODE_DEV_PRIVATE_KEY. Attestation is a MOCK
 * (`dev_mode: true`) and the arbiter must never allowlist a dev signer for
 * real cases.
 */
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { NodeConfig } from './config.js';
import { DstackClient } from './dstack.js';
import { ethAddressOfPrivateKey } from './signer.js';
import { bytesToHex, hexToBytes } from './util.js';

export interface SigningIdentity {
  source: 'dstack' | 'dev';
  /** secp256k1 secret key — keep in memory only; never log, never serve. */
  privateKey: Uint8Array;
  /** Ethereum address of the signing key (published; goes on the allowlist/registry). */
  address: string;
  /** dstack GetKey derivation metadata (dstack mode; published in the attestation report). */
  keyDerivation?: {
    path: string;
    purpose: string;
    algorithm: 'secp256k1';
    hardening: 'sha256(GetKey.key)';
    signature_chain: string[];
  };
}

const DEV_KEY_FILENAME = 'dev-signing-key.hex';

function assertValidSecret(key: Uint8Array): void {
  // getPublicKey throws on out-of-range scalars (0 or >= curve order).
  secp256k1.getPublicKey(key, true);
}

export async function resolveDstackIdentity(
  config: NodeConfig,
  client: DstackClient = new DstackClient(config.dstackSocket),
): Promise<SigningIdentity> {
  const derived = await client.getKey(config.dstackKeyPath, config.dstackKeyPurpose, 'secp256k1');
  const keyBytes = hexToBytes(derived.key);
  if (keyBytes === null || keyBytes.length === 0) {
    throw new Error('dstack GetKey returned non-hex key material');
  }
  const privateKey = new Uint8Array(createHash('sha256').update(keyBytes).digest());
  assertValidSecret(privateKey);
  return {
    source: 'dstack',
    privateKey,
    address: ethAddressOfPrivateKey(privateKey),
    keyDerivation: {
      path: config.dstackKeyPath,
      purpose: config.dstackKeyPurpose,
      algorithm: 'secp256k1',
      hardening: 'sha256(GetKey.key)',
      signature_chain: derived.signature_chain,
    },
  };
}

export async function resolveDevIdentity(config: NodeConfig): Promise<SigningIdentity> {
  if (config.devPrivateKeyHex !== undefined) {
    const key = hexToBytes(config.devPrivateKeyHex);
    if (key === null || key.length !== 32) {
      throw new Error('EDICT_NODE_DEV_PRIVATE_KEY must be 32 bytes of hex');
    }
    assertValidSecret(key);
    return { source: 'dev', privateKey: key, address: ethAddressOfPrivateKey(key) };
  }

  await mkdir(config.dataDir, { recursive: true });
  const keyPath = join(config.dataDir, DEV_KEY_FILENAME);
  try {
    const persisted = hexToBytes((await readFile(keyPath, 'utf8')).trim());
    if (persisted !== null && persisted.length === 32) {
      assertValidSecret(persisted);
      return { source: 'dev', privateKey: persisted, address: ethAddressOfPrivateKey(persisted) };
    }
  } catch {
    // no persisted key yet — generate below
  }

  let key: Uint8Array;
  do {
    key = new Uint8Array(randomBytes(32));
  } while (!isValidSecret(key));
  await writeFile(keyPath, `${bytesToHex(key)}\n`, { mode: 0o600 });
  return { source: 'dev', privateKey: key, address: ethAddressOfPrivateKey(key) };
}

function isValidSecret(key: Uint8Array): boolean {
  try {
    assertValidSecret(key);
    return true;
  } catch {
    return false;
  }
}

export async function resolveIdentity(config: NodeConfig, client?: DstackClient): Promise<SigningIdentity> {
  return config.mode === 'dstack' ? resolveDstackIdentity(config, client) : resolveDevIdentity(config);
}
