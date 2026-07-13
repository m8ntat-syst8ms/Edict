/** Generate test-only execution-signer keys for the native NEAR runner. */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { CREDENTIALS_DIR, sha256 } from './common.js';

export interface DemoSigner {
  label: string;
  warning: string;
  providerId: string;
  scheme: 'ecdsa_secp256k1_eth';
  privateKeyHex: string;
  address: string;
  attestationPlaceholderSha256Hex: string;
}

const SIGNERS: Array<{ file: string; label: string; providerId: string }> = [
  { file: 'demo-signer-a.json', label: 'demo-signer-a', providerId: 'test-operator-a' },
  { file: 'demo-signer-b.json', label: 'demo-signer-b', providerId: 'test-operator-b' },
  { file: 'demo-signer-a2.json', label: 'demo-signer-a2', providerId: 'test-operator-a' },
];

export function ethAddress(privateKey: Uint8Array): string {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return `0x${Buffer.from(keccak_256(publicKey.slice(1)).slice(-20)).toString('hex')}`;
}

export function loadDemoSigner(label: string): DemoSigner {
  const file = join(CREDENTIALS_DIR, `${label}.json`);
  if (!existsSync(file)) throw new Error(`missing ${file}; generate test signers first`);
  return JSON.parse(readFileSync(file, 'utf8')) as DemoSigner;
}

function generate(): DemoSigner[] {
  mkdirSync(CREDENTIALS_DIR, { recursive: true, mode: 0o700 });
  const records: DemoSigner[] = [];
  for (const signer of SIGNERS) {
    const file = join(CREDENTIALS_DIR, signer.file);
    if (existsSync(file)) {
      records.push(JSON.parse(readFileSync(file, 'utf8')) as DemoSigner);
      continue;
    }

    const privateKey = Uint8Array.from(randomBytes(32));
    const address = ethAddress(privateKey);
    const record: DemoSigner = {
      label: signer.label,
      warning: 'TESTNET KEY ONLY. Never reuse in production.',
      providerId: signer.providerId,
      scheme: 'ecdsa_secp256k1_eth',
      privateKeyHex: Buffer.from(privateKey).toString('hex'),
      address,
      attestationPlaceholderSha256Hex: sha256(
        `EDICT TESTNET PLACEHOLDER ATTESTATION:${address}`,
      ).toString('hex'),
    };
    writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
    records.push(record);
  }
  return records;
}

if (process.argv[1]?.endsWith('gen-demo-signers.js')) {
  for (const signer of generate()) {
    console.log(`${signer.label}: ${signer.address} (${signer.providerId})`);
  }
}
