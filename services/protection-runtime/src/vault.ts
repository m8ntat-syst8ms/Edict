import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256Hex } from '@edict/evidence';

export interface EvidenceVaultPutResult {
  sha256: string;
  vaultRef: string;
}

export interface EvidenceVault {
  put(plaintext: string): Promise<EvidenceVaultPutResult>;
  get(sha256: string): Promise<string | undefined>;
}

export class MemoryEvidenceVault implements EvidenceVault {
  private readonly blobs = new Map<string, string>();

  async put(plaintext: string): Promise<EvidenceVaultPutResult> {
    const sha256 = sha256Hex(plaintext);
    const existing = this.blobs.get(sha256);
    if (existing !== undefined && existing !== plaintext) throw new Error(`sha256 collision for evidence ${sha256}`);
    this.blobs.set(sha256, plaintext);
    return { sha256, vaultRef: `memory:${sha256}` };
  }

  async get(sha256: string): Promise<string | undefined> {
    return this.blobs.get(sha256);
  }
}

interface EncryptedBlob {
  version: 'edict-evidence-aes256gcm-1';
  sha256: string;
  iv: string;
  tag: string;
  ciphertext: string;
}

/**
 * Content-addressed AES-256-GCM vault. The key is injected at process start
 * and is never written beside the evidence or into the event log.
 */
export class EncryptedFileEvidenceVault implements EvidenceVault {
  private readonly key: Buffer;

  constructor(readonly root: string, key: Uint8Array) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
      throw new TypeError('evidence vault key must be exactly 32 bytes');
    }
    this.key = Buffer.from(key);
  }

  private pathFor(sha256: string): string {
    if (!/^[0-9a-f]{64}$/.test(sha256)) throw new TypeError('evidence sha256 must be lowercase hex');
    return join(this.root, sha256.slice(0, 2), `${sha256}.json`);
  }

  async put(plaintext: string): Promise<EvidenceVaultPutResult> {
    const sha256 = sha256Hex(plaintext);
    const path = this.pathFor(sha256);
    await mkdir(join(this.root, sha256.slice(0, 2)), { recursive: true, mode: 0o700 });
    try {
      const current = await this.get(sha256);
      if (current !== undefined) {
        const a = Buffer.from(current);
        const b = Buffer.from(plaintext);
        if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error(`sha256 collision for evidence ${sha256}`);
        return { sha256, vaultRef: `encrypted-file:${sha256}` };
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(sha256, 'ascii'));
    const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const blob: EncryptedBlob = {
      version: 'edict-evidence-aes256gcm-1',
      sha256,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    try {
      await writeFile(path, JSON.stringify(blob), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const current = await this.get(sha256);
      if (current !== plaintext) throw new Error(`conflicting evidence blob ${sha256}`);
    }
    return { sha256, vaultRef: `encrypted-file:${sha256}` };
  }

  async get(sha256: string): Promise<string | undefined> {
    let raw: string;
    try {
      raw = await readFile(this.pathFor(sha256), 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
    const blob = JSON.parse(raw) as EncryptedBlob;
    if (blob.version !== 'edict-evidence-aes256gcm-1' || blob.sha256 !== sha256) {
      throw new Error(`invalid encrypted evidence envelope ${sha256}`);
    }
    const decipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(blob.iv, 'base64'));
    decipher.setAAD(Buffer.from(sha256, 'ascii'));
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
    if (sha256Hex(plaintext) !== sha256) throw new Error(`decrypted evidence hash mismatch ${sha256}`);
    return plaintext;
  }
}
