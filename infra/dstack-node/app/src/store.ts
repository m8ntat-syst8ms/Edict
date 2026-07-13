/**
 * Persistent on-disk signature store — one JSON document per completion,
 * written BEFORE the completion response is returned to the client and kept
 * FOREVER (no cache expiry). This deliberately fixes the weakness of the
 * managed providers: NEAR AI's `/v1/signature/{chat_id}` cache expires and
 * Phala's lives ~5 minutes, forcing the arbiter to archive proofs
 * immediately; on OUR node a proof can be re-fetched years later.
 *
 * Layout: `${dir}/sig_<sanitized chat id>_<sha256(chat id)[0..16]>.json`.
 * The hash suffix disambiguates chat ids that sanitize to the same filename
 * and makes lookups deterministic without an index.
 */
import { randomUUID } from 'node:crypto';
import { link, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sanitizeName, sha256Hex } from './util.js';

export interface SignatureDoc {
  api_version: 'edict-node/1';
  chat_id: string;
  model_id: string;
  request_sha256: string;
  response_sha256: string;
  /** The exact signed envelope: `${model_id}:${request_sha256}:${response_sha256}`. */
  text: string;
  /** 65-byte r||s||v personal-message signature, 0x-hex. */
  signature: string;
  signing_address: string;
  signing_algo: 'ecdsa';
  signature_scheme: 'ecdsa_secp256k1_eth';
  created_at_unix_ms: number;
}

/** A completion id is already bound to different signed bytes. */
export class SignatureConflictError extends Error {
  readonly chatId: string;

  constructor(chatId: string) {
    super(`signature store already contains a different proof for chat id "${chatId}"`);
    this.name = 'SignatureConflictError';
    this.chatId = chatId;
  }
}

export class SignatureStore {
  constructor(private readonly dir: string) {}

  private pathFor(chatId: string): string {
    return join(this.dir, `sig_${sanitizeName(chatId).slice(0, 80)}_${sha256Hex(chatId).slice(0, 16)}.json`);
  }

  /**
   * Atomic immutable create (complete temp file + hard link). Replaying the
   * exact document is idempotent; rebinding a chat id to different bytes is a
   * conflict. Proof identifiers must never become mutable pointers.
   */
  async put(doc: SignatureDoc): Promise<string> {
    await mkdir(this.dir, { recursive: true });
    const path = this.pathFor(doc.chat_id);
    const tmp = `${path}.tmp-${process.pid}-${randomUUID()}`;
    await writeFile(tmp, `${JSON.stringify(doc, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    try {
      await link(tmp, path);
      return path;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
      const existing = await this.get(doc.chat_id);
      if (existing !== undefined && JSON.stringify(existing) === JSON.stringify(doc)) return path;
      throw new SignatureConflictError(doc.chat_id);
    } finally {
      await unlink(tmp).catch(() => undefined);
    }
  }

  async get(chatId: string): Promise<SignatureDoc | undefined> {
    try {
      const raw = await readFile(this.pathFor(chatId), 'utf8');
      return JSON.parse(raw) as SignatureDoc;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      if (err instanceof SyntaxError) return undefined; // torn/corrupt file — treat as absent
      throw err;
    }
  }
}
