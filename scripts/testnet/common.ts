/**
 * Shared plumbing for the Edict native NEAR testnet scripts.
 *
 * Transactions are signed/sent by shelling out to `near` (near-cli-rs) with
 * `sign-with-access-key-file` pointing at the gitignored credentials in
 * `scripts/testnet/.credentials/`. Views and assertions go straight to the
 * testnet JSON-RPC. No new runtime dependencies — dev tooling only.
 */
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCRIPT_DIR = dirname(dirname(fileURLToPath(import.meta.url))); // scripts/testnet (compiled file lives in dist/)
export const REPO_ROOT = join(SCRIPT_DIR, '..', '..');
export const CREDENTIALS_DIR = join(SCRIPT_DIR, '.credentials');
export const RPC_URL = process.env.NEAR_TESTNET_RPC_URL ?? 'https://test.rpc.fastnear.com';
export const NEAR_CLI = process.env.NEAR_CLI
  ?? (existsSync(join(homedir(), '.local', 'node', 'bin', 'near'))
    ? join(homedir(), '.local', 'node', 'bin', 'near')
    : 'near');

/** Deployment suffix minted at account-creation time (see README). */
export function suffix(): string {
  const fromEnv = process.env.EDICT_TESTNET_SUFFIX;
  if (fromEnv) return fromEnv;
  const f = join(CREDENTIALS_DIR, 'suffix.txt');
  if (!existsSync(f)) {
    throw new Error(`no EDICT_TESTNET_SUFFIX env var and no ${f} — create the testnet accounts first (README step 2)`);
  }
  const m = readFileSync(f, 'utf8').match(/SUFFIX=([a-z0-9]+)/);
  if (!m) throw new Error(`malformed ${f}`);
  return m[1];
}

export interface Accounts {
  requester: string;
  worker: string;
}

export function accounts(): Accounts {
  const s = suffix();
  return {
    requester: `edict-req-${s}.testnet`,
    worker: `edict-wrk-${s}.testnet`,
  };
}

export function credentialFile(accountId: string): string {
  const f = join(CREDENTIALS_DIR, `${accountId}.json`);
  if (!existsSync(f)) throw new Error(`missing credential file ${f}`);
  return f;
}

// ---------------------------------------------------------------------------
// near-cli-rs transaction helpers
// ---------------------------------------------------------------------------

export interface NearCallResult {
  ok: boolean;
  txHash: string | null;
  output: string;
}

export function nearCommand(argv: string[], allowFailure = false): NearCallResult {
  const res = spawnSync(NEAR_CLI, argv, { encoding: 'utf8', timeout: 180_000 });
  const output = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
  const txHash = output.match(/Transaction ID:\s*([1-9A-HJ-NP-Za-km-z]{32,})/)?.[1] ?? null;
  const ok = res.status === 0 && !/error/i.test(res.stderr ?? '');
  if (!ok && !allowFailure) {
    throw new Error(`near command failed (${NEAR_CLI} ${argv.join(' ')}):\n${output}`);
  }
  return { ok, txHash, output };
}

/** `near contract call-function as-transaction ...` via near-cli-rs. */
export function nearCall(opts: {
  contract: string;
  method: string;
  args: unknown;
  gas?: string;
  deposit?: string;
  signAs: string;
  /** Expected to fail: do not throw on nonzero exit. */
  allowFailure?: boolean;
}): NearCallResult {
  const argv = [
    'contract', 'call-function', 'as-transaction',
    opts.contract, opts.method,
    'json-args', JSON.stringify(opts.args),
    'prepaid-gas', opts.gas ?? '100 Tgas',
    'attached-deposit', opts.deposit ?? '0 NEAR',
    'sign-as', opts.signAs,
    'network-config', 'testnet',
    'sign-with-access-key-file', credentialFile(opts.signAs),
    'send',
  ];
  return nearCommand(argv, opts.allowFailure ?? false);
}

// ---------------------------------------------------------------------------
// JSON-RPC helpers (views, balances, tx receipts)
// ---------------------------------------------------------------------------

export async function nearRpc(method: string, params: unknown): Promise<any> {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 'edict-demo', method, params }),
    });
    const body: any = await res.json();
    if (body.error) {
      if (attempt < 4) {
        await new Promise((r) => setTimeout(r, 1500 * attempt));
        continue;
      }
      throw new Error(`RPC ${method} error: ${JSON.stringify(body.error)}`);
    }
    return body.result;
  }
}

/** Call a view function; returns the JSON-decoded result. */
export async function viewFunction<T>(contract: string, method: string, args: unknown): Promise<T> {
  const result = await nearRpc('query', {
    request_type: 'call_function',
    finality: 'final',
    account_id: contract,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  });
  return JSON.parse(Buffer.from(result.result).toString('utf8')) as T;
}

/** Account balance in yoctoNEAR. */
export async function viewBalance(accountId: string): Promise<bigint> {
  const result = await nearRpc('query', {
    request_type: 'view_account',
    finality: 'final',
    account_id: accountId,
  });
  return BigInt(result.amount);
}

/** Full transaction status incl. receipts (for return values + logs). */
export async function txStatus(txHash: string, signerId: string): Promise<any> {
  return nearRpc('tx', { tx_hash: txHash, sender_account_id: signerId, wait_until: 'FINAL' });
}

/** SuccessValue of the transaction, JSON-decoded (null if none). */
export function txReturnValue(status: any): unknown {
  const sv = status?.status?.SuccessValue;
  if (sv === undefined || sv === null) return null;
  const raw = Buffer.from(sv, 'base64').toString('utf8');
  return raw.length ? JSON.parse(raw) : null;
}

/** All receipt logs of the transaction, flattened. */
export function txLogs(status: any): string[] {
  const out: string[] = [];
  for (const ro of status?.receipts_outcome ?? []) out.push(...(ro.outcome?.logs ?? []));
  return out;
}

// ---------------------------------------------------------------------------
// misc
// ---------------------------------------------------------------------------

export function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data).digest();
}

export function bytesToNumberArray(b: Uint8Array): number[] {
  return Array.from(b);
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

export function randomNonce(): Uint8Array {
  return Uint8Array.from(randomBytes(32));
}

export const NEAR = 10n ** 24n;

export function fmtNear(yocto: bigint): string {
  const whole = yocto / NEAR;
  const frac = ((yocto % NEAR) * 10_000n) / NEAR; // 4 decimal places
  return `${whole}.${frac.toString().padStart(4, '0')} NEAR`;
}

export function explorerTx(hash: string): string {
  return `https://testnet.nearblocks.io/txns/${hash}`;
}
