#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BLOCK_HASH = 'GBRYPr7dzEr5FcA8ssCvBkGQEZLrZWYz5SKenicG6ZLH';
const CODE_HASH_BASE58 = 'HUJ89jxFhsXF17XS8L5kmxz7te8AKfdWw2xzrVYo7aoj';
const SHA256_HEX = 'f4b908b631562d62c133cc58b0a053dab41d6e243990c54694ac42264679f4ea';
const ACCOUNT_ID = 'intents.near';
const RPC_URL = process.env.NEAR_MAINNET_RPC ?? 'https://rpc.mainnet.near.org';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = resolve(root, 'target', `intents-verifier-${SHA256_HEX}.wasm`);

function verify(bytes) {
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== SHA256_HEX) {
    throw new Error(`pinned Intents Verifier SHA-256 mismatch: expected ${SHA256_HEX}, got ${digest}`);
  }
}

try {
  const cached = readFileSync(output);
  verify(cached);
  process.stdout.write(`${output}\n`);
  process.exit(0);
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
}

const response = await fetch(RPC_URL, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    id: 'edict-pinned-intents-verifier',
    method: 'query',
    params: {
      request_type: 'view_code',
      block_id: BLOCK_HASH,
      account_id: ACCOUNT_ID,
    },
  }),
});
if (!response.ok) throw new Error(`NEAR RPC HTTP ${response.status}`);
const payload = await response.json();
if (payload.error !== undefined || typeof payload.result?.code_base64 !== 'string') {
  throw new Error(`NEAR RPC did not return pinned Verifier code: ${JSON.stringify(payload.error)}`);
}
if (payload.result.hash !== CODE_HASH_BASE58) {
  throw new Error(`pinned Intents Verifier code hash mismatch: ${String(payload.result.hash)}`);
}
const bytes = Buffer.from(payload.result.code_base64, 'base64');
verify(bytes);
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, bytes);
process.stdout.write(`${output}\n`);
