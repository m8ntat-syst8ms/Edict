/**
 * Environment configuration for the edict-node service.
 *
 * The MODE is EXPLICIT and required: `EDICT_NODE_MODE=dstack` (production,
 * inside a dstack CVM — signing key derived via the dstack guest agent,
 * attestation = real TDX quote) or `EDICT_NODE_MODE=dev` (local development —
 * locally persisted key, clearly-labeled mock attestation `{dev_mode:true}`).
 * There is deliberately NO default and NO auto-detection: a court node must
 * never silently boot with an unattested key.
 */

export type NodeMode = 'dstack' | 'dev';

export interface NodeConfig {
  mode: NodeMode;
  host: string;
  port: number;
  /** OpenAI-compatible base URL of the wrapped local model server (…/v1). */
  localModelUrl: string;
  /** Persistent state: signature store (+ dev key in dev mode). */
  dataDir: string;
  /** When set, reject completion requests whose body `model` differs. */
  modelIdPin: string | undefined;
  /** When set, all /v1/* endpoints require `Authorization: Bearer <key>`. */
  apiKey: string | undefined;
  /** dstack guest agent unix socket (dstack mode). */
  dstackSocket: string;
  /** GetKey derivation path + purpose (dstack mode). Pin these forever — they determine the signing address. */
  dstackKeyPath: string;
  dstackKeyPurpose: string;
  /** Dev mode only: fixed private key (hex). Otherwise generated + persisted under dataDir. */
  devPrivateKeyHex: string | undefined;
  maxBodyBytes: number;
  /** Maximum time for one local model completion. */
  upstreamTimeoutMs: number;
}

export function loadConfig(env: Record<string, string | undefined> = process.env): NodeConfig {
  const mode = env.EDICT_NODE_MODE;
  if (mode !== 'dstack' && mode !== 'dev') {
    throw new Error(
      "EDICT_NODE_MODE must be set explicitly to 'dstack' (in-TEE production) or 'dev' " +
        '(local development with a MOCK attestation). Refusing to guess.',
    );
  }
  const port = Number(env.EDICT_NODE_PORT ?? '8100');
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`EDICT_NODE_PORT is not a valid port: ${env.EDICT_NODE_PORT}`);
  }
  const localModelUrl = (env.LOCAL_MODEL_URL ?? 'http://127.0.0.1:8000/v1').trim().replace(/\/+$/, '');
  let parsedModelUrl: URL;
  try {
    parsedModelUrl = new URL(localModelUrl);
  } catch {
    throw new Error(`LOCAL_MODEL_URL is not a valid URL: ${localModelUrl}`);
  }
  if (parsedModelUrl.protocol !== 'http:' && parsedModelUrl.protocol !== 'https:') {
    throw new Error('LOCAL_MODEL_URL must use http: or https:');
  }
  const modelIdPin = emptyToUndef(env.EDICT_NODE_MODEL_ID);
  const apiKey = emptyToUndef(env.EDICT_NODE_API_KEY);
  const maxBodyBytes = positiveInt(env.EDICT_NODE_MAX_BODY_BYTES ?? String(10 * 1024 * 1024), 'EDICT_NODE_MAX_BODY_BYTES');
  const upstreamTimeoutMs = positiveInt(env.EDICT_NODE_UPSTREAM_TIMEOUT_MS ?? '180000', 'EDICT_NODE_UPSTREAM_TIMEOUT_MS');
  if (maxBodyBytes > 100 * 1024 * 1024) throw new Error('EDICT_NODE_MAX_BODY_BYTES must be <= 104857600');
  if (upstreamTimeoutMs > 15 * 60 * 1000) throw new Error('EDICT_NODE_UPSTREAM_TIMEOUT_MS must be <= 900000');
  if (mode === 'dstack' && modelIdPin === undefined) {
    throw new Error('EDICT_NODE_MODEL_ID is required in dstack mode so signed envelopes cannot mislabel the served model');
  }
  if (mode === 'dstack' && (apiKey === undefined || apiKey.length < 32)) {
    throw new Error('EDICT_NODE_API_KEY is required in dstack mode and must be at least 32 characters');
  }
  const config: NodeConfig = {
    mode,
    host: env.EDICT_NODE_HOST ?? '0.0.0.0',
    port,
    localModelUrl,
    dataDir: env.EDICT_NODE_DATA_DIR ?? (mode === 'dstack' ? '/data' : './data'),
    modelIdPin,
    apiKey,
    dstackSocket: env.DSTACK_SOCKET ?? '/var/run/dstack.sock',
    dstackKeyPath: env.DSTACK_KEY_PATH ?? 'edict/proof-signing',
    dstackKeyPurpose: env.DSTACK_KEY_PURPOSE ?? 'edict-node-proof-signing-v1',
    devPrivateKeyHex: emptyToUndef(env.EDICT_NODE_DEV_PRIVATE_KEY),
    maxBodyBytes,
    upstreamTimeoutMs,
  };
  if (config.dstackKeyPath.length === 0 || config.dstackKeyPurpose.length === 0) {
    throw new Error('DSTACK_KEY_PATH and DSTACK_KEY_PURPOSE must be non-empty');
  }
  return config;
}

function emptyToUndef(s: string | undefined): string | undefined {
  const trimmed = s?.trim();
  return trimmed !== undefined && trimmed.length > 0 ? trimmed : undefined;
}

function positiveInt(raw: string, name: string): number {
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}
