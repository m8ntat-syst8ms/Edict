#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  EdictNodeProvider,
  MockProvider,
  NearAiProvider,
  PhalaProvider,
} from '@edict/arbiter';
import type { InferenceProvider } from '@edict/core';
import { SANDBOX_MOCK_SEATS } from '@edict/sdk';
import { HttpExecutionSignatureCollector, type ExecutionSignerEndpoint } from './executionSigners.js';
import { HttpPermissionlessRelayer } from './relayer.js';
import { EncryptedFileEvidenceVault } from './vault.js';
import { NearIntentsConnector, NearJsonRpcViewClient, NearNativeConnector } from './nearIntentsConnector.js';
import { ProtectionRuntime } from './runtime.js';
import { startProtectionRuntimeServer, protectionRuntimeServerUrl } from './server.js';
import { JsonlProtectionEventStore } from './store.js';
import type { VerdictWebhookTarget } from './types.js';

interface CliOptions {
  port: number;
  dataDir: string;
  rail: 'near-intents' | 'near-native';
  connectorId: string;
  rpcUrl: string;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    port: Number(process.env.PORT ?? 4890),
    dataDir: process.env.EDICT_RUNTIME_DATA_DIR ?? join(homedir(), '.edict-protect-runtime'),
    rail: process.env.EDICT_RUNTIME_RAIL === 'near-native' ? 'near-native' : 'near-intents',
    connectorId: process.env.EDICT_CONNECTOR_ID ?? process.env.EDICT_INTENTS_CONNECTOR_ID ?? '',
    rpcUrl: process.env.NEAR_RPC_URL ?? '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    if (arg === '--port' || arg === '-p') options.port = Number(argv[++index]);
    else if (arg === '--data-dir') options.dataDir = argv[++index]!;
    else if (arg === '--rail') {
      const rail = argv[++index];
      if (rail !== 'near-intents' && rail !== 'near-native') throw new Error('--rail must be near-intents or near-native');
      options.rail = rail;
    }
    else if (arg === '--connector-id') options.connectorId = argv[++index]!;
    else if (arg === '--rpc-url') options.rpcUrl = argv[++index]!;
    else if (arg === '--help' || arg === '-h') {
      console.log('usage: edict-protection-runtime [--port 4890] [--data-dir PATH] [--rail near-intents|near-native] [--connector-id ID] [--rpc-url URL]');
      process.exit(0);
    } else throw new Error(`unknown argument ${arg}`);
  }
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535) throw new Error('port is invalid');
  options.connectorId ||= options.rail === 'near-native' ? 'near-native-testnet' : 'near-intents-mainnet';
  options.rpcUrl ||= options.rail === 'near-native' ? 'https://test.rpc.fastnear.com' : 'https://free.rpc.fastnear.com';
  return options;
}

async function vaultKey(dataDir: string): Promise<Buffer> {
  const value = process.env.EDICT_EVIDENCE_KEY_HEX;
  if (value === undefined) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('EDICT_EVIDENCE_KEY_HEX is required in production');
    }
    const path = join(dataDir, 'development-evidence.key');
    try {
      const existing = (await readFile(path, 'utf8')).trim();
      if (!/^[0-9a-f]{64}$/.test(existing)) throw new Error('development evidence key file is malformed');
      return Buffer.from(existing, 'hex');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const generated = randomBytes(32);
      await writeFile(path, generated.toString('hex'), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      console.warn(`EDICT_EVIDENCE_KEY_HEX is unset; created a local development key at ${path}`);
      return generated;
    }
  }
  if (!/^[0-9a-fA-F]{64}$/.test(value)) throw new Error('EDICT_EVIDENCE_KEY_HEX must be exactly 64 hex characters');
  return Buffer.from(value, 'hex');
}

function jsonEnv<T>(name: string, fallback: T): T {
  const raw = process.env[name];
  if (raw === undefined || raw.trim().length === 0) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`${name} must be valid JSON`);
  }
}

function providerMap(archiveDir: string): Map<string, InferenceProvider> {
  const providers = new Map<string, InferenceProvider>();
  if (process.env.EDICT_RUNTIME_MOCK_PROVIDERS === 'true') {
    if (process.env.NODE_ENV === 'production') throw new Error('mock arbiter providers are forbidden in production');
    for (const seat of SANDBOX_MOCK_SEATS) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  if (process.env.NEARAI_API_KEY !== undefined) {
    const provider = new NearAiProvider({ archiveDir: join(archiveDir, 'nearai') });
    providers.set(provider.id, provider);
  }
  if (process.env.PHALA_API_KEY !== undefined) {
    const provider = new PhalaProvider({ archiveDir: join(archiveDir, 'phala') });
    providers.set(provider.id, provider);
  }
  if (process.env.EDICT_NODE_BASE_URL !== undefined) {
    const provider = new EdictNodeProvider({ archiveDir: join(archiveDir, 'edict-node') });
    providers.set(provider.id, provider);
  }
  return providers;
}

function webhookTargets(): VerdictWebhookTarget[] {
  const definitions = jsonEnv<Array<{ id: string; url: string; secretEnv: string }>>('EDICT_WEBHOOKS_JSON', []);
  return definitions.map((definition) => {
    const secret = process.env[definition.secretEnv];
    if (secret === undefined) throw new Error(`webhook ${definition.id} secret env ${definition.secretEnv} is unset`);
    return { id: definition.id, url: definition.url, secret };
  });
}

const options = parseArgs(process.argv.slice(2));
await mkdir(options.dataDir, { recursive: true, mode: 0o700 });
const evidenceKey = await vaultKey(options.dataDir);
const archiveDir = join(options.dataDir, 'arbiter');
const providers = providerMap(archiveDir);
const signerEndpoints = jsonEnv<ExecutionSignerEndpoint[]>('EDICT_EXECUTION_SIGNERS_JSON', []);
const executionSignatures = signerEndpoints.length > 0
  ? new HttpExecutionSignatureCollector({ endpoints: signerEndpoints })
  : undefined;
const relayerEndpoint = process.env.EDICT_RELAYER_URL;
const relayer = relayerEndpoint === undefined
  ? undefined
  : new HttpPermissionlessRelayer(relayerEndpoint, process.env.EDICT_RELAYER_TOKEN);
const connector = options.rail === 'near-native'
  ? new NearNativeConnector(options.connectorId, new NearJsonRpcViewClient(options.rpcUrl))
  : new NearIntentsConnector(options.connectorId, new NearJsonRpcViewClient(options.rpcUrl));
const runtime = new ProtectionRuntime({
  eventStore: new JsonlProtectionEventStore(join(options.dataDir, 'events.jsonl')),
  evidenceVault: new EncryptedFileEvidenceVault(join(options.dataDir, 'evidence'), evidenceKey),
  connectors: [connector],
  ...(providers.size > 0 ? { adjudicator: { providers, archiveDir } } : {}),
  ...(executionSignatures !== undefined ? { executionSignatures } : {}),
  ...(relayer !== undefined ? { relayer, autoRelay: true } : {}),
  verdictWebhooks: webhookTargets(),
});
const apiTokens = process.env.EDICT_RUNTIME_API_TOKEN === undefined ? [] : [process.env.EDICT_RUNTIME_API_TOKEN];
if (apiTokens.length === 0 && process.env.NODE_ENV === 'production') {
  throw new Error('EDICT_RUNTIME_API_TOKEN is required in production');
}
const server = await startProtectionRuntimeServer(runtime, { port: options.port, apiTokens });
console.log(`Edict Protect runtime listening on ${protectionRuntimeServerUrl(server)}`);
if (providers.size === 0) console.warn('No live arbiter providers configured; disputes will remain queued until providers are added');
if (executionSignatures === undefined) console.warn('No execution signer endpoints configured; final decisions will not become relayable');
if (relayer === undefined) console.warn('No relayer configured; permissionless plans remain available through the API');

const pollIntervalMs = Number(process.env.EDICT_RUNTIME_POLL_MS ?? 15_000);
if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 1_000) {
  throw new Error('EDICT_RUNTIME_POLL_MS must be an integer of at least 1000');
}
let stopping = false;
let timer: NodeJS.Timeout | undefined;
async function loop(): Promise<void> {
  if (stopping) return;
  try {
    await runtime.pollConnectors();
  } catch (error) {
    console.error(`runtime poll failed: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    if (!stopping) timer = setTimeout(() => void loop(), pollIntervalMs);
  }
}
void loop();

function shutdown(): void {
  stopping = true;
  if (timer !== undefined) clearTimeout(timer);
  server.close(() => process.exit(0));
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
