import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCustomerSettlementExecutionDigest, MockProvider } from '@edict/arbiter';
import type { CaseObject, FinalVerdict } from '@edict/core';
import { canonicalize, sha256Hex } from '@edict/evidence';
import { createProtectionEvent } from './events.js';
import {
  HttpExecutionSignatureCollector,
  validateExecutionSignatureRequest,
} from './executionSigners.js';
import { ProtectionRuntimeHttpClient } from './client.js';
import { HttpPermissionlessRelayer } from './relayer.js';
import { ProtectionRuntime } from './runtime.js';
import { protectionRuntimeServerUrl, startProtectionRuntimeServer } from './server.js';
import { JsonlProtectionEventStore, MemoryProtectionEventStore } from './store.js';
import { EncryptedFileEvidenceVault, MemoryEvidenceVault } from './vault.js';
import { runtimeVerifierPolicySha256 } from './verifierPolicy.js';
import type { ExecutionSignatureRequest, RuntimeVerifierPolicy } from './types.js';

const PROTECTION_ID = 'a'.repeat(64);

function executionRequest(quorum = 2): ExecutionSignatureRequest {
  const caseObject: CaseObject = {
    caseId: 'a1b2c3d4-0000-4000-8000-0000000000aa',
    caseType: 'bilateral',
    publicity: 'sealed',
    requester: { agentId: 'requester.near' },
    worker: { agentId: 'worker.near' },
    orderMandateHash: PROTECTION_ID,
    evidence: [{ kind: 'order_mandate', sha256: PROTECTION_ID, submitter: 'system', authenticated: true }],
    valueUsd: 100,
    tier: 'B',
    custodyMode: 'M2_external_escrow',
    railRef: { rail: 'near-intents' },
    legalProfile: { governingLaw: 'england_wales', seat: 'london', rules: 'edict-drr-v0.1', enforcementTier: 'E0' },
    openedAtUnixMs: 1_750_000_000_000,
    decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins'] },
  };
  const verdict: FinalVerdict = {
    caseId: caseObject.caseId,
    ruling: { kind: 'worker_wins' },
    final: true,
    reasoningSha256: 'b'.repeat(64),
    votes: [],
    quality: { majority: 'unanimous', swapFlipRate: 0, injectionFlags: [], escalated: false },
    legalProfile: caseObject.legalProfile,
    issuedAtUnixMs: 1_750_000_001_000,
  };
  const policy: RuntimeVerifierPolicy = {
    scheme: 'ecdsa_secp256k1_eth',
    quorum,
    signers: [1, 2, 3].map((suffix) => ({
      signingAddress: `0x${String(suffix).repeat(40)}`,
      operatorId: `operator-${suffix}`,
      edictControlled: false,
      attestationSha256Hex: String(suffix).repeat(64),
    })),
  };
  const verdictSha256Hex = sha256Hex(canonicalize(verdict));
  const nonceHex = 'd'.repeat(64);
  const executionContext = {
    settlementAccountId: 'protect.near',
    orderMandateSha256Hex: PROTECTION_ID,
    caseIdSha256Hex: sha256Hex(caseObject.caseId),
    round: 1 as const,
    rulingCanonical: 'worker_wins',
    issuedAtUnixMs: verdict.issuedAtUnixMs,
    verifierPolicySha256Hex: runtimeVerifierPolicySha256(policy),
  };
  return {
    protectionId: PROTECTION_ID,
    caseObject,
    verdict,
    verdictSha256Hex,
    executionDigestHex: buildCustomerSettlementExecutionDigest({
      ...executionContext,
      verdictSha256Hex,
      nonce: Buffer.from(nonceHex, 'hex'),
    }),
    nonceHex,
    policy,
    executionContext,
  };
}

test('runtime verifier-policy hash matches the Rust Borsh vector', () => {
  const signer = (operatorId: string, suffix: number, edictControlled: boolean) => ({
    signingAddress: `0x${suffix.toString(16).padStart(40, '0')}`,
    operatorId,
    edictControlled,
    attestationSha256Hex: suffix.toString(16).padStart(2, '0').repeat(32),
  });
  assert.equal(runtimeVerifierPolicySha256({
    scheme: 'ecdsa_secp256k1_eth',
    quorum: 2,
    signers: [
      signer('edict', 1, true),
      signer('independent-a', 2, false),
      signer('independent-b', 3, false),
    ],
  }), '43af56e807df1d1340869d46ec64590e6d2ff5660d98ba8a1aa3c82cd703038d');
});

function warningEvent() {
  return createProtectionEvent({
    protectionId: PROTECTION_ID,
    type: 'connector_warning',
    source: { kind: 'runtime', id: 'test', externalId: 'warning-1' },
    effectiveAtUnixMs: 1_750_000_000_000,
    observedAtUnixMs: 1_750_000_000_100,
    payload: { code: 'test', message: 'test warning' },
    authentication: { kind: 'runtime', reason: 'test' },
  });
}

test('JSONL event store survives restart, ignores observation-time retries and detects tampering', async () => {
  const root = await mkdtemp(join(tmpdir(), 'edict-runtime-store-'));
  const path = join(root, 'events.jsonl');
  const first = new JsonlProtectionEventStore(path);
  const event = warningEvent();
  assert.equal(await first.append(event), 'appended');
  assert.equal(await first.append({ ...event, observedAtUnixMs: event.observedAtUnixMs + 1_000 }), 'duplicate');

  const restarted = new JsonlProtectionEventStore(path);
  assert.equal((await restarted.list()).length, 1);
  const raw = await readFile(path, 'utf8');
  await writeFile(path, raw.replace('test warning', 'tampered warning'), 'utf8');
  await assert.rejects(new JsonlProtectionEventStore(path).initialize(), /payload hash mismatch/);
});

test('encrypted evidence vault is content-addressed and fails closed under a wrong key', async () => {
  const root = await mkdtemp(join(tmpdir(), 'edict-runtime-vault-'));
  const key = randomBytes(32);
  const vault = new EncryptedFileEvidenceVault(root, key);
  const stored = await vault.put('sealed evidence bytes');
  assert.equal(await vault.get(stored.sha256), 'sealed evidence bytes');
  assert.equal((await vault.put('sealed evidence bytes')).sha256, stored.sha256);
  const disk = await readFile(join(root, stored.sha256.slice(0, 2), `${stored.sha256}.json`), 'utf8');
  assert.doesNotMatch(disk, /sealed evidence bytes/);
  const wrongKey = new EncryptedFileEvidenceVault(root, randomBytes(32));
  await assert.rejects(wrongKey.get(stored.sha256));
});

test('runtime HTTP server exposes public health but protects customer data with bearer auth', async () => {
  const archiveDir = await mkdtemp(join(tmpdir(), 'edict-runtime-setup-'));
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    adjudicator: {
      providers: new Map([['only-provider', new MockProvider('only-provider')]]),
      archiveDir,
    },
  });
  const hexToken = 'f'.repeat(64);
  const server = await startProtectionRuntimeServer(runtime, { port: 0, apiTokens: ['correct-token', hexToken] });
  const base = protectionRuntimeServerUrl(server);
  try {
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json() as { custody: string }).custody, 'none');
    const denied = await fetch(`${base}/v1/activity`);
    assert.equal(denied.status, 401);
    const accepted = await fetch(`${base}/v1/activity`, { headers: { authorization: 'Bearer correct-token' } });
    assert.equal(accepted.status, 200);
    assert.deepEqual((await accepted.json() as { activity: unknown[] }).activity, []);
    const acceptedHex = await fetch(`${base}/v1/activity`, { headers: { authorization: `Bearer ${hexToken}` } });
    assert.equal(acceptedHex.status, 200, '64-hex plaintext tokens are not confused with stored digests');
    const setup = await fetch(`${base}/v1/setup`, { headers: { authorization: 'Bearer correct-token' } });
    const setupBody = await setup.json() as {
      runtime: string;
      capabilities: {
        observation: { ready: boolean };
        adjudication: { ready: boolean; providerCount: number; minimumProviderCount: number };
        executionSignatures: { ready: boolean };
        missingRequired: string[];
      };
      custody: { customerFundsHeld: boolean; customerKeysHeld: boolean };
    };
    assert.equal(setupBody.runtime, 'configuration_required');
    assert.equal(setupBody.capabilities.observation.ready, false);
    assert.equal(setupBody.capabilities.adjudication.ready, false);
    assert.equal(setupBody.capabilities.adjudication.providerCount, 1);
    assert.equal(setupBody.capabilities.adjudication.minimumProviderCount, 2);
    assert.equal(setupBody.capabilities.executionSignatures.ready, false);
    assert.equal(setupBody.capabilities.missingRequired.length, 3);
    assert.equal(setupBody.custody.customerFundsHeld, false);
    assert.equal(setupBody.custody.customerKeysHeld, false);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('runtime HTTP server cannot expose customer data outside loopback without authentication', async () => {
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
  });
  await assert.rejects(
    startProtectionRuntimeServer(runtime, { host: '0.0.0.0', port: 0 }),
    /API token is required/,
  );
  await assert.rejects(
    startProtectionRuntimeServer(runtime, { port: 0, apiTokens: [''] }),
    /must not be empty/,
  );
});

test('runtime rejects plaintext remote webhook transport and embedded URL credentials', async () => {
  for (const url of ['http://customer.invalid/verdict', 'https://user:secret@customer.invalid/verdict']) {
    const runtime = new ProtectionRuntime({
      eventStore: new MemoryProtectionEventStore(),
      evidenceVault: new MemoryEvidenceVault(),
      verdictWebhooks: [{ id: 'customer', url, secret: 'runtime-webhook-secret-123' }],
    });
    await assert.rejects(runtime.initialize(), /HTTPS|credentials/);
  }
});

test('HTTP execution collector tolerates one signer outage but enforces requested quorum', async () => {
  const requests: Array<Record<string, unknown>> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/down')) throw new Error('offline');
    requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
    const suffix = url.endsWith('/one') ? '1' : '2';
    return new Response(JSON.stringify({
      signing_address: `0x${suffix.repeat(40)}`,
      signature: `0x${suffix.repeat(130)}`,
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const collector = new HttpExecutionSignatureCollector({
    endpoints: [
      { id: 'one', url: 'https://signer.invalid/one' },
      { id: 'two', url: 'https://signer.invalid/two' },
      { id: 'down', url: 'https://signer.invalid/down' },
    ],
    fetchImpl,
  });
  assert.equal((await collector.collect(executionRequest())).length, 2);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request['caseObject'] !== undefined
    && request['verdict'] !== undefined && request['policy'] !== undefined));
  const tampered = executionRequest();
  tampered.verdict.ruling = { kind: 'requester_wins' };
  await assert.rejects(collector.collect(tampered), /verdict hash|ruling/);
  assert.equal(requests.length, 2, 'invalid requests are rejected before any signer sees them');
  await assert.rejects(collector.collect(executionRequest(3)), /quorum unavailable/);
});

test('execution signature request validation is total and rejects malformed policy bytes', () => {
  assert.deepEqual(validateExecutionSignatureRequest(null), ['execution request must be an object']);
  const malformed = executionRequest() as unknown as Record<string, unknown>;
  malformed['policy'] = { scheme: 'ecdsa_secp256k1_eth', quorum: 2, signers: [null, null] };
  assert.match(validateExecutionSignatureRequest(malformed).join('; '), /signers\[0\] must be an object/);
  const nonCanonical = executionRequest() as unknown as Record<string, unknown>;
  (nonCanonical['verdict'] as Record<string, unknown>)['unsupportedBigInt'] = 1n;
  assert.doesNotThrow(() => validateExecutionSignatureRequest(nonCanonical));
  assert.match(validateExecutionSignatureRequest(nonCanonical).join('; '), /not canonical JSON/);
});

test('execution signer endpoints require protected transport without URL credentials', () => {
  for (const url of ['http://signer.invalid/sign', 'https://user:secret@signer.invalid/sign']) {
    assert.throws(() => new HttpExecutionSignatureCollector({
      endpoints: [
        { id: 'one', url },
        { id: 'two', url: 'https://signer-two.invalid/sign' },
      ],
    }), /HTTPS|credentials/);
  }
});

test('runtime clients and relayers never send credentials over unprotected transport', () => {
  for (const baseUrl of ['http://runtime.invalid', 'https://user:secret@runtime.invalid']) {
    assert.throws(
      () => new ProtectionRuntimeHttpClient({ baseUrl, apiToken: 'secret' }),
      /HTTPS|credentials/,
    );
  }
  for (const endpoint of ['http://relayer.invalid/submit', 'https://user:secret@relayer.invalid/submit']) {
    assert.throws(
      () => new HttpPermissionlessRelayer(endpoint, 'secret'),
      /HTTPS|credentials/,
    );
  }
  assert.throws(
    () => new HttpPermissionlessRelayer('https://relayer.invalid/submit', undefined, fetch, 0),
    /timeout/,
  );
});
