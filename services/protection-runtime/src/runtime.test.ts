import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { MockProvider, ethPersonalBytesDigest } from '@edict/arbiter';
import { canonicalize, sha256Hex, type DeliveryManifest } from '@edict/evidence';
import {
  nearIntentsRoute,
  nearIntentsSettlementBinding,
} from '@edict/near-intents';
import { adapterRef } from '@edict/near-deployer';
import {
  customerContractSettlement,
  createEdict,
  profileHash,
  standardProfile,
} from '@edict/sdk';
import { NearIntentsConnector, NearNativeConnector, type NearViewClient } from './nearIntentsConnector.js';
import { ProtectionRuntime } from './runtime.js';
import { signedActionMessage } from './signatures.js';
import { MemoryProtectionEventStore } from './store.js';
import { MemoryEvidenceVault } from './vault.js';
import { verifyRuntimeWebhook } from './webhooks.js';
import { runtimeVerifierPolicySha256 } from './verifierPolicy.js';
import type {
  ExecutionSignatureCollector,
  PermissionlessRelayer,
  ProtectionEventDraft,
  ProtectionRegistration,
  RelayPlan,
  RuntimeVerifierSigner,
  RuntimeVerifierPolicy,
  SignedActionEnvelope,
  SignedActionName,
  SignedActionPayloadMap,
} from './types.js';

const START = Date.now() - 60_000;
const DAY = 86_400_000;
const runtimeServers: Array<{ close(callback?: () => void): void }> = [];

afterEach(() => {
  for (const server of runtimeServers.splice(0)) server.close();
});

interface PartyKey {
  publicHex: string;
  privateKey: KeyObject;
}

type IntentsRegistration = ProtectionRegistration & {
  intents: NonNullable<ProtectionRegistration['intents']>;
};

type NativeRegistration = ProtectionRegistration & {
  nativeNear: NonNullable<ProtectionRegistration['nativeNear']>;
};

function partyKey(): PartyKey {
  const pair = generateKeyPairSync('ed25519');
  const der = pair.publicKey.export({ format: 'der', type: 'spki' });
  return { publicHex: der.subarray(-32).toString('hex'), privateKey: pair.privateKey };
}

function signed<A extends SignedActionName>(
  key: PartyKey,
  role: 'requester' | 'worker',
  protectionId: string,
  action: A,
  payload: SignedActionPayloadMap[A],
  nonce: string,
  issuedAtUnixMs = START,
): SignedActionEnvelope<A> {
  const unsigned: SignedActionEnvelope<A> = {
    version: 'edict-protect-signed-action-1',
    action,
    protectionId,
    signer: `ed25519:${key.publicHex}`,
    role,
    nonce,
    issuedAtUnixMs,
    expiresAtUnixMs: issuedAtUnixMs + 10 * 60_000,
    scheme: 'ed25519',
    publicKey: key.publicHex,
    payload,
    signature: '',
  };
  return {
    ...unsigned,
    signature: nodeSign(null, Buffer.from(signedActionMessage(unsigned)), key.privateKey).toString('hex'),
  };
}

const SIGNER_PRIVS = [
  new Uint8Array(32).fill(0x31),
  new Uint8Array(32).fill(0x32),
  new Uint8Array(32).fill(0x33),
];

function addressOf(privateKey: Uint8Array): string {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  return `0x${Buffer.from(keccak_256(publicKey.slice(1)).slice(-20)).toString('hex')}`;
}

function verifierSigner(index: number): RuntimeVerifierSigner {
  return {
    signingAddress: addressOf(SIGNER_PRIVS[index]!),
    operatorId: `operator-${index + 1}`,
    edictControlled: index === 0,
    attestationSha256Hex: `${index + 1}`.repeat(64),
  };
}

function verifierPolicy(): RuntimeVerifierPolicy {
  return {
    scheme: 'ecdsa_secp256k1_eth',
    quorum: 2,
    signers: [verifierSigner(0), verifierSigner(1), verifierSigner(2)],
  };
}

function executionSignature(privateKey: Uint8Array, digestHex: string): string {
  const digest = ethPersonalBytesDigest(Buffer.from(digestHex, 'hex'));
  const recovered = secp256k1.sign(digest, privateKey, { format: 'recovered', prehash: false });
  return `0x${Buffer.concat([Buffer.from(recovered.slice(1)), Buffer.from([recovered[0]! + 27])]).toString('hex')}`;
}

async function fixture(now = START, paymentId = 'pay-001', amountUsd = 100): Promise<{
  registration: IntentsRegistration;
  requester: PartyKey;
  worker: PartyKey;
}> {
  const requester = partyKey();
  const worker = partyKey();
  const profile = standardProfile();
  const policy = verifierPolicy();
  const route = nearIntentsRoute({
    settlementAccount: 'protect.acme.near',
    settlementAsset: 'nep141:usdc.omft.near',
    removalIntentsAccount: 'protection-pool.near',
  });
  const settlement = nearIntentsSettlementBinding(route, {
    resolutionTimeoutMs: 3 * DAY,
    livenessFallback: 'refund_requester',
  });
  const client = createEdict({ mode: 'live', profile, settlement });
  const result = await client.protectPayment({
    paymentId,
    requester: `ed25519:${requester.publicHex}`,
    worker: `ed25519:${worker.publicHex}`,
    promise: 'Deliver result.json matching the committed checksum.',
    acceptanceCriteria: [{
      id: 'AC-1',
      statement: 'result.json must match the committed checksum',
      machineCheck: { kind: 'hash_equals', params: { path: 'result.json', sha256: 'a'.repeat(64) } },
    }],
    amountUsd,
    deadlineUnixMs: now + DAY,
    currency: { asset: 'USDC', rail: 'near-intents' },
  });
  return {
    requester,
    worker,
    registration: {
      version: 'edict-protection-registration-1',
      mandate: result.mandate,
      mandateHash: result.mandateHash,
      legalPolicyHash: result.legalPolicyHash,
      profile,
      profileHash: profileHash(profile),
      evidenceCommitments: result.evidenceCommitments,
      intents: {
        connectorId: 'near-mainnet',
        route,
        requesterIntentsAccount: 'requester.near',
        workerIntentsAccount: 'worker.near',
        principalAtomic: String(Math.round(amountUsd * 1_000_000)),
        challengeWindowMs: profile.legalPolicy.challengeWindowMs,
        resolutionTimeoutMs: 3 * DAY,
        disputeBondBps: 500,
        verifierPolicySha256Hex: runtimeVerifierPolicySha256(policy),
        verifierPolicy: policy,
      },
      integrationRef: 'test-rail',
    },
  };
}

async function nativeFixture(now = START): Promise<{
  registration: NativeRegistration;
  requester: PartyKey;
  worker: PartyKey;
}> {
  const requester = partyKey();
  const worker = partyKey();
  const profile = standardProfile();
  const policy = verifierPolicy();
  const settlementAccount = 'protect.customer.testnet';
  const settlement = customerContractSettlement(adapterRef(settlementAccount), {
    resolutionTimeoutMs: 3 * DAY,
    livenessFallback: 'refund_requester',
  });
  const client = createEdict({ mode: 'live', profile, settlement });
  const result = await client.protectPayment({
    paymentId: 'native-pay-001',
    requester: `ed25519:${requester.publicHex}`,
    worker: `ed25519:${worker.publicHex}`,
    promise: 'Deliver result.json matching the committed checksum.',
    acceptanceCriteria: [{
      id: 'AC-1',
      statement: 'result.json must match the committed checksum',
      machineCheck: { kind: 'hash_equals', params: { path: 'result.json', sha256: 'a'.repeat(64) } },
    }],
    amountUsd: 100,
    deadlineUnixMs: now + DAY,
    currency: { asset: 'NEAR', rail: 'near-native-testnet' },
  });
  return {
    requester,
    worker,
    registration: {
      version: 'edict-protection-registration-1',
      mandate: result.mandate,
      mandateHash: result.mandateHash,
      legalPolicyHash: result.legalPolicyHash,
      profile,
      profileHash: profileHash(profile),
      evidenceCommitments: result.evidenceCommitments,
      nativeNear: {
        version: 'edict-native-near-runtime-1',
        connectorId: 'near-native-testnet',
        network: 'testnet',
        settlementAccount,
        settlementAsset: 'native:near',
        requesterAccount: 'requester.testnet',
        workerAccount: 'worker.testnet',
        principalAtomic: '20000000000000000000000',
        challengeWindowMs: profile.legalPolicy.challengeWindowMs,
        resolutionTimeoutMs: 3 * DAY,
        disputeBondBps: 500,
        verifierPolicySha256Hex: runtimeVerifierPolicySha256(policy),
        verifierPolicy: policy,
      },
      integrationRef: 'native-test-rail',
    },
  };
}

function funding(registration: IntentsRegistration, at = START): ProtectionEventDraft<'funding_confirmed'> {
  return {
    protectionId: registration.mandateHash,
    type: 'funding_confirmed',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'tx:fund' },
    effectiveAtUnixMs: at,
    observedAtUnixMs: at,
    payload: {
      requester: registration.intents.requesterIntentsAccount,
      worker: registration.intents.workerIntentsAccount,
      tokenId: registration.intents.route.settlementAsset,
      principalAtomic: registration.intents.principalAtomic,
      transactionHash: 'fund-tx',
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      receiptId: 'fund-receipt',
      finality: 'final',
    },
  };
}

test('registration is idempotent and rejects any Edict custody capability', async () => {
  const { registration } = await fixture();
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => START,
  });
  const first = await runtime.register(registration);
  const second = await runtime.register(structuredClone(registration));
  assert.equal(first.protectionId, registration.mandateHash);
  assert.equal(second.events.length, 1);
  const unsafe = structuredClone(registration);
  (unsafe.mandate.settlement as { edictOperatorCanTransfer: boolean }).edictOperatorCanTransfer = true;
  unsafe.mandateHash = sha256Hex(canonicalize(unsafe.mandate));
  await assert.rejects(runtime.register(unsafe), /custody|transfer/i);

  const noRoster = structuredClone(registration);
  delete noRoster.profile.juryPolicy.seats;
  noRoster.profileHash = profileHash(noRoster.profile);
  await assert.rejects(runtime.register(noRoster), /explicit immutable jury seat roster/);

  const malformedMandate = structuredClone(registration);
  malformedMandate.mandate.acceptanceCriteria = [];
  malformedMandate.mandateHash = sha256Hex(canonicalize(malformedMandate.mandate));
  const mandateCommitment = malformedMandate.evidenceCommitments.find((entry) => entry.kind === 'order_mandate')!;
  mandateCommitment.sha256 = malformedMandate.mandateHash;
  await assert.rejects(runtime.register(malformedMandate), /acceptanceCriteria.*non-empty/);

  const swappedPolicy = structuredClone(registration);
  swappedPolicy.profile.legalPolicy.policyId = 'different-legal-policy';
  swappedPolicy.profileHash = profileHash(swappedPolicy.profile);
  await assert.rejects(runtime.register(swappedPolicy), /Profile Legal Policy does not match/);

  const understatedPrincipal = structuredClone(registration);
  understatedPrincipal.intents.principalAtomic = '1000000';
  await assert.rejects(runtime.register(understatedPrincipal), /micro-USDC/);

  const overPrecise = (await fixture(START, 'over-precise-usdc', 1.0000001)).registration;
  await assert.rejects(runtime.register(overPrecise), /at most 6 decimal places/);

  const oversizedPrincipal = structuredClone(registration);
  oversizedPrincipal.intents.principalAtomic = (1n << 128n).toString();
  await assert.rejects(runtime.register(oversizedPrincipal), /uint128/);

  const malformedStanding = structuredClone(registration);
  malformedStanding.standingChallengeAuthorization = {
    version: 'edict-standing-challenge-1',
    party: 'worker',
    triggerKinds: ['objective_failure'],
    caseId: 'a1b2c3d4-0000-4000-8000-0000000000aa',
    caseIdSha256: sha256Hex('a1b2c3d4-0000-4000-8000-0000000000aa'),
    bondAtomic: '5000000',
    expiresAtUnixMs: malformedStanding.mandate.deadlineUnixMs + 1,
    signedIntentSha256: sha256Hex(canonicalize({ signed: true })),
    signedIntent: { signed: true },
  };
  await assert.rejects(runtime.register(malformedStanding), /must be signed by the requester/);

  const nativeMainnet = (await nativeFixture()).registration;
  nativeMainnet.nativeNear.network = 'mainnet';
  await assert.rejects(runtime.register(nativeMainnet), /native NEAR on testnet only/);

  const numericNativePrincipal = (await nativeFixture()).registration;
  (numericNativePrincipal.nativeNear as unknown as Record<string, unknown>)['principalAtomic'] = 20_000;
  await assert.rejects(runtime.register(numericNativePrincipal), /positive atomic-unit integer/);

  const numericNativeAccount = (await nativeFixture()).registration;
  (numericNativeAccount.nativeNear as unknown as Record<string, unknown>)['requesterAccount'] = 12;
  await assert.rejects(runtime.register(numericNativeAccount), /requester account is invalid/);

  const tierC = (await fixture(START, 'tier-c-placement', 2_000)).registration;
  tierC.profile.juryPolicy.seats = tierC.profile.juryPolicy.seats!.slice(0, 2);
  tierC.profileHash = profileHash(tierC.profile);
  await assert.rejects(runtime.register(tierC), /tier C.*3 distinct jury providers/);

  const raceRuntime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => START,
  });
  const conflicting = structuredClone(registration);
  conflicting.profile.name = 'edict-preset-standard-conflict';
  conflicting.profileHash = profileHash(conflicting.profile);
  const registrations = await Promise.allSettled([
    raceRuntime.register(registration),
    raceRuntime.register(conflicting),
  ]);
  assert.equal(registrations.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(registrations.filter((outcome) => outcome.status === 'rejected').length, 1);
  assert.equal((await raceRuntime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'protection_registered').length, 1);
});

test('signed ingress verifies party identity and rejects nonce replay', async () => {
  const { registration, worker } = await fixture();
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => START,
  });
  await runtime.register(registration);
  const approval = signed(worker, 'worker', registration.mandateHash, 'approve_protection', {}, 'approval-nonce');
  await runtime.handleSignedAction(approval);
  await assert.rejects(runtime.handleSignedAction(approval), /nonce has already been used/);
  const projection = await runtime.getProtection(registration.mandateHash);
  assert.equal(projection.workerApproved, true);
  assert.equal(projection.attention.some((entry) => entry.kind === 'counterparty_approval'), false);
});

test('signed ingress is closed-schema and rejects concurrent nonce reuse', async () => {
  const { registration, worker } = await fixture();
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => START,
  });
  await runtime.register(registration);

  const concurrent = signed(worker, 'worker', registration.mandateHash, 'approve_protection', {}, 'concurrent-nonce');
  const outcomes = await Promise.allSettled([
    runtime.handleSignedAction(concurrent),
    runtime.handleSignedAction(concurrent),
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected').length, 1);
  assert.equal((await runtime.listEvents(registration.mandateHash)).filter((event) => event.type === 'protection_accepted').length, 1);

  const unknownAction = structuredClone(signed(
    worker, 'worker', registration.mandateHash, 'approve_protection', {}, 'unknown-action-nonce',
  ));
  (unknownAction as unknown as { action: string }).action = 'arbitrary_transfer';
  await assert.rejects(runtime.handleSignedAction(unknownAction as SignedActionEnvelope), /action name is unsupported/);

  const invalidEvidence = structuredClone(signed(
    worker,
    'worker',
    registration.mandateHash,
    'attach_evidence',
    { kind: 'party_submission', plaintext: 'evidence' },
    'invalid-evidence-nonce',
  )) as SignedActionEnvelope<'attach_evidence'>;
  (invalidEvidence.payload as { kind: string }).kind = 'order_mandate';
  await assert.rejects(runtime.handleSignedAction(invalidEvidence), /evidence kind is unsupported/);

  const extraField = structuredClone(signed(
    worker, 'worker', registration.mandateHash, 'approve_protection', {}, 'extra-field-nonce',
  )) as SignedActionEnvelope<'approve_protection'>;
  (extraField.payload as Record<string, unknown>)['admin'] = true;
  await assert.rejects(runtime.handleSignedAction(extraField), /unknown field admin/);

  const malformedDelivery = signed(
    worker,
    'worker',
    registration.mandateHash,
    'attach_evidence',
    {
      kind: 'delivery_manifest',
      plaintext: canonicalize({
        formatClaims: [],
        workerAgentId: registration.mandate.worker.agentId,
        orderMandateHash: registration.mandateHash,
        deliveredAtUnixMs: START,
      }),
    },
    'malformed-delivery-nonce',
  );
  await assert.rejects(runtime.handleSignedAction(malformedDelivery), /artifactHashes/);
  assert.equal((await runtime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'evidence_attached').length, 0);
});

test('signed ingress serializes competing challenge requests for one dispute round', async () => {
  const { registration, requester } = await fixture();
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => START + 2_000,
  });
  await runtime.register(registration);
  await runtime.ingest(funding(registration));
  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'delivery_submitted',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'delivery-race' },
    effectiveAtUnixMs: START + 1_000,
    observedAtUnixMs: START + 1_000,
    payload: {
      manifestSha256: 'a'.repeat(64),
      deliveredAtUnixMs: START + 1_000,
      worker: registration.intents.workerIntentsAccount,
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      finality: 'final',
    },
  });

  const outcomes = await Promise.allSettled([
    runtime.handleSignedAction(signed(
      requester, 'requester', registration.mandateHash, 'open_challenge', {}, 'challenge-race-one', START + 2_000,
    )),
    runtime.handleSignedAction(signed(
      requester, 'requester', registration.mandateHash, 'open_challenge', {}, 'challenge-race-two', START + 2_000,
    )),
  ]);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((outcome) => outcome.status === 'rejected').length, 1);
  assert.equal((await runtime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'challenge_requested').length, 1);
});

test('deadline scheduler emits one contract-revalidated permissionless timeout plan', async () => {
  const { registration } = await fixture();
  let now = registration.mandate.deadlineUnixMs + 1;
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => now,
  });
  await runtime.register(registration);
  await runtime.ingest(funding(registration));
  await runtime.tick(now);
  await runtime.tick(now + 10_000);
  const projection = await runtime.getProtection(registration.mandateHash, now);
  const timeoutPlans = projection.relayPlans.filter((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'claim_timeout');
  assert.equal(timeoutPlans.length, 1);
  assert.equal(timeoutPlans[0]!.authorization, 'permissionless');
  assert.equal(timeoutPlans[0]!.guarantees.noCustomerKey, true);

  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'settlement_finalized',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'timeout-settled-elsewhere' },
    effectiveAtUnixMs: now + 20_000,
    observedAtUnixMs: now + 20_000,
    payload: {
      ruling: 'requester_wins',
      requesterClaimAtomic: '0',
      workerClaimAtomic: '0',
      settledAtUnixMs: now + 20_000,
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      finality: 'final',
    },
  });
  assert.equal((await runtime.getProtection(registration.mandateHash, now + 20_000)).relayPlans.length, 0);
});

test('NEAR Intents connector is idempotent and rejects mismatched on-chain facts', async () => {
  const { registration } = await fixture();
  let transportDown = false;
  const order = {
    order_mandate_sha256: [...Buffer.from(registration.mandateHash, 'hex')],
    settlement_binding_sha256: [...Buffer.from(sha256Hex(canonicalize(registration.mandate.settlement)), 'hex')],
    requester: registration.intents.requesterIntentsAccount,
    worker: registration.intents.workerIntentsAccount,
    principal: registration.intents.principalAtomic,
    state: 'funded' as const,
    deadline_ms: registration.mandate.deadlineUnixMs,
    acceptance_window_ms: registration.mandate.acceptanceWindowMs,
    challenge_window_ms: registration.intents.challengeWindowMs,
    resolution_timeout_ms: registration.intents.resolutionTimeoutMs,
    verifier_policy_sha256: [...Buffer.from(registration.intents.verifierPolicySha256Hex, 'hex')],
    delivery: null,
    dispute: null,
    redo_count: 0,
    last_resolution: null,
  };
  const view: NearViewClient = {
    async callFunction<T>(_account: string, method: string): Promise<T> {
      if (transportDown) throw new Error('RPC unavailable');
      if (method === 'get_order') return structuredClone(order) as T;
      if (method === 'get_rounds') return [] as T;
      throw new Error(`unexpected ${method}`);
    },
  };
  const connector = new NearIntentsConnector('near-mainnet', view, () => START);
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    connectors: [connector],
    now: () => START,
  });
  await runtime.register(registration);
  const firstPoll = await runtime.pollConnectors();
  const secondPoll = await runtime.pollConnectors();
  assert.equal(firstPoll.appendedEventIds.length, 1);
  assert.deepEqual(secondPoll.appendedEventIds, []);
  const fundingEvents = (await runtime.listEvents(registration.mandateHash)).filter((event) => event.type === 'funding_confirmed');
  assert.equal(fundingEvents.length, 1);

  order.principal = '999';
  const observations = await connector.poll([{
    registration,
    events: await runtime.listEvents(registration.mandateHash),
  }]);
  assert.equal(observations.length, 1);
  assert.equal(observations[0]!.type, 'connector_warning');
  const mismatch = observations[0] as ProtectionEventDraft<'connector_warning'>;
  assert.equal(mismatch.payload.code, 'near_intents_state_mismatch');
  assert.match(mismatch.payload.message, /principal/);

  order.principal = registration.intents.principalAtomic;
  transportDown = true;
  await runtime.pollConnectors();
  const projection = await runtime.getProtection(registration.mandateHash);
  assert.equal(projection.state, 'protected');
  assert.equal(projection.attention.filter((item) => item.kind === 'connector_availability').length, 1);
  transportDown = false;
  await runtime.pollConnectors();
  const recovered = await runtime.getProtection(registration.mandateHash);
  assert.equal(recovered.attention.filter((item) => item.kind === 'connector_availability').length, 0);
  assert.equal((await runtime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'connector_recovered').length, 1);
});

test('connector claim snapshots reconcile a withdrawal whose relay receipt was lost', async () => {
  const { registration } = await fixture();
  let workerClaim = registration.intents.principalAtomic;
  const resolution = {
    ruling: { kind: 'worker_wins' },
    source: { kind: 'verified_proof' },
    resolved_at_ms: START + 1_000,
  };
  const order = {
    order_mandate_sha256: [...Buffer.from(registration.mandateHash, 'hex')],
    settlement_binding_sha256: [...Buffer.from(sha256Hex(canonicalize(registration.mandate.settlement)), 'hex')],
    requester: registration.intents.requesterIntentsAccount,
    worker: registration.intents.workerIntentsAccount,
    principal: registration.intents.principalAtomic,
    state: 'settled' as const,
    deadline_ms: registration.mandate.deadlineUnixMs,
    acceptance_window_ms: registration.mandate.acceptanceWindowMs,
    challenge_window_ms: registration.intents.challengeWindowMs,
    resolution_timeout_ms: registration.intents.resolutionTimeoutMs,
    verifier_policy_sha256: [...Buffer.from(registration.intents.verifierPolicySha256Hex, 'hex')],
    delivery: null,
    dispute: null,
    redo_count: 0,
    last_resolution: resolution,
  };
  const view: NearViewClient = {
    async callFunction<T>(_account: string, method: string, args: Record<string, unknown>): Promise<T> {
      if (method === 'get_order') return structuredClone(order) as T;
      if (method === 'claim_of') {
        return (args['account_id'] === registration.intents.workerIntentsAccount ? workerClaim : '0') as T;
      }
      throw new Error(`unexpected ${method}`);
    },
  };
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    connectors: [new NearIntentsConnector('near-mainnet', view, () => START + 2_000)],
    now: () => START + 2_000,
  });
  await runtime.register(registration);
  await runtime.pollConnectors();
  assert.equal((await runtime.getProtection(registration.mandateHash)).relayPlans.filter((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'withdraw_claim').length, 1);

  workerClaim = '0';
  await runtime.pollConnectors();
  const projection = await runtime.getProtection(registration.mandateHash);
  assert.equal(projection.relayPlans.length, 0);
  const settlements = projection.events.filter((event) => event.type === 'settlement_finalized');
  assert.equal(settlements.length, 2);
  assert.equal(settlements.at(-1)?.type === 'settlement_finalized'
    && settlements.at(-1)?.payload.workerClaimAtomic, '0');
});

test('native NEAR connector observes final state, blocks mismatches and returns a keyless wallet action', async () => {
  const { registration, requester } = await nativeFixture();
  const manifestSha256 = 'b'.repeat(64);
  const order = {
    order_mandate_sha256: [...Buffer.from(registration.mandateHash, 'hex')],
    settlement_binding_sha256: [...Buffer.from(sha256Hex(canonicalize(registration.mandate.settlement)), 'hex')],
    requester: registration.nativeNear.requesterAccount,
    worker: registration.nativeNear.workerAccount,
    principal: registration.nativeNear.principalAtomic,
    state: 'delivered' as const,
    deadline_ms: registration.mandate.deadlineUnixMs,
    acceptance_window_ms: registration.mandate.acceptanceWindowMs,
    challenge_window_ms: registration.nativeNear.challengeWindowMs,
    resolution_timeout_ms: registration.nativeNear.resolutionTimeoutMs,
    verifier_policy_sha256: [...Buffer.from(registration.nativeNear.verifierPolicySha256Hex, 'hex')],
    delivery: {
      manifest_sha256: [...Buffer.from(manifestSha256, 'hex')],
      delivered_at_ms: START + 1_000,
    },
    dispute: null,
    redo_count: 0,
    last_resolution: null,
  };
  const view: NearViewClient = {
    async callFunction<T>(_account: string, method: string): Promise<T> {
      if (method === 'get_order') return structuredClone(order) as T;
      if (method === 'get_rounds') return [] as T;
      throw new Error(`unexpected ${method}`);
    },
  };
  const connector = new NearNativeConnector('near-native-testnet', view, () => START + 2_000);
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    connectors: [connector],
    now: () => START + 2_000,
  });
  await runtime.register(registration);
  await runtime.pollConnectors();
  const events = await runtime.listEvents(registration.mandateHash);
  const funded = events.find((event) => event.type === 'funding_confirmed');
  assert.equal(funded?.source.kind, 'near_native');
  assert.equal(events.filter((event) => event.type === 'delivery_submitted').length, 1);

  const challenge = await runtime.handleSignedAction(signed(
    requester,
    'requester',
    registration.mandateHash,
    'open_challenge',
    { statement: 'The committed output does not match.' },
    'native-challenge-nonce',
    START + 2_000,
  ));
  const action = challenge.action as Record<string, unknown>;
  assert.equal(action['kind'], 'near_function_call');
  assert.equal(action['contractId'], registration.nativeNear.settlementAccount);
  assert.equal(action['methodName'], 'open_dispute');
  assert.equal(action['depositYocto'], '1000000000000000000000');
  assert.equal(action['signer'], 'requester');
  assert.equal('privateKey' in action, false);
  assert.equal('secretKey' in action, false);

  order.principal = '999';
  const mismatch = await connector.poll([{ registration, events: await runtime.listEvents(registration.mandateHash) }]);
  assert.equal(mismatch.length, 1);
  assert.equal(mismatch[0]!.type, 'connector_warning');
  const warning = mismatch[0] as ProtectionEventDraft<'connector_warning'>;
  assert.equal(warning.payload.code, 'near_native_state_mismatch');
  await runtime.ingest(warning);
  assert.equal((await runtime.getProtection(registration.mandateHash)).state, 'blocked');
});

test('full signed challenge, adjudication, quorum authorization, webhook and relay lifecycle', async () => {
  const { registration, requester, worker } = await fixture();
  let now = START;
  const relayed: RelayPlan[] = [];
  const relayer: PermissionlessRelayer = {
    async relay(plan) {
      relayed.push(structuredClone(plan));
      return { transactionHash: `tx-${plan.planId.slice(0, 12)}` };
    },
  };
  const collector: ExecutionSignatureCollector = {
    async collect(request) {
      return [1, 2].map((index) => ({
        signing_address: addressOf(SIGNER_PRIVS[index]!),
        signature: executionSignature(SIGNER_PRIVS[index]!, request.executionDigestHex),
      }));
    },
  };
  const webhookBodies: Array<{ body: string; signature: string }> = [];
  const webhookSecret = 'runtime-webhook-secret-123';
  const webhookFetch: typeof fetch = async (_input, init) => {
    webhookBodies.push({
      body: String(init?.body),
      signature: String((init?.headers as Record<string, string>)['x-edict-signature']),
    });
    const status = webhookBodies.length <= 3 ? 503 : 200;
    return new Response('{}', { status, headers: { 'content-type': 'application/json' } });
  };
  const providers = new Map<string, MockProvider>();
  for (const seat of registration.profile.juryPolicy.seats ?? []) {
    if (!providers.has(seat.providerId)) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  const archiveDir = await mkdtemp(join(tmpdir(), 'edict-runtime-arbiter-'));
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    adjudicator: { providers, archiveDir },
    executionSignatures: collector,
    relayer,
    autoRelay: true,
    verdictWebhooks: [{ id: 'customer', url: 'https://customer.invalid/verdict', secret: webhookSecret }],
    webhookFetch,
    now: () => now,
  });
  await runtime.register(registration);
  await runtime.ingest(funding(registration));
  await runtime.handleSignedAction(signed(
    worker,
    'worker',
    registration.mandateHash,
    'approve_protection',
    {},
    'worker-approval',
  ));
  const manifest: DeliveryManifest = {
    artifactHashes: [{ path: 'result.json', sha256: 'a'.repeat(64), mediaType: 'application/json' }],
    formatClaims: ['application/json'],
    workerAgentId: registration.mandate.worker.agentId,
    orderMandateHash: registration.mandateHash,
    deliveredAtUnixMs: START + 1_000,
  };
  await runtime.handleSignedAction(signed(
    worker,
    'worker',
    registration.mandateHash,
    'attach_evidence',
    { kind: 'delivery_manifest', plaintext: canonicalize(manifest) },
    'delivery-nonce',
    START + 1_000,
  ));
  const challenge = await runtime.handleSignedAction(signed(
    requester,
    'requester',
    registration.mandateHash,
    'open_challenge',
    { statement: 'The output does not satisfy the promised result.' },
    'challenge-nonce',
    START + 2_000,
  ));
  assert.equal((challenge.action as { intent: string }).intent, 'transfer');
  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'challenge_opened',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'tx:challenge' },
    effectiveAtUnixMs: START + 3_000,
    observedAtUnixMs: START + 3_000,
    payload: {
      caseId: challenge.caseId,
      caseIdSha256: challenge.caseIdSha256!,
      by: 'requester',
      openedAtUnixMs: START + 3_000,
      bondAtomic: '5000000',
      round: 1,
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      receiptId: 'challenge-receipt',
      finality: 'final',
    },
  });
  now = START + 4_000;
  const decided = await runtime.tick(now);
  assert.equal(decided.webhookDeliveries[0]?.delivered, false);
  assert.equal(webhookBodies.length, 3);
  const verdictEvent = (await runtime.listEvents(registration.mandateHash)).find((event) => event.type === 'verdict_issued');
  assert.ok(verdictEvent?.type === 'verdict_issued');
  assert.equal(verdictEvent.payload.verdict.final, true);
  assert.equal(verdictEvent.payload.execution?.signatures.length, 2);
  const failedWebhook = (await runtime.listEvents(registration.mandateHash)).find(
    (event) => event.type === 'webhook_delivery_recorded' && !event.payload.delivered,
  );
  assert.ok(failedWebhook?.type === 'webhook_delivery_recorded');
  assert.equal((await runtime.getProtection(registration.mandateHash, now)).attention.some(
    (entry) => entry.kind === 'webhook_delivery'), true);
  now = failedWebhook.payload.nextAttemptAtUnixMs! - 1;
  await runtime.tick(now);
  assert.equal(webhookBodies.length, 3, 'durable backoff prevents a hot retry loop');
  now += 1;
  const retried = await runtime.tick(now);
  assert.equal(retried.webhookDeliveries[0]?.delivered, true);
  assert.equal(webhookBodies.length, 4);
  assert.equal(verifyRuntimeWebhook(webhookBodies[3]!.body, webhookBodies[3]!.signature, webhookSecret), true);
  assert.equal((await runtime.getProtection(registration.mandateHash, now)).attention.some(
    (entry) => entry.kind === 'webhook_delivery'), false);
  await runtime.tick(now + 1);
  assert.equal(webhookBodies.length, 4, 'successful delivery remains idempotent across future ticks');
  const beforeWindow = await runtime.getProtection(registration.mandateHash, now);
  const rulingPlan = beforeWindow.relayPlans.find((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'submit_ruling');
  assert.ok(rulingPlan, JSON.stringify({
    plans: beforeWindow.relayPlans,
    events: beforeWindow.events.map((event) => event.type),
  }));
  assert.equal(relayed.length, 0, 'challenge window prevents early relay');

  now = verdictEvent.payload.verdict.issuedAtUnixMs + registration.intents.challengeWindowMs;
  await runtime.tick(now);
  assert.equal(relayed.some((plan) => plan.kind === 'near_function_call' && plan.methodName === 'submit_ruling'), true);

  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'settlement_finalized',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'tx:settle' },
    effectiveAtUnixMs: now + 1,
    observedAtUnixMs: now + 1,
    payload: {
      ruling: 'worker_wins',
      requesterClaimAtomic: '100',
      workerClaimAtomic: '99999900',
      transactionHash: 'settlement-tx',
      settledAtUnixMs: now + 1,
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      receiptId: 'settlement-receipt',
      finality: 'final',
    },
  });
  now += 2;
  await runtime.tick(now);
  const withdrawals = relayed.filter((plan) => plan.kind === 'near_function_call' && plan.methodName === 'withdraw_claim');
  assert.equal(withdrawals.length, 2);
  assert.ok(withdrawals.every((plan) => plan.kind === 'near_function_call' && plan.depositYocto === '0'));
  assert.equal((await runtime.getProtection(registration.mandateHash, now)).state, 'settled');
});

test('redo scopes adjudication to round two and removes redo from its decision space', async () => {
  const { registration, requester, worker } = await fixture(START, 'runtime-redo-rounds');
  let now = START + 1_000;
  const providers = new Map<string, MockProvider>();
  for (const seat of registration.profile.juryPolicy.seats ?? []) {
    if (!providers.has(seat.providerId)) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    adjudicator: { providers, archiveDir: await mkdtemp(join(tmpdir(), 'edict-runtime-redo-')) },
    now: () => now,
  });
  await runtime.register(registration);
  await runtime.ingest(funding(registration));

  const delivery = async (nonce: string, deliveredAtUnixMs: number): Promise<void> => {
    now = deliveredAtUnixMs;
    const manifest: DeliveryManifest = {
      artifactHashes: [{ path: 'result.json', sha256: 'a'.repeat(64), mediaType: 'application/json' }],
      formatClaims: ['application/json'],
      workerAgentId: registration.mandate.worker.agentId,
      orderMandateHash: registration.mandateHash,
      deliveredAtUnixMs,
    };
    await runtime.handleSignedAction(signed(
      worker,
      'worker',
      registration.mandateHash,
      'attach_evidence',
      { kind: 'delivery_manifest', plaintext: canonicalize(manifest) },
      nonce,
      deliveredAtUnixMs,
    ));
  };
  const openRound = async (round: 1 | 2, requestedAt: number, openedAt: number): Promise<void> => {
    now = requestedAt;
    const requested = await runtime.handleSignedAction(signed(
      requester,
      'requester',
      registration.mandateHash,
      'open_challenge',
      { statement: `Review round ${round}.` },
      `round-${round}-challenge`,
      requestedAt,
    ));
    await runtime.ingest({
      protectionId: registration.mandateHash,
      type: 'challenge_opened',
      source: { kind: 'near_intents', id: 'near-mainnet', externalId: `round-${round}-opened` },
      effectiveAtUnixMs: openedAt,
      observedAtUnixMs: openedAt,
      payload: {
        caseId: requested.caseId,
        caseIdSha256: requested.caseIdSha256!,
        by: 'requester',
        openedAtUnixMs: openedAt,
        bondAtomic: round === 1 ? '5000000' : '0',
        round,
      },
      authentication: {
        kind: 'connector_receipt',
        contractId: registration.intents.route.settlementAccount,
        receiptId: `round-${round}-receipt`,
        finality: 'final',
      },
    });
  };

  await delivery('round-1-delivery', START + 1_000);
  await openRound(1, START + 2_000, START + 3_000);
  now = START + 4_000;
  await runtime.tick(now);
  let verdicts = (await runtime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'verdict_issued',
  );
  assert.equal(verdicts.length, 1);

  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'redo_ordered',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'round-1-redo' },
    effectiveAtUnixMs: START + 5_000,
    observedAtUnixMs: START + 5_000,
    payload: { newDeadlineUnixMs: START + DAY, bondHeldAtomic: '5000000', round: 1 },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      receiptId: 'redo-receipt',
      finality: 'final',
    },
  });
  await delivery('round-2-delivery', START + 6_000);
  await openRound(2, START + 7_000, START + 8_000);
  now = START + 9_000;
  await runtime.tick(now);

  verdicts = (await runtime.listEvents(registration.mandateHash)).filter(
    (event) => event.type === 'verdict_issued',
  );
  assert.equal(verdicts.length, 2);
  const second = verdicts[1]!;
  assert.equal(second.type, 'verdict_issued');
  assert.equal(second.payload.caseObject.round?.number, 2);
  assert.equal(second.payload.caseObject.round?.priorCaseId, verdicts[0]!.type === 'verdict_issued'
    ? verdicts[0]!.payload.caseObject.caseId : undefined);
  assert.deepEqual(second.payload.caseObject.decisionSpace, {
    kind: 'escrow_branches',
    permitted: ['requester_wins', 'worker_wins', 'split'],
  });
});

test('redo starts a fresh clean-path deadline and ignores the completed round-one challenge', async () => {
  const { registration } = await fixture(START, 'runtime-redo-deadline');
  const redoDeadline = registration.mandate.deadlineUnixMs + 10_000;
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    now: () => redoDeadline + 1,
  });
  await runtime.register(registration);
  await runtime.ingest(funding(registration));
  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'challenge_opened',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'completed-round-1-challenge' },
    effectiveAtUnixMs: START + 1_000,
    observedAtUnixMs: START + 1_000,
    payload: {
      caseId: 'a1b2c3d4-0000-4000-8000-0000000000aa',
      caseIdSha256: sha256Hex('a1b2c3d4-0000-4000-8000-0000000000aa'),
      by: 'requester',
      openedAtUnixMs: START + 1_000,
      bondAtomic: '5000000',
      round: 1,
    },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      finality: 'final',
    },
  });
  await runtime.ingest({
    protectionId: registration.mandateHash,
    type: 'redo_ordered',
    source: { kind: 'near_intents', id: 'near-mainnet', externalId: 'completed-round-1-redo' },
    effectiveAtUnixMs: START + 2_000,
    observedAtUnixMs: START + 2_000,
    payload: { newDeadlineUnixMs: redoDeadline, bondHeldAtomic: '5000000', round: 1 },
    authentication: {
      kind: 'connector_receipt',
      contractId: registration.intents.route.settlementAccount,
      finality: 'final',
    },
  });

  await runtime.tick(redoDeadline + 1);
  const events = await runtime.listEvents(registration.mandateHash);
  const deadline = events.find((event) => event.type === 'deadline_elapsed'
    && event.payload.deadlineUnixMs === redoDeadline);
  assert.ok(deadline?.type === 'deadline_elapsed');
  assert.equal(deadline.payload.deadlineKind, 'delivery');
  const projection = await runtime.getProtection(registration.mandateHash, redoDeadline + 1);
  assert.equal(projection.relayPlans.some((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'claim_timeout'), true);
  assert.equal(projection.relayPlans.some((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'execute_liveness_fallback'), false);
});

test('one aggregate account withdrawal acknowledges simultaneous plans across protections', async () => {
  const first = await fixture(START, 'aggregate-withdrawal-1');
  const second = await fixture(START, 'aggregate-withdrawal-2');
  const submitted: RelayPlan[] = [];
  const runtime = new ProtectionRuntime({
    eventStore: new MemoryProtectionEventStore(),
    evidenceVault: new MemoryEvidenceVault(),
    relayer: {
      async relay(plan) {
        submitted.push(structuredClone(plan));
        return { transactionHash: 'aggregate-withdrawal-tx' };
      },
    },
    autoRelay: true,
    now: () => START + 2_000,
  });
  for (const registration of [first.registration, second.registration]) {
    await runtime.register(registration);
    await runtime.ingest({
      protectionId: registration.mandateHash,
      type: 'settlement_finalized',
      source: { kind: 'near_intents', id: 'near-mainnet', externalId: `settled:${registration.mandateHash}` },
      effectiveAtUnixMs: START + 1_000,
      observedAtUnixMs: START + 1_000,
      payload: {
        ruling: 'worker_wins',
        requesterClaimAtomic: '0',
        workerClaimAtomic: '200000000',
        settledAtUnixMs: START + 1_000,
      },
      authentication: {
        kind: 'connector_receipt',
        contractId: registration.intents.route.settlementAccount,
        finality: 'final',
      },
    });
  }

  const tick = await runtime.tick(START + 2_000);
  assert.equal(submitted.length, 1, 'the contract-wide worker claim is withdrawn once');
  assert.equal(tick.relayedPlanIds.length, 2, 'both protection plans retain the shared transaction receipt');
  assert.equal(new Set(tick.relayedPlanIds).size, 2);
  for (const registration of [first.registration, second.registration]) {
    const projection = await runtime.getProtection(registration.mandateHash, START + 2_000);
    assert.equal(projection.relayPlans.length, 0);
    const receipt = projection.events.find((event) => event.type === 'relay_submitted');
    assert.equal(receipt?.type === 'relay_submitted' && receipt.payload.transactionHash, 'aggregate-withdrawal-tx');
  }
});
