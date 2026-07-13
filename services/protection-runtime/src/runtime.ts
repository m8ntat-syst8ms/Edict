import { createHash } from 'node:crypto';
import {
  adjudicate,
  buildCustomerSettlementExecutionDigest,
  canonicalRuling,
  ethPersonalBytesDigest,
  recoverEthAddress,
} from '@edict/arbiter';
import {
  assertExecutableVerdict,
  decisionSpaceForRound,
  tierForValueUsd,
  type CaseObject,
  type EvidenceCommitment,
  type FinalVerdict,
  type Outcome,
  type ValueTier,
  type VerdictObject,
} from '@edict/core';
import {
  assertValidDeliveryManifest,
  canonicalDeliveryManifestHash,
  canonicalize,
  sha256Hex,
  type DeliveryManifest,
} from '@edict/evidence';
import {
  buildDisputeBondTransfer,
  buildPartyAuthCall,
  disputeBondAtomic,
  openHeldDisputeAction,
} from '@edict/near-intents';
import {
  dispositionFor,
} from '@edict/sdk';
import { createProtectionEvent } from './events.js';
import { runtimeSettlementBinding } from './binding.js';
import { evaluateObjectiveFailures } from './objective.js';
import { projectAll, projectProtection } from './projector.js';
import { assertValidProtectionRegistration } from './registration.js';
import {
  BuiltInSignedActionVerifier,
  normalizedPartyIdentity,
  signerMatchesParty,
  type SignedActionVerifier,
} from './signatures.js';
import type { ProtectionEventStore } from './store.js';
import type { EvidenceVault } from './vault.js';
import { deliverRuntimeWebhook, type WebhookDeliveryResult } from './webhooks.js';
import type {
  AnyProtectionEvent,
  ExecutionAuthorization,
  ExecutionSignatureCollector,
  NearFunctionCallRelayPlan,
  PermissionlessRelayer,
  ProtectionConnector,
  ProtectionEvent,
  ProtectionEventDraft,
  ProtectionEventType,
  ProtectionProjection,
  ProtectionRegistration,
  RelayPlan,
  RuntimeAdjudicatorConfig,
  SignedActionEnvelope,
  SignedActionName,
  SignedIntentRelayPlan,
  VerdictSignature,
  VerdictWebhookTarget,
} from './types.js';

export interface ProtectionRuntimeOptions {
  eventStore: ProtectionEventStore;
  evidenceVault: EvidenceVault;
  signatureVerifier?: SignedActionVerifier;
  connectors?: ProtectionConnector[];
  adjudicator?: RuntimeAdjudicatorConfig;
  executionSignatures?: ExecutionSignatureCollector;
  relayer?: PermissionlessRelayer;
  autoRelay?: boolean;
  verdictWebhooks?: VerdictWebhookTarget[];
  webhookFetch?: typeof fetch;
  now?: () => number;
}

export interface SignedActionResult {
  event: AnyProtectionEvent;
  action?: unknown;
  caseId?: string;
  caseIdSha256?: string;
}

export interface RuntimeTickResult {
  appendedEventIds: string[];
  relayedPlanIds: string[];
  webhookDeliveries: WebhookDeliveryResult[];
}

function uuidFromSeed(seed: string): string {
  const h = createHash('sha256').update(seed).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${'89ab'[parseInt(h[16]!, 16) % 4]}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

function bytes32(hex: string): number[] {
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new TypeError('expected lowercase sha256 hex');
  return [...Buffer.from(hex, 'hex')];
}

function tierFor(registration: ProtectionRegistration): ValueTier {
  const value = registration.mandate.priceUsd;
  const candidates = tierForValueUsd(value);
  if (candidates.length === 0) throw new RangeError(`valueUsd ${value} is outside Edict's supported bands`);
  const thresholds = registration.profile.tierThresholds ?? { aMaxUsd: 10, bMaxUsd: 1_000 };
  const preferred: ValueTier = value <= thresholds.aMaxUsd ? 'A' : value <= thresholds.bMaxUsd ? 'B' : 'C';
  return candidates.includes(preferred) ? preferred : candidates[0]!;
}

function rustRuling(outcome: Outcome): Record<string, unknown> {
  switch (outcome.kind) {
    case 'requester_wins':
    case 'worker_wins':
      return { kind: outcome.kind };
    case 'split':
      return { kind: 'split', requester_bps: outcome.requesterBps };
    case 'redo':
      return { kind: 'redo', new_deadline_unix_ms: outcome.newDeadlineUnixMs };
    default:
      throw new TypeError(`outcome ${outcome.kind} cannot execute on the Intents settlement contract`);
  }
}

function isFinal(verdict: VerdictObject): verdict is FinalVerdict {
  return verdict.final === true;
}

function planId(input: unknown): string {
  return sha256Hex(`edict-relay-plan:${canonicalize(input)}`);
}

function withdrawalRelayKey(plan: RelayPlan): string | undefined {
  if (plan.kind !== 'near_function_call' || plan.methodName !== 'withdraw_claim') return undefined;
  const accountId = plan.args['account_id'];
  return typeof accountId === 'string' ? `${plan.contractId}\0${accountId}` : undefined;
}

function currentRoundContext(stream: AnyProtectionEvent[]): {
  round: 1 | 2;
  events: AnyProtectionEvent[];
  redo?: ProtectionEvent<'redo_ordered'>;
} {
  for (let index = stream.length - 1; index >= 0; index -= 1) {
    const event = stream[index]!;
    if (event.type === 'redo_ordered') {
      return { round: 2, events: stream.slice(index + 1), redo: event };
    }
  }
  return { round: 1, events: stream };
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function closed(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const extra = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extra.length > 0) throw new TypeError(`${label} contains unknown field ${extra[0]}`);
}

const PARTY_EVIDENCE_KINDS = new Set([
  'delivery_manifest',
  'delivery_receipt',
  'interaction_log_head',
  'payment_receipt',
  'party_submission',
  'zktls_proof',
  'tee_runtime_attestation',
  'c2pa_manifest',
]);

function assertSignedActionShape(value: unknown): asserts value is SignedActionEnvelope {
  const envelope = record(value, 'signed action');
  closed(envelope, [
    'version', 'action', 'protectionId', 'signer', 'role', 'nonce', 'issuedAtUnixMs',
    'expiresAtUnixMs', 'scheme', 'publicKey', 'payload', 'signature',
  ], 'signed action');
  if (envelope['version'] !== 'edict-protect-signed-action-1') {
    throw new TypeError('signed action version is unsupported');
  }
  if (typeof envelope['protectionId'] !== 'string' || !/^[0-9a-f]{64}$/.test(envelope['protectionId'])) {
    throw new TypeError('signed action protectionId must be lowercase sha256 hex');
  }
  if (!['approve_protection', 'attach_evidence', 'open_challenge'].includes(String(envelope['action']))) {
    throw new TypeError('signed action name is unsupported');
  }
  if (envelope['role'] !== 'requester' && envelope['role'] !== 'worker') {
    throw new TypeError('signed action role must be requester or worker');
  }
  if (!['eip191', 'ed25519', 'custom'].includes(String(envelope['scheme']))) {
    throw new TypeError('signed action scheme is unsupported');
  }
  if (typeof envelope['signer'] !== 'string' || envelope['signer'].trim().length === 0
      || envelope['signer'].length > 512) throw new TypeError('signed action signer is invalid');
  if (typeof envelope['signature'] !== 'string' || envelope['signature'].length === 0
      || envelope['signature'].length > 4_096) throw new TypeError('signed action signature is invalid');
  if (typeof envelope['nonce'] !== 'string' || envelope['nonce'].trim().length < 8
      || envelope['nonce'].length > 200) throw new TypeError('signed action nonce is invalid');
  if (!Number.isSafeInteger(envelope['issuedAtUnixMs']) || !Number.isSafeInteger(envelope['expiresAtUnixMs'])
      || (envelope['issuedAtUnixMs'] as number) >= (envelope['expiresAtUnixMs'] as number)) {
    throw new TypeError('signed action lifetime is invalid');
  }
  if (envelope['scheme'] === 'ed25519'
      && (typeof envelope['publicKey'] !== 'string' || envelope['publicKey'].length > 512)) {
    throw new TypeError('ed25519 publicKey is invalid');
  }
  if (envelope['scheme'] !== 'ed25519' && envelope['publicKey'] !== undefined) {
    throw new TypeError('publicKey is only valid for ed25519 signed actions');
  }

  const payload = record(envelope['payload'], 'signed action payload');
  if (envelope['action'] === 'approve_protection') {
    closed(payload, ['reference'], 'approve_protection payload');
    if (payload['reference'] !== undefined
        && (typeof payload['reference'] !== 'string' || payload['reference'].length > 512)) {
      throw new TypeError('approval reference is invalid');
    }
    return;
  }
  if (envelope['action'] === 'attach_evidence') {
    closed(payload, ['kind', 'plaintext', 'uri'], 'attach_evidence payload');
    if (typeof payload['kind'] !== 'string' || !PARTY_EVIDENCE_KINDS.has(payload['kind'])) {
      throw new TypeError('party evidence kind is unsupported');
    }
    if (typeof payload['plaintext'] !== 'string' || payload['plaintext'].length === 0
        || payload['plaintext'].length > 1_500_000) throw new TypeError('evidence plaintext is invalid');
    if (payload['uri'] !== undefined
        && (typeof payload['uri'] !== 'string' || payload['uri'].length > 2_048 || /[\u0000-\u001f]/.test(payload['uri']))) {
      throw new TypeError('evidence URI is invalid');
    }
    return;
  }
  closed(payload, ['statement', 'requestedAtUnixMs'], 'open_challenge payload');
  if (payload['statement'] !== undefined
      && (typeof payload['statement'] !== 'string' || payload['statement'].length > 1_000_000)) {
    throw new TypeError('challenge statement is invalid');
  }
  if (payload['requestedAtUnixMs'] !== undefined
      && (!Number.isSafeInteger(payload['requestedAtUnixMs'])
        || (payload['requestedAtUnixMs'] as number) < (envelope['issuedAtUnixMs'] as number)
        || (payload['requestedAtUnixMs'] as number) > (envelope['expiresAtUnixMs'] as number))) {
    throw new TypeError('challenge request time must be inside the signed action lifetime');
  }
}

function webhookRetryDelayMs(failedDeliveries: number): number {
  return Math.min(30_000 * 2 ** Math.min(Math.max(failedDeliveries - 1, 0), 7), 60 * 60_000);
}

function validateExecutionSignatures(
  digestHex: string,
  signatures: VerdictSignature[],
  registration: ProtectionRegistration,
): void {
  const policy = runtimeSettlementBinding(registration).verifierPolicy;
  if (signatures.length < policy.quorum || signatures.length > policy.signers.length) {
    throw new Error('execution signature count cannot satisfy the immutable verifier policy');
  }
  const personalDigest = ethPersonalBytesDigest(Buffer.from(digestHex, 'hex'));
  const seenAddresses = new Set<string>();
  const operators = new Set<string>();
  for (const entry of signatures) {
    const address = entry.signing_address.toLowerCase();
    if (seenAddresses.has(address)) throw new Error('execution signature address is duplicated');
    seenAddresses.add(address);
    const signer = policy.signers.find((candidate) => candidate.signingAddress === address);
    if (signer === undefined) throw new Error(`execution signer ${address} is outside the immutable policy`);
    const recovered = recoverEthAddress(entry.signature, personalDigest);
    if (recovered?.toLowerCase() !== address) throw new Error(`execution signature does not bind digest for ${address}`);
    operators.add(signer.operatorId);
  }
  if (operators.size < policy.quorum) throw new Error('distinct-operator execution quorum was not met');
}

export class ProtectionRuntime {
  private readonly signatureVerifier: SignedActionVerifier;
  private readonly connectors: ProtectionConnector[];
  private readonly now: () => number;
  private events: AnyProtectionEvent[] = [];
  private initialized?: Promise<void>;
  private mutationQueue: Promise<void> = Promise.resolve();
  private readonly activeSignedNonces = new Set<string>();

  constructor(readonly options: ProtectionRuntimeOptions) {
    this.signatureVerifier = options.signatureVerifier ?? new BuiltInSignedActionVerifier();
    this.connectors = options.connectors ?? [];
    this.now = options.now ?? Date.now;
  }

  private withMutationLock<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.mutationQueue.then(operation);
    this.mutationQueue = run.then(() => undefined, () => undefined);
    return run;
  }

  async initialize(): Promise<void> {
    this.initialized ??= (async () => {
      const webhookIds = new Set<string>();
      for (const target of this.options.verdictWebhooks ?? []) {
        if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(target.id)) {
          throw new TypeError('webhook target id must be 1-64 stable identifier characters');
        }
        if (webhookIds.has(target.id)) throw new TypeError(`duplicate webhook target id ${target.id}`);
        webhookIds.add(target.id);
        if (target.secret.length < 16) throw new TypeError(`webhook ${target.id} secret must contain at least 16 characters`);
        const url = new URL(target.url);
        const localHttp = url.protocol === 'http:' && url.hostname === '127.0.0.1';
        if (url.protocol !== 'https:' && !localHttp) {
          throw new TypeError(`webhook ${target.id} URL must use HTTPS (or loopback HTTP for development)`);
        }
        if (url.username.length > 0 || url.password.length > 0) {
          throw new TypeError(`webhook ${target.id} URL cannot contain credentials`);
        }
      }
      await this.options.eventStore.initialize();
      this.events = await this.options.eventStore.list();
    })();
    await this.initialized;
  }

  private async append<T extends ProtectionEventType>(
    draft: ProtectionEventDraft<T>,
  ): Promise<ProtectionEvent<T>> {
    await this.initialize();
    const event = createProtectionEvent(draft);
    const result = await this.options.eventStore.append(event as AnyProtectionEvent);
    if (result === 'appended') this.events.push(event as AnyProtectionEvent);
    const persisted = this.events.find((candidate) => candidate.eventId === event.eventId);
    return structuredClone((persisted ?? event) as ProtectionEvent<T>);
  }

  private stream(protectionId: string): AnyProtectionEvent[] {
    return this.events
      .filter((event) => event.protectionId === protectionId)
      .sort((a, b) => a.effectiveAtUnixMs - b.effectiveAtUnixMs
        || a.observedAtUnixMs - b.observedAtUnixMs
        || a.eventId.localeCompare(b.eventId));
  }

  private registration(protectionId: string): ProtectionRegistration {
    const event = this.stream(protectionId).find((candidate) => candidate.type === 'protection_registered');
    if (event?.type !== 'protection_registered') throw new Error(`unknown protection ${protectionId}`);
    return structuredClone(event.payload.registration);
  }

  async register(registration: ProtectionRegistration): Promise<ProtectionProjection> {
    return this.withMutationLock(() => this.registerUnlocked(registration));
  }

  private async registerUnlocked(registration: ProtectionRegistration): Promise<ProtectionProjection> {
    await this.initialize();
    assertValidProtectionRegistration(registration);
    const existing = this.stream(registration.mandateHash).find((event) => event.type === 'protection_registered');
    if (existing?.type === 'protection_registered') {
      if (canonicalize(existing.payload.registration) !== canonicalize(registration)) {
        throw new Error(`protection ${registration.mandateHash} is already registered with different bytes`);
      }
      return projectProtection(this.stream(registration.mandateHash), this.now());
    }

    const mandateBlob = await this.options.evidenceVault.put(canonicalize(registration.mandate));
    if (mandateBlob.sha256 !== registration.mandateHash) throw new Error('vault canonical mandate hash mismatch');
    const legalBlob = await this.options.evidenceVault.put(canonicalize(registration.mandate.legalPolicy));
    if (legalBlob.sha256 !== registration.legalPolicyHash) throw new Error('vault Legal Policy hash mismatch');
    if (registration.profile.customerPolicyPack !== undefined) {
      await this.options.evidenceVault.put(canonicalize(registration.profile.customerPolicyPack));
    }

    const now = this.now();
    await this.append({
      protectionId: registration.mandateHash,
      type: 'protection_registered',
      source: {
        kind: 'integration',
        id: registration.integrationRef ?? 'edict-sdk',
        externalId: registration.integrationRef ?? registration.mandateHash,
      },
      effectiveAtUnixMs: now,
      observedAtUnixMs: now,
      payload: { registration: structuredClone(registration) },
      authentication: registration.integrationRef !== undefined
        ? { kind: 'trusted_integration', integrationRef: registration.integrationRef }
        : { kind: 'runtime', reason: 'validated SDK registration' },
    });
    return projectProtection(this.stream(registration.mandateHash), now);
  }

  async ingest<T extends ProtectionEventType>(draft: ProtectionEventDraft<T>): Promise<ProtectionEvent<T>> {
    return this.withMutationLock(() => this.ingestUnlocked(draft));
  }

  private async ingestUnlocked<T extends ProtectionEventType>(draft: ProtectionEventDraft<T>): Promise<ProtectionEvent<T>> {
    await this.initialize();
    this.registration(draft.protectionId);
    return this.append(draft);
  }

  async listEvents(protectionId?: string): Promise<AnyProtectionEvent[]> {
    await this.initialize();
    return structuredClone(protectionId === undefined ? this.events : this.stream(protectionId));
  }

  async listProtections(nowUnixMs = this.now()): Promise<ProtectionProjection[]> {
    await this.initialize();
    return projectAll(this.events, nowUnixMs);
  }

  async getProtection(protectionId: string, nowUnixMs = this.now()): Promise<ProtectionProjection> {
    await this.initialize();
    return projectProtection(this.stream(protectionId), nowUnixMs);
  }

  private async verifySignedAction<A extends SignedActionName>(
    envelope: SignedActionEnvelope<A>,
  ): Promise<{ registration: ProtectionRegistration; digestSha256: string }> {
    await this.initialize();
    const registration = this.registration(envelope.protectionId);
    const verification = await this.signatureVerifier.verify(envelope, this.now());
    if (!verification.ok) throw new Error(`signed action rejected: ${verification.reason ?? 'verification failed'}`);
    const party = envelope.role === 'requester' ? registration.mandate.requester : registration.mandate.worker;
    if (envelope.scheme !== 'custom' && !signerMatchesParty(envelope.signer, party.agentId)) {
      throw new Error(`signed action signer is not the mandate ${envelope.role}`);
    }
    const replayed = this.events.some((event) =>
      event.authentication.kind === 'signed_message'
      && event.authentication.signer.toLowerCase() === envelope.signer.toLowerCase()
      && event.authentication.nonce === envelope.nonce);
    if (replayed) throw new Error('signed action nonce has already been used');
    return { registration, digestSha256: verification.digestSha256 };
  }

  private signedAuthentication<A extends SignedActionName>(
    envelope: SignedActionEnvelope<A>,
    digestSha256: string,
  ) {
    return {
      kind: 'signed_message' as const,
      scheme: envelope.scheme,
      signer: envelope.signer,
      role: envelope.role,
      nonce: envelope.nonce,
      digestSha256,
    };
  }

  async handleSignedAction<A extends SignedActionName>(
    envelope: SignedActionEnvelope<A>,
  ): Promise<SignedActionResult> {
    assertSignedActionShape(envelope);
    const nonceKey = `${normalizedPartyIdentity(envelope.signer)}:${envelope.nonce}`;
    if (this.activeSignedNonces.has(nonceKey)) throw new Error('signed action nonce is already being processed');
    this.activeSignedNonces.add(nonceKey);
    try {
      return await this.withMutationLock(() => this.handleSignedActionUnlocked(envelope));
    } finally {
      this.activeSignedNonces.delete(nonceKey);
    }
  }

  private async handleSignedActionUnlocked<A extends SignedActionName>(
    envelope: SignedActionEnvelope<A>,
  ): Promise<SignedActionResult> {
    const { registration, digestSha256 } = await this.verifySignedAction(envelope);
    const now = this.now();
    const source = {
      kind: 'signed_api' as const,
      id: envelope.signer,
      externalId: `${envelope.signer}:${envelope.nonce}`,
    };
    const authentication = this.signedAuthentication(envelope, digestSha256);

    if (envelope.action === 'approve_protection') {
      const payload = envelope.payload as { reference?: string };
      const event = await this.append({
        protectionId: envelope.protectionId,
        type: 'protection_accepted',
        source,
        effectiveAtUnixMs: envelope.issuedAtUnixMs,
        observedAtUnixMs: now,
        payload: {
          party: envelope.role,
          ...(payload.reference !== undefined ? { reference: payload.reference } : {}),
        },
        authentication,
      });
      return { event };
    }

    if (envelope.action === 'attach_evidence') {
      const payload = envelope.payload as { kind: EvidenceCommitment['kind']; plaintext: string; uri?: string };
      if (payload.kind === 'order_mandate' || payload.kind === 'legal_policy' || payload.kind === 'customer_policy_pack'
          || payload.kind === 'authority_credential') {
        throw new Error(`parties cannot replace system evidence kind ${payload.kind}`);
      }
      let plaintext = payload.plaintext;
      let delivery: DeliveryManifest | undefined;
      if (payload.kind === 'delivery_manifest') {
        try {
          delivery = JSON.parse(payload.plaintext) as DeliveryManifest;
        } catch {
          throw new Error('delivery_manifest evidence must be canonical JSON');
        }
        assertValidDeliveryManifest(delivery);
        const canonical = canonicalize(delivery);
        if (canonical !== payload.plaintext) throw new Error('delivery_manifest evidence must use canonical JSON bytes');
        if (delivery.orderMandateHash !== envelope.protectionId) throw new Error('delivery manifest references another mandate');
        if (delivery.workerAgentId !== registration.mandate.worker.agentId || envelope.role !== 'worker') {
          throw new Error('only the mandate worker may attach its delivery manifest');
        }
        plaintext = canonical;
      }
      const stored = await this.options.evidenceVault.put(plaintext);
      const event = await this.append({
        protectionId: envelope.protectionId,
        type: 'evidence_attached',
        source,
        effectiveAtUnixMs: envelope.issuedAtUnixMs,
        observedAtUnixMs: now,
        payload: {
          kind: payload.kind,
          sha256: stored.sha256,
          submitter: envelope.role,
          authenticated: true,
          vaultRef: stored.vaultRef,
          ...(payload.uri !== undefined ? { uri: payload.uri } : {}),
        },
        authentication,
      });
      if (delivery !== undefined) {
        const manifestSha256 = canonicalDeliveryManifestHash(delivery);
        if (manifestSha256 !== stored.sha256) throw new Error('canonical delivery manifest hash mismatch');
        await this.append({
          protectionId: envelope.protectionId,
          type: 'delivery_submitted',
          source: { ...source, externalId: `${source.externalId}:delivery` },
          effectiveAtUnixMs: delivery.deliveredAtUnixMs,
          observedAtUnixMs: now,
          payload: {
            manifestSha256,
            deliveredAtUnixMs: delivery.deliveredAtUnixMs,
            worker: registration.mandate.worker.agentId,
          },
          authentication,
        });
        await this.recordObjectiveFailures(registration, delivery, manifestSha256, now);
      }
      return { event };
    }

    const stream = this.stream(envelope.protectionId);
    if (!stream.some((event) => event.type === 'funding_confirmed')) throw new Error('challenge requires confirmed funding');
    if (!stream.some((event) => event.type === 'delivery_submitted')) throw new Error('challenge requires a delivered order');
    if (stream.some((event) => event.type === 'settlement_finalized')) throw new Error('settled protection cannot be challenged');
    const currentRound = currentRoundContext(stream);
    if (currentRound.events.some((event) => event.type === 'challenge_requested' || event.type === 'challenge_opened')) {
      throw new Error('a challenge is already pending or open for this round');
    }
    const round = currentRound.round;
    const payload = envelope.payload as { statement?: string; requestedAtUnixMs?: number };
    const caseId = uuidFromSeed(`edict-runtime-case:${envelope.protectionId}:${envelope.nonce}`);
    const caseIdSha256 = sha256Hex(caseId);
    let statementSha256: string | undefined;
    if (payload.statement !== undefined && payload.statement.length > 0) {
      const stored = await this.options.evidenceVault.put(payload.statement);
      statementSha256 = stored.sha256;
      await this.append({
        protectionId: envelope.protectionId,
        type: 'evidence_attached',
        source: { ...source, externalId: `${source.externalId}:statement` },
        effectiveAtUnixMs: envelope.issuedAtUnixMs,
        observedAtUnixMs: now,
        payload: {
          kind: 'party_submission',
          sha256: stored.sha256,
          submitter: envelope.role,
          authenticated: true,
          vaultRef: stored.vaultRef,
        },
        authentication,
      });
    }
    const binding = runtimeSettlementBinding(registration);
    const bondAtomic = disputeBondAtomic(binding.principalAtomic, binding.disputeBondBps);
    const action = binding.kind === 'near_intents'
      ? (round === 1
          ? buildDisputeBondTransfer(binding.intentsRoute!, {
              orderMandateSha256: envelope.protectionId,
              caseIdSha256,
              bondAtomic,
            })
          : buildPartyAuthCall(binding.intentsRoute!, openHeldDisputeAction(envelope.protectionId, caseIdSha256)))
      : {
          kind: 'near_function_call',
          contractId: binding.settlementAccount,
          methodName: 'open_dispute',
          args: {
            order_mandate_sha256: bytes32(envelope.protectionId),
            case_id_sha256: bytes32(caseIdSha256),
          },
          gas: '100000000000000',
          depositYocto: round === 1 ? bondAtomic : '0',
          signer: envelope.role,
        };
    const event = await this.append({
      protectionId: envelope.protectionId,
      type: 'challenge_requested',
      source,
      effectiveAtUnixMs: payload.requestedAtUnixMs ?? envelope.issuedAtUnixMs,
      observedAtUnixMs: now,
      payload: {
        caseId,
        caseIdSha256,
        by: envelope.role,
        ...(statementSha256 !== undefined ? { statementSha256 } : {}),
        bondAtomic,
        action,
        standingAuthorizationUsed: false,
      },
      authentication,
    });
    return { event, action, caseId, caseIdSha256 };
  }

  private async recordObjectiveFailures(
    registration: ProtectionRegistration,
    delivery: DeliveryManifest,
    manifestSha256: string,
    now: number,
  ): Promise<void> {
    const stream = this.stream(registration.mandateHash);
    const authorizationUsed = stream.some((event) => event.type === 'challenge_requested'
      && event.payload.standingAuthorizationUsed
      && event.source.externalId === registration.standingChallengeAuthorization?.signedIntentSha256);
    for (const failure of evaluateObjectiveFailures(registration.mandate, delivery)) {
      const authorization = registration.standingChallengeAuthorization;
      const usable = authorization !== undefined
        && authorization.party === 'requester'
        && authorization.triggerKinds.includes('objective_failure')
        && authorization.expiresAtUnixMs > now
        && !authorizationUsed;
      await this.append({
        protectionId: registration.mandateHash,
        type: 'objective_failure_detected',
        source: {
          kind: 'runtime',
          id: 'objective-checks',
          externalId: `${manifestSha256}:${failure.criterionId}`,
        },
        effectiveAtUnixMs: now,
        observedAtUnixMs: now,
        payload: {
          criterionId: failure.criterionId,
          reason: failure.reason,
          manifestSha256,
          requiresPartySignature: !usable,
        },
        authentication: { kind: 'runtime', reason: 'deterministic signed-manifest check' },
      });
      if (usable) await this.createStandingChallenge(registration, authorization!, now);
    }
  }

  private async createStandingChallenge(
    registration: ProtectionRegistration,
    authorization: NonNullable<ProtectionRegistration['standingChallengeAuthorization']>,
    now: number,
  ): Promise<void> {
    const existing = this.stream(registration.mandateHash).some((event) => event.type === 'challenge_requested');
    if (existing) return;
    await this.append({
      protectionId: registration.mandateHash,
      type: 'challenge_requested',
      source: { kind: 'runtime', id: 'objective-checks', externalId: authorization.signedIntentSha256 },
      effectiveAtUnixMs: now,
      observedAtUnixMs: now,
      payload: {
        caseId: authorization.caseId,
        caseIdSha256: authorization.caseIdSha256,
        by: authorization.party,
        bondAtomic: authorization.bondAtomic,
        action: authorization.signedIntent,
        standingAuthorizationUsed: true,
      },
      authentication: { kind: 'runtime', reason: 'pre-signed objective-failure authorization' },
    });
    const raw: Omit<SignedIntentRelayPlan, 'planId'> = {
      version: 'edict-relay-plan-1',
      protectionId: registration.mandateHash,
      kind: 'near_signed_intent',
      signedIntent: authorization.signedIntent,
      signedIntentSha256: authorization.signedIntentSha256,
      eligibleAtUnixMs: now,
      expiresAtUnixMs: authorization.expiresAtUnixMs,
      authorization: 'party_pre_signed',
      guarantees: { noCustomerKey: true, noArbitraryRecipient: true, contractRevalidates: true },
    };
    const plan: SignedIntentRelayPlan = { ...raw, planId: planId(raw) };
    await this.appendRelayPlan(plan, now);
  }

  async pollConnectors(): Promise<RuntimeTickResult> {
    return this.withMutationLock(() => this.pollConnectorsUnlocked());
  }

  private async pollConnectorsUnlocked(): Promise<RuntimeTickResult> {
    await this.initialize();
    const registrations = this.events
      .filter((event): event is ProtectionEvent<'protection_registered'> => event.type === 'protection_registered')
      .map((event) => ({ registration: event.payload.registration, events: this.stream(event.protectionId) }));
    const appendedEventIds: string[] = [];
    const knownEventIds = new Set(this.events.map((event) => event.eventId));
    for (const connector of this.connectors) {
      const drafts = await connector.poll(registrations);
      for (const draft of drafts) {
        const event = await this.append(draft);
        if (!knownEventIds.has(event.eventId)) {
          knownEventIds.add(event.eventId);
          appendedEventIds.push(event.eventId);
        }
      }
    }
    const tick = await this.tickUnlocked(this.now());
    return {
      appendedEventIds: [...new Set([...appendedEventIds, ...tick.appendedEventIds])],
      relayedPlanIds: tick.relayedPlanIds,
      webhookDeliveries: tick.webhookDeliveries,
    };
  }

  async tick(nowUnixMs = this.now()): Promise<RuntimeTickResult> {
    return this.withMutationLock(() => this.tickUnlocked(nowUnixMs));
  }

  private async tickUnlocked(nowUnixMs: number): Promise<RuntimeTickResult> {
    await this.initialize();
    const before = new Set(this.events.map((event) => event.eventId));
    const webhookDeliveries: WebhookDeliveryResult[] = [];
    const registrationEvents = this.events.filter(
      (event): event is ProtectionEvent<'protection_registered'> => event.type === 'protection_registered',
    );
    for (const registrationEvent of registrationEvents) {
      const registration = registrationEvent.payload.registration;
      const protectionId = registration.mandateHash;
      const stream = this.stream(protectionId);
      if (stream.some((event) => event.type === 'settlement_finalized')) {
        await this.scheduleClaimWithdrawals(registration, stream, nowUnixMs);
        webhookDeliveries.push(...await this.deliverPendingVerdictWebhooks(registration, nowUnixMs));
        continue;
      }
      await this.scheduleCleanPathTimeout(registration, stream, nowUnixMs);
      const roundEvents = currentRoundContext(this.stream(protectionId)).events;
      const challenge = [...roundEvents].reverse().find(
        (event): event is ProtectionEvent<'challenge_opened'> => event.type === 'challenge_opened',
      );
      const verdictEvent = [...roundEvents].reverse().find(
        (event): event is ProtectionEvent<'verdict_issued'> => event.type === 'verdict_issued'
          && event.payload.caseObject.caseId === challenge?.payload.caseId,
      );
      if (challenge?.payload.caseId !== undefined && verdictEvent === undefined && this.options.adjudicator !== undefined) {
        await this.adjudicateProtection(registration, challenge, nowUnixMs);
      }
      await this.authorizeAndScheduleVerdict(registration, nowUnixMs);
      await this.scheduleLivenessFallback(registration, nowUnixMs);
      webhookDeliveries.push(...await this.deliverPendingVerdictWebhooks(registration, nowUnixMs));
    }
    const relayedPlanIds = await this.relayEligible(nowUnixMs);
    return {
      appendedEventIds: this.events.filter((event) => !before.has(event.eventId)).map((event) => event.eventId),
      relayedPlanIds,
      webhookDeliveries,
    };
  }

  private async scheduleCleanPathTimeout(
    registration: ProtectionRegistration,
    stream: AnyProtectionEvent[],
    now: number,
  ): Promise<void> {
    const binding = runtimeSettlementBinding(registration);
    if (!stream.some((event) => event.type === 'funding_confirmed')) return;
    const currentRound = currentRoundContext(stream);
    if (currentRound.events.some((event) => event.type === 'challenge_opened')) return;
    const delivery = [...currentRound.events].reverse().find(
      (event): event is ProtectionEvent<'delivery_submitted'> => event.type === 'delivery_submitted'
    );
    const deadlineKind = delivery === undefined ? 'delivery' : 'acceptance';
    const deadline = delivery === undefined
      ? (currentRound.redo?.payload.newDeadlineUnixMs ?? registration.mandate.deadlineUnixMs)
      : delivery.payload.deliveredAtUnixMs + registration.mandate.acceptanceWindowMs;
    if (now <= deadline) return;
    await this.append({
      protectionId: registration.mandateHash,
      type: 'deadline_elapsed',
      source: { kind: 'runtime', id: 'deadline-scheduler', externalId: `${deadlineKind}:${deadline}` },
      effectiveAtUnixMs: deadline + 1,
      observedAtUnixMs: now,
      payload: { deadlineKind, deadlineUnixMs: deadline },
      authentication: { kind: 'runtime', reason: 'signed mandate deadline' },
    });
    const raw: Omit<NearFunctionCallRelayPlan, 'planId'> = {
      version: 'edict-relay-plan-1',
      protectionId: registration.mandateHash,
      kind: 'near_function_call',
      contractId: binding.settlementAccount,
      methodName: 'claim_timeout',
      args: { order_mandate_sha256: bytes32(registration.mandateHash) },
      gas: '80000000000000',
      depositYocto: '0',
      eligibleAtUnixMs: deadline + 1,
      authorization: 'permissionless',
      guarantees: { noCustomerKey: true, noArbitraryRecipient: true, contractRevalidates: true },
    };
    await this.appendRelayPlan({ ...raw, planId: planId(raw) }, now);
  }

  private async adjudicateProtection(
    registration: ProtectionRegistration,
    challenge: ProtectionEvent<'challenge_opened'>,
    now: number,
  ): Promise<void> {
    const binding = runtimeSettlementBinding(registration);
    const caseId = challenge.payload.caseId!;
    const stream = this.stream(registration.mandateHash);
    const evidence: EvidenceCommitment[] = structuredClone(registration.evidenceCommitments);
    const plaintext: Record<string, string> = {};
    for (const commitment of evidence) {
      const blob = await this.options.evidenceVault.get(commitment.sha256);
      if (blob !== undefined) plaintext[commitment.sha256] = blob;
    }
    for (const event of stream) {
      if (event.type !== 'evidence_attached') continue;
      if (!evidence.some((entry) => entry.sha256 === event.payload.sha256 && entry.kind === event.payload.kind)) {
        evidence.push({
          kind: event.payload.kind,
          sha256: event.payload.sha256,
          submitter: event.payload.submitter,
          authenticated: event.payload.authenticated,
          ...(event.payload.uri !== undefined ? { uri: event.payload.uri } : {}),
        });
      }
      const blob = await this.options.evidenceVault.get(event.payload.sha256);
      if (blob !== undefined) plaintext[event.payload.sha256] = blob;
    }
    const delivery = [...stream].reverse().find(
      (event): event is ProtectionEvent<'delivery_submitted'> => event.type === 'delivery_submitted'
        && event.effectiveAtUnixMs <= challenge.effectiveAtUnixMs,
    );
    if (delivery !== undefined && !evidence.some((entry) => entry.kind === 'delivery_manifest' && entry.sha256 === delivery.payload.manifestSha256)) {
      evidence.push({
        kind: 'delivery_manifest',
        sha256: delivery.payload.manifestSha256,
        submitter: 'worker',
        authenticated: true,
      });
    }
    const priorRedo = [...stream].reverse().find((event) => event.type === 'redo_ordered');
    const effectiveDeadline = priorRedo?.type === 'redo_ordered'
      ? priorRedo.payload.newDeadlineUnixMs
      : registration.mandate.deadlineUnixMs;
    const caseObject: CaseObject = {
      caseId,
      caseType: 'bilateral',
      publicity: registration.profile.defaults.publicity ?? 'sealed',
      requester: structuredClone(registration.mandate.requester),
      worker: structuredClone(registration.mandate.worker),
      orderMandateHash: registration.mandateHash,
      legalPolicyHash: registration.legalPolicyHash,
      ...(delivery !== undefined ? { deliveryManifestHash: delivery.payload.manifestSha256 } : {}),
      evidence,
      valueUsd: registration.mandate.priceUsd,
      tier: tierFor(registration),
      custodyMode: registration.mandate.settlement!.custodyMode,
      railRef: {
        rail: registration.mandate.currency.rail,
        adapterRef: registration.mandate.settlement!.adapterRef,
        fundsController: registration.mandate.settlement!.fundsController,
        profileHash: registration.profileHash,
        connectorId: binding.connectorId,
      },
      legalProfile: structuredClone(registration.mandate.legalProfile),
      openedAtUnixMs: challenge.payload.openedAtUnixMs,
      decisionSpace: decisionSpaceForRound(registration.mandate.decisionSpace, challenge.payload.round),
      round: {
        number: challenge.payload.round,
        effectiveDeadlineUnixMs: effectiveDeadline,
        ...(challenge.payload.round === 2
          ? {
              priorCaseId: stream.find((event) => event.type === 'verdict_issued')?.type === 'verdict_issued'
                ? (stream.find((event) => event.type === 'verdict_issued') as ProtectionEvent<'verdict_issued'>).payload.caseObject.caseId
                : undefined,
              priorVerdictSha256: stream.find((event) => event.type === 'verdict_issued')?.type === 'verdict_issued'
                ? sha256Hex(canonicalize((stream.find((event) => event.type === 'verdict_issued') as ProtectionEvent<'verdict_issued'>).payload.verdict))
                : undefined,
            }
          : {}),
      },
    };
    const adjudicator = this.options.adjudicator!;
    const verdict = await adjudicate(caseObject, plaintext, {
      seats: registration.profile.juryPolicy.seats ?? [],
      providers: adjudicator.providers,
      archiveDir: adjudicator.archiveDir,
      ...(registration.profile.juryPolicy.requireProofs !== undefined
        ? { requireProofs: registration.profile.juryPolicy.requireProofs }
        : {}),
      ...(registration.profile.juryPolicy.proofPolicy !== undefined
        ? { proofPolicy: registration.profile.juryPolicy.proofPolicy }
        : {}),
    });
    const disposition = dispositionFor(verdict, registration.profile, caseObject.tier, caseObject.valueUsd);
    let execution: ExecutionAuthorization | undefined;
    if (isFinal(verdict) && disposition.route !== 'human_review') {
      try {
        execution = await this.collectExecutionAuthorization(registration, caseObject, verdict);
      } catch {
        execution = undefined;
      }
    }
    await this.append({
      protectionId: registration.mandateHash,
      type: 'verdict_issued',
      source: { kind: 'arbiter', id: '@edict/arbiter', externalId: sha256Hex(canonicalize(verdict)) },
      effectiveAtUnixMs: verdict.issuedAtUnixMs,
      observedAtUnixMs: now,
      payload: {
        caseObject,
        verdict,
        disposition,
        ...(execution !== undefined ? { execution } : {}),
      },
      authentication: { kind: 'runtime', reason: 'configured multi-provider arbiter pipeline' },
    });
    if (disposition.route === 'human_review') {
      await this.append({
        protectionId: registration.mandateHash,
        type: 'review_required',
        source: { kind: 'runtime', id: 'escalation-policy', externalId: caseId },
        effectiveAtUnixMs: verdict.issuedAtUnixMs,
        observedAtUnixMs: now,
        payload: {
          caseId,
          trigger: disposition.trigger ?? verdict.quality.escalationReason ?? 'policy-required review',
          disposition,
        },
        authentication: { kind: 'runtime', reason: 'signed Protection Profile escalation policy' },
      });
    }
  }

  private async deliverPendingVerdictWebhooks(
    registration: ProtectionRegistration,
    now: number,
  ): Promise<WebhookDeliveryResult[]> {
    const targets = this.options.verdictWebhooks ?? [];
    if (targets.length === 0) return [];
    const stream = this.stream(registration.mandateHash);
    const verdicts = stream.filter(
      (event): event is ProtectionEvent<'verdict_issued'> => event.type === 'verdict_issued',
    );
    const deliveries: WebhookDeliveryResult[] = [];
    for (const verdict of verdicts) {
      for (const target of targets) {
        const prior = this.stream(registration.mandateHash).filter(
          (event): event is ProtectionEvent<'webhook_delivery_recorded'> =>
            event.type === 'webhook_delivery_recorded'
            && event.payload.verdictEventId === verdict.eventId
            && event.payload.targetId === target.id,
        );
        if (prior.some((event) => event.payload.delivered)) continue;
        const latest = prior.at(-1);
        if (latest?.payload.nextAttemptAtUnixMs !== undefined
            && latest.payload.nextAttemptAtUnixMs > now) continue;

        const result = await deliverRuntimeWebhook(target, verdict, {
          fetchImpl: this.options.webhookFetch,
        });
        const deliveryNumber = prior.length + 1;
        const failedDeliveries = prior.filter((event) => !event.payload.delivered).length + (result.delivered ? 0 : 1);
        const nextAttemptAtUnixMs = result.delivered
          ? undefined
          : now + webhookRetryDelayMs(failedDeliveries);
        await this.append({
          protectionId: registration.mandateHash,
          type: 'webhook_delivery_recorded',
          source: {
            kind: 'runtime',
            id: 'verdict-webhook',
            externalId: `${verdict.eventId}:${target.id}:${deliveryNumber}`,
          },
          effectiveAtUnixMs: now,
          observedAtUnixMs: now,
          payload: {
            targetId: target.id,
            verdictEventId: verdict.eventId,
            deliveryNumber,
            delivered: result.delivered,
            transportAttempts: result.attempts,
            attemptedAtUnixMs: now,
            ...(nextAttemptAtUnixMs !== undefined ? { nextAttemptAtUnixMs } : {}),
            ...(result.status !== undefined ? { status: result.status } : {}),
            ...(result.error !== undefined ? { error: result.error } : {}),
          },
          authentication: { kind: 'runtime', reason: 'HMAC-signed verdict webhook delivery record' },
        });
        deliveries.push(result);
      }
    }
    return deliveries;
  }

  private async collectExecutionAuthorization(
    registration: ProtectionRegistration,
    caseObject: CaseObject,
    verdict: FinalVerdict,
  ): Promise<ExecutionAuthorization | undefined> {
    if (this.options.executionSignatures === undefined) return undefined;
    assertExecutableVerdict(verdict, caseObject.decisionSpace);
    const binding = runtimeSettlementBinding(registration);
    const verdictSha256Hex = sha256Hex(canonicalize(verdict));
    const nonceHex = sha256Hex(`edict-execution-nonce:${registration.mandateHash}:${caseObject.caseId}:${verdictSha256Hex}`);
    const round = (caseObject.round?.number ?? 1) as 1 | 2;
    const rulingCanonical = canonicalRuling(verdict.ruling as Parameters<typeof canonicalRuling>[0]);
    const executionContext = {
      settlementAccountId: binding.settlementAccount,
      orderMandateSha256Hex: registration.mandateHash,
      caseIdSha256Hex: sha256Hex(caseObject.caseId),
      round,
      rulingCanonical,
      issuedAtUnixMs: verdict.issuedAtUnixMs,
      verifierPolicySha256Hex: binding.verifierPolicySha256Hex,
    };
    const executionDigestHex = buildCustomerSettlementExecutionDigest({
      ...executionContext,
      verdictSha256Hex,
      nonce: Buffer.from(nonceHex, 'hex'),
    });
    const signatures = await this.options.executionSignatures.collect({
      protectionId: registration.mandateHash,
      caseObject,
      verdict,
      verdictSha256Hex,
      executionDigestHex,
      nonceHex,
      policy: binding.verifierPolicy,
      executionContext,
    });
    validateExecutionSignatures(executionDigestHex, signatures, registration);
    return { executionDigestHex, nonceHex, signatures: structuredClone(signatures) };
  }

  private async authorizeAndScheduleVerdict(registration: ProtectionRegistration, now: number): Promise<void> {
    const binding = runtimeSettlementBinding(registration);
    const stream = this.stream(registration.mandateHash);
    const roundEvents = currentRoundContext(stream).events;
    const challenge = [...roundEvents].reverse().find(
      (event): event is ProtectionEvent<'challenge_opened'> => event.type === 'challenge_opened'
        && event.payload.caseId !== undefined,
    );
    if (challenge === undefined) return;
    const verdictEvent = [...roundEvents].reverse().find(
      (event): event is ProtectionEvent<'verdict_issued'> => event.type === 'verdict_issued'
        && event.payload.caseObject.caseId === challenge.payload.caseId,
    );
    if (verdictEvent === undefined || !isFinal(verdictEvent.payload.verdict)
        || verdictEvent.payload.disposition.route === 'human_review') return;
    let execution = verdictEvent.payload.execution;
    const authorized = [...stream].reverse().find(
      (event): event is ProtectionEvent<'execution_authorized'> => event.type === 'execution_authorized'
        && event.payload.caseId === verdictEvent.payload.caseObject.caseId,
    );
    execution ??= authorized?.payload.authorization;
    if (execution === undefined && this.options.executionSignatures !== undefined) {
      try {
        execution = await this.collectExecutionAuthorization(
          registration,
          verdictEvent.payload.caseObject,
          verdictEvent.payload.verdict,
        );
      } catch {
        execution = undefined;
      }
      if (execution !== undefined) {
        await this.append({
          protectionId: registration.mandateHash,
          type: 'execution_authorized',
          source: { kind: 'runtime', id: 'execution-quorum', externalId: execution.executionDigestHex },
          effectiveAtUnixMs: now,
          observedAtUnixMs: now,
          payload: { caseId: verdictEvent.payload.caseObject.caseId, authorization: execution },
          authentication: { kind: 'runtime', reason: 'independent contract verifier quorum' },
        });
      }
    }
    if (execution === undefined) return;
    const verdict = verdictEvent.payload.verdict;
    const eligibleAtUnixMs = verdict.issuedAtUnixMs + binding.challengeWindowMs;
    const expiresAtUnixMs = challenge.payload.openedAtUnixMs + binding.resolutionTimeoutMs;
    const raw: Omit<NearFunctionCallRelayPlan, 'planId'> = {
      version: 'edict-relay-plan-1',
      protectionId: registration.mandateHash,
      kind: 'near_function_call',
      contractId: binding.settlementAccount,
      methodName: 'submit_ruling',
      args: {
        order_mandate_sha256: bytes32(registration.mandateHash),
        ruling: rustRuling(verdict.ruling),
        verdict_sha256: bytes32(sha256Hex(canonicalize(verdict))),
        issued_at_ms: verdict.issuedAtUnixMs,
        nonce: bytes32(execution.nonceHex),
        signatures: execution.signatures,
      },
      gas: '200000000000000',
      depositYocto: '0',
      eligibleAtUnixMs,
      expiresAtUnixMs,
      authorization: 'verdict_quorum',
      guarantees: { noCustomerKey: true, noArbitraryRecipient: true, contractRevalidates: true },
    };
    await this.appendRelayPlan({ ...raw, planId: planId(raw) }, now);
  }

  private async scheduleLivenessFallback(registration: ProtectionRegistration, now: number): Promise<void> {
    const binding = runtimeSettlementBinding(registration);
    const stream = this.stream(registration.mandateHash);
    const challenge = [...currentRoundContext(stream).events].reverse().find(
      (event): event is ProtectionEvent<'challenge_opened'> => event.type === 'challenge_opened',
    );
    if (challenge === undefined) return;
    const deadline = challenge.payload.openedAtUnixMs + binding.resolutionTimeoutMs;
    if (now <= deadline || stream.some((event) => event.type === 'settlement_finalized')) return;
    await this.append({
      protectionId: registration.mandateHash,
      type: 'deadline_elapsed',
      source: { kind: 'runtime', id: 'deadline-scheduler', externalId: `resolution:${deadline}` },
      effectiveAtUnixMs: deadline + 1,
      observedAtUnixMs: now,
      payload: { deadlineKind: 'resolution', deadlineUnixMs: deadline },
      authentication: { kind: 'runtime', reason: 'signed settlement liveness timeout' },
    });
    if (registration.mandate.settlement!.livenessFallback === 'controller_resolution') return;
    const raw: Omit<NearFunctionCallRelayPlan, 'planId'> = {
      version: 'edict-relay-plan-1',
      protectionId: registration.mandateHash,
      kind: 'near_function_call',
      contractId: binding.settlementAccount,
      methodName: 'execute_liveness_fallback',
      args: { order_mandate_sha256: bytes32(registration.mandateHash), controller_ruling: null },
      gas: '100000000000000',
      depositYocto: '0',
      eligibleAtUnixMs: deadline + 1,
      authorization: 'permissionless',
      guarantees: { noCustomerKey: true, noArbitraryRecipient: true, contractRevalidates: true },
    };
    await this.appendRelayPlan({ ...raw, planId: planId(raw) }, now);
  }

  private async appendRelayPlan(plan: RelayPlan, now: number): Promise<void> {
    if (this.stream(plan.protectionId).some((event) =>
      event.type === 'relay_ready' && event.payload.plan.planId === plan.planId)) return;
    await this.append({
      protectionId: plan.protectionId,
      type: 'relay_ready',
      source: { kind: 'runtime', id: 'permissionless-relay', externalId: plan.planId },
      effectiveAtUnixMs: Math.max(plan.eligibleAtUnixMs, now),
      observedAtUnixMs: now,
      payload: { plan },
      authentication: { kind: 'runtime', reason: 'contract-revalidated relay plan' },
    });
  }

  private async relayEligible(now: number): Promise<string[]> {
    if (this.options.relayer === undefined || this.options.autoRelay !== true) return [];
    const projections = projectAll(this.events, now);
    const pending = projections.flatMap((projection) => projection.relayPlans);
    const relayed: string[] = [];
    const acknowledged = new Set<string>();
    for (const projection of projections) {
      for (const plan of projection.relayPlans) {
        if (acknowledged.has(plan.planId)) continue;
        if (plan.eligibleAtUnixMs > now || (plan.expiresAtUnixMs !== undefined && plan.expiresAtUnixMs < now)) continue;
        let result;
        try {
          result = await this.options.relayer.relay(plan);
        } catch {
          continue;
        }
        const withdrawalKey = withdrawalRelayKey(plan);
        const coveredPlans = withdrawalKey === undefined
          ? [plan]
          : pending.filter((candidate) =>
              withdrawalRelayKey(candidate) === withdrawalKey
              && candidate.eligibleAtUnixMs <= now
              && (candidate.expiresAtUnixMs === undefined || candidate.expiresAtUnixMs >= now));
        for (const covered of coveredPlans) {
          if (acknowledged.has(covered.planId)) continue;
          await this.append({
            protectionId: covered.protectionId,
            type: 'relay_submitted',
            source: { kind: 'relayer', id: 'permissionless-relayer', externalId: result.transactionHash },
            effectiveAtUnixMs: now,
            observedAtUnixMs: now,
            payload: { planId: covered.planId, transactionHash: result.transactionHash, submittedAtUnixMs: now },
            authentication: {
              kind: 'runtime',
              reason: withdrawalKey === undefined
                ? 'relayer submission receipt'
                : 'aggregate fixed-account claim withdrawal receipt',
            },
          });
          acknowledged.add(covered.planId);
          relayed.push(covered.planId);
        }
      }
    }
    return relayed;
  }

  private async scheduleClaimWithdrawals(
    registration: ProtectionRegistration,
    stream: AnyProtectionEvent[],
    now: number,
  ): Promise<void> {
    const binding = runtimeSettlementBinding(registration);
    const settled = [...stream].reverse().find(
      (event): event is ProtectionEvent<'settlement_finalized'> => event.type === 'settlement_finalized',
    );
    if (settled === undefined) return;
    for (const [accountId, amount] of [
      [binding.requesterAccount, settled.payload.requesterClaimAtomic],
      [binding.workerAccount, settled.payload.workerClaimAtomic],
    ] as const) {
      if (amount === undefined || BigInt(amount) === 0n) continue;
      const raw: Omit<NearFunctionCallRelayPlan, 'planId'> = {
        version: 'edict-relay-plan-1',
        protectionId: registration.mandateHash,
        kind: 'near_function_call',
        contractId: binding.settlementAccount,
        methodName: 'withdraw_claim',
        args: { account_id: accountId },
        gas: '60000000000000',
        depositYocto: '0',
        eligibleAtUnixMs: settled.payload.settledAtUnixMs,
        authorization: 'permissionless',
        guarantees: { noCustomerKey: true, noArbitraryRecipient: true, contractRevalidates: true },
      };
      await this.appendRelayPlan({ ...raw, planId: planId(raw) }, now);
    }
  }
}
