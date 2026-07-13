import type {
  CaseObject,
  EvidenceCommitment,
  EvidenceKind,
  InferenceProvider,
  OrderMandate,
  Outcome,
  VerdictObject,
} from '@edict/core';
import type { NearIntentsRoute } from '@edict/near-intents';
import type {
  EscalationDisposition,
  ProtectResult,
  ProtectionProfile,
} from '@edict/sdk';

export const PROTECTION_REGISTRATION_VERSION = 'edict-protection-registration-1' as const;
export const PROTECTION_EVENT_VERSION = 'edict-protection-event-1' as const;
export const SIGNED_ACTION_VERSION = 'edict-protect-signed-action-1' as const;
export const RELAY_PLAN_VERSION = 'edict-relay-plan-1' as const;
export const NATIVE_NEAR_RUNTIME_BINDING_VERSION = 'edict-native-near-runtime-1' as const;

export interface RuntimeVerifierSigner {
  signingAddress: string;
  operatorId: string;
  edictControlled: boolean;
  attestationSha256Hex: string;
}

export interface RuntimeVerifierPolicy {
  scheme: 'ecdsa_secp256k1_eth';
  quorum: number;
  signers: RuntimeVerifierSigner[];
}

/**
 * The chain-specific facts needed to observe and relay an Intents-backed
 * protection. No private key, withdrawal credential or spending capability
 * belongs in this object.
 */
export interface IntentsRuntimeBinding {
  connectorId: string;
  route: NearIntentsRoute;
  requesterIntentsAccount: string;
  workerIntentsAccount: string;
  principalAtomic: string;
  challengeWindowMs: number;
  resolutionTimeoutMs: number;
  disputeBondBps: number;
  verifierPolicySha256Hex: string;
  verifierPolicy: RuntimeVerifierPolicy;
}

/** Native-NEAR M2 binding used by the public testnet staging stack and native release track. */
export interface NativeNearRuntimeBinding {
  version: typeof NATIVE_NEAR_RUNTIME_BINDING_VERSION;
  connectorId: string;
  network: 'mainnet' | 'testnet';
  settlementAccount: string;
  settlementAsset: 'native:near';
  requesterAccount: string;
  workerAccount: string;
  principalAtomic: string;
  challengeWindowMs: number;
  resolutionTimeoutMs: number;
  disputeBondBps: number;
  verifierPolicySha256Hex: string;
  verifierPolicy: RuntimeVerifierPolicy;
}

/** An already-signed, single-use party intent that the runtime may only relay. */
export interface StandingChallengeAuthorization {
  version: 'edict-standing-challenge-1';
  party: 'requester' | 'worker';
  triggerKinds: Array<'objective_failure'>;
  caseId: string;
  caseIdSha256: string;
  bondAtomic: string;
  expiresAtUnixMs: number;
  signedIntentSha256: string;
  /** Opaque wallet/Intents payload. Its signature and nonce remain intact. */
  signedIntent: unknown;
}

export interface ProtectionRegistration {
  version: typeof PROTECTION_REGISTRATION_VERSION;
  mandate: OrderMandate;
  mandateHash: string;
  legalPolicyHash: string;
  profile: ProtectionProfile;
  profileHash: string;
  evidenceCommitments: EvidenceCommitment[];
  intents?: IntentsRuntimeBinding;
  nativeNear?: NativeNearRuntimeBinding;
  integrationRef?: string;
  standingChallengeAuthorization?: StandingChallengeAuthorization;
}

export type ProtectionEventType =
  | 'protection_registered'
  | 'protection_accepted'
  | 'funding_confirmed'
  | 'delivery_submitted'
  | 'acceptance_signed'
  | 'challenge_requested'
  | 'challenge_opened'
  | 'evidence_attached'
  | 'objective_failure_detected'
  | 'deadline_elapsed'
  | 'verdict_issued'
  | 'webhook_delivery_recorded'
  | 'execution_authorized'
  | 'review_required'
  | 'redo_ordered'
  | 'relay_ready'
  | 'relay_submitted'
  | 'settlement_finalized'
  | 'connector_warning'
  | 'connector_recovered';

export interface ProtectionEventSource {
  kind: 'integration' | 'signed_api' | 'near_intents' | 'near_native' | 'runtime' | 'arbiter' | 'relayer';
  id: string;
  /** Stable upstream id: receipt id, signed nonce, timer key or verdict hash. */
  externalId: string;
}

export type ProtectionEventAuthentication =
  | { kind: 'runtime'; reason: string }
  | { kind: 'trusted_integration'; integrationRef: string }
  | { kind: 'connector_receipt'; contractId: string; receiptId?: string; finality: 'final' }
  | {
      kind: 'signed_message';
      scheme: SignedActionScheme;
      signer: string;
      role: 'requester' | 'worker';
      nonce: string;
      digestSha256: string;
    };

export interface ProtectionEventPayloadMap {
  protection_registered: { registration: ProtectionRegistration };
  protection_accepted: { party: 'requester' | 'worker'; reference?: string };
  funding_confirmed: {
    requester: string;
    worker: string;
    tokenId: string;
    principalAtomic: string;
    transactionHash?: string;
  };
  delivery_submitted: {
    manifestSha256: string;
    deliveredAtUnixMs: number;
    worker?: string;
    transactionHash?: string;
  };
  acceptance_signed: { requester: string; acceptedAtUnixMs: number; transactionHash?: string };
  challenge_requested: {
    caseId: string;
    caseIdSha256: string;
    by: 'requester' | 'worker';
    statementSha256?: string;
    bondAtomic: string;
    action: unknown;
    standingAuthorizationUsed: boolean;
  };
  challenge_opened: {
    caseId?: string;
    caseIdSha256: string;
    by: 'requester' | 'worker';
    openedAtUnixMs: number;
    bondAtomic: string;
    round: 1 | 2;
    transactionHash?: string;
  };
  evidence_attached: {
    kind: EvidenceKind;
    sha256: string;
    submitter: EvidenceCommitment['submitter'];
    authenticated: boolean;
    vaultRef: string;
    uri?: string;
  };
  objective_failure_detected: {
    criterionId: string;
    reason: string;
    manifestSha256: string;
    requiresPartySignature: boolean;
  };
  deadline_elapsed: {
    deadlineKind: 'delivery' | 'acceptance' | 'challenge' | 'resolution';
    deadlineUnixMs: number;
  };
  verdict_issued: {
    caseObject: CaseObject;
    verdict: VerdictObject;
    disposition: EscalationDisposition;
    execution?: ExecutionAuthorization;
  };
  webhook_delivery_recorded: {
    targetId: string;
    verdictEventId: string;
    deliveryNumber: number;
    delivered: boolean;
    transportAttempts: number;
    attemptedAtUnixMs: number;
    nextAttemptAtUnixMs?: number;
    status?: number;
    error?: string;
  };
  execution_authorized: {
    caseId: string;
    authorization: ExecutionAuthorization;
  };
  review_required: {
    caseId: string;
    trigger: string;
    disposition: EscalationDisposition;
  };
  redo_ordered: {
    newDeadlineUnixMs: number;
    bondHeldAtomic: string;
    round: 1;
    transactionHash?: string;
  };
  relay_ready: { plan: RelayPlan };
  relay_submitted: { planId: string; transactionHash: string; submittedAtUnixMs: number };
  settlement_finalized: {
    ruling: string;
    /** Contract-wide claim balance observed for this fixed account, not per-order attribution. */
    requesterClaimAtomic?: string;
    /** Contract-wide claim balance observed for this fixed account, not per-order attribution. */
    workerClaimAtomic?: string;
    transactionHash?: string;
    settledAtUnixMs: number;
  };
  connector_warning: { code: string; message: string; context?: Record<string, unknown> };
  connector_recovered: { warningEventId: string; codes: string[]; message: string };
}

export interface ProtectionEvent<T extends ProtectionEventType = ProtectionEventType> {
  version: typeof PROTECTION_EVENT_VERSION;
  eventId: string;
  protectionId: string;
  type: T;
  source: ProtectionEventSource;
  effectiveAtUnixMs: number;
  observedAtUnixMs: number;
  payloadSha256: string;
  payload: ProtectionEventPayloadMap[T];
  authentication: ProtectionEventAuthentication;
}

export type AnyProtectionEvent = {
  [K in ProtectionEventType]: ProtectionEvent<K>;
}[ProtectionEventType];

export interface ProtectionEventDraft<T extends ProtectionEventType = ProtectionEventType> {
  protectionId: string;
  type: T;
  source: ProtectionEventSource;
  effectiveAtUnixMs: number;
  observedAtUnixMs?: number;
  payload: ProtectionEventPayloadMap[T];
  authentication: ProtectionEventAuthentication;
}

export type SignedActionScheme = 'eip191' | 'ed25519' | 'custom';
export type SignedActionName = 'approve_protection' | 'open_challenge' | 'attach_evidence';

export interface SignedActionPayloadMap {
  approve_protection: { reference?: string };
  open_challenge: { statement?: string; requestedAtUnixMs?: number };
  attach_evidence: {
    kind: EvidenceKind;
    plaintext: string;
    uri?: string;
  };
}

export interface SignedActionEnvelope<A extends SignedActionName = SignedActionName> {
  version: typeof SIGNED_ACTION_VERSION;
  action: A;
  protectionId: string;
  signer: string;
  role: 'requester' | 'worker';
  nonce: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  scheme: SignedActionScheme;
  /** Raw 32-byte ed25519 public key, hex or base64. Required for ed25519. */
  publicKey?: string;
  payload: SignedActionPayloadMap[A];
  signature: string;
}

export interface VerdictSignature {
  signing_address: string;
  signature: string;
}

export interface ExecutionAuthorization {
  executionDigestHex: string;
  nonceHex: string;
  signatures: VerdictSignature[];
}

export interface ExecutionSignatureRequest {
  protectionId: string;
  caseObject: CaseObject;
  verdict: VerdictObject & { final: true };
  verdictSha256Hex: string;
  executionDigestHex: string;
  nonceHex: string;
  policy: RuntimeVerifierPolicy;
  executionContext: {
    settlementAccountId: string;
    orderMandateSha256Hex: string;
    caseIdSha256Hex: string;
    round: 1 | 2;
    rulingCanonical: string;
    issuedAtUnixMs: number;
    verifierPolicySha256Hex: string;
  };
}

export interface ExecutionSignatureCollector {
  collect(request: ExecutionSignatureRequest): Promise<VerdictSignature[]>;
}

export interface NearFunctionCallRelayPlan {
  version: typeof RELAY_PLAN_VERSION;
  planId: string;
  protectionId: string;
  kind: 'near_function_call';
  contractId: string;
  methodName: 'claim_timeout' | 'submit_ruling' | 'execute_liveness_fallback' | 'withdraw_claim';
  args: Record<string, unknown>;
  gas: string;
  depositYocto: string;
  eligibleAtUnixMs: number;
  expiresAtUnixMs?: number;
  authorization: 'permissionless' | 'verdict_quorum';
  guarantees: {
    noCustomerKey: true;
    noArbitraryRecipient: true;
    contractRevalidates: true;
  };
}

export interface SignedIntentRelayPlan {
  version: typeof RELAY_PLAN_VERSION;
  planId: string;
  protectionId: string;
  kind: 'near_signed_intent';
  signedIntent: unknown;
  signedIntentSha256: string;
  eligibleAtUnixMs: number;
  expiresAtUnixMs: number;
  authorization: 'party_pre_signed';
  guarantees: {
    noCustomerKey: true;
    noArbitraryRecipient: true;
    contractRevalidates: true;
  };
}

export type RelayPlan = NearFunctionCallRelayPlan | SignedIntentRelayPlan;

export interface RelayResult {
  transactionHash: string;
}

export interface PermissionlessRelayer {
  relay(plan: RelayPlan): Promise<RelayResult>;
}

export type ProtectionRuntimeState =
  | 'setup_required'
  | 'awaiting_funding'
  | 'protected'
  | 'delivered'
  | 'challenged'
  | 'review_required'
  | 'settlement_ready'
  | 'settled'
  | 'blocked';

export interface ProtectionAttention {
  id: string;
  protectionId: string;
  kind:
    | 'counterparty_approval'
    | 'party_signature'
    | 'evidence_required'
    | 'human_review'
    | 'execution_signatures'
    | 'webhook_delivery'
    | 'connector_availability'
    | 'connector_integrity';
  title: string;
  detail: string;
  createdAtUnixMs: number;
}

export interface ProtectionProjection {
  protectionId: string;
  state: ProtectionRuntimeState;
  title: string;
  counterparty: string;
  amountUsd: number;
  asset: string;
  createdAtUnixMs: number;
  updatedAtUnixMs: number;
  deliveryDeadlineUnixMs: number;
  nextDeadlineUnixMs?: number;
  requesterApproved: boolean;
  workerApproved: boolean;
  events: AnyProtectionEvent[];
  attention: ProtectionAttention[];
  relayPlans: RelayPlan[];
  latestVerdict?: VerdictObject;
  latestOutcome?: Outcome;
}

export interface RuntimeAdjudicatorConfig {
  providers: Map<string, InferenceProvider>;
  archiveDir: string;
}

export interface ConnectorProtectionContext {
  registration: ProtectionRegistration;
  events: AnyProtectionEvent[];
}

/** Canonical connector contract implemented by NEAR Intents and future rails. */
export interface ProtectionConnector {
  readonly id: string;
  poll(contexts: ConnectorProtectionContext[]): Promise<ProtectionEventDraft[]>;
}

interface RegistrationFromProtectOptionsBase {
  profile: ProtectionProfile;
  integrationRef?: string;
  standingChallengeAuthorization?: StandingChallengeAuthorization;
}

export type RegistrationFromProtectOptions = RegistrationFromProtectOptionsBase & (
  | { intents: IntentsRuntimeBinding; nativeNear?: never }
  | { intents?: never; nativeNear: NativeNearRuntimeBinding }
);

export interface ProtectResultLike extends Pick<
  ProtectResult,
  'mandate' | 'mandateHash' | 'legalPolicyHash' | 'profileHash' | 'evidenceCommitments'
> {}

export interface VerdictWebhookTarget {
  id: string;
  url: string;
  secret: string;
}
