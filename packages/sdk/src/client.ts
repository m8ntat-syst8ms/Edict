/**
 * The Edict client — a seven-line wallet-native payment surface, with the
 * full profile and enterprise legal machinery available when required.
 *
 * `createEdict({ mode, profile })` returns a client whose whole lifecycle is:
 *
 *   protectPayment() — protect a payment from two party identifiers, a
 *                      promise, amount and deadline; the default Standard
 *                      profile is wallet-native E0 and needs no Edict KYB.
 *   protect(order)   — build an OrderMandate from profile defaults +
 *                      the order, run the pre-commitment lint gate, and
 *                      return everything a wallet / rail needs (canonical
 *                      hash, EIP-712 typed data, NEP-413 payload, evidence
 *                      commitment, profile hash, lint report).
 *   deliver(ref, m)  — build + hash the worker's delivery manifest.
 *   accept(ref)      — pure acceptance helper (auto-pays in the sandbox).
 *   dispute(ref, d)  — assemble the canonical CaseObject, verify every
 *                      evidence plaintext against its commitment, and run
 *                      the @edict/arbiter pipeline over three
 *                      disjoint-family MockProvider seats (sandbox mode).
 *   settle(verdict)  — derive a SettlementDirective, then apply it only to the
 *                      sandbox's simulated customer ledger.
 *
 * Human escalation (review policy) is a PROFILE-LEVEL POLICY: dispute() computes
 * an EscalationDisposition from the profile's humanEscalation election
 * (see ./escalation.ts); appeal(ref, by) invokes the optional_appeal right;
 * resolveHumanReview(ref, { ruling, reviewerRef }) produces the
 * human-reviewed final verdict that lifts the settle() hold. The invariant
 * is never weakened: an escalated verdict never settles — only a NEW
 * human-reviewed verdict (or the venue's pre-committed programmatic
 * fallback outside this SDK) resolves it.
 *
 * Sandbox mode is fully offline and deterministic. Live mode intentionally
 * keeps this client to pure mandate, delivery and settlement-directive
 * builders; the separate @edict/protection-runtime observes and resolves live
 * protections. Direct dispute/settle calls throw {@link LiveModeError}.
 */

import { createHash, randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  AcceptanceCriterion,
  CaseObject,
  CaseType,
  DecisionSpace,
  EvidenceCommitment,
  EvidenceKind,
  FinalVerdict,
  InferenceProvider,
  JurySeatSpec,
  LegalProfile,
  OrderMandate,
  Outcome,
  PartyRef,
  Publicity,
  SettlementBinding,
  SettlementDirective,
  ValueTier,
  VerdictObject,
} from '@edict/core';
import {
  assertExecutableVerdict,
  decisionSpaceForRound,
  tierForValueUsd,
  validateAuthorityCredentialRef,
  validateOutcome,
  validateSettlementBinding,
} from '@edict/core';
import {
  assertValidDeliveryManifest,
  buildEip712TypedData,
  buildEvidenceCommitment,
  buildNep413Payload,
  canonicalDeliveryManifestHash,
  canonicalOrderMandateHash,
  canonicalize,
  normalizeSha256,
  sha256Hex,
  type ArtifactHash,
  type DeliveryManifest,
  type Eip712TypedData,
  type Nep413Payload,
} from '@edict/evidence';
import { adjudicate, MockProvider, type ArbiterConfig, type ProofPolicy } from '@edict/arbiter';
import { lintMandate, type LintReport } from '@edict/linter';
import {
  CustodyBoundaryError,
  EscalatedVerdictError,
  EvidenceMismatchError,
  LintGateError,
  LiveModeError,
  PendingReviewError,
  ProfileValidationError,
  ProtectionStateError,
  ReviewOutcomeError,
  UnknownProtectionError,
  VerdictMismatchError,
} from './errors.js';
import { dispositionFor, type EscalationDisposition } from './escalation.js';
import {
  SANDBOX_MOCK_SEATS,
  assertValidProfile,
  profileHash as computeProfileHash,
  type ProtectionProfile,
} from './profile.js';
import { standardProfile } from './presets.js';
import { SandboxEscrow, type EscrowRecord } from './sandbox.js';
import { buildSettlementDirective } from './settlement.js';
import { signVerdictWebhook } from './webhook.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type EdictMode = 'sandbox' | 'live';

export interface CreateEdictOptions {
  mode: EdictMode;
  /** Defaults to the wallet-native profile. Pass a profile only to customize policy. */
  profile?: ProtectionProfile;
  /** One-time customer-hosted settlement configuration; orders may override it. */
  settlement?: SettlementBinding;
  /** providerId -> InferenceProvider; defaults to one MockProvider per seat provider. */
  providers?: Map<string, InferenceProvider>;
  /** Optional one-off proof-verification policy; defaults to profile.juryPolicy.proofPolicy. */
  proofPolicy?: ProofPolicy;
  /** Where the arbiter archives proofs/reasoning/verdicts. Default: <os tmp>/edict-sdk-archive. */
  archiveDir?: string;
  /** When set, `onVerdict` deliveries are HMAC-signed with this secret. */
  webhookSecret?: string;
}

export interface ProtectOrderInput {
  /** The ordering party (pays). An agent id is enough for wallet-native mode. */
  requester: PartyRef;
  /** The delivering party (is paid). An agent id is enough for wallet-native mode. */
  worker: PartyRef;
  description: string;
  acceptanceCriteria: AcceptanceCriterion[];
  priceUsd: number;
  deadlineUnixMs: number;
  /** Per-order overrides of the profile defaults. */
  overrides?: {
    currency?: { asset: string; rail: string };
    acceptanceWindowMs?: number;
    legalProfile?: LegalProfile;
    decisionSpace?: DecisionSpace;
    /** Customer, wallet or rail-controlled settlement boundary. Edict is never a controller. */
    settlement?: SettlementBinding;
    maeEvents?: string[];
    /** Fixed mandate nonce (default: random uuid v4). */
    nonce?: string;
  };
}

/** The payment-first integration surface; policy and jury settings come from the client preset. */
export interface ProtectPaymentInput {
  /** Existing rail/payment identifier; bound into the mandate nonce when supplied. */
  paymentId?: string;
  requester: string | PartyRef;
  worker: string | PartyRef;
  /** Plain-language promise the payment is conditional on. */
  promise: string;
  amountUsd: number;
  deadlineUnixMs: number;
  currency?: { asset: string; rail: string };
  /** Optional structured criteria; otherwise the promise becomes AC-1. */
  acceptanceCriteria?: AcceptanceCriterion[];
  /** Defaults to an external payment-rail adapter derived from currency.rail. */
  settlement?: SettlementBinding;
}

export interface ProtectResult {
  mandate: OrderMandate;
  /** canonicalOrderMandateHash — what CaseObject.orderMandateHash references. */
  mandateHash: string;
  /** Canonical hash of the exact signed Legal Policy. */
  legalPolicyHash: string;
  /** Present when customer T&Cs were admitted through a Customer Policy Pack. */
  customerPolicyPackHash?: string;
  /** EIP-712 typed data the requester/worker wallets sign on EVM rails. */
  eip712: Eip712TypedData;
  /** NEP-413 signMessage payload for NEAR rails (same flattened content). */
  nep413: Nep413Payload;
  /** The order_mandate evidence commitment (venue-verified). */
  evidenceCommitments: EvidenceCommitment[];
  /** Signed proof that funds remain with the customer, wallet or payment rail. */
  settlement: SettlementBinding;
  /** sha256 of the canonical ProtectionProfile this order was protected under. */
  profileHash: string;
  lint: LintReport;
}

/** Accepts the ProtectResult itself, anything carrying its mandateHash, or the hash. */
export type ProtectRef = string | { mandateHash: string };

export interface DeliverInput {
  artifactHashes: ArtifactHash[];
  formatClaims?: string[];
  deliveredAtUnixMs?: number;
}

export interface DeliverResult {
  manifest: DeliveryManifest;
  /** canonicalDeliveryManifestHash — what CaseObject.deliveryManifestHash references. */
  manifestHash: string;
  commitment: EvidenceCommitment;
}

export interface AcceptResult {
  mandateHash: string;
  acceptedAtUnixMs: number;
  /** Sandbox mode only: the escrow record after the payout. */
  escrow?: EscrowRecord;
}

export interface ExtraEvidenceInput {
  kind: EvidenceKind;
  /** The evidence plaintext (raw bytes as a string; hashed as-is). */
  plaintext: string;
  submitter: EvidenceCommitment['submitter'];
  /** Optional pre-computed sha256 — verified against the plaintext (mismatch throws). */
  sha256?: string;
  authenticated?: boolean;
  uri?: string;
}

export interface DisputeInput {
  submissions: { requester?: string; worker?: string };
  extraEvidence?: ExtraEvidenceInput[];
  /** Which party posts the sandbox dispute bond. Default 'requester'. */
  by?: 'requester' | 'worker';
  /** Case shape. Default 'bilateral'. */
  caseType?: CaseType;
  /** Default: profile.defaults.publicity, else 'sealed' ('public' for public_resolution). */
  publicity?: Publicity;
  /** Case opening time (unix ms). Default Date.now(); pin it for reproducible runs. */
  openedAtUnixMs?: number;
}

export type ProtectionStatus = 'protected' | 'delivered' | 'accepted' | 'disputed' | 'redo' | 'settled';

/**
 * Human-review lifecycle of a disputed protection (review policy):
 * 'queued' — the disposition routed to human review (quality-gate trip or a
 *            required_above_value final awaiting the bench);
 * 'appealed' — a party invoked its optional_appeal right on a final verdict;
 * 'resolved' — a human reviewer issued the resolution (the record's verdict
 *              is now the human-reviewed one; settle() operates on it).
 * While 'queued'/'appealed', settle() throws {@link PendingReviewError}.
 */
export type ReviewState = 'queued' | 'appealed' | 'resolved';

/** Immutable snapshot of one completed adjudication round. */
export interface ProtectionRound {
  number: number;
  caseObject: CaseObject;
  verdict: VerdictObject;
  /** Pure instruction emitted before the sandbox test ledger applies it. */
  settlementDirective: SettlementDirective;
  escrow: EscrowRecord;
}

export interface ProtectionRecord {
  status: ProtectionStatus;
  mandate: OrderMandate;
  mandateHash: string;
  protect: ProtectResult;
  manifest?: DeliveryManifest;
  manifestHash?: string;
  manifestCommitment?: EvidenceCommitment;
  acceptedAtUnixMs?: number;
  currentDeadlineUnixMs: number;
  rounds: ProtectionRound[];
  caseObject?: CaseObject;
  verdict?: VerdictObject;
  /** Routing under the profile's humanEscalation policy — set by dispute(). */
  disposition?: EscalationDisposition;
  /** Human-review lifecycle (see {@link ReviewState}); absent = no review involved. */
  reviewState?: ReviewState;
  /** Which party invoked appeal() (audit). */
  appealedBy?: 'requester' | 'worker';
}

export interface VerdictWebhookEvent {
  verdict: VerdictObject;
  /** Canonical verdict JSON (the signed bytes). */
  payload: string;
  /** Present iff the client was created with a webhookSecret. */
  signature?: string;
}

export type VerdictWebhookHandler = (event: VerdictWebhookEvent) => void | Promise<void>;

/**
 * Fired (and awaited) whenever a disposition routes a case to
 * 'human_review' — a quality-gate/mandatory routing computed by dispute(),
 * or a party appeal via appeal(). Subscribe with `onEscalation` to feed a
 * review queue / bench-notification pipeline.
 */
export interface EscalationEvent {
  mandateHash: string;
  caseId: string;
  verdict: VerdictObject;
  disposition: EscalationDisposition;
}

export type EscalationHandler = (event: EscalationEvent) => void | Promise<void>;

/** Input to {@link EdictClient.resolveHumanReview}. */
export interface ResolveHumanReviewInput {
  /** The reviewer's ruling — MUST lie within the case's pre-committed decision space. */
  ruling: Outcome;
  /** Bench member / reviewer identity ref (never inline PII) — goes on humanReview.reviewerRef. */
  reviewerRef: string;
  /** Resolution time (unix ms). Default Date.now(); pin it for reproducible tests. */
  decidedAtUnixMs?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Type guard narrowing a VerdictObject to the executable FinalVerdict.
 * NOTE: this checks the `final` flag ONLY. Anything that EXECUTES a verdict
 * must call `assertExecutableVerdict(verdict, space)` from @edict/core
 * instead (or in addition) — it also re-checks quality.escalated, the
 * outcome-in-space invariant and attack-severity injection flags. Both
 * `EdictClient.settle` and `SandboxEscrow.settle` do so.
 */
export function isFinalVerdict(v: VerdictObject): v is FinalVerdict {
  return v.final === true;
}

/** uuid-v4-SHAPED id derived from a seed (same seed → same case id). */
function deterministicUuidV4(seed: string): string {
  const h = createHash('sha256').update(seed).digest('hex');
  return (
    `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-` +
    `${'89ab'[parseInt(h[16]!, 16) % 4]}${h.slice(17, 20)}-${h.slice(20, 32)}`
  );
}

/**
 * Tier for a case value: the profile's preference where the canonical value bands
 * bands allow it, otherwise the canonical tier (cases must always validate).
 */
function tierFor(valueUsd: number, thresholds?: { aMaxUsd: number; bMaxUsd: number }): ValueTier {
  const candidates = tierForValueUsd(valueUsd);
  if (candidates.length === 0) {
    throw new RangeError(`valueUsd ${valueUsd} is outside every Edict value band (tier C caps at $100k)`);
  }
  const t = thresholds ?? { aMaxUsd: 10, bMaxUsd: 1_000 };
  const preferred: ValueTier = valueUsd <= t.aMaxUsd ? 'A' : valueUsd <= t.bMaxUsd ? 'B' : 'C';
  return candidates.includes(preferred) ? preferred : candidates[0]!;
}

const DEFAULT_CURRENCY = { asset: 'USDC', rail: 'sdk-sandbox' } as const;

function sandboxAuthority(party: PartyRef): PartyRef {
  if (party.authorityCredentialRef !== undefined && party.principalKybRef !== undefined) return { ...party };
  const principalKybRef = party.principalKybRef ?? `kyb:sandbox:self-attested:${sha256Hex(party.agentId).slice(0, 16)}`;
  const descriptor = {
    version: 'edict-sandbox-authority-1',
    principalKybRef,
    agentId: party.agentId,
  };
  return {
    ...party,
    principalKybRef,
    authorityCredentialRef: {
      credentialId: `sandbox:${party.agentId}`,
      sha256: sha256Hex(canonicalize(descriptor)),
      issuer: 'edict:sandbox:self-attested',
      revocationRegistry: 'edict:sandbox:none',
    },
  };
}

function externalSettlementForRail(rail: string): SettlementBinding {
  return {
    custodyMode: 'M2_external_escrow',
    fundsController: 'payment_rail',
    adapterRef: `rail:${rail}`,
    edictOperatorCanTransfer: false,
    edictOperatorCanFreeze: false,
    edictOperatorIsRequiredSigner: false,
    resolutionTimeoutMs: 72 * 60 * 60 * 1_000,
    livenessFallback: 'controller_resolution',
  };
}

/** Freeze a cloned policy so its committed hash cannot drift after client construction. */
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export function createEdict(opts: CreateEdictOptions): EdictClient {
  return new EdictClient(opts);
}

export class EdictClient {
  readonly mode: EdictMode;
  readonly profile: ProtectionProfile;
  /** sha256 of the canonical profile — recorded on every dispute's railRef. */
  readonly profileHash: string;
  /** In-memory escrow ledger (auto-wired in sandbox mode; inert in live mode). */
  readonly escrow: SandboxEscrow;

  private readonly seats: JurySeatSpec[];
  private readonly providers: Map<string, InferenceProvider>;
  private readonly proofPolicy: ProofPolicy | undefined;
  private readonly archiveDir: string;
  private readonly webhookSecret: string | undefined;
  private readonly defaultSettlement: SettlementBinding | undefined;
  private readonly records = new Map<string, ProtectionRecord>();
  private readonly caseToMandate = new Map<string, string>();
  private readonly verdictHandlers = new Set<VerdictWebhookHandler>();
  private readonly escalationHandlers = new Set<EscalationHandler>();

  constructor(opts: CreateEdictOptions) {
    if (opts.mode !== 'sandbox' && opts.mode !== 'live') {
      throw new TypeError(`mode must be 'sandbox' or 'live', got ${String(opts.mode)}`);
    }
    const suppliedProfile = opts.profile ?? standardProfile();
    assertValidProfile(suppliedProfile);
    this.mode = opts.mode;
    const normalizedProfile = structuredClone(suppliedProfile);
    if (normalizedProfile.humanEscalation !== undefined) {
      normalizedProfile.legalPolicy.humanEscalation = structuredClone(normalizedProfile.humanEscalation);
    }
    this.profile = deepFreeze(normalizedProfile);
    this.profileHash = computeProfileHash(this.profile);
    this.escrow = new SandboxEscrow();

    if (opts.settlement !== undefined) {
      const problems = validateSettlementBinding(opts.settlement, 'settlement');
      if (problems.length > 0) throw new TypeError(problems.join('; '));
      this.defaultSettlement = deepFreeze(structuredClone(opts.settlement));
    } else {
      this.defaultSettlement = undefined;
    }

    this.seats = (this.profile.juryPolicy.seats ?? SANDBOX_MOCK_SEATS).map((s) => ({ ...s }));
    const allowlist = this.profile.juryPolicy.provenanceAllowlist;
    if (allowlist !== undefined) {
      const offending = this.seats.filter((s) => !allowlist.includes(s.providerId));
      if (offending.length > 0) {
        throw new ProfileValidationError(
          offending.map(
            (s) => `seat ${s.seatId}: providerId "${s.providerId}" is not in the provenanceAllowlist`,
          ),
        );
      }
    }
    this.providers = opts.providers !== undefined ? new Map(opts.providers) : buildMockProviderMap(this.seats);
    const proofPolicy = opts.proofPolicy ?? this.profile.juryPolicy.proofPolicy;
    this.proofPolicy = proofPolicy !== undefined ? structuredClone(proofPolicy) : undefined;
    this.archiveDir = opts.archiveDir ?? join(tmpdir(), 'edict-sdk-archive');
    this.webhookSecret = opts.webhookSecret;
  }

  // --- protect ---------------------------------------------------------------

  /**
   * Protect an existing payment using only the fields a rail already has.
   * Wallet-native mode needs no KYB or delegated-authority credential.
   */
  async protectPayment(payment: ProtectPaymentInput): Promise<ProtectResult> {
    if (typeof payment.promise !== 'string' || payment.promise.trim().length === 0) {
      throw new TypeError('promise must be a non-empty string');
    }
    const party = (value: string | PartyRef, path: string): PartyRef => {
      if (typeof value === 'string') {
        if (value.trim().length === 0) throw new TypeError(`${path} must be a non-empty agent id`);
        return { agentId: value.trim() };
      }
      return { ...value };
    };
    const promise = payment.promise.trim();
    const criteria = payment.acceptanceCriteria?.map((criterion) => structuredClone(criterion)) ?? [
      { id: 'AC-1', statement: promise },
    ];
    const rail = payment.currency?.rail ?? DEFAULT_CURRENCY.rail;
    return this.protect({
      requester: party(payment.requester, 'requester'),
      worker: party(payment.worker, 'worker'),
      description: promise,
      acceptanceCriteria: criteria,
      priceUsd: payment.amountUsd,
      deadlineUnixMs: payment.deadlineUnixMs,
      overrides: {
        ...(payment.currency !== undefined ? { currency: { ...payment.currency } } : {}),
        ...(payment.paymentId !== undefined ? { nonce: `payment:${rail}:${payment.paymentId}` } : {}),
        ...(payment.settlement !== undefined ? { settlement: structuredClone(payment.settlement) } : {}),
      },
    });
  }

  /**
   * Build the OrderMandate from profile defaults and the order, run the
   * lint gate, and (sandbox only) lock test value in the simulated ledger.
   * Throws {@link LintGateError} when the gate blocks.
   */
  async protect(order: ProtectOrderInput): Promise<ProtectResult> {
    if (!Number.isFinite(order.priceUsd) || order.priceUsd <= 0 || order.priceUsd > 100_000) {
      throw new RangeError(`priceUsd must be in (0, 100000] (tier C cap), got ${order.priceUsd}`);
    }
    const d = this.profile.defaults;
    const o = order.overrides ?? {};
    const orderTier = tierFor(order.priceUsd, this.profile.tierThresholds);
    const requestedLegalProfile = o.legalProfile ?? d.legalProfile;
    const legalProfile: LegalProfile = {
      ...requestedLegalProfile,
      // DRR Rule 6.1 is a hard product rule, not an integrator preference.
      ...(orderTier === 'A' ? { enforcementTier: 'E0' as const } : {}),
    };
    const legalPolicy = structuredClone(this.profile.legalPolicy);
    if (this.profile.humanEscalation !== undefined) {
      legalPolicy.humanEscalation = structuredClone(this.profile.humanEscalation);
    }
    if (legalProfile.enforcementTier !== 'E0' && legalPolicy.assuranceMode !== 'enterprise_legal') {
      throw new TypeError(
        `${legalProfile.enforcementTier} requires legalPolicy.assuranceMode 'enterprise_legal'; ` +
          'wallet_native and rail_verified are E0 settlement modes',
      );
    }
    const enterpriseLegal = legalPolicy.assuranceMode === 'enterprise_legal';
    const requester = enterpriseLegal && this.mode === 'sandbox'
      ? sandboxAuthority(order.requester)
      : { ...order.requester };
    const worker = enterpriseLegal && this.mode === 'sandbox'
      ? sandboxAuthority(order.worker)
      : { ...order.worker };
    for (const [party, path] of [
      [requester, 'requester'],
      [worker, 'worker'],
    ] as const) {
      if (enterpriseLegal && party.principalKybRef === undefined) {
        throw new TypeError(`${path}.principalKybRef is required for enterprise_legal protection`);
      }
      if (enterpriseLegal || party.authorityCredentialRef !== undefined) {
        const problems = validateAuthorityCredentialRef(party.authorityCredentialRef, `${path}.authorityCredentialRef`);
        if (problems.length > 0) throw new TypeError(problems.join('; '));
      }
    }
    const currency = o.currency ?? { ...DEFAULT_CURRENCY };
    const configuredSettlement = o.settlement ?? this.defaultSettlement;
    if (this.mode === 'live' && configuredSettlement === undefined) {
      throw new CustodyBoundaryError([
        'live protection requires a customer-controlled settlement binding; configure it once in createEdict({ settlement }) or provide an order-level binding',
      ]);
    }
    const settlement = structuredClone(
      configuredSettlement ?? externalSettlementForRail(currency.rail),
    );
    const settlementProblems = validateSettlementBinding(settlement);
    if (settlementProblems.length > 0) throw new TypeError(settlementProblems.join('; '));
    const mandate: OrderMandate = {
      version: 'edict-om-2',
      requester,
      worker,
      description: order.description,
      acceptanceCriteria: order.acceptanceCriteria,
      priceUsd: order.priceUsd,
      currency,
      deadlineUnixMs: order.deadlineUnixMs,
      acceptanceWindowMs: o.acceptanceWindowMs ?? d.acceptanceWindowMs,
      legalProfile,
      legalPolicy,
      decisionSpace: o.decisionSpace ?? structuredClone(d.decisionSpace),
      settlement,
      maeEvents: o.maeEvents ?? [...(d.maeEvents ?? [])],
      nonce: o.nonce ?? randomUUID(),
    };

    // --- lint gate (BEFORE funds lock) ---------------------------------------
    const lint = lintMandate(mandate);
    const gate = this.profile.lintGate;
    const reasons: string[] = [];
    if (gate.blockOnError && lint.findings.some((f) => f.severity === 'error')) {
      reasons.push('mandate has error-severity lint findings (lintGate.blockOnError)');
    }
    if (lint.score < gate.minScore) {
      reasons.push(`lint score ${lint.score} is below lintGate.minScore ${gate.minScore}`);
    }
    if (reasons.length > 0) throw new LintGateError(lint, reasons);

    const mandateHash = canonicalOrderMandateHash(mandate);
    const signedLegalPolicy = mandate.legalPolicy!;
    const legalPolicyHash = sha256Hex(canonicalize(signedLegalPolicy));
    const mandateCommitment: EvidenceCommitment = {
      ...buildEvidenceCommitment('order_mandate', mandate, 'system'),
      authenticated: true, // the SDK built + hashed the mandate itself (venue-verified)
    };
    const legalPolicyCommitment: EvidenceCommitment = {
      kind: 'legal_policy',
      sha256: legalPolicyHash,
      submitter: 'system',
      authenticated: true,
      ...(signedLegalPolicy.rules.uri !== undefined ? { uri: signedLegalPolicy.rules.uri } : {}),
    };
    const authorityCommitments: EvidenceCommitment[] = [mandate.requester, mandate.worker].flatMap((party) => {
      const ref = party.authorityCredentialRef;
      if (ref === undefined) return [];
      return [{
        kind: 'authority_credential' as const,
        sha256: ref.sha256,
        submitter: 'venue' as const,
        // A reference is not verification. A live venue adapter may promote
        // this only after checking issuer proof, scope, time and revocation.
        authenticated: false,
        ...(ref.uri !== undefined ? { uri: ref.uri } : {}),
      }];
    });
    let customerPolicyPackHash: string | undefined;
    let customerPolicyCommitment: EvidenceCommitment | undefined;
    if (this.profile.customerPolicyPack !== undefined) {
      customerPolicyPackHash = sha256Hex(canonicalize(this.profile.customerPolicyPack));
      customerPolicyCommitment = {
        kind: 'customer_policy_pack',
        sha256: customerPolicyPackHash,
        submitter: 'venue',
        authenticated: true,
        ...(this.profile.legalPolicy.customerPolicyPack?.uri !== undefined
          ? { uri: this.profile.legalPolicy.customerPolicyPack.uri }
          : {}),
      };
    }
    const result: ProtectResult = {
      mandate,
      mandateHash,
      legalPolicyHash,
      ...(customerPolicyPackHash !== undefined ? { customerPolicyPackHash } : {}),
      eip712: buildEip712TypedData(mandate),
      // Recipient is the mode-scoped verifier; the 32-byte NEP-413 entropy is
      // the mandate hash itself (deterministic, collision-free per mandate).
      nep413: buildNep413Payload(mandate, `edict-arbiter.${this.mode}`, Buffer.from(mandateHash, 'hex')),
      evidenceCommitments: [
        mandateCommitment,
        legalPolicyCommitment,
        ...authorityCommitments,
        ...(customerPolicyCommitment !== undefined ? [customerPolicyCommitment] : []),
      ],
      settlement: structuredClone(settlement),
      profileHash: this.profileHash,
      lint,
    };

    if (this.mode === 'sandbox') {
      this.escrow.fund({
        escrowId: mandateHash,
        requesterAgentId: mandate.requester.agentId,
        workerAgentId: mandate.worker.agentId,
        amountUsd: mandate.priceUsd,
      });
    }

    const stored = structuredClone(result);
    this.records.set(mandateHash, {
      status: 'protected',
      mandate: stored.mandate,
      mandateHash,
      protect: stored,
      currentDeadlineUnixMs: mandate.deadlineUnixMs,
      rounds: [],
    });
    return result;
  }

  // --- deliver -----------------------------------------------------------------

  /** Build + hash the worker's delivery manifest for a protected order. */
  async deliver(ref: ProtectRef, input: DeliverInput): Promise<DeliverResult> {
    const rec = this.resolve(ref);
    if (rec.status !== 'protected' && rec.status !== 'redo') {
      throw new ProtectionStateError(`protection ${rec.mandateHash} is '${rec.status}' — deliver() needs 'protected' or 'redo'`);
    }
    const deliveredAtUnixMs = input.deliveredAtUnixMs ?? Date.now();
    if (deliveredAtUnixMs > rec.currentDeadlineUnixMs) {
      throw new ProtectionStateError(
        `delivery at ${deliveredAtUnixMs} is after the effective deadline ${rec.currentDeadlineUnixMs}`,
      );
    }
    const manifest: DeliveryManifest = {
      artifactHashes: input.artifactHashes.map((a) => ({ ...a })),
      formatClaims: input.formatClaims ?? [],
      workerAgentId: rec.mandate.worker.agentId,
      orderMandateHash: rec.mandateHash,
      deliveredAtUnixMs,
    };
    assertValidDeliveryManifest(manifest);
    const manifestHash = canonicalDeliveryManifestHash(manifest);
    const commitment: EvidenceCommitment = {
      ...buildEvidenceCommitment('delivery_manifest', manifest, 'worker'),
      authenticated: true,
    };
    if (this.mode === 'sandbox') {
      this.escrow.deliver(rec.mandateHash, manifest.deliveredAtUnixMs);
    }
    rec.status = 'delivered';
    rec.manifest = structuredClone(manifest);
    rec.manifestHash = manifestHash;
    rec.manifestCommitment = structuredClone(commitment);
    return { manifest, manifestHash, commitment };
  }

  // --- accept ------------------------------------------------------------------

  /** Pure acceptance helper (v0 — no chain calls). Sandbox: pays the worker. */
  async accept(ref: ProtectRef): Promise<AcceptResult> {
    const rec = this.resolve(ref);
    if (rec.status !== 'delivered') {
      throw new ProtectionStateError(`protection ${rec.mandateHash} is '${rec.status}' — accept() needs 'delivered'`);
    }
    const acceptedAtUnixMs = Date.now();
    rec.status = 'accepted';
    rec.acceptedAtUnixMs = acceptedAtUnixMs;
    const out: AcceptResult = { mandateHash: rec.mandateHash, acceptedAtUnixMs };
    if (this.mode === 'sandbox') {
      out.escrow = this.escrow.accept(rec.mandateHash);
    }
    return out;
  }

  /**
   * When the acceptance window auto-releases: deliveredAt + acceptanceWindowMs
   * (unix ms). Pure helper — throws unless the order has been delivered.
   */
  autoAcceptDeadline(ref: ProtectRef): number {
    const rec = this.resolve(ref);
    if (rec.manifest === undefined) {
      throw new ProtectionStateError(
        `protection ${rec.mandateHash} has no delivery manifest — the auto-accept clock starts at delivery`,
      );
    }
    return rec.manifest.deliveredAtUnixMs + rec.mandate.acceptanceWindowMs;
  }

  // --- dispute ------------------------------------------------------------------

  /**
   * Assemble the canonical CaseObject, verify every evidence plaintext
   * hash-matches its commitment, and (sandbox) adjudicate through the
   * @edict/arbiter pipeline. Returns the VerdictObject.
   */
  async dispute(ref: ProtectRef, input: DisputeInput): Promise<VerdictObject> {
    if (this.mode !== 'sandbox') throw new LiveModeError('dispute()');
    const rec = this.resolve(ref);
    if (rec.status === 'accepted' || rec.status === 'settled') {
      throw new ProtectionStateError(`protection ${rec.mandateHash} is '${rec.status}' — nothing left to dispute`);
    }
    // A repeated call is a retry/read, never a retrial. In particular it must
    // not clear an appeal or mandatory-review hold by replacing the record's
    // disposition with a freshly computed one.
    if (rec.status === 'disputed') {
      if (rec.verdict === undefined) {
        throw new ProtectionStateError(`protection ${rec.mandateHash} is disputed but has no recorded verdict`);
      }
      return structuredClone(rec.verdict);
    }

    const caseType: CaseType = input.caseType ?? 'bilateral';
    const publicity: Publicity =
      input.publicity ??
      this.profile.defaults.publicity ??
      (caseType === 'public_resolution' ? 'public' : 'sealed');
    const openedAtUnixMs = input.openedAtUnixMs ?? Date.now();
    if (rec.rounds.length >= 2) throw new ProtectionStateError(`protection ${rec.mandateHash} exhausted its two-round limit`);
    const roundNumber: 1 | 2 = rec.rounds.length === 0 ? 1 : 2;
    const caseId = deterministicUuidV4(`edict-sdk-case:${rec.mandateHash}:round:${roundNumber}`);

    // --- evidence: commitments + sealed plaintexts -----------------------------
    const evidence: EvidenceCommitment[] = [...rec.protect.evidenceCommitments];
    const plaintext: Record<string, string> = {
      [rec.mandateHash]: canonicalize(rec.mandate),
      [rec.protect.legalPolicyHash]: canonicalize(rec.mandate.legalPolicy),
    };
    if (rec.protect.customerPolicyPackHash !== undefined && this.profile.customerPolicyPack !== undefined) {
      plaintext[rec.protect.customerPolicyPackHash] = canonicalize(this.profile.customerPolicyPack);
    }
    if (rec.manifest !== undefined && rec.manifestHash !== undefined && rec.manifestCommitment !== undefined) {
      evidence.push(rec.manifestCommitment);
      plaintext[rec.manifestHash] = canonicalize(rec.manifest);
    }
    for (const [submitter, text] of [
      ['requester', input.submissions.requester],
      ['worker', input.submissions.worker],
    ] as const) {
      if (text === undefined || text.length === 0) continue;
      const sha256 = sha256Hex(text);
      evidence.push({ kind: 'party_submission', sha256, submitter, authenticated: false });
      plaintext[sha256] = text;
    }
    for (const extra of input.extraEvidence ?? []) {
      const sha256 = sha256Hex(extra.plaintext);
      if (extra.sha256 !== undefined && normalizeSha256(extra.sha256) !== sha256) {
        throw new EvidenceMismatchError([
          `${extra.kind} (${extra.submitter}): declared sha256 ${extra.sha256} does not match the plaintext hash ${sha256}`,
        ]);
      }
      const commitment: EvidenceCommitment = {
        kind: extra.kind,
        sha256,
        submitter: extra.submitter,
        authenticated: extra.authenticated ?? false,
      };
      if (extra.uri !== undefined) commitment.uri = extra.uri;
      evidence.push(commitment);
      plaintext[sha256] = extra.plaintext;
    }

    // Belt-and-braces: every sealed plaintext must hash to a commitment we carry.
    const committed = new Set(evidence.map((c) => c.sha256));
    const mismatches = Object.entries(plaintext)
      .filter(([key, text]) => sha256Hex(text) !== key || !committed.has(key))
      .map(([key]) => `plaintext keyed ${key.slice(0, 12)}… does not hash-match a case evidence commitment`);
    if (mismatches.length > 0) throw new EvidenceMismatchError(mismatches);

    const caseObj: CaseObject = {
      caseId,
      caseType,
      publicity,
      requester: { ...rec.mandate.requester },
      worker: { ...rec.mandate.worker },
      orderMandateHash: rec.mandateHash,
      legalPolicyHash: rec.protect.legalPolicyHash,
      ...(rec.manifestHash !== undefined ? { deliveryManifestHash: rec.manifestHash } : {}),
      evidence,
      valueUsd: rec.mandate.priceUsd,
      tier: tierFor(rec.mandate.priceUsd, this.profile.tierThresholds),
      custodyMode: rec.mandate.settlement!.custodyMode,
      railRef: {
        rail: rec.mandate.currency.rail,
        adapterRef: rec.mandate.settlement!.adapterRef,
        fundsController: rec.mandate.settlement!.fundsController,
        profileHash: this.profileHash,
      },
      legalProfile: { ...rec.mandate.legalProfile },
      openedAtUnixMs,
      decisionSpace: decisionSpaceForRound(rec.mandate.decisionSpace, roundNumber),
      round: roundNumber === 1
        ? { number: 1, effectiveDeadlineUnixMs: rec.currentDeadlineUnixMs }
        : {
            number: 2,
            effectiveDeadlineUnixMs: rec.currentDeadlineUnixMs,
            priorCaseId: rec.rounds[0]!.caseObject.caseId,
            priorVerdictSha256: sha256Hex(canonicalize(rec.rounds[0]!.verdict)),
          },
    };

    // --- sandbox escrow wiring (idempotent for repeat dispute() calls) ---------
    const escrowRec = this.escrow.record(rec.mandateHash);
    if (escrowRec !== undefined && escrowRec.status !== 'disputed') {
      this.escrow.dispute(rec.mandateHash, input.by ?? 'requester', { caseId });
    } else if (escrowRec !== undefined && escrowRec.caseId !== caseId) {
      this.escrow.bindCase(rec.mandateHash, caseId);
    }

    // --- the arbiter pipeline over the configured jury --------------------
    const config: ArbiterConfig = {
      seats: this.seats.map((s) => ({ ...s })),
      providers: this.providers,
      archiveDir: this.archiveDir,
      ...(this.profile.juryPolicy.requireProofs !== undefined
        ? { requireProofs: this.profile.juryPolicy.requireProofs }
        : {}),
      ...(this.proofPolicy !== undefined ? { proofPolicy: this.proofPolicy } : {}),
    };
    const verdict = await adjudicate(caseObj, plaintext, config);

    rec.status = 'disputed';
    rec.caseObject = structuredClone(caseObj);
    rec.verdict = structuredClone(verdict);
    this.caseToMandate.set(caseId, rec.mandateHash);

    // --- human escalation policy (review policy): compute + store the routing ------
    // Computed once for the adjudication. Retry calls return the stored verdict
    // above, preserving any review/appeal hold. The arbiter stayed policy-free;
    // the profile's election is applied HERE.
    const disposition = dispositionFor(verdict, this.profile, caseObj.tier, caseObj.valueUsd);
    rec.disposition = disposition;
    delete rec.appealedBy;
    if (disposition.route === 'human_review') {
      rec.reviewState = 'queued';
    } else {
      delete rec.reviewState;
    }

    // --- webhook fan-out --------------------------------------------------------
    for (const handler of this.verdictHandlers) {
      const eventVerdict = structuredClone(verdict);
      let event: VerdictWebhookEvent;
      if (this.webhookSecret !== undefined) {
        const signed = signVerdictWebhook(eventVerdict, this.webhookSecret);
        event = { verdict: eventVerdict, payload: signed.payload, signature: signed.signature };
      } else {
        event = { verdict: eventVerdict, payload: canonicalize(eventVerdict) };
      }
      await handler(event);
    }
    if (disposition.route === 'human_review') {
      await this.emitEscalation({ mandateHash: rec.mandateHash, caseId, verdict, disposition });
    }
    return structuredClone(verdict);
  }

  // --- settlement directive + sandbox application -------------------------------

  /**
   * Build the pure handoff for a customer-hosted settlement executor. This
   * performs every finality, review-state, case-binding and exact-verdict
   * check used by sandbox settlement, but it performs no I/O and moves no
   * funds. Production integrations should apply the returned directive only
   * after independently rebuilding it in their own trust boundary.
   */
  prepareSettlement(verdict: FinalVerdict): SettlementDirective {
    if (verdict.final !== true) {
      throw new EscalatedVerdictError(
        verdict.caseId,
        (verdict as { quality?: { escalationReason?: string } }).quality?.escalationReason,
      );
    }
    const mandateHash = this.caseToMandate.get(verdict.caseId);
    const rec = mandateHash !== undefined ? this.records.get(mandateHash) : undefined;
    if (rec !== undefined) {
      if (rec.reviewState === 'queued' || rec.reviewState === 'appealed') {
        throw new PendingReviewError(verdict.caseId, rec.reviewState);
      }
      if (rec.reviewState === 'resolved' && verdict.humanReview === undefined) {
        throw new ProtectionStateError(
          `case ${verdict.caseId} was resolved by human review — prepare the human-reviewed verdict ` +
            '(getRecord(ref).verdict), not the superseded AI verdict',
        );
      }
    }
    if (rec?.caseObject !== undefined) {
      assertExecutableVerdict(verdict, rec.caseObject.decisionSpace);
    }
    if (rec?.verdict === undefined || rec.caseObject === undefined) {
      throw new ProtectionStateError(`case ${verdict.caseId} has no decision recorded by this client`);
    }
    const expectedSha256 = sha256Hex(canonicalize(rec.verdict));
    const receivedSha256 = sha256Hex(canonicalize(verdict));
    if (expectedSha256 !== receivedSha256) {
      throw new VerdictMismatchError(verdict.caseId, expectedSha256, receivedSha256);
    }
    return buildSettlementDirective(rec.mandate, rec.caseObject, verdict);
  }

  /**
   * Execute a FINAL verdict on the sandbox escrow (payout branch + bond
   * economics). Compile-time `FinalVerdict` only; at runtime the core
   * `assertExecutableVerdict` guard re-checks the verdict against the
   * disputed case's pre-committed decision space (final, not escalated,
   * ruling in-space, no attack-severity injection flags unless the verdict
   * is human-reviewed) BEFORE the escrow moves money — a cast can no longer
   * smuggle a non-executable verdict through. `SandboxEscrow.settle`
   * applies the same guard against the escrow branch vocabulary as defence
   * in depth.
   *
   * Human-review holds (review policy): while the record's reviewState is
   * 'queued' (human_review disposition — including a CLEAN above-threshold
   * final under 'required_above_value') or 'appealed', settle throws
   * {@link PendingReviewError}; `resolveHumanReview` lifts the hold by
   * producing the human-reviewed verdict, which is then the ONLY verdict
   * this record settles on.
   */
  settle(verdict: FinalVerdict): EscrowRecord {
    if (this.mode !== 'sandbox') throw new LiveModeError('settle()');
    const settlementDirective = this.prepareSettlement(verdict);
    const mandateHash = this.caseToMandate.get(verdict.caseId);
    const rec = mandateHash !== undefined ? this.records.get(mandateHash) : undefined;
    if (rec === undefined || rec.caseObject === undefined) {
      throw new ProtectionStateError(`case ${verdict.caseId} has no decision recorded by this client`);
    }
    const escrowRec = this.escrow.settle(verdict);
    rec.rounds.push({
      number: rec.rounds.length + 1,
      caseObject: structuredClone(rec.caseObject),
      verdict: structuredClone(verdict),
      settlementDirective: structuredClone(settlementDirective),
      escrow: structuredClone(escrowRec),
    });
    if (verdict.ruling.kind === 'redo') {
      rec.status = 'redo';
      rec.currentDeadlineUnixMs = verdict.ruling.newDeadlineUnixMs;
      delete rec.manifest;
      delete rec.manifestHash;
      delete rec.manifestCommitment;
      delete rec.caseObject;
      delete rec.verdict;
      delete rec.disposition;
      delete rec.reviewState;
      delete rec.appealedBy;
    } else {
      rec.status = 'settled';
    }
    return escrowRec;
  }

  // --- human escalation (review policy) -------------------------------------------

  /**
   * A party invokes its optional_appeal right on a FINAL verdict: valid only
   * while the record's disposition is 'appealable' (mode 'optional_appeal')
   * and the record is not settled. Marks reviewState 'appealed' (trigger
   * 'party_appeal'), BLOCKS settle() until `resolveHumanReview`, and fires
   * `onEscalation` handlers. Appeal-window/bond mechanics are DRR territory
   * (DRR Rule 26) — the SDK records the signed policy but does not yet
   * clock-enforce the appeal window or collect the appeal Bond.
   */
  async appeal(ref: ProtectRef, by: 'requester' | 'worker'): Promise<EscalationDisposition> {
    if (by !== 'requester' && by !== 'worker') {
      throw new TypeError(`appeal by must be 'requester' or 'worker', got ${String(by)}`);
    }
    const rec = this.resolve(ref);
    if (rec.status === 'settled') {
      throw new ProtectionStateError(`protection ${rec.mandateHash} is settled — nothing left to appeal`);
    }
    if (rec.disposition?.route !== 'appealable' || rec.verdict === undefined || rec.caseObject === undefined) {
      throw new ProtectionStateError(
        `protection ${rec.mandateHash} is not appealable (disposition ${rec.disposition?.route ?? 'none'}, ` +
          `mode ${rec.disposition?.mode ?? 'unresolved'}) — appeal() needs a final verdict under 'optional_appeal'`,
      );
    }
    const disposition: EscalationDisposition = {
      route: 'human_review',
      trigger: 'party_appeal',
      mode: rec.disposition.mode,
    };
    rec.disposition = disposition;
    rec.reviewState = 'appealed';
    rec.appealedBy = by;
    await this.emitEscalation({
      mandateHash: rec.mandateHash,
      caseId: rec.caseObject.caseId,
      verdict: rec.verdict,
      disposition,
    });
    return disposition;
  }

  /**
   * A human reviewer resolves a case that is 'queued' or 'appealed': the
   * ruling is validated against the case's PRE-COMMITTED decision space
   * (the bench is bound by the same verdict-oracle invariant as the AI
   * jury — {@link ReviewOutcomeError} on violation), then a NEW final
   * VerdictObject is produced and stored on the record:
   *
   * - `final: true`, `quality.escalated: false` (escalationReason dropped),
   * - the AI jury's votes / injection flags / majority record PRESERVED for
   *   audit,
   * - `humanReview` set (`basis` 'appeal' for appealed cases, 'quality_gate'
   *   otherwise) — the audit marker that satisfies the core gate's
   *   attack-flag check without any opt-out.
   *
   * settle() then works on the returned verdict. The escalated/superseded AI
   * verdict itself remains non-executable forever (the invariant).
   */
  resolveHumanReview(ref: ProtectRef, input: ResolveHumanReviewInput): VerdictObject {
    const rec = this.resolve(ref);
    if (typeof input.reviewerRef !== 'string' || input.reviewerRef.length === 0) {
      throw new TypeError('resolveHumanReview: reviewerRef must be a non-empty string');
    }
    // Pending = queued/appealed, or a human_review disposition whose state
    // tracking is absent (defensive). A 'resolved' record is NEVER pending —
    // one bench resolution per verdict.
    const pending =
      rec.reviewState === 'queued' ||
      rec.reviewState === 'appealed' ||
      (rec.reviewState === undefined && rec.disposition?.route === 'human_review');
    if (!pending || rec.verdict === undefined || rec.caseObject === undefined) {
      throw new ProtectionStateError(
        `protection ${rec.mandateHash} has no pending human review ` +
          `(reviewState ${rec.reviewState ?? 'none'}, disposition ${rec.disposition?.route ?? 'none'})`,
      );
    }
    const problems = validateOutcome(input.ruling, rec.caseObject.decisionSpace, 'ruling');
    if (problems.length > 0) throw new ReviewOutcomeError(problems);

    const basis: 'appeal' | 'quality_gate' = rec.reviewState === 'appealed' ? 'appeal' : 'quality_gate';
    const ai = rec.verdict;
    const quality: VerdictObject['quality'] = {
      majority: ai.quality.majority,
      swapFlipRate: ai.quality.swapFlipRate,
      injectionFlags: [...ai.quality.injectionFlags],
      escalated: false,
      ...(ai.quality.excludedSeats !== undefined ? { excludedSeats: ai.quality.excludedSeats.map((e) => ({ ...e })) } : {}),
    };
    const reviewed: VerdictObject = {
      ...ai,
      ruling: structuredClone(input.ruling),
      final: true,
      votes: ai.votes, // the AI jury's record is preserved verbatim for audit
      quality,
      humanReview: {
        reviewerRef: input.reviewerRef,
        decidedAtUnixMs: input.decidedAtUnixMs ?? Date.now(),
        basis,
      },
    };
    rec.verdict = structuredClone(reviewed);
    rec.reviewState = 'resolved';
    return structuredClone(reviewed);
  }

  private async emitEscalation(event: EscalationEvent): Promise<void> {
    for (const handler of this.escalationHandlers) {
      await handler(event);
    }
  }

  // --- webhooks -------------------------------------------------------------------

  /**
   * Register a verdict webhook handler for the sandbox path: invoked (and
   * awaited) with the signed canonical payload after every dispute()
   * adjudication. Returns an unsubscribe function.
   */
  onVerdict(handler: VerdictWebhookHandler): () => void {
    this.verdictHandlers.add(handler);
    return () => this.verdictHandlers.delete(handler);
  }

  /**
   * Register a human-escalation handler (like onVerdict): invoked (and
   * awaited) whenever a disposition routes a case to 'human_review' —
   * a quality-gate / required_above_value routing computed by dispute(), or
   * a party appeal via appeal(). Returns an unsubscribe function.
   */
  onEscalation(handler: EscalationHandler): () => void {
    this.escalationHandlers.add(handler);
    return () => this.escalationHandlers.delete(handler);
  }

  // --- introspection ----------------------------------------------------------------

  /** Full lifecycle record for a protection (throws on unknown refs). */
  getRecord(ref: ProtectRef): ProtectionRecord {
    return structuredClone(this.resolve(ref));
  }

  private resolve(ref: ProtectRef): ProtectionRecord {
    const hash = typeof ref === 'string' ? ref : ref.mandateHash;
    const rec = this.records.get(hash);
    if (rec === undefined) throw new UnknownProtectionError(hash);
    return rec;
  }
}

/** One deterministic MockProvider per distinct providerId (docket parity). */
function buildMockProviderMap(seats: JurySeatSpec[]): Map<string, InferenceProvider> {
  const providers = new Map<string, InferenceProvider>();
  for (const seat of seats) {
    if (!providers.has(seat.providerId)) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  return providers;
}
