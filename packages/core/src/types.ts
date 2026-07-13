/**
 * Edict core types — the canonical, rail-neutral schemas.
 *
 * These types are the coordination contract for the whole system (core coordination rules).
 * The arbiter pipeline only ever sees a `CaseObject` plus sealed evidence; rails
 * plug in through `RailAdapter`; inference operators plug in through
 * `InferenceProvider`. Nothing in this file may assume a specific settlement
 * rail, chain, or inference vendor.
 */

// ---------------------------------------------------------------------------
// Rulings & tiers
// ---------------------------------------------------------------------------

/**
 * The closed ruling vocabulary. Payout branches are pre-committed at escrow
 * funding time; the arbiter can only select among them (non-custodial
 * invariant). Mirrors the NEAR Agent Market vocabulary for M2 compatibility.
 */
export type Ruling =
  | { kind: 'requester_wins' }
  | { kind: 'worker_wins' }
  | { kind: 'split'; requesterBps: number } // 0..10_000, remainder to worker
  | { kind: 'redo'; newDeadlineUnixMs: number };

/** The four pre-committed settlement payout branches. */
export type EscrowRulingKind = 'requester_wins' | 'worker_wins' | 'split' | 'redo';

/**
 * What the jury is allowed to decide — committed at case-opening time, the
 * arbiter can only select within it. Custody separation is enforced
 * independently:
 *
 * - `escrow_branches`  — fixed requester/worker/split/redo payout branches.
 * - `categorical`      — a closed label set, e.g. market resolution YES/NO/INVALID.
 *                        `invalidOutcome`, when present, names which member of
 *                        `outcomes` is the "invalid / void" branch.
 * - `bounded_scalar`   — a numeric quantum in [min, max], e.g. insurance payout.
 */
export type DecisionSpace =
  | { kind: 'escrow_branches'; permitted: EscrowRulingKind[] }
  | { kind: 'categorical'; outcomes: string[]; invalidOutcome?: string }
  | { kind: 'bounded_scalar'; min: number; max: number; unit: string };

/**
 * A decision within a DecisionSpace. The unchanged 4-branch `Ruling` shape is
 * valid only for `escrow_branches` spaces; check membership with
 * `validateOutcome(outcome, space)` from ./validate.ts.
 *
 * Canonical outcome strings used by execution digests:
 * - escrow (as today): `"requester_wins" | "worker_wins" | "split:<bps>" | "redo:<newDeadlineUnixMs>"`
 * - categorical:       `"outcome:<label>"`
 * - scalar:            `"quantum:<value>"` where `<value>` is the canonical JSON
 *                      number encoding (ES2015+ shortest round-trip, i.e.
 *                      `JSON.stringify(value)`).
 *
 * The current on-chain contracts implement only the four escrow forms.
 * Categorical and scalar outcomes require separate executors.
 */
export type Outcome =
  | Ruling                                          // valid only for escrow_branches spaces
  | { kind: 'categorical'; outcome: string }
  | { kind: 'scalar'; value: number };

/**
 * Case shapes sharing the two-party structure (see CaseObject role mapping):
 * - `bilateral`          — classic order/delivery dispute.
 * - `public_resolution`  — a bonded challenge to a proposed public resolution.
 * - `claim`              — a claim against a pool/underwriter.
 */
export type CaseType = 'bilateral' | 'public_resolution' | 'claim';

/** Whether the proceedings/verdict are sealed to the parties or public. */
export type Publicity = 'sealed' | 'public';

/** Value tiers drive jury size, bonds, windows and human escalation (canonical value bands). */
export type ValueTier = 'A' | 'B' | 'C'; // A: <$10, B: $10–1k, C: $1k–100k

/**
 * Human escalation policy (review-policy invariant — signed profile election):
 * humans are a CONFIGURABLE SAFETY VALVE, not a default mode. The mode is a
 * profile-level election governing where an escalated/uncertain verdict
 * routes NEXT — never whether it can settle (escalated verdicts remain
 * non-executable regardless of mode):
 *
 * - `off`                  — rules/AI only; escalations fall back to the
 *                            venue's pre-committed programmatic fallback.
 * - `optional_appeal`      — AI verdicts stand; a party may pay to appeal a
 *                            final verdict to the human bench within the
 *                            acceptance window.
 * - `quality_gate`         — quality-gate trips (no majority, swap
 *                            inconsistency, low confidence, injection
 *                            attack, …) route to human review.
 * - `required_above_value` — cases at or above the elected USD threshold
 *                            (profile `humanEscalation.thresholdUsd`,
 *                            default: the tier-C floor, $1000) ALWAYS route
 *                            to human review — tier-agnostic; even clean
 *                            final verdicts wait for review before
 *                            settlement.
 *
 * Tier defaults when a profile does not elect: A → off, B → optional_appeal,
 * C → quality_gate. The policy mapping lives in @edict/sdk
 * (`effectiveEscalationMode`, `dispositionFor`); the arbiter stays
 * policy-free and only emits the triggers.
 */
export type HumanEscalationMode = 'off' | 'optional_appeal' | 'quality_gate' | 'required_above_value';

/**
 * Who staffs a human review when the escalation policy routes a case to one
 * (review policy / profile schema): Edict's own bench, a panel the
 * customer constitutes, or an external institutional arbitrator.
 */
export type ReviewerPool = 'edict_bench' | 'customer_panel' | 'external_arbitrator';

/**
 * The closed vocabulary of events that can route a case to the human bench
 * (review-policy invariant). All but `party_appeal` are derived from signals the
 * arbiter already emits on `VerdictObject.quality` (see
 * `triggerFromVerdict` in @edict/sdk); `party_appeal` is raised by a party
 * invoking its appeal right under `optional_appeal`.
 */
export type EscalationTrigger =
  | 'no_majority'
  | 'insufficient_attested_seats'
  | 'swap_inconsistency'
  | 'low_confidence'
  | 'injection_attack'
  | 'out_of_policy_evidence'
  | 'party_appeal';

/** Legal enforcement tiers (enforcement policy). */
export type EnforcementTier = 'E0' | 'E1' | 'E2' | 'E3';

/**
 * Custody vocabulary used by case records and evaluation fixtures. Production
 * adapters accept only externally controlled settlement modes.
 */
export type CustodyMode = 'M1_native_escrow' | 'M2_external_escrow' | 'M3_chain_signatures' | 'M4_no_custody';

/** Production modes in which Edict never holds funds or custody credentials. */
export type ExternalCustodyMode = 'M2_external_escrow' | 'M4_no_custody';

/** The only permitted controllers of a production settlement integration. */
export type FundsController = 'requester_wallet' | 'customer_contract' | 'payment_rail';

/** Pre-committed result if no valid final determination arrives in time. */
export type LivenessFallback =
  | 'refund_requester'
  | 'release_worker'
  | 'split_50_50'
  | 'controller_resolution';

/** Confidentiality scope selected for a settlement integration. */
export type ConfidentialSettlementMode =
  | 'confidential_transport'
  | 'confidential_settlement';

/** Whether an unavailable confidential route may expose settlement publicly. */
export type ConfidentialityFallback = 'fail_closed' | 'allow_public_settlement';

/**
 * Optional signed privacy boundary. Omission means public settlement.
 * `capabilitySha256` pins the adapter/deployment evidence that substantiates
 * the privacy claim; the separate policy hash pins who may disclose what.
 */
export interface SettlementConfidentiality {
  mode: ConfidentialSettlementMode;
  capabilitySha256: string;
  disclosurePolicySha256: string;
  fallback: ConfidentialityFallback;
  /** Required only when the parties expressly permit a public downgrade. */
  publicFallbackAdapterRef?: string;
}

/**
 * Signed settlement boundary for edict-om-2. `adapterRef` identifies the
 * customer-hosted wallet, contract or rail integration that controls funds.
 * There is deliberately no Edict controller value.
 */
export interface SettlementBinding {
  custodyMode: ExternalCustodyMode;
  fundsController: FundsController;
  adapterRef: string;
  edictOperatorCanTransfer: false;
  edictOperatorCanFreeze: false;
  edictOperatorIsRequiredSigner: false;
  /** Duration after the dispute record closes before the fallback becomes available. */
  resolutionTimeoutMs: number;
  livenessFallback: LivenessFallback;
  /** Omitted for public settlement. Confidential modes are capability-bound. */
  confidentiality?: SettlementConfidentiality;
}

// ---------------------------------------------------------------------------
// Legal profile (legal-policy schema)
// ---------------------------------------------------------------------------

export type GoverningLaw = 'england_wales' | 'new_york' | 'delaware' | 'singapore' | 'difc' | 'swiss_substantive';
/** Launch-configured E2 seats. Omission is product scope, not a legal conclusion; expansion requires local review. */
export type Seat = 'london' | 'new_york' | 'singapore' | 'difc';

export interface LegalProfile {
  governingLaw: GoverningLaw;
  seat: Seat;
  /** Rules body incorporated by reference, e.g. "edict-drr-v0.1". */
  rules: string;
  enforcementTier: EnforcementTier;
}

/** A versioned document pinned by its sha256 and, optionally, a retrieval URI. */
export interface ContentAddressedDocumentRef {
  id: string;
  version: string;
  /** Lowercase sha256 of the exact referenced bytes. */
  sha256: string;
  uri?: string;
}

/** Human-routing policy that is signed as part of the Legal Policy. */
export interface HumanEscalationPolicy {
  mode: HumanEscalationMode;
  triggers?: EscalationTrigger[];
  perTier?: Partial<Record<ValueTier, HumanEscalationMode>>;
  thresholdUsd?: number;
  appealWindowMs?: number;
  appealBondMultiplier?: number;
  reviewerPool?: ReviewerPool;
}

export type E2ImplementationTiming = 'implement_then_arbitrate' | 'hold_pending_award';

/**
 * How much identity/legal assurance an order elects:
 *
 * - wallet_native: wallet/account signatures identify the parties; technical
 *   settlement only, with no Edict KYB requirement.
 * - rail_verified: the payment rail vouches for opaque account identities;
 *   Edict does not repeat the rail's onboarding.
 * - enterprise_legal: named legal principals and scoped agent delegation are
 *   required for contract/arbitration-backed use.
 */
export type AssuranceMode = 'wallet_native' | 'rail_verified' | 'enterprise_legal';

/**
 * The complete off-chain legal election for an order. The order mandate signs
 * a hash of this object, which in turn pins the exact Rules bytes and any
 * customer policy pack. Keeping it separate from `LegalProfile` preserves the
 * compact routing fields while making every legally operative option explicit.
 */
export interface LegalPolicy {
  version: 'edict-legal-policy-1';
  policyId: string;
  assuranceMode: AssuranceMode;
  rules: ContentAddressedDocumentRef;
  challengeWindowMs: number;
  humanEscalation: HumanEscalationPolicy;
  e2ImplementationTiming: E2ImplementationTiming;
  customerPolicyPack?: ContentAddressedDocumentRef;
  /** Disclosed destination for the non-counterparty half of a forfeited Bond. */
  bondRemovalDestination: 'protocol_burn' | 'protection_pool';
}

/** The compact content reference embedded in and signed with an OrderMandate. */
export interface LegalPolicyRef extends ContentAddressedDocumentRef {
  id: string;
}

/** A normalized customer term that Edict may treat as a rule of decision. */
export interface CustomerRuleOfDecision {
  id: string;
  statement: string;
  /** Clause identifiers in the customer's source terms supporting this rule. */
  sourceClauseIds: string[];
  appliesToCriterionIds?: string[];
}

/**
 * Customer T&Cs are admitted through this signed, versioned policy module.
 * Raw terms remain evidence; only the normalized rules below become judicial
 * instructions, after hash verification and injection screening.
 */
export interface CustomerPolicyPack {
  version: 'edict-customer-policy-1';
  policyId: string;
  sourceTerms: ContentAddressedDocumentRef[];
  rulesOfDecision: CustomerRuleOfDecision[];
  /**
   * Fixed safe hierarchy, highest precedence first. Customer policy may
   * supplement the order and Edict DRR, but cannot displace mandatory law or
   * override the transaction-specific order mandate.
   */
  orderOfPrecedence: ['mandatory_law', 'order_mandate', 'customer_policy', 'edict_drr'];
}

export type AuthorityAction = 'protect' | 'deliver' | 'accept' | 'dispute' | 'settle' | 'appeal';

/** Reference carried with a party; the credential plaintext may stay sealed. */
export interface AuthorityCredentialRef {
  credentialId: string;
  sha256: string;
  issuer: string;
  revocationRegistry: string;
  uri?: string;
}

/**
 * Principal-to-agent delegation credential. KYB identifies the principal;
 * this separate credential proves the named agent key has authority, within a
 * bounded scope and validity period, subject to an externally checked
 * signature and revocation registry.
 */
export interface AgentAuthorityCredential {
  version: 'edict-authority-1';
  credentialId: string;
  principalKybRef: string;
  agentId: string;
  scope: {
    actions: AuthorityAction[];
    maxValueUsd?: number;
    rails?: string[];
    currencies?: string[];
  };
  validFromUnixMs: number;
  validUntilUnixMs: number;
  issuer: { id: string; keyId: string };
  revocation: { registry: string; nonce: string };
  proof: {
    scheme: 'eip712' | 'nep413' | 'jws' | 'cose';
    signature: string;
  };
}

// ---------------------------------------------------------------------------
// Parties, evidence, case
// ---------------------------------------------------------------------------

export interface PartyRef {
  /** Rail-scoped agent identifier (wallet, agent-id, DID). */
  agentId: string;
  /**
   * Reference to the KYB record of the agent's legal principal (never inline
   * PII). Optional for wallet-native and rail-verified settlement; validation
   * requires it for E2/E3 legal enforcement. New SDK E1 orders also require it
   * because E1 is available only through the enterprise-legal assurance mode.
   */
  principalKybRef?: string;
  /**
   * Principal-to-agent delegation pinned to an authenticated credential.
   * Omission means the signing wallet/account acts for itself. Enterprise-legal
   * profiles require it; wallet-native profiles do not.
   */
  authorityCredentialRef?: AuthorityCredentialRef;
  /** Optional ERC-8004 identity pointer (chainId + registry + tokenId). */
  erc8004Ref?: string;
}

export type EvidenceKind =
  | 'order_mandate'        // signed order incl. machine-readable acceptance criteria
  | 'legal_policy'         // signed policy object: rules hash, windows, escalation, E2 timing
  | 'customer_policy_pack' // normalized customer T&Cs module, pre-committed before funding
  | 'authority_credential' // principal-to-agent delegation credential
  | 'delivery_manifest'    // provider-signed artifact hashes + format claims
  | 'delivery_receipt'     // client-signed receipt (receipt ≠ acceptance)
  | 'interaction_log_head' // hash-chain head, anchored
  | 'payment_receipt'      // x402 / AP2 mandate / on-chain settlement proof
  | 'party_submission'     // free-form pleading (adversarial by construction)
  | 'zktls_proof'
  | 'tee_runtime_attestation'
  | 'c2pa_manifest';

export interface EvidenceCommitment {
  kind: EvidenceKind;
  /** sha256 of the canonical bytes; content itself stays sealed off-chain. */
  sha256: string;
  /**
   * Who committed it. `third_party` is a bonded third-party submission —
   * valid ONLY on `public_resolution` cases (enforced in validation).
   */
  submitter: 'requester' | 'worker' | 'venue' | 'system' | 'third_party';
  /** Where the sealed blob lives (vault URI, arweave tx, ipfs cid). */
  uri?: string;
  /** Weight guidance per evidence policy burden defaults. */
  authenticated: boolean;
}

/**
 * The canonical case. The two-party structure is KEPT across every caseType;
 * the roles map as follows:
 *
 * | caseType            | requester                                   | worker                                          |
 * |---------------------|---------------------------------------------|-------------------------------------------------|
 * | `bilateral`         | the ordering party (opened / paid)          | the delivering party (delivered / was paid)     |
 * | `public_resolution` | the bonded CHALLENGER disputing the outcome | the PROPOSER defending the proposed resolution  |
 * | `claim`             | the CLAIMANT asserting the claim            | the POOL / UNDERWRITER the claim is made against|
 */
export interface CaseObject {
  caseId: string;                    // uuid v4
  caseType: CaseType;                // role mapping above
  publicity: Publicity;              // public_resolution SHOULD be 'public' (warn-level rule)
  requester: PartyRef;               // see role mapping above
  worker: PartyRef;                  // see role mapping above
  orderMandateHash: string;          // sha256; MUST match an order_mandate commitment
  /** Present on edict-om-2 cases; MUST match a legal_policy commitment. */
  legalPolicyHash?: string;
  deliveryManifestHash?: string;     // absent => non-delivery claim path
  evidence: EvidenceCommitment[];
  valueUsd: number;
  tier: ValueTier;
  custodyMode: CustodyMode;
  /** Opaque rail pointer, e.g. { rail: "near-agent-market", jobId } — adapters own its meaning. */
  railRef: { rail: string; [k: string]: unknown };
  legalProfile: LegalProfile;
  openedAtUnixMs: number;
  /** What the jury may decide — pre-committed at case opening; the jury selects WITHIN this space ONLY. */
  decisionSpace: DecisionSpace;
  /** Append-only adjudication round context. Absent only on legacy cases. */
  round?: {
    number: number;
    effectiveDeadlineUnixMs: number;
    priorCaseId?: string;
    priorVerdictSha256?: string;
  };
}

// ---------------------------------------------------------------------------
// Jury, proofs, verdict
// ---------------------------------------------------------------------------

export interface JurySeatSpec {
  /** Stable seat id, e.g. "nearai:glm-5.1". */
  seatId: string;
  providerId: string;   // registered InferenceProvider id
  modelId: string;      // exact pinned model identifier at the provider
  modelFamily: string;  // e.g. "glm" | "qwen" | "gpt-oss" — disjointness is enforced across seats
}

/** Per-inference proof normalised across providers (provider abstraction). */
export interface ProviderProof {
  providerId: string;
  modelId: string;
  requestSha256: string;
  responseSha256: string;
  /**
   * Provider-native signature. The signed envelope depends on the scheme:
   * `ecdsa_secp256k1_eth` / `ed25519` / `ecdsa_p256` sign
   * `${modelId}:${requestSha256}:${responseSha256}`;
   * `ecdsa_secp256k1_eth_bodyhashes` (Phala/RedPill ACI legacy signature
   * profile) signs `${requestSha256}:${responseSha256}` — the model is bound
   * through the request bytes themselves.
   */
  signature?: string;
  signatureScheme?:
    | 'ecdsa_secp256k1_eth'
    | 'ecdsa_secp256k1_eth_bodyhashes'
    | 'ecdsa_p256'
    | 'ed25519'
    | 'none_mock';
  signingAddress?: string;
  /** Attestation bundle reference — archived AT INFERENCE TIME (caches expire). */
  attestationRef?: string;
  fetchedAtUnixMs: number;
}

export interface JuryVote {
  seat: JurySeatSpec;
  /** Two passes with party positions swapped; both recorded. */
  passes: Array<{
    orientation: 'requester_first' | 'worker_first';
    /**
     * The pass's decision. Like VerdictObject.ruling, a pass must lie within
     * the case's decisionSpace, whatever its kind.
     */
    ruling: Outcome;
    reasoningSha256: string;
    proof: ProviderProof;
  }>;
  /**
   * Seat is swap-consistent iff both passes yield the same outcome (escrow:
   * same ruling kind, split within tolerance; categorical: same label;
   * scalar: values within the pipeline's scalar swap tolerance).
   */
  swapConsistent: boolean;
}

export interface VerdictObject {
  caseId: string;
  /**
   * The decided outcome — MUST lie within the case's `decisionSpace` (check
   * with `validateOutcome`). Escrow cases carry the unchanged 4-branch Ruling
   * shape; categorical/scalar spaces carry the corresponding Outcome variants.
   */
  ruling: Outcome;
  /**
   * Execution gate. `true` ONLY when the quorum was met and no escalation
   * gate tripped — i.e. the pipeline stands behind the ruling as executable.
   * Escalated verdicts (quality.escalated) carry an advisory fallback ruling
   * but are NEVER executable: they MUST have final=false and be routed up a
   * tier instead of settled.
   */
  final: boolean;
  /** sha256 of the full structured reasoning document (parties get plaintext; registry gets redacted). */
  reasoningSha256: string;
  votes: JuryVote[];
  /** Aggregate quality gates. */
  quality: {
    majority: 'unanimous' | 'majority' | 'none';
    swapFlipRate: number;        // 0..1 across seats
    injectionFlags: string[];    // non-empty => was screened/escalated
    escalated: boolean;          // true => routed up a tier instead of final
    escalationReason?: string;
    /**
     * Seats excluded from the majority calculation because their inference
     * proof could not be attested (attestation execution gate). Recorded for
     * auditability; when exclusions drop counted seats below quorum the
     * verdict escalates with escalationReason 'insufficient_attested_seats'.
     */
    excludedSeats?: Array<{ seatId: string; reason: string }>;
  };
  legalProfile: LegalProfile;
  issuedAtUnixMs: number;
  /** Optional E2 layer: reference to the adopted arbitral award document. */
  awardRef?: { arbitratorId: string; awardSha256: string; seat: Seat };
  /**
   * THE audit marker distinguishing bench-resolved verdicts from purely
   * AI-adjudicated ones. Set ONLY when a human reviewer resolved the case
   * (quality-gate routing, mandatory high-value review, or a party appeal —
   * review-policy invariant). A human-reviewed verdict preserves the AI jury's
   * votes/quality record for auditability while carrying the reviewer's
   * ruling; `assertExecutableVerdict` accepts attack-severity injection
   * flags on such verdicts because a human has inspected the contaminated
   * record and stands behind the outcome.
   */
  humanReview?: {
    /** Who resolved it (bench member / reviewer identity ref — never inline PII). */
    reviewerRef: string;
    decidedAtUnixMs: number;
    /** Why a human was in the loop: a quality-gate/mandatory routing or a party appeal. */
    basis: 'quality_gate' | 'appeal';
  };
}

/**
 * A verdict that is executable on a rail. The type-level `final: true`
 * refinement means escalated / advisory verdicts (final=false) can never be
 * turned into a `SettlementDirective` — narrowing must happen (and be
 * checked) at the boundary, e.g. `if (v.final) buildSettlementDirective(...)`.
 */
export type FinalVerdict = VerdictObject & { final: true };

/** The money instruction a customer-controlled adapter may apply. */
export type SettlementAction =
  | { kind: 'allocate'; requesterBps: number; workerBps: number }
  | { kind: 'hold_for_redo'; newDeadlineUnixMs: number }
  | { kind: 'record_only' };

/**
 * Pure, signed-outcome-derived data. Creating or publishing this object does
 * not move funds; the customer, requester wallet or payment rail validates and
 * applies it in infrastructure that Edict cannot access or administer.
 */
export interface SettlementDirective {
  version: 'edict-settlement-1';
  caseId: string;
  orderMandateHash: string;
  verdictSha256: string;
  issuedAtUnixMs: number;
  settlement: SettlementBinding;
  railRef: { rail: string; [k: string]: unknown };
  outcome: Outcome;
  action: SettlementAction;
}

// ---------------------------------------------------------------------------
// Pluggable layers
// ---------------------------------------------------------------------------

/**
 * Attested inference provider . Implementations: NEAR AI Cloud,
 * Phala Cloud, self-hosted dstack node, mock. Jury placement rules — enforced
 * by the pipeline, not by providers: no providerId may hold a majority of
 * seats; Tier C spans ≥3 providers.
 */
export interface InferenceProvider {
  id: string;
  /** OpenAI-compatible chat completion at temperature 0 with byte-exact request/response capture. */
  complete(req: {
    modelId: string;
    messages: Array<{ role: 'system' | 'user'; content: string }>;
    maxTokens?: number;
  }): Promise<{
    text: string;
    requestSha256: string;
    responseSha256: string;
    raw: unknown;
  }>;
  /** Fetch + archive the per-inference proof immediately (provider caches expire). */
  getProof(completionRef: unknown): Promise<ProviderProof>;
}

/**
 * Customer-hosted rail adapter (rail-adapter boundary): intake, signed custody binding
 * and settlement-directive preparation. It contains no adjudication logic and
 * MUST run in infrastructure controlled by the customer, requester or payment
 * rail. Edict never receives its keys, withdrawal permissions or balances.
 */
export interface RailAdapter {
  rail: string;
  custodyMode: ExternalCustodyMode;
  fundsController: FundsController;
  /** Normalise a rail-native dispute into the canonical case object. */
  intake(railNative: unknown): Promise<CaseObject>;
  /**
   * Prepare the pure directive the adapter owner may apply. This method MUST
   * NOT transfer funds, sign a custody transaction or call a withdrawal API.
   *
   * Accepts ONLY `FinalVerdict` (final=true): escalated / advisory verdicts
   * are never actionable. Compile-time narrowing is NOT enough: adapters
   * MUST call `assertExecutableVerdict(verdict, case.decisionSpace)` (from
   * @edict/core) before preparing a directive. It re-checks that the verdict
   * is final, not escalated, that the ruling lies within the case's
   * pre-committed decision space, and that no attack-severity injection
   * flags ride on the verdict. The customer-controlled settlement component
   * independently verifies the mandate, verdict hash and directive before it
   * moves its own funds.
   */
  prepareSettlement(verdict: FinalVerdict, caseObject: CaseObject): Promise<SettlementDirective>;
}

// ---------------------------------------------------------------------------
// Order mandate (evidence-mandate SDK implements signing; spec C5)
// ---------------------------------------------------------------------------

export interface AcceptanceCriterion {
  id: string;                       // "AC-1"
  statement: string;                // human/machine-readable requirement
  machineCheck?: {                  // optional deterministic check
    kind: 'hash_equals' | 'schema_valid' | 'deadline_before' | 'contains' | 'custom';
    params: Record<string, unknown>;
  };
}

export interface OrderMandate {
  /** v2 adds a signed Legal Policy and authority-credential commitments. */
  version: 'edict-om-1' | 'edict-om-2';
  requester: PartyRef;
  worker: PartyRef;
  description: string;
  acceptanceCriteria: AcceptanceCriterion[];
  priceUsd: number;
  currency: { asset: string; rail: string };
  deadlineUnixMs: number;
  acceptanceWindowMs: number;       // auto-release after this post-delivery window
  legalProfile: LegalProfile;
  /** Required for edict-om-2; omitted only on legacy edict-om-1 records. */
  legalPolicy?: LegalPolicy;
  /** What the jury may decide (same type the CaseObject carries). */
  decisionSpace: DecisionSpace;
  /** Required for edict-om-2: signed proof that Edict has no custody role. */
  settlement?: SettlementBinding;
  /** Qualified code deference: enumerated Material Adverse Exception events (DRR Rule 33). */
  maeEvents: string[];
  nonce: string;
}
