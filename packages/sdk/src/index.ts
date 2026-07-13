/**
 * @edict/sdk — the seven-lines-to-integrate developer surface (SDK integration contract).
 *
 * createEdict → protect → deliver → accept | dispute → directive, with a
 * ProtectionProfile committed once, a pre-commitment lint gate, a simulated
 * sandbox ledger, and signed verdict webhooks. Production funds stay with the
 * customer-hosted wallet or rail. See examples/quickstart.ts.
 */

export {
  EdictClient,
  createEdict,
  isFinalVerdict,
  type AcceptResult,
  type CreateEdictOptions,
  type DeliverInput,
  type DeliverResult,
  type DisputeInput,
  type EdictMode,
  type EscalationEvent,
  type EscalationHandler,
  type ExtraEvidenceInput,
  type ProtectOrderInput,
  type ProtectPaymentInput,
  type ProtectRef,
  type ProtectResult,
  type ProtectionRecord,
  type ProtectionRound,
  type ProtectionStatus,
  type ResolveHumanReviewInput,
  type ReviewState,
  type VerdictWebhookEvent,
  type VerdictWebhookHandler,
} from './client.js';

export {
  SANDBOX_MOCK_SEATS,
  assertValidProfile,
  defaultProfile,
  profileHash,
  validateProfile,
  type ProtectionProfile,
} from './profile.js';

// Human escalation policy mapping (review policy): profile-elected routing of
// escalated/uncertain verdicts. The arbiter stays policy-free — it emits the
// triggers; THIS module maps them; surfaces render the disposition.
export {
  DEFAULT_REQUIRED_ABOVE_VALUE_THRESHOLD_USD,
  dispositionFor,
  effectiveEscalationMode,
  requiredAboveValueApplies,
  triggerFromVerdict,
  type EscalationDisposition,
  type EscalationRoute,
} from './escalation.js';

// Convenience re-exports of the core policy vocabulary.
export type { AssuranceMode, EscalationTrigger, HumanEscalationMode, ReviewerPool } from '@edict/core';
export type {
  ConfidentialityFallback,
  ConfidentialSettlementMode,
  ExternalCustodyMode,
  FundsController,
  LivenessFallback,
  SettlementConfidentiality,
  SettlementAction,
  SettlementBinding,
  SettlementDirective,
} from '@edict/core';

export {
  buildSettlementDirective,
  allocateAtomicSettlement,
  customerContractSettlement,
  customerContractSettlementFromManifest,
  nearIntentsSettlementFromManifest,
  type CustomerContractSettlementOptions,
  type ManifestSettlementOptions,
  type AtomicSettlementAllocation,
  verifySettlementDirective,
} from './settlement.js';

// Cross-chain transport. NEAR Intents supplies quotes, liquidity and wallet
// authentication; Edict's customer-approved keyless account remains the only
// component allowed to bind funds to an order or allocate a ruling.
export {
  CONFIDENTIAL_INTENTS_ADAPTER_VERSION,
  CONFIDENTIAL_INTENTS_CAPABILITY_VERSION,
  INTENTS_SETTLEMENT_ADAPTER_VERSION,
  NEAR_INTENTS_FUNDING_VERSION,
  NEAR_INTENTS_MAINNET_CONTRACT,
  NEAR_INTENTS_ROUTE_VERSION,
  ONE_CLICK_API_BASE_URL,
  acceptAction,
  assertClaimPayoutQuoteFields,
  assertProtectionFundingQuoteFields,
  assertSignedClaimPayoutQuote,
  assertSignedProtectionFundingQuote,
  buildClaimPayoutQuote,
  buildDisputeBondTransfer,
  buildPartyAuthCall,
  buildProtectionFundingQuote,
  buildProtectionFundingTransfer,
  confidentialIntentsAdapterRef,
  confidentialIntentsAuditScopeDigest,
  confidentialIntentsCapabilityDigest,
  confidentialIntentsSettlementBinding,
  controllerFallbackAction,
  deliverAction,
  disputeBondAtomic,
  nearIntentsAdapterRef,
  nearIntentsRoute,
  nearIntentsRouteDigest,
  nearIntentsSettlementBinding,
  openHeldDisputeAction,
  validateConfidentialIntentsCapability,
  verifiedFundingReceipt,
  type ClaimPayoutQuoteInput,
  type ConfidentialIntentsAuditEvidence,
  type ConfidentialIntentsBindingOptions,
  type ConfidentialIntentsCapability,
  type EdictRulingKind,
  type IntentsAuthCallIntent,
  type IntentsControllerRuling,
  type IntentsFundOrder,
  type IntentsPartyAction,
  type IntentsTransferIntent,
  type NearIntentsBindingOptions,
  type NearIntentsRoute,
  type OneClickExecutionStatus,
  type OneClickQuoteRequest,
  type OneClickQuoteResponse,
  type ProtectionFundingQuoteInput,
  type VerifiedFundingReceipt,
} from '@edict/near-intents';

export {
  verifyIntentsRuntime,
  type IntentsDeploymentManifest,
  type IntentsRuntimeStatus,
} from '@edict/near-deployer';

// Canonical user-facing terminology shared by the console, MCP server, and apps.
export {
  TERMINOLOGY,
  lifecycleState,
  plainOutcome,
  statusColor,
  userFacing,
  LIFECYCLE_STATES,
  type LifecycleRecordLike,
  type LifecycleState,
} from './terminology.js';

// Preset protection policies (product interface): Basic / Standard /
// High Assurance, each hash-committed with a canonical profileHash.
export {
  PRESETS,
  basicProfile,
  enterpriseLegalProfile,
  highAssuranceProfile,
  presetByKey,
  standardProfile,
  type PresetDefinition,
  type PresetKey,
} from './presets.js';

export {
  DEFAULT_DISPUTE_BOND_FRACTION,
  SandboxEscrow,
  type EscrowPartyRole,
  type EscrowRecord,
  type EscrowRound,
  type EscrowSettlement,
  type EscrowStatus,
  type SandboxEscrowOptions,
} from './sandbox.js';

export {
  WEBHOOK_SIGNATURE_PREFIX,
  signVerdictWebhook,
  verifyVerdictWebhook,
  type SignedVerdictWebhook,
} from './webhook.js';

// THE executable-verdict gate (re-exported from @edict/core): both settle()
// surfaces call it; RailAdapter implementations MUST call it too.
export { assertExecutableVerdict, ExecutableVerdictError } from '@edict/core';

export {
  EscalatedVerdictError,
  CustodyBoundaryError,
  EscrowStateError,
  EvidenceMismatchError,
  InsufficientFundsError,
  LintGateError,
  LiveModeError,
  PendingReviewError,
  ProfileValidationError,
  ProtectionStateError,
  ReviewOutcomeError,
  UnknownProtectionError,
  UnsupportedRulingError,
  VerdictMismatchError,
} from './errors.js';
