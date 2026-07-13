/**
 * Production structural validation for the canonical CaseObject (zero deps).
 *
 * TypeScript types vanish at runtime; case objects arrive as untrusted JSON
 * from rails, CLIs and harnesses. `validateCaseObject` re-checks every field
 * against the canonical schema in ./types.ts:
 *
 * - closed enums for every enum type (ruling kinds, tiers, custody modes,
 *   governing law, seat, evidence kinds, submitters, case types, publicity,
 *   decision-space kinds),
 * - format checks (uuid v4 caseId, 64-hex sha256 hashes),
 * - tier/value consistency (A: <$10, B: $10–1k, C: $1k–100k; shared band
 *   edges are accepted in either adjacent tier),
 * - decisionSpace structural checks (escrow permitted non-empty + deduped;
 *   categorical ≥2 distinct outcomes, invalidOutcome ∈ outcomes when present;
 *   bounded_scalar min < max, non-empty unit),
 * - conditional KYB: PartyRef.principalKybRef is required only at E2/E3;
 *   wallet-native and rail-verified bilateral settlement remains pseudonymous,
 * - `third_party` evidence submitters are valid only on public_resolution cases,
 * - sane timestamps (unix ms between 2000-01-01 and 3000-01-01),
 * - unknown-key rejection on CaseObject and every nested closed object
 *   (PartyRef, EvidenceCommitment, LegalProfile, DecisionSpace). `railRef` is
 *   open by design (rail adapters own its extra keys) but must carry `rail`,
 * - evidence cross-references: an order_mandate commitment matching
 *   orderMandateHash MUST exist (and a delivery_manifest commitment matching
 *   deliveryManifestHash, when present).
 *
 * Error strings are formatted `<path>: <message>` (e.g.
 * `case.evidence[2].kind: must be one of: …`) so callers can split them back
 * into structured issues. WARNING-level rules (SHOULD, not MUST — e.g.
 * public_resolution cases SHOULD have publicity 'public') are reported in the
 * same array prefixed `warn:`; they never flip `ok` to false.
 */

import type {
  AuthorityAction,
  AssuranceMode,
  CaseType,
  ConfidentialityFallback,
  ConfidentialSettlementMode,
  CustodyMode,
  DecisionSpace,
  EnforcementTier,
  EscalationTrigger,
  EscrowRulingKind,
  EvidenceCommitment,
  EvidenceKind,
  ExternalCustodyMode,
  FinalVerdict,
  FundsController,
  GoverningLaw,
  HumanEscalationMode,
  LivenessFallback,
  OrderMandate,
  Publicity,
  ReviewerPool,
  Ruling,
  Seat,
  SettlementBinding,
  ValueTier,
  VerdictObject,
} from './types.js';

// ---------------------------------------------------------------------------
// Closed vocabularies (values mirrored from the type unions in ./types.ts)
// ---------------------------------------------------------------------------

export const RULING_KINDS: ReadonlyArray<Ruling['kind']> = ['requester_wins', 'worker_wins', 'split', 'redo'];
export const VALUE_TIERS: ReadonlyArray<ValueTier> = ['A', 'B', 'C'];
export const ENFORCEMENT_TIERS: ReadonlyArray<EnforcementTier> = ['E0', 'E1', 'E2', 'E3'];
export const CUSTODY_MODES: ReadonlyArray<CustodyMode> = [
  'M1_native_escrow', 'M2_external_escrow', 'M3_chain_signatures', 'M4_no_custody',
];
export const EXTERNAL_CUSTODY_MODES: ReadonlyArray<ExternalCustodyMode> = [
  'M2_external_escrow', 'M4_no_custody',
];
export const FUNDS_CONTROLLERS: ReadonlyArray<FundsController> = [
  'requester_wallet', 'customer_contract', 'payment_rail',
];
export const LIVENESS_FALLBACKS: ReadonlyArray<LivenessFallback> = [
  'refund_requester', 'release_worker', 'split_50_50', 'controller_resolution',
];
export const CONFIDENTIAL_SETTLEMENT_MODES: ReadonlyArray<ConfidentialSettlementMode> = [
  'confidential_transport', 'confidential_settlement',
];
export const CONFIDENTIALITY_FALLBACKS: ReadonlyArray<ConfidentialityFallback> = [
  'fail_closed', 'allow_public_settlement',
];
export const GOVERNING_LAWS: ReadonlyArray<GoverningLaw> = [
  'england_wales', 'new_york', 'delaware', 'singapore', 'difc', 'swiss_substantive',
];
export const SEATS: ReadonlyArray<Seat> = ['london', 'new_york', 'singapore', 'difc'];
export const EVIDENCE_KINDS: ReadonlyArray<EvidenceKind> = [
  'order_mandate', 'legal_policy', 'customer_policy_pack', 'authority_credential',
  'delivery_manifest', 'delivery_receipt', 'interaction_log_head',
  'payment_receipt', 'party_submission', 'zktls_proof', 'tee_runtime_attestation', 'c2pa_manifest',
];
export const EVIDENCE_SUBMITTERS: ReadonlyArray<EvidenceCommitment['submitter']> = [
  'requester', 'worker', 'venue', 'system', 'third_party',
];
export const CASE_TYPES: ReadonlyArray<CaseType> = ['bilateral', 'public_resolution', 'claim'];
export const PUBLICITIES: ReadonlyArray<Publicity> = ['sealed', 'public'];
export const DECISION_SPACE_KINDS: ReadonlyArray<DecisionSpace['kind']> = [
  'escrow_branches', 'categorical', 'bounded_scalar',
];
export const HUMAN_ESCALATION_MODES: ReadonlyArray<HumanEscalationMode> = [
  'off', 'optional_appeal', 'quality_gate', 'required_above_value',
];
export const REVIEWER_POOLS: ReadonlyArray<ReviewerPool> = [
  'edict_bench', 'customer_panel', 'external_arbitrator',
];
export const ESCALATION_TRIGGERS: ReadonlyArray<EscalationTrigger> = [
  'no_majority', 'insufficient_attested_seats', 'swap_inconsistency', 'low_confidence',
  'injection_attack', 'out_of_policy_evidence', 'party_appeal',
];
export const AUTHORITY_ACTIONS: ReadonlyArray<AuthorityAction> = [
  'protect', 'deliver', 'accept', 'dispute', 'settle', 'appeal',
];
export const E2_IMPLEMENTATION_TIMINGS = ['implement_then_arbitrate', 'hold_pending_award'] as const;
export const BOND_REMOVAL_DESTINATIONS = ['protocol_burn', 'protection_pool'] as const;
export const ASSURANCE_MODES: ReadonlyArray<AssuranceMode> = [
  'wallet_native', 'rail_verified', 'enterprise_legal',
];

export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
export const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Sane unix-ms bounds: 2000-01-01T00:00:00Z .. 3000-01-01T00:00:00Z. */
const UNIX_MS_MIN = 946_684_800_000;
const UNIX_MS_MAX = 32_503_680_000_000;

// Closed key sets (unknown keys rejected).
const CASE_KEYS = [
  'caseId', 'caseType', 'publicity', 'requester', 'worker', 'orderMandateHash', 'legalPolicyHash', 'deliveryManifestHash',
  'evidence', 'valueUsd', 'tier', 'custodyMode', 'railRef', 'legalProfile', 'openedAtUnixMs', 'decisionSpace',
  'round',
] as const;
const PARTY_KEYS = ['agentId', 'principalKybRef', 'authorityCredentialRef', 'erc8004Ref'] as const;
const COMMITMENT_KEYS = ['kind', 'sha256', 'submitter', 'uri', 'authenticated'] as const;
const LEGAL_PROFILE_KEYS = ['governingLaw', 'seat', 'rules', 'enforcementTier'] as const;
const CONTENT_REF_KEYS = ['id', 'version', 'sha256', 'uri'] as const;
const AUTHORITY_REF_KEYS = ['credentialId', 'sha256', 'issuer', 'revocationRegistry', 'uri'] as const;
const SETTLEMENT_BINDING_KEYS = [
  'custodyMode', 'fundsController', 'adapterRef', 'edictOperatorCanTransfer',
  'edictOperatorCanFreeze', 'edictOperatorIsRequiredSigner',
  'resolutionTimeoutMs', 'livenessFallback', 'confidentiality',
] as const;
const SETTLEMENT_CONFIDENTIALITY_KEYS = [
  'mode', 'capabilitySha256', 'disclosurePolicySha256', 'fallback',
  'publicFallbackAdapterRef',
] as const;
const HUMAN_ESCALATION_POLICY_KEYS = [
  'mode', 'triggers', 'perTier', 'thresholdUsd', 'appealWindowMs', 'appealBondMultiplier', 'reviewerPool',
] as const;
const LEGAL_POLICY_KEYS = [
  'version', 'policyId', 'assuranceMode', 'rules', 'challengeWindowMs', 'humanEscalation', 'e2ImplementationTiming',
  'customerPolicyPack', 'bondRemovalDestination',
] as const;
const CUSTOMER_POLICY_KEYS = ['version', 'policyId', 'sourceTerms', 'rulesOfDecision', 'orderOfPrecedence'] as const;
const CUSTOMER_RULE_KEYS = ['id', 'statement', 'sourceClauseIds', 'appliesToCriterionIds'] as const;
const POLICY_PRECEDENCE = ['mandatory_law', 'order_mandate', 'customer_policy', 'edict_drr'] as const;
const ROUND_KEYS = ['number', 'effectiveDeadlineUnixMs', 'priorCaseId', 'priorVerdictSha256'] as const;
const ORDER_MANDATE_KEYS = [
  'version', 'requester', 'worker', 'description', 'acceptanceCriteria', 'priceUsd', 'currency',
  'deadlineUnixMs', 'acceptanceWindowMs', 'legalProfile', 'legalPolicy', 'decisionSpace', 'settlement',
  'maeEvents', 'nonce',
] as const;
const ACCEPTANCE_CRITERION_KEYS = ['id', 'statement', 'machineCheck'] as const;
const MACHINE_CHECK_KEYS = ['kind', 'params'] as const;
const MACHINE_CHECK_KINDS = ['hash_equals', 'schema_valid', 'deadline_before', 'contains', 'custom'] as const;
const CURRENCY_KEYS = ['asset', 'rail'] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function rejectUnknownKeys(
  errors: string[],
  v: Record<string, unknown>,
  path: string,
  allowed: readonly string[],
): void {
  for (const k of Object.keys(v)) {
    if (!allowed.includes(k)) errors.push(`${path}.${k}: unknown key — this object has a closed field set`);
  }
}

function checkString(
  errors: string[],
  v: unknown,
  path: string,
  opts?: { re?: RegExp; hint?: string },
): v is string {
  if (typeof v !== 'string' || v.length === 0) {
    errors.push(`${path}: must be a non-empty string`);
    return false;
  }
  if (opts?.re && !opts.re.test(v)) {
    errors.push(`${path}: does not match expected format${opts.hint ? ` (${opts.hint})` : ''}`);
    return false;
  }
  return true;
}

function checkEnum<T extends string>(
  errors: string[],
  v: unknown,
  path: string,
  allowed: ReadonlyArray<T>,
): v is T {
  if (typeof v !== 'string' || !(allowed as ReadonlyArray<string>).includes(v)) {
    errors.push(`${path}: must be one of: ${allowed.join(', ')}`);
    return false;
  }
  return true;
}

function checkUnixMs(errors: string[], v: unknown, path: string): v is number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) {
    errors.push(`${path}: must be an integer unix-ms timestamp`);
    return false;
  }
  if (v < UNIX_MS_MIN || v > UNIX_MS_MAX) {
    errors.push(`${path}: timestamp ${v} is outside the sane range [${UNIX_MS_MIN}, ${UNIX_MS_MAX}] (unix ms, 2000–3000 AD)`);
    return false;
  }
  return true;
}

function checkPositiveInteger(errors: string[], v: unknown, path: string): v is number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v <= 0) {
    errors.push(`${path}: must be a positive integer`);
    return false;
  }
  return true;
}

/** Validate a versioned sha256 content reference. */
export function validateContentAddressedDocumentRef(v: unknown, path = 'documentRef'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (ContentAddressedDocumentRef)`];
  rejectUnknownKeys(errors, v, path, CONTENT_REF_KEYS);
  checkString(errors, v.id, `${path}.id`);
  checkString(errors, v.version, `${path}.version`);
  checkString(errors, v.sha256, `${path}.sha256`, { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  if (v.uri !== undefined) checkString(errors, v.uri, `${path}.uri`);
  return errors;
}

/** Validate the compact principal-to-agent credential reference. */
export function validateAuthorityCredentialRef(v: unknown, path = 'authorityCredentialRef'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (AuthorityCredentialRef)`];
  rejectUnknownKeys(errors, v, path, AUTHORITY_REF_KEYS);
  checkString(errors, v.credentialId, `${path}.credentialId`);
  checkString(errors, v.sha256, `${path}.sha256`, { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  checkString(errors, v.issuer, `${path}.issuer`);
  checkString(errors, v.revocationRegistry, `${path}.revocationRegistry`);
  if (v.uri !== undefined) checkString(errors, v.uri, `${path}.uri`);
  return errors;
}

/** Validate a capability-bound confidential-settlement election. */
export function validateSettlementConfidentiality(v: unknown, path = 'confidentiality'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (SettlementConfidentiality)`];
  rejectUnknownKeys(errors, v, path, SETTLEMENT_CONFIDENTIALITY_KEYS);
  checkEnum(errors, v.mode, `${path}.mode`, CONFIDENTIAL_SETTLEMENT_MODES);
  if (checkString(errors, v.capabilitySha256, `${path}.capabilitySha256`, {
    re: SHA256_HEX_RE,
    hint: 'sha256 hex',
  }) && /^0+$/.test(v.capabilitySha256)) {
    errors.push(`${path}.capabilitySha256: zero hash cannot substantiate a confidentiality claim`);
  }
  if (checkString(errors, v.disclosurePolicySha256, `${path}.disclosurePolicySha256`, {
    re: SHA256_HEX_RE,
    hint: 'sha256 hex',
  }) && /^0+$/.test(v.disclosurePolicySha256)) {
    errors.push(`${path}.disclosurePolicySha256: zero hash cannot identify a disclosure policy`);
  }
  checkEnum(errors, v.fallback, `${path}.fallback`, CONFIDENTIALITY_FALLBACKS);
  if (v.fallback === 'allow_public_settlement') {
    checkString(errors, v.publicFallbackAdapterRef, `${path}.publicFallbackAdapterRef`);
  } else if (v.publicFallbackAdapterRef !== undefined) {
    errors.push(`${path}.publicFallbackAdapterRef: must be absent when privacy fallback is fail_closed`);
  }
  return errors;
}

/** Validate the signed, customer-controlled settlement boundary. */
export function validateSettlementBinding(v: unknown, path = 'settlement'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (SettlementBinding)`];
  rejectUnknownKeys(errors, v, path, SETTLEMENT_BINDING_KEYS);
  checkEnum(errors, v.custodyMode, `${path}.custodyMode`, EXTERNAL_CUSTODY_MODES);
  checkEnum(errors, v.fundsController, `${path}.fundsController`, FUNDS_CONTROLLERS);
  checkString(errors, v.adapterRef, `${path}.adapterRef`);
  if (v.edictOperatorCanTransfer !== false) {
    errors.push(`${path}.edictOperatorCanTransfer: must be false (Edict cannot hold or transfer customer funds)`);
  }
  if (v.edictOperatorCanFreeze !== false) {
    errors.push(`${path}.edictOperatorCanFreeze: must be false (Edict cannot freeze customer funds)`);
  }
  if (v.edictOperatorIsRequiredSigner !== false) {
    errors.push(`${path}.edictOperatorIsRequiredSigner: must be false (Edict cannot be a required settlement signer)`);
  }
  checkPositiveInteger(errors, v.resolutionTimeoutMs, `${path}.resolutionTimeoutMs`);
  checkEnum(errors, v.livenessFallback, `${path}.livenessFallback`, LIVENESS_FALLBACKS);
  if (v.confidentiality !== undefined) {
    errors.push(...validateSettlementConfidentiality(v.confidentiality, `${path}.confidentiality`));
  }
  return errors;
}

/** Runtime type guard for integrations accepting untrusted settlement JSON. */
export function isSettlementBinding(v: unknown): v is SettlementBinding {
  return validateSettlementBinding(v).length === 0;
}

/** Validate the signed human-escalation election shared by profiles and Legal Policies. */
export function validateHumanEscalationPolicy(v: unknown, path = 'humanEscalation'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (HumanEscalationPolicy)`];
  rejectUnknownKeys(errors, v, path, HUMAN_ESCALATION_POLICY_KEYS);
  checkEnum(errors, v.mode, `${path}.mode`, HUMAN_ESCALATION_MODES);
  if (v.triggers !== undefined) {
    if (!Array.isArray(v.triggers) || v.triggers.length === 0) {
      errors.push(`${path}.triggers: must be a non-empty array when present`);
    } else {
      const seen = new Set<string>();
      v.triggers.forEach((trigger, i) => {
        if (checkEnum(errors, trigger, `${path}.triggers[${i}]`, ESCALATION_TRIGGERS)) {
          if (seen.has(trigger)) errors.push(`${path}.triggers[${i}]: duplicate trigger '${trigger}'`);
          seen.add(trigger);
        }
      });
    }
  }
  if (v.perTier !== undefined) {
    if (!isRecord(v.perTier)) errors.push(`${path}.perTier: must map value tiers to modes`);
    else {
      rejectUnknownKeys(errors, v.perTier, `${path}.perTier`, VALUE_TIERS);
      for (const tier of VALUE_TIERS) {
        if (v.perTier[tier] !== undefined) {
          checkEnum(errors, v.perTier[tier], `${path}.perTier.${tier}`, HUMAN_ESCALATION_MODES);
        }
      }
    }
  }
  if (v.thresholdUsd !== undefined &&
      (typeof v.thresholdUsd !== 'number' || !Number.isFinite(v.thresholdUsd) || v.thresholdUsd <= 0)) {
    errors.push(`${path}.thresholdUsd: must be a positive finite number`);
  }
  if (v.appealWindowMs !== undefined) checkPositiveInteger(errors, v.appealWindowMs, `${path}.appealWindowMs`);
  if (v.appealBondMultiplier !== undefined &&
      (typeof v.appealBondMultiplier !== 'number' || !Number.isFinite(v.appealBondMultiplier) || v.appealBondMultiplier <= 0)) {
    errors.push(`${path}.appealBondMultiplier: must be a positive finite number`);
  }
  if (v.reviewerPool !== undefined) checkEnum(errors, v.reviewerPool, `${path}.reviewerPool`, REVIEWER_POOLS);
  return errors;
}

/** Validate the policy object whose canonical hash is signed by edict-om-2. */
export function validateLegalPolicy(v: unknown, path = 'legalPolicy'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (LegalPolicy)`];
  rejectUnknownKeys(errors, v, path, LEGAL_POLICY_KEYS);
  if (v.version !== 'edict-legal-policy-1') errors.push(`${path}.version: must be 'edict-legal-policy-1'`);
  checkString(errors, v.policyId, `${path}.policyId`);
  checkEnum(errors, v.assuranceMode, `${path}.assuranceMode`, ASSURANCE_MODES);
  errors.push(...validateContentAddressedDocumentRef(v.rules, `${path}.rules`));
  if (checkPositiveInteger(errors, v.challengeWindowMs, `${path}.challengeWindowMs`) &&
      (v.challengeWindowMs < 2 * 60 * 60 * 1_000 || v.challengeWindowMs > 24 * 60 * 60 * 1_000)) {
    errors.push(`${path}.challengeWindowMs: must be between 2 and 24 hours`);
  }
  errors.push(...validateHumanEscalationPolicy(v.humanEscalation, `${path}.humanEscalation`));
  checkEnum(errors, v.e2ImplementationTiming, `${path}.e2ImplementationTiming`, E2_IMPLEMENTATION_TIMINGS);
  if (v.customerPolicyPack !== undefined) {
    errors.push(...validateContentAddressedDocumentRef(v.customerPolicyPack, `${path}.customerPolicyPack`));
  }
  checkEnum(errors, v.bondRemovalDestination, `${path}.bondRemovalDestination`, BOND_REMOVAL_DESTINATIONS);
  return errors;
}

/** Validate the structured customer T&Cs module before it can become instructions. */
export function validateCustomerPolicyPack(v: unknown, path = 'customerPolicyPack'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (CustomerPolicyPack)`];
  rejectUnknownKeys(errors, v, path, CUSTOMER_POLICY_KEYS);
  if (v.version !== 'edict-customer-policy-1') errors.push(`${path}.version: must be 'edict-customer-policy-1'`);
  checkString(errors, v.policyId, `${path}.policyId`);
  if (!Array.isArray(v.sourceTerms) || v.sourceTerms.length === 0) {
    errors.push(`${path}.sourceTerms: must be a non-empty array of content-addressed terms`);
  } else {
    v.sourceTerms.forEach((ref, i) => errors.push(...validateContentAddressedDocumentRef(ref, `${path}.sourceTerms[${i}]`)));
  }
  if (!Array.isArray(v.rulesOfDecision) || v.rulesOfDecision.length === 0) {
    errors.push(`${path}.rulesOfDecision: must be a non-empty array`);
  } else {
    const ids = new Set<string>();
    v.rulesOfDecision.forEach((rule, i) => {
      const rulePath = `${path}.rulesOfDecision[${i}]`;
      if (!isRecord(rule)) {
        errors.push(`${rulePath}: must be an object`);
        return;
      }
      rejectUnknownKeys(errors, rule, rulePath, CUSTOMER_RULE_KEYS);
      if (checkString(errors, rule.id, `${rulePath}.id`)) {
        if (ids.has(rule.id)) errors.push(`${rulePath}.id: duplicate rule id '${rule.id}'`);
        ids.add(rule.id);
      }
      checkString(errors, rule.statement, `${rulePath}.statement`);
      for (const field of ['sourceClauseIds', 'appliesToCriterionIds'] as const) {
        const value = rule[field];
        if (field === 'appliesToCriterionIds' && value === undefined) continue;
        if (!Array.isArray(value) || value.length === 0) errors.push(`${rulePath}.${field}: must be a non-empty string array`);
        else value.forEach((item, j) => checkString(errors, item, `${rulePath}.${field}[${j}]`));
      }
    });
  }
  if (!Array.isArray(v.orderOfPrecedence)) {
    errors.push(`${path}.orderOfPrecedence: must be an array`);
  } else {
    const precedence = v.orderOfPrecedence;
    const seen = new Set<string>();
    precedence.forEach((item, i) => {
      if (checkEnum(errors, item, `${path}.orderOfPrecedence[${i}]`, POLICY_PRECEDENCE)) {
        if (seen.has(item)) errors.push(`${path}.orderOfPrecedence[${i}]: duplicate '${item}'`);
        seen.add(item);
      }
    });
    for (const required of POLICY_PRECEDENCE) {
      if (!seen.has(required)) errors.push(`${path}.orderOfPrecedence: must include '${required}'`);
    }
    if (
      precedence.length === POLICY_PRECEDENCE.length &&
      !POLICY_PRECEDENCE.every((item, i) => precedence[i] === item)
    ) {
      errors.push(
        `${path}.orderOfPrecedence: must use the fixed safe hierarchy ${POLICY_PRECEDENCE.join(' > ')}`,
      );
    }
  }
  return errors;
}

/** Structural validation for a full authority credential before external signature verification. */
export function validateAgentAuthorityCredential(v: unknown, path = 'authorityCredential'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object (AgentAuthorityCredential)`];
  rejectUnknownKeys(errors, v, path, [
    'version', 'credentialId', 'principalKybRef', 'agentId', 'scope', 'validFromUnixMs', 'validUntilUnixMs',
    'issuer', 'revocation', 'proof',
  ]);
  if (v.version !== 'edict-authority-1') errors.push(`${path}.version: must be 'edict-authority-1'`);
  checkString(errors, v.credentialId, `${path}.credentialId`);
  checkString(errors, v.principalKybRef, `${path}.principalKybRef`);
  checkString(errors, v.agentId, `${path}.agentId`);
  if (!isRecord(v.scope)) errors.push(`${path}.scope: must be an object`);
  else {
    rejectUnknownKeys(errors, v.scope, `${path}.scope`, ['actions', 'maxValueUsd', 'rails', 'currencies']);
    if (!Array.isArray(v.scope.actions) || v.scope.actions.length === 0) errors.push(`${path}.scope.actions: must be non-empty`);
    else v.scope.actions.forEach((a, i) => checkEnum(errors, a, `${path}.scope.actions[${i}]`, AUTHORITY_ACTIONS));
    if (v.scope.maxValueUsd !== undefined &&
        (typeof v.scope.maxValueUsd !== 'number' || !Number.isFinite(v.scope.maxValueUsd) || v.scope.maxValueUsd <= 0)) {
      errors.push(`${path}.scope.maxValueUsd: must be a positive finite number`);
    }
    for (const key of ['rails', 'currencies'] as const) {
      const value = v.scope[key];
      if (value !== undefined) {
        if (!Array.isArray(value) || value.length === 0) errors.push(`${path}.scope.${key}: must be a non-empty string array`);
        else value.forEach((item, i) => checkString(errors, item, `${path}.scope.${key}[${i}]`));
      }
    }
  }
  const fromOk = checkUnixMs(errors, v.validFromUnixMs, `${path}.validFromUnixMs`);
  const untilOk = checkUnixMs(errors, v.validUntilUnixMs, `${path}.validUntilUnixMs`);
  if (fromOk && untilOk && (v.validUntilUnixMs as number) <= (v.validFromUnixMs as number)) {
    errors.push(`${path}.validUntilUnixMs: must be later than validFromUnixMs`);
  }
  for (const [key, keys] of [
    ['issuer', ['id', 'keyId']],
    ['revocation', ['registry', 'nonce']],
    ['proof', ['scheme', 'signature']],
  ] as const) {
    const value: unknown = v[key as string];
    if (!isRecord(value)) errors.push(`${path}.${key}: must be an object`);
    else {
      rejectUnknownKeys(errors, value, `${path}.${key}`, keys);
      for (const field of keys) checkString(errors, value[field], `${path}.${key}.${field}`);
      if (key === 'proof') checkEnum(errors, value.scheme, `${path}.proof.scheme`, ['eip712', 'nep413', 'jws', 'cose']);
    }
  }
  return errors;
}

/**
 * Canonical value bands. Shared band edges (exactly $10 / $1k / $100k) are
 * accepted in either adjacent tier. Empty result = outside all bands.
 */
export function tierForValueUsd(valueUsd: number): ValueTier[] {
  const tiers: ValueTier[] = [];
  if (valueUsd < 10) tiers.push('A');
  if (valueUsd >= 10 && valueUsd <= 1_000) tiers.push('B');
  if (valueUsd >= 1_000 && valueUsd <= 100_000) tiers.push('C');
  return tiers;
}

// ---------------------------------------------------------------------------
// Ruling validation (closed vocabulary + parameter bounds)
// ---------------------------------------------------------------------------

/**
 * Validate an unknown value against the canonical `Ruling` shape. Returns
 * `<path>: <message>` error strings ([] = valid). Checks the closed kind
 * vocabulary, split requesterBps in 0..10000 (integer), redo
 * newDeadlineUnixMs sanity, and rejects unknown keys.
 */
export function validateRuling(v: unknown, path = 'ruling'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object ({ kind, ... })`];
  if (!checkEnum(errors, v.kind, `${path}.kind`, RULING_KINDS)) return errors;
  const kind = v.kind as Ruling['kind'];
  if (kind === 'split') {
    rejectUnknownKeys(errors, v, path, ['kind', 'requesterBps']);
    const bps = v.requesterBps;
    if (typeof bps !== 'number' || !Number.isInteger(bps) || bps < 0 || bps > 10_000) {
      errors.push(`${path}.requesterBps: must be an integer in 0..10000 (basis points to the requester)`);
    }
  } else if (kind === 'redo') {
    rejectUnknownKeys(errors, v, path, ['kind', 'newDeadlineUnixMs']);
    checkUnixMs(errors, v.newDeadlineUnixMs, `${path}.newDeadlineUnixMs`);
  } else {
    rejectUnknownKeys(errors, v, path, ['kind']);
  }
  return errors;
}

// ---------------------------------------------------------------------------
// DecisionSpace validation (structural) + outcome-in-space checker
// ---------------------------------------------------------------------------

/**
 * Validate an unknown value against the canonical `DecisionSpace` shape.
 * Returns `<path>: <message>` error strings ([] = valid):
 *
 * - `escrow_branches`: `permitted` non-empty, closed escrow kinds, deduplicated.
 * - `categorical`: ≥2 distinct non-empty outcome labels, no duplicates;
 *   `invalidOutcome` (when present) must be one of `outcomes`.
 * - `bounded_scalar`: finite `min` < finite `max`, non-empty `unit`.
 * - unknown keys rejected per kind.
 */
export function validateDecisionSpace(v: unknown, path = 'decisionSpace'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object ({ kind, ... })`];
  if (!checkEnum(errors, v.kind, `${path}.kind`, DECISION_SPACE_KINDS)) return errors;
  const kind = v.kind as DecisionSpace['kind'];

  if (kind === 'escrow_branches') {
    rejectUnknownKeys(errors, v, path, ['kind', 'permitted']);
    if (!Array.isArray(v.permitted) || v.permitted.length === 0) {
      errors.push(`${path}.permitted: must be a non-empty array of escrow ruling kinds (the jury needs a branch to select)`);
    } else {
      const seen = new Set<string>();
      v.permitted.forEach((k, i) => {
        if (checkEnum(errors, k, `${path}.permitted[${i}]`, RULING_KINDS)) {
          if (seen.has(k)) errors.push(`${path}.permitted[${i}]: duplicate ruling kind '${k}'`);
          seen.add(k);
        }
      });
      if (seen.size === 1 && seen.has('redo')) {
        errors.push(`${path}.permitted: must include at least one terminal ruling in addition to redo`);
      }
    }
  } else if (kind === 'categorical') {
    rejectUnknownKeys(errors, v, path, ['kind', 'outcomes', 'invalidOutcome']);
    let outcomes: string[] | null = null;
    if (!Array.isArray(v.outcomes)) {
      errors.push(`${path}.outcomes: must be an array of outcome labels`);
    } else {
      const seen = new Set<string>();
      let allStrings = true;
      v.outcomes.forEach((o, i) => {
        if (typeof o !== 'string' || o.length === 0) {
          errors.push(`${path}.outcomes[${i}]: must be a non-empty string`);
          allStrings = false;
        } else {
          if (seen.has(o)) errors.push(`${path}.outcomes[${i}]: duplicate outcome '${o}'`);
          seen.add(o);
        }
      });
      if (seen.size < 2) {
        errors.push(`${path}.outcomes: must contain at least 2 distinct outcomes`);
      }
      if (allStrings) outcomes = v.outcomes as string[];
    }
    if (v.invalidOutcome !== undefined && checkString(errors, v.invalidOutcome, `${path}.invalidOutcome`)) {
      if (outcomes !== null && !outcomes.includes(v.invalidOutcome as string)) {
        errors.push(`${path}.invalidOutcome: '${String(v.invalidOutcome)}' must be one of the declared outcomes`);
      }
    }
  } else { // bounded_scalar
    rejectUnknownKeys(errors, v, path, ['kind', 'min', 'max', 'unit']);
    const minOk = typeof v.min === 'number' && Number.isFinite(v.min);
    const maxOk = typeof v.max === 'number' && Number.isFinite(v.max);
    if (!minOk) errors.push(`${path}.min: must be a finite number`);
    if (!maxOk) errors.push(`${path}.max: must be a finite number`);
    if (minOk && maxOk && (v.min as number) >= (v.max as number)) {
      errors.push(`${path}: min (${String(v.min)}) must be strictly less than max (${String(v.max)})`);
    }
    checkString(errors, v.unit, `${path}.unit`);
  }
  return errors;
}

/** Apply the pre-committed one-redo rule to the outcome space for a case round. */
export function decisionSpaceForRound(space: DecisionSpace, round: 1 | 2): DecisionSpace {
  if (round === 1) return structuredClone(space);
  if (space.kind === 'escrow_branches') {
    const permitted = space.permitted.filter((kind) => kind !== 'redo');
    if (permitted.length === 0) {
      throw new RangeError('round 2 requires at least one pre-committed terminal ruling');
    }
    return { kind: 'escrow_branches', permitted };
  }
  return structuredClone(space);
}

/**
 * Outcome-in-space checker: validate an unknown outcome value against a
 * DecisionSpace. Returns `<path>: <message>` error strings ([] = the outcome
 * is well-formed AND lies within the space):
 *
 * - `escrow_branches`: the outcome must be a well-formed `Ruling` (same
 *   checks as `validateRuling`) whose kind is among `space.permitted`.
 * - `categorical`: `{ kind: 'categorical', outcome }` with `outcome` one of
 *   `space.outcomes` (`invalidOutcome` is a member of `outcomes`, so it is
 *   selectable like any other label).
 * - `bounded_scalar`: `{ kind: 'scalar', value }` with finite `value` in
 *   `[min, max]` (inclusive).
 *
 * A structurally invalid space fails closed: the space errors are returned
 * and the outcome is NOT accepted.
 */
export function validateOutcome(outcome: unknown, space: DecisionSpace, path = 'outcome'): string[] {
  const spaceErrors = validateDecisionSpace(space, 'decisionSpace');
  if (spaceErrors.length > 0) {
    return [`${path}: cannot be checked against a structurally invalid decision space`, ...spaceErrors];
  }
  if (!isRecord(outcome)) return [`${path}: must be an object ({ kind, ... })`];
  const errors: string[] = [];

  switch (space.kind) {
    case 'escrow_branches': {
      const rulingErrors = validateRuling(outcome, path);
      if (rulingErrors.length > 0) return rulingErrors;
      const kind = outcome.kind as EscrowRulingKind;
      if (!space.permitted.includes(kind)) {
        errors.push(`${path}.kind: ruling '${kind}' is not among the permitted escrow branches (${space.permitted.join(', ')})`);
      }
      return errors;
    }
    case 'categorical': {
      if (outcome.kind !== 'categorical') {
        return [`${path}.kind: must be 'categorical' for a categorical decision space, got '${String(outcome.kind)}'`];
      }
      rejectUnknownKeys(errors, outcome, path, ['kind', 'outcome']);
      if (checkString(errors, outcome.outcome, `${path}.outcome`) && !space.outcomes.includes(outcome.outcome as string)) {
        errors.push(`${path}.outcome: '${String(outcome.outcome)}' is not in the decision space outcomes (${space.outcomes.join(', ')})`);
      }
      return errors;
    }
    case 'bounded_scalar': {
      if (outcome.kind !== 'scalar') {
        return [`${path}.kind: must be 'scalar' for a bounded_scalar decision space, got '${String(outcome.kind)}'`];
      }
      rejectUnknownKeys(errors, outcome, path, ['kind', 'value']);
      const value = outcome.value;
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        errors.push(`${path}.value: must be a finite number`);
      } else if (value < space.min || value > space.max) {
        errors.push(`${path}.value: ${value} is outside the bounded scalar range [${space.min}, ${space.max}] ${space.unit}`);
      }
      return errors;
    }
  }
}

// ---------------------------------------------------------------------------
// Executable-verdict guard, used everywhere a
// verdict is about to move money)
// ---------------------------------------------------------------------------

/** Thrown by {@link assertExecutableVerdict} when a verdict is not executable. */
export class ExecutableVerdictError extends Error {
  readonly caseId: string;
  readonly problems: string[];
  constructor(caseId: string, problems: string[]) {
    super(
      `verdict for case ${caseId} is not executable:\n- ${problems.join('\n- ')}\n` +
        'escalated / out-of-space / attack-flagged verdicts are never executable; route the case up a tier instead of settling',
    );
    this.name = 'ExecutableVerdictError';
    this.caseId = caseId;
    this.problems = problems;
  }
}

const HUMAN_REVIEW_KEYS = ['reviewerRef', 'decidedAtUnixMs', 'basis'] as const;
const HUMAN_REVIEW_BASES = ['quality_gate', 'appeal'] as const;

/**
 * Structural check of an optional `VerdictObject.humanReview` marker.
 * Returns `<path>: <message>` error strings ([] = well-formed). A marker that
 * fails this check NEVER earns the attack-flag exemption in
 * {@link assertExecutableVerdict} — a junk object cannot impersonate a human
 * reviewer (fails closed).
 */
export function validateHumanReview(v: unknown, path = 'humanReview'): string[] {
  const errors: string[] = [];
  if (!isRecord(v)) return [`${path}: must be an object ({ reviewerRef, decidedAtUnixMs, basis })`];
  rejectUnknownKeys(errors, v, path, HUMAN_REVIEW_KEYS);
  checkString(errors, v.reviewerRef, `${path}.reviewerRef`);
  checkUnixMs(errors, v.decidedAtUnixMs, `${path}.decidedAtUnixMs`);
  checkEnum(errors, v.basis, `${path}.basis`, HUMAN_REVIEW_BASES);
  return errors;
}

/**
 * THE executable-verdict gate. Every component that executes a verdict on a
 * rail (the sandbox and every customer-hosted settlement executor) MUST call
 * this before moving money. It asserts, at runtime, everything the
 * `FinalVerdict` type promises
 * at compile time — plus the quality invariants a cast can smuggle past:
 *
 * - `verdict.final === true`,
 * - `verdict.quality.escalated === false` (a final-but-escalated verdict is
 *   a pipeline bug — fails closed). NOTE: `humanReview` does NOT bypass this:
 *   a human resolution is a NEW verdict (final=true, escalated=false,
 *   humanReview set) — the escalated AI verdict itself stays non-executable
 *   forever, whatever the profile's escalation mode,
 * - the ruling lies within the case's pre-committed decision space
 *   (`validateOutcome` — the verdict-oracle invariant at the money boundary),
 * - `humanReview`, when present, is structurally well-formed
 *   ({@link validateHumanReview}),
 * - NO attack-severity (`attack:`-prefixed) entries in
 *   `quality.injectionFlags`, UNLESS either
 *   (a) a well-formed `humanReview` marker is present — a human reviewer
 *       inspected the contaminated record and issued/confirmed the ruling
 *       (review-policy invariant); the flags stay on the record for audit but no
 *       longer block execution, since the injection risk they guard against
 *       (an attacker steering the AI jury) is answered by the human
 *       resolution itself, or
 *   (b) `opts.allowAttackFlags` is set. Tier A/B verdicts may legitimately
 *       be final with attack flags on the record (the arbiter's gate only
 *       escalates tier C); an executor that accepts that risk without a
 *       human in the loop must opt in EXPLICITLY.
 *
 * Throws {@link ExecutableVerdictError}; on return, `verdict` is narrowed to
 * `FinalVerdict`.
 */
export function assertExecutableVerdict(
  verdict: VerdictObject,
  space: DecisionSpace,
  opts: { allowAttackFlags?: boolean } = {},
): asserts verdict is FinalVerdict {
  const problems: string[] = [];
  if (verdict.final !== true) {
    problems.push(
      `final=${String(verdict.final)} — only final verdicts are executable` +
        (verdict.quality?.escalationReason !== undefined ? ` (escalationReason: ${verdict.quality.escalationReason})` : ''),
    );
  }
  if (verdict.quality?.escalated !== false) {
    problems.push(
      `quality.escalated=${String(verdict.quality?.escalated)} — an escalated (or malformed-quality) verdict is never executable`,
    );
  }
  const outcomeErrors = validateOutcome(verdict.ruling, space, 'ruling');
  problems.push(...outcomeErrors);
  // A structurally valid humanReview marker is the audit trail of a bench
  // resolution; a malformed one is rejected AND earns no exemption below.
  let humanReviewed = false;
  if (verdict.humanReview !== undefined) {
    const reviewErrors = validateHumanReview(verdict.humanReview, 'humanReview');
    problems.push(...reviewErrors);
    humanReviewed = reviewErrors.length === 0;
  }
  if (opts.allowAttackFlags !== true && !humanReviewed) {
    const attackFlags = (verdict.quality?.injectionFlags ?? []).filter((f) => f.startsWith('attack:'));
    if (attackFlags.length > 0) {
      problems.push(
        `quality.injectionFlags carries attack-severity entries (${attackFlags.join(', ')}) — ` +
          'only a human-reviewed verdict (humanReview set) or an explicit allowAttackFlags: true opt-in executes anyway',
      );
    }
  }
  if (problems.length > 0) throw new ExecutableVerdictError(verdict.caseId, problems);
}

// ---------------------------------------------------------------------------
// Nested object validators
// ---------------------------------------------------------------------------

function validatePartyRef(errors: string[], v: unknown, path: string): void {
  if (!isRecord(v)) {
    errors.push(`${path}: must be an object (PartyRef)`);
    return;
  }
  rejectUnknownKeys(errors, v, path, PARTY_KEYS);
  checkString(errors, v.agentId, `${path}.agentId`);
  // The conditional requirement for bilateral E2/E3 cases
  // lives in validateCaseObject where caseType and enforcementTier are known.
  if (v.principalKybRef !== undefined) checkString(errors, v.principalKybRef, `${path}.principalKybRef`);
  if (v.authorityCredentialRef !== undefined) {
    errors.push(...validateAuthorityCredentialRef(v.authorityCredentialRef, `${path}.authorityCredentialRef`));
  }
  if (v.erc8004Ref !== undefined) checkString(errors, v.erc8004Ref, `${path}.erc8004Ref`);
}

function appendEvidenceCommitmentProblems(errors: string[], v: unknown, path: string): void {
  if (!isRecord(v)) {
    errors.push(`${path}: must be an object (EvidenceCommitment)`);
    return;
  }
  rejectUnknownKeys(errors, v, path, COMMITMENT_KEYS);
  checkEnum(errors, v.kind, `${path}.kind`, EVIDENCE_KINDS);
  checkString(errors, v.sha256, `${path}.sha256`, { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  checkEnum(errors, v.submitter, `${path}.submitter`, EVIDENCE_SUBMITTERS);
  if (typeof v.authenticated !== 'boolean') errors.push(`${path}.authenticated: must be a boolean`);
  if (v.uri !== undefined) checkString(errors, v.uri, `${path}.uri`);
}

/** Validate one untrusted evidence-commitment wire object. */
export function validateEvidenceCommitment(v: unknown, path = 'evidenceCommitment'): string[] {
  const errors: string[] = [];
  appendEvidenceCommitmentProblems(errors, v, path);
  return errors;
}

function validateLegalProfile(errors: string[], v: unknown, path: string): void {
  if (!isRecord(v)) {
    errors.push(`${path}: must be an object (LegalProfile)`);
    return;
  }
  rejectUnknownKeys(errors, v, path, LEGAL_PROFILE_KEYS);
  checkEnum(errors, v.governingLaw, `${path}.governingLaw`, GOVERNING_LAWS);
  checkEnum(errors, v.seat, `${path}.seat`, SEATS);
  checkString(errors, v.rules, `${path}.rules`);
  checkEnum(errors, v.enforcementTier, `${path}.enforcementTier`, ENFORCEMENT_TIERS);
}

/** Full closed-schema validation for untrusted order-mandate JSON. */
export function validateOrderMandate(value: unknown, path = 'mandate'): string[] {
  const errors: string[] = [];
  if (!isRecord(value)) return [`${path}: must be a JSON object (OrderMandate)`];
  rejectUnknownKeys(errors, value, path, ORDER_MANDATE_KEYS);
  if (value.version !== 'edict-om-1' && value.version !== 'edict-om-2') {
    errors.push(`${path}.version: must be 'edict-om-1' or 'edict-om-2'`);
  }
  validatePartyRef(errors, value.requester, `${path}.requester`);
  validatePartyRef(errors, value.worker, `${path}.worker`);
  if (isRecord(value.requester) && isRecord(value.worker)
      && typeof value.requester.agentId === 'string' && value.requester.agentId === value.worker.agentId) {
    errors.push(`${path}: requester and worker agentId must differ`);
  }
  checkString(errors, value.description, `${path}.description`);

  const criterionIds = new Set<string>();
  if (!Array.isArray(value.acceptanceCriteria) || value.acceptanceCriteria.length === 0) {
    errors.push(`${path}.acceptanceCriteria: must be a non-empty array`);
  } else {
    value.acceptanceCriteria.forEach((criterion, index) => {
      const criterionPath = `${path}.acceptanceCriteria[${index}]`;
      if (!isRecord(criterion)) {
        errors.push(`${criterionPath}: must be an object`);
        return;
      }
      rejectUnknownKeys(errors, criterion, criterionPath, ACCEPTANCE_CRITERION_KEYS);
      if (checkString(errors, criterion.id, `${criterionPath}.id`)) {
        if (criterionIds.has(criterion.id)) errors.push(`${criterionPath}.id: duplicate criterion id '${criterion.id}'`);
        criterionIds.add(criterion.id);
      }
      checkString(errors, criterion.statement, `${criterionPath}.statement`);
      if (criterion.machineCheck !== undefined) {
        if (!isRecord(criterion.machineCheck)) {
          errors.push(`${criterionPath}.machineCheck: must be an object`);
        } else {
          rejectUnknownKeys(errors, criterion.machineCheck, `${criterionPath}.machineCheck`, MACHINE_CHECK_KEYS);
          checkEnum(errors, criterion.machineCheck.kind, `${criterionPath}.machineCheck.kind`, MACHINE_CHECK_KINDS);
          if (!isRecord(criterion.machineCheck.params)) {
            errors.push(`${criterionPath}.machineCheck.params: must be an object`);
          }
        }
      }
    });
  }

  if (typeof value.priceUsd !== 'number' || !Number.isFinite(value.priceUsd)
      || value.priceUsd <= 0 || value.priceUsd > 100_000) {
    errors.push(`${path}.priceUsd: must be a finite number in (0, 100000]`);
  }
  if (!isRecord(value.currency)) {
    errors.push(`${path}.currency: must be an object`);
  } else {
    rejectUnknownKeys(errors, value.currency, `${path}.currency`, CURRENCY_KEYS);
    checkString(errors, value.currency.asset, `${path}.currency.asset`);
    checkString(errors, value.currency.rail, `${path}.currency.rail`);
  }
  checkUnixMs(errors, value.deadlineUnixMs, `${path}.deadlineUnixMs`);
  checkPositiveInteger(errors, value.acceptanceWindowMs, `${path}.acceptanceWindowMs`);
  validateLegalProfile(errors, value.legalProfile, `${path}.legalProfile`);
  errors.push(...validateDecisionSpace(value.decisionSpace, `${path}.decisionSpace`));

  if (!Array.isArray(value.maeEvents)) {
    errors.push(`${path}.maeEvents: must be an array`);
  } else {
    value.maeEvents.forEach((event, index) => checkString(errors, event, `${path}.maeEvents[${index}]`));
  }
  checkString(errors, value.nonce, `${path}.nonce`);

  if (value.version === 'edict-om-2') {
    errors.push(...validateLegalPolicy(value.legalPolicy, `${path}.legalPolicy`));
    errors.push(...validateSettlementBinding(value.settlement, `${path}.settlement`));
    if (isRecord(value.legalProfile) && isRecord(value.legalPolicy)) {
      if (value.legalProfile.rules !== (value.legalPolicy.rules as Record<string, unknown> | undefined)?.id) {
        errors.push(`${path}.legalProfile.rules: must match ${path}.legalPolicy.rules.id`);
      }
      const assuranceMode = value.legalPolicy.assuranceMode;
      const enforcementTier = value.legalProfile.enforcementTier;
      if ((assuranceMode === 'wallet_native' || assuranceMode === 'rail_verified') && enforcementTier !== 'E0') {
        errors.push(`${path}.legalProfile.enforcementTier: wallet-native and rail-verified mandates must use E0`);
      }
      if (assuranceMode === 'enterprise_legal') {
        for (const role of ['requester', 'worker'] as const) {
          const party = value[role];
          if (isRecord(party) && party.principalKybRef === undefined) {
            errors.push(`${path}.${role}.principalKybRef: required for enterprise_legal assurance`);
          }
          if (isRecord(party) && party.authorityCredentialRef === undefined) {
            errors.push(`${path}.${role}.authorityCredentialRef: required for enterprise_legal assurance`);
          }
        }
      }
    }
  } else {
    if (value.legalPolicy !== undefined) errors.push(`${path}.legalPolicy: must be absent from edict-om-1`);
    if (value.settlement !== undefined) errors.push(`${path}.settlement: must be absent from edict-om-1`);
  }
  return errors;
}

// ---------------------------------------------------------------------------
// CaseObject validator
// ---------------------------------------------------------------------------

export interface CaseValidationResult {
  /** True iff there are no hard errors. Advisory `warn:`-prefixed entries do NOT flip this. */
  ok: boolean;
  /**
   * `<path>: <message>` strings; empty iff the case is fully clean. Entries
   * prefixed `warn:` are advisory (SHOULD-level rules) and do not affect `ok`.
   */
  errors: string[];
}

/**
 * Full structural validation of an unknown value against the canonical
 * CaseObject schema (see module doc). Pure and deterministic; never throws.
 */
export function validateCaseObject(x: unknown): CaseValidationResult {
  const errors: string[] = [];
  if (!isRecord(x)) {
    return { ok: false, errors: ['case: must be a JSON object (CaseObject)'] };
  }

  rejectUnknownKeys(errors, x, 'case', CASE_KEYS);

  checkString(errors, x.caseId, 'case.caseId', { re: UUID_V4_RE, hint: 'uuid v4' });
  const caseTypeOk = checkEnum(errors, x.caseType, 'case.caseType', CASE_TYPES);
  checkEnum(errors, x.publicity, 'case.publicity', PUBLICITIES);
  validatePartyRef(errors, x.requester, 'case.requester');
  validatePartyRef(errors, x.worker, 'case.worker');

  // --- conditional KYB: E2/E3 needs legally serviceable principals. Wallet-
  // native and rail-verified E0/E1 cases may use opaque account identifiers. --
  const enforcementTier = isRecord(x.legalProfile) ? x.legalProfile.enforcementTier : undefined;
  const kybRequired = enforcementTier === 'E2' || enforcementTier === 'E3';
  if (kybRequired) {
    for (const [party, path] of [
      [x.requester, 'case.requester'],
      [x.worker, 'case.worker'],
    ] as const) {
      if (isRecord(party) && party.principalKybRef === undefined) {
        errors.push(`${path}.principalKybRef: required when enforcementTier is E2/E3`);
      }
    }
  }
  // E2/E3 also binds the credential proving that each agent key may act for
  // the KYB principal. Wallet-native E0/E1 uses the wallet signature itself.
  if (kybRequired && x.legalPolicyHash !== undefined) {
    for (const [party, path] of [
      [x.requester, 'case.requester'],
      [x.worker, 'case.worker'],
    ] as const) {
      if (isRecord(party) && party.authorityCredentialRef === undefined) {
        errors.push(`${path}.authorityCredentialRef: required on Legal-Policy-bound E2/E3 cases`);
      }
    }
  }
  checkString(errors, x.orderMandateHash, 'case.orderMandateHash', { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  if (x.legalPolicyHash !== undefined) {
    checkString(errors, x.legalPolicyHash, 'case.legalPolicyHash', { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  }
  if (x.deliveryManifestHash !== undefined) {
    checkString(errors, x.deliveryManifestHash, 'case.deliveryManifestHash', { re: SHA256_HEX_RE, hint: 'sha256 hex' });
  }

  // --- evidence array --------------------------------------------------------
  if (!Array.isArray(x.evidence) || x.evidence.length === 0) {
    errors.push('case.evidence: must be a non-empty array of EvidenceCommitment');
  } else {
    x.evidence.forEach((e, i) => {
      appendEvidenceCommitmentProblems(errors, e, `case.evidence[${i}]`);
      // third_party (bonded third-party submission) is only meaningful where
      // outsiders may intervene: public_resolution cases.
      if (caseTypeOk && x.caseType !== 'public_resolution' && isRecord(e) && e.submitter === 'third_party') {
        errors.push(`case.evidence[${i}].submitter: 'third_party' submissions are valid only on public_resolution cases`);
      }
    });
  }

  // --- value / tier consistency ----------------------------------------------
  if (typeof x.valueUsd !== 'number' || !Number.isFinite(x.valueUsd)) {
    errors.push('case.valueUsd: must be a finite number');
  } else if (x.valueUsd <= 0) {
    errors.push('case.valueUsd: must be > 0');
  } else if (checkEnum(errors, x.tier, 'case.tier', VALUE_TIERS)) {
    const allowed = tierForValueUsd(x.valueUsd);
    if (allowed.length === 0) {
      errors.push('case.valueUsd: outside all value bands (max $100k for tier C)');
    } else if (!allowed.includes(x.tier as ValueTier)) {
      errors.push(
        `case.tier: tier ${String(x.tier)} inconsistent with valueUsd=${x.valueUsd} (expected ${allowed.join(' or ')})`,
      );
    }
  }

  checkEnum(errors, x.custodyMode, 'case.custodyMode', CUSTODY_MODES);

  // railRef is open by design (rail adapters own extra keys) but must name a rail.
  if (!isRecord(x.railRef)) errors.push('case.railRef: must be an object with a rail field');
  else checkString(errors, x.railRef.rail, 'case.railRef.rail');

  validateLegalProfile(errors, x.legalProfile, 'case.legalProfile');

  // DRR Rule 6.1 policy: Tier A is programmatic E0 in every event. This is a
  // hard boundary rather than a profile convention, so no Tier A case can
  // accidentally acquire E1/E2/E3 legal effect.
  if (x.tier === 'A' && isRecord(x.legalProfile) && x.legalProfile.enforcementTier !== 'E0') {
    errors.push(`case.legalProfile.enforcementTier: Tier A must use E0, got '${String(x.legalProfile.enforcementTier)}'`);
  }

  checkUnixMs(errors, x.openedAtUnixMs, 'case.openedAtUnixMs');

  // --- decisionSpace: structural checks (see validateDecisionSpace) -----------
  errors.push(...validateDecisionSpace(x.decisionSpace, 'case.decisionSpace'));

  if (x.round !== undefined) {
    if (!isRecord(x.round)) errors.push('case.round: must be an object');
    else {
      rejectUnknownKeys(errors, x.round, 'case.round', ROUND_KEYS);
      if (typeof x.round.number !== 'number' || !Number.isSafeInteger(x.round.number) || x.round.number < 1 || x.round.number > 2) {
        errors.push('case.round.number: must be integer 1 or 2 (v0 permits at most one redo)');
      }
      checkUnixMs(errors, x.round.effectiveDeadlineUnixMs, 'case.round.effectiveDeadlineUnixMs');
      if (x.round.number === 1 && (x.round.priorCaseId !== undefined || x.round.priorVerdictSha256 !== undefined)) {
        errors.push('case.round: round 1 must not carry priorCaseId/priorVerdictSha256');
      }
      if (x.round.number === 2) {
        checkString(errors, x.round.priorCaseId, 'case.round.priorCaseId', { re: UUID_V4_RE, hint: 'uuid v4' });
        checkString(errors, x.round.priorVerdictSha256, 'case.round.priorVerdictSha256', { re: SHA256_HEX_RE, hint: 'sha256 hex' });
        if (isRecord(x.decisionSpace) && x.decisionSpace.kind === 'escrow_branches'
            && Array.isArray(x.decisionSpace.permitted) && x.decisionSpace.permitted.includes('redo')) {
          errors.push('case.decisionSpace.permitted: redo is unavailable in round 2');
        }
      }
    }
  }

  // --- warning-level (SHOULD) rules -------------------------------------------
  // Public-resolution proceedings SHOULD be public: a sealed challenge to a
  // public outcome undermines the credibility of the resolution.
  if (caseTypeOk && x.caseType === 'public_resolution' && x.publicity === 'sealed') {
    errors.push("warn:case.publicity: public_resolution cases SHOULD have publicity 'public'");
  }

  // --- evidence cross-references ----------------------------------------------
  if (typeof x.orderMandateHash === 'string' && Array.isArray(x.evidence)) {
    const match = x.evidence.some(
      (e) => isRecord(e) && e.kind === 'order_mandate' && e.sha256 === x.orderMandateHash,
    );
    if (!match) {
      errors.push('case.orderMandateHash: MUST match an evidence commitment of kind order_mandate');
    }
  }
  if (typeof x.legalPolicyHash === 'string' && Array.isArray(x.evidence)) {
    const match = x.evidence.some(
      (e) => isRecord(e) && e.kind === 'legal_policy' && e.sha256 === x.legalPolicyHash && e.authenticated === true,
    );
    if (!match) {
      errors.push('case.legalPolicyHash: MUST match an authenticated evidence commitment of kind legal_policy');
    }
  }
  if (x.legalPolicyHash !== undefined && Array.isArray(x.evidence)) {
    for (const [party, path] of [
      [x.requester, 'case.requester'],
      [x.worker, 'case.worker'],
    ] as const) {
      const ref = isRecord(party) && isRecord(party.authorityCredentialRef)
        ? party.authorityCredentialRef
        : undefined;
      if (ref !== undefined && typeof ref.sha256 === 'string') {
        const match = x.evidence.some(
          (e) => isRecord(e) && e.kind === 'authority_credential' && e.sha256 === ref.sha256,
        );
        if (!match) errors.push(`${path}.authorityCredentialRef.sha256: must match authority_credential evidence`);
      }
    }
  }
  if (typeof x.deliveryManifestHash === 'string' && Array.isArray(x.evidence)) {
    const match = x.evidence.some(
      (e) => isRecord(e) && e.kind === 'delivery_manifest' && e.sha256 === x.deliveryManifestHash,
    );
    if (!match) {
      errors.push('case.deliveryManifestHash: must match an evidence commitment of kind delivery_manifest');
    }
  }

  // `warn:`-prefixed entries are advisory (SHOULD-level); only hard errors flip ok.
  return { ok: !errors.some((e) => !e.startsWith('warn:')), errors };
}
