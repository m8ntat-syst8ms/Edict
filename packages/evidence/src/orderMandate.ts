/**
 * Order-mandate hashing and wallet-signable payload construction (spec C5).
 *
 * This module does NOT sign anything — wallets sign. It builds the exact
 * payloads wallets are asked to sign (EIP-712 for EVM rails, NEP-413 for
 * NEAR rails) and verifies canonical hashes.
 *
 * ## What exactly is signed
 *
 * Both rails sign the same *flattened mapping* of the mandate, produced by
 * {@link flattenOrderMandate}:
 *
 * | field                    | EIP-712 type | source                                              |
 * |--------------------------|--------------|-----------------------------------------------------|
 * | version                  | string       | om.version                                          |
 * | requesterAgentId         | string       | om.requester.agentId                                |
 * | workerAgentId            | string       | om.worker.agentId                                   |
 * | description              | string       | om.description                                      |
 * | acceptanceCriteriaSha256 | bytes32      | 0x + sha256(canonical JSON of om.acceptanceCriteria)|
 * | priceUsdE6               | uint256      | round(om.priceUsd * 1e6), decimal string            |
 * | currencyAsset            | string       | om.currency.asset                                   |
 * | currencyRail             | string       | om.currency.rail                                    |
 * | deadlineUnixMs           | uint256      | om.deadlineUnixMs, decimal string                   |
 * | acceptanceWindowMs       | uint256      | om.acceptanceWindowMs, decimal string               |
 * | governingLaw             | string       | om.legalProfile.governingLaw                        |
 * | seat                     | string       | om.legalProfile.seat                                |
 * | rules                    | string       | om.legalProfile.rules                               |
 * | enforcementTier          | string       | om.legalProfile.enforcementTier                     |
 * | decisionSpaceSha256      | bytes32      | 0x + sha256(canonical JSON of om.decisionSpace)     |
 * | legalPolicySha256        | bytes32      | v2: sha256(canonical JSON of om.legalPolicy)        |
 * | assuranceMode            | string       | v2: wallet_native, rail_verified or enterprise_legal|
 * | custodyMode              | string       | v2: external escrow or no-custody only              |
 * | fundsController          | string       | v2: requester wallet, customer contract or rail     |
 * | settlementAdapterRef     | string       | v2: customer-hosted settlement adapter reference    |
 * | edictOperatorCanTransfer | bool         | v2: always false                                    |
 * | edictOperatorCanFreeze   | bool         | v2: always false                                    |
 * | edictRequiredSigner      | bool         | v2: always false                                    |
 * | resolutionTimeoutMs      | uint256      | v2: customer fallback availability timeout          |
 * | livenessFallback         | string       | v2: pre-committed no-Edict fallback                 |
 * | settlementPrivacyMode    | string       | v2: public, confidential transport or settlement    |
 * | privacyCapabilitySha256  | bytes32      | v2: exact evidence supporting the privacy claim     |
 * | disclosurePolicySha256   | bytes32      | v2: exact selective-disclosure policy               |
 * | privacyFallback          | string       | v2: fail closed or permit public settlement         |
 * | publicFallbackAdapterRef | string       | v2: exact public route, empty unless expressly used |
 * | rulesSha256              | bytes32      | v2: exact Edict Rules bytes hash                    |
 * | challengeWindowMs        | uint256      | v2: post-determination challenge window             |
 * | humanEscalationSha256    | bytes32      | v2: hash of the complete escalation election        |
 * | e2ImplementationTiming   | string       | v2: implement_then_arbitrate or hold_pending_award  |
 * | bondRemovalDestination   | string       | v2: protocol_burn or protection_pool                |
 * | requesterAuthoritySha256 | bytes32      | v2: delegation hash, or zero for self-authority      |
 * | workerAuthoritySha256    | bytes32      | v2: delegation hash, or zero for self-authority      |
 * | maeEvents                | string[]     | om.maeEvents (order preserved)                      |
 * | nonce                    | string       | om.nonce                                            |
 *
 * `decisionSpaceSha256` is the SHA-256 hash of the canonical DecisionSpace
 * JSON. The signature therefore binds every branch,
 * label and bound byte-for-byte while the signed envelope stays flat.
 *
 * Deliberately NOT signed directly:
 * - `requester.principalKybRef` / `erc8004Ref` (and the worker's): directory
 *   metadata that may rotate. Enterprise-legal v2 orders sign the immutable
 *   authority-credential hash instead. Wallet-native orders use an all-zero
 *   authority hash: the mandate's own wallet signature proves self-authority.
 * - The full `acceptanceCriteria` text: flattened to its canonical sha256.
 *   The signature still binds every criterion byte-for-byte — presenting
 *   different criteria later cannot reproduce the hash.
 * - The full `decisionSpace` object: flattened to `decisionSpaceSha256` in
 *   the same way.
 *
 * Distinct from signing, {@link canonicalOrderMandateHash} hashes the full
 * OrderMandate object (all fields, canonical JSON). That hash is what
 * `CaseObject.orderMandateHash` and evidence commitments reference.
 */

import { validateSettlementBinding, type OrderMandate } from '@edict/core';
import { canonicalize, normalizeSha256, sha256Canonical } from './hash.js';

// ---------------------------------------------------------------------------
// Canonical hash of the full mandate
// ---------------------------------------------------------------------------

/**
 * sha256 (lowercase hex) over the canonical JSON of the FULL OrderMandate.
 * This is the value referenced by `CaseObject.orderMandateHash` and by
 * `order_mandate` evidence commitments.
 */
export function canonicalOrderMandateHash(om: OrderMandate): string {
  return sha256Canonical(om);
}

/**
 * Verify a mandate against an expected sha256 (case-insensitive, optional
 * `0x` prefix). Returns false — never throws — on a malformed expected hash.
 */
export function verifyOrderMandateHash(om: OrderMandate, expectedSha256: string): boolean {
  const expected = normalizeSha256(expectedSha256);
  if (expected === null) return false;
  return canonicalOrderMandateHash(om) === expected;
}

// ---------------------------------------------------------------------------
// Flattened signing mapping (shared by EIP-712 and NEP-413)
// ---------------------------------------------------------------------------

/** The flattened, rail-neutral mapping that wallets actually sign. */
export interface FlattenedOrderMandate {
  version: string;
  requesterAgentId: string;
  workerAgentId: string;
  description: string;
  /** 0x-prefixed sha256 of the canonical JSON of om.acceptanceCriteria. */
  acceptanceCriteriaSha256: string;
  /** Price in micro-USD (integer), decimal string — EIP-712 has no floats. */
  priceUsdE6: string;
  currencyAsset: string;
  currencyRail: string;
  deadlineUnixMs: string;
  acceptanceWindowMs: string;
  governingLaw: string;
  seat: string;
  rules: string;
  enforcementTier: string;
  /**
   * 0x-prefixed SHA-256 of the canonical JSON of om.decisionSpace. The
   * signature binds the whole DecisionSpace byte-for-byte.
   */
  decisionSpaceSha256: string;
  /** edict-om-2 fields; omitted from the legacy v1 signing type. */
  legalPolicySha256?: string;
  assuranceMode?: string;
  custodyMode?: string;
  fundsController?: string;
  settlementAdapterRef?: string;
  edictOperatorCanTransfer?: boolean;
  edictOperatorCanFreeze?: boolean;
  edictRequiredSigner?: boolean;
  resolutionTimeoutMs?: string;
  livenessFallback?: string;
  settlementPrivacyMode?: string;
  privacyCapabilitySha256?: string;
  disclosurePolicySha256?: string;
  privacyFallback?: string;
  publicFallbackAdapterRef?: string;
  rulesSha256?: string;
  challengeWindowMs?: string;
  humanEscalationSha256?: string;
  e2ImplementationTiming?: string;
  bondRemovalDestination?: string;
  requesterAuthoritySha256?: string;
  workerAuthoritySha256?: string;
  maeEvents: string[];
  nonce: string;
}

/** bytes32 sentinel: the signing account acts for itself, with no delegation credential. */
const ZERO_SHA256 = `0x${'0'.repeat(64)}`;
const SELF_AUTHORITY_SHA256 = ZERO_SHA256;

function toUintString(value: number, label: string): string {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer, got ${value}`);
  }
  return String(value);
}

/**
 * Produce the documented flattened mapping (see module doc for the exact
 * field table). Deterministic: same mandate → same mapping.
 */
export function flattenOrderMandate(om: OrderMandate): FlattenedOrderMandate {
  if (!Number.isFinite(om.priceUsd) || om.priceUsd < 0) {
    throw new TypeError(`priceUsd must be a non-negative finite number, got ${om.priceUsd}`);
  }
  const priceUsdE6 = Math.round(om.priceUsd * 1e6);
  const flattened: FlattenedOrderMandate = {
    version: om.version,
    requesterAgentId: om.requester.agentId,
    workerAgentId: om.worker.agentId,
    description: om.description,
    acceptanceCriteriaSha256: `0x${sha256Canonical(om.acceptanceCriteria)}`,
    priceUsdE6: toUintString(priceUsdE6, 'priceUsdE6 (round(priceUsd*1e6))'),
    currencyAsset: om.currency.asset,
    currencyRail: om.currency.rail,
    deadlineUnixMs: toUintString(om.deadlineUnixMs, 'deadlineUnixMs'),
    acceptanceWindowMs: toUintString(om.acceptanceWindowMs, 'acceptanceWindowMs'),
    governingLaw: om.legalProfile.governingLaw,
    seat: om.legalProfile.seat,
    rules: om.legalProfile.rules,
    enforcementTier: om.legalProfile.enforcementTier,
    decisionSpaceSha256: `0x${sha256Canonical(om.decisionSpace)}`,
    maeEvents: [...om.maeEvents],
    nonce: om.nonce,
  };
  if (om.version === 'edict-om-2') {
    if (om.legalPolicy === undefined) throw new TypeError('edict-om-2 requires legalPolicy');
    if (om.settlement === undefined) throw new TypeError('edict-om-2 requires a customer-controlled settlement binding');
    const settlementProblems = validateSettlementBinding(om.settlement);
    if (settlementProblems.length > 0) {
      throw new TypeError(`edict-om-2 settlement is invalid: ${settlementProblems.join('; ')}`);
    }
    const requesterAuthority = om.requester.authorityCredentialRef;
    const workerAuthority = om.worker.authorityCredentialRef;
    flattened.legalPolicySha256 = `0x${sha256Canonical(om.legalPolicy)}`;
    flattened.assuranceMode = om.legalPolicy.assuranceMode;
    flattened.custodyMode = om.settlement.custodyMode;
    flattened.fundsController = om.settlement.fundsController;
    flattened.settlementAdapterRef = om.settlement.adapterRef;
    flattened.edictOperatorCanTransfer = false;
    flattened.edictOperatorCanFreeze = false;
    flattened.edictRequiredSigner = false;
    flattened.resolutionTimeoutMs = toUintString(
      om.settlement.resolutionTimeoutMs,
      'settlement.resolutionTimeoutMs',
    );
    flattened.livenessFallback = om.settlement.livenessFallback;
    flattened.settlementPrivacyMode = om.settlement.confidentiality?.mode ?? 'public';
    flattened.privacyCapabilitySha256 = om.settlement.confidentiality === undefined
      ? ZERO_SHA256
      : `0x${om.settlement.confidentiality.capabilitySha256}`;
    flattened.disclosurePolicySha256 = om.settlement.confidentiality === undefined
      ? ZERO_SHA256
      : `0x${om.settlement.confidentiality.disclosurePolicySha256}`;
    flattened.privacyFallback = om.settlement.confidentiality?.fallback ?? 'not_applicable';
    flattened.publicFallbackAdapterRef =
      om.settlement.confidentiality?.publicFallbackAdapterRef ?? '';
    flattened.rulesSha256 = `0x${om.legalPolicy.rules.sha256}`;
    flattened.challengeWindowMs = toUintString(om.legalPolicy.challengeWindowMs, 'challengeWindowMs');
    flattened.humanEscalationSha256 = `0x${sha256Canonical(om.legalPolicy.humanEscalation)}`;
    flattened.e2ImplementationTiming = om.legalPolicy.e2ImplementationTiming;
    flattened.bondRemovalDestination = om.legalPolicy.bondRemovalDestination;
    flattened.requesterAuthoritySha256 = requesterAuthority === undefined
      ? SELF_AUTHORITY_SHA256
      : `0x${requesterAuthority.sha256}`;
    flattened.workerAuthoritySha256 = workerAuthority === undefined
      ? SELF_AUTHORITY_SHA256
      : `0x${workerAuthority.sha256}`;
  }
  return flattened;
}

// ---------------------------------------------------------------------------
// EIP-712 (EVM rails)
// ---------------------------------------------------------------------------

export interface Eip712TypedData {
  domain: { name: 'EdictOrderMandate'; version: '1' | '2'; chainId?: number };
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: 'OrderMandate';
  message: FlattenedOrderMandate;
}

/** Field order is part of the EIP-712 type hash — never reorder. */
const ORDER_MANDATE_712_FIELDS: Array<{ name: keyof FlattenedOrderMandate; type: string }> = [
  { name: 'version', type: 'string' },
  { name: 'requesterAgentId', type: 'string' },
  { name: 'workerAgentId', type: 'string' },
  { name: 'description', type: 'string' },
  { name: 'acceptanceCriteriaSha256', type: 'bytes32' },
  { name: 'priceUsdE6', type: 'uint256' },
  { name: 'currencyAsset', type: 'string' },
  { name: 'currencyRail', type: 'string' },
  { name: 'deadlineUnixMs', type: 'uint256' },
  { name: 'acceptanceWindowMs', type: 'uint256' },
  { name: 'governingLaw', type: 'string' },
  { name: 'seat', type: 'string' },
  { name: 'rules', type: 'string' },
  { name: 'enforcementTier', type: 'string' },
  { name: 'decisionSpaceSha256', type: 'bytes32' },
  { name: 'maeEvents', type: 'string[]' },
  { name: 'nonce', type: 'string' },
];

/** Appended only for edict-om-2; the compatibility type hash remains stable. */
const ORDER_MANDATE_712_V2_FIELDS: Array<{ name: keyof FlattenedOrderMandate; type: string }> = [
  { name: 'legalPolicySha256', type: 'bytes32' },
  { name: 'assuranceMode', type: 'string' },
  { name: 'custodyMode', type: 'string' },
  { name: 'fundsController', type: 'string' },
  { name: 'settlementAdapterRef', type: 'string' },
  { name: 'edictOperatorCanTransfer', type: 'bool' },
  { name: 'edictOperatorCanFreeze', type: 'bool' },
  { name: 'edictRequiredSigner', type: 'bool' },
  { name: 'resolutionTimeoutMs', type: 'uint256' },
  { name: 'livenessFallback', type: 'string' },
  { name: 'settlementPrivacyMode', type: 'string' },
  { name: 'privacyCapabilitySha256', type: 'bytes32' },
  { name: 'disclosurePolicySha256', type: 'bytes32' },
  { name: 'privacyFallback', type: 'string' },
  { name: 'publicFallbackAdapterRef', type: 'string' },
  { name: 'rulesSha256', type: 'bytes32' },
  { name: 'challengeWindowMs', type: 'uint256' },
  { name: 'humanEscalationSha256', type: 'bytes32' },
  { name: 'e2ImplementationTiming', type: 'string' },
  { name: 'bondRemovalDestination', type: 'string' },
  { name: 'requesterAuthoritySha256', type: 'bytes32' },
  { name: 'workerAuthoritySha256', type: 'bytes32' },
];

/**
 * Build the EIP-712 typed-data envelope for an order mandate.
 *
 * - `domain` is `{ name: 'EdictOrderMandate', version: '1' }`, plus `chainId`
 *   when provided (recommended on EVM rails for replay protection; the
 *   mandate `nonce` also protects cross-domain replay).
 * - `types` intentionally omits `EIP712Domain` — ethers v6 rejects it and
 *   viem reconstructs it from `domain`; `primaryType` is explicit for
 *   libraries that need it.
 * - `message` is the flattened mapping from {@link flattenOrderMandate};
 *   uint256 values are decimal strings (JSON-safe, accepted by ethers/viem).
 */
export function buildEip712TypedData(om: OrderMandate, chainId?: number): Eip712TypedData {
  const domain: Eip712TypedData['domain'] = {
    name: 'EdictOrderMandate',
    version: om.version === 'edict-om-2' ? '2' : '1',
  };
  if (chainId !== undefined) {
    if (!Number.isSafeInteger(chainId) || chainId <= 0) {
      throw new TypeError(`chainId must be a positive safe integer, got ${chainId}`);
    }
    domain.chainId = chainId;
  }
  return {
    domain,
    types: {
      OrderMandate: [
        ...ORDER_MANDATE_712_FIELDS,
        ...(om.version === 'edict-om-2' ? ORDER_MANDATE_712_V2_FIELDS : []),
      ].map((f) => ({ name: f.name, type: f.type })),
    },
    primaryType: 'OrderMandate',
    message: flattenOrderMandate(om),
  };
}

// ---------------------------------------------------------------------------
// NEP-413 (NEAR rails)
// ---------------------------------------------------------------------------

export interface Nep413Payload {
  /**
   * The message string the wallet signs: canonical JSON (sorted keys, no
   * whitespace) of the same flattened mapping as EIP-712 signs. Both rails
   * therefore commit to identical mandate content.
   */
  message: string;
  /** Verifier account id the signature is addressed to (NEP-413 `recipient`). */
  recipient: string;
  /** Exactly 32 bytes of caller-supplied entropy (NEP-413 `nonce`). */
  nonce: Uint8Array;
  /** Optional NEP-413 callback URL (browser-wallet flows). */
  callbackUrl?: string;
}

/**
 * Build a NEP-413 `signMessage` payload for an order mandate.
 *
 * The wallet is expected to sign per NEP-413: sha256 over borsh-serialised
 * `{ tag: 2^31 + 413, message, nonce, recipient, callbackUrl? }` with an
 * ed25519 full-access-key-excluded signer. That serialisation and the
 * signature are the wallet's job — this function only constructs the inputs.
 *
 * `nonce32` must be exactly 32 bytes; it is defensively copied.
 */
export function buildNep413Payload(
  om: OrderMandate,
  recipient: string,
  nonce32: Uint8Array,
  callbackUrl?: string,
): Nep413Payload {
  if (!(nonce32 instanceof Uint8Array) || nonce32.length !== 32) {
    throw new TypeError(`nonce32 must be exactly 32 bytes, got ${nonce32?.length ?? 'non-Uint8Array'}`);
  }
  if (typeof recipient !== 'string' || recipient.length === 0) {
    throw new TypeError('recipient must be a non-empty string');
  }
  const payload: Nep413Payload = {
    message: canonicalize(flattenOrderMandate(om)),
    recipient,
    nonce: Uint8Array.from(nonce32),
  };
  if (callbackUrl !== undefined) payload.callbackUrl = callbackUrl;
  return payload;
}
