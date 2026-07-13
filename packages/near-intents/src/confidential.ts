/**
 * Release-gated Confidential Intents settlement profile.
 *
 * NEAR's public materials describe the privacy properties and private shard,
 * but do not currently publish a stable contract/RPC integration interface.
 * This module therefore binds independently verified capability evidence; it
 * does not invent an endpoint, submit a transaction or make a privacy claim
 * from confidential transport into an otherwise public settlement contract.
 */

import { createHash } from 'node:crypto';
import type {
  ConfidentialityFallback,
  LivenessFallback,
  SettlementBinding,
} from '@edict/core';
import { validateSettlementBinding } from '@edict/core';

export const CONFIDENTIAL_INTENTS_CAPABILITY_VERSION =
  'edict-confidential-intents-capability-1' as const;
export const CONFIDENTIAL_INTENTS_ADAPTER_VERSION =
  'near-confidential-intents:v1' as const;

const SHA256_HEX = /^[0-9a-f]{64}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const CAPABILITY_KEYS = new Set([
  'version',
  'provider',
  'environment',
  'privateShardNetwork',
  'privateIntentsContract',
  'privateSettlementAccount',
  'deploymentMode',
  'settlementVisibility',
  'publicRecord',
  'settlementCodeSha256Hex',
  'providerInterfaceSha256Hex',
  'validatorPolicySha256Hex',
  'bridgeAttestationPolicySha256Hex',
  'disclosurePolicySha256Hex',
  'disclosureReceiptSchemaSha256Hex',
  'settlementAccessKeys',
  'edictAccessKeys',
  'customerApproved',
  'immutableActiveOrders',
  'externalAuditStatus',
  'externalAuditEvidence',
  'canaryStatus',
  'canaryReceiptSha256Hex',
  'capabilitySha256Hex',
]);
const AUDIT_EVIDENCE_KEYS = new Set([
  'auditor', 'reportUri', 'reportSha256Hex', 'completedOn', 'auditedScopeSha256Hex',
]);

export interface ConfidentialIntentsAuditEvidence {
  auditor: string;
  reportUri: string;
  reportSha256Hex: string;
  completedOn: string;
  /** Digest of every privacy- and custody-critical capability field. */
  auditedScopeSha256Hex: string;
}

/**
 * Evidence supplied by the private-shard provider/integrator and checked by
 * an independent auditor. It is not proof merely because it has this shape.
 */
export interface ConfidentialIntentsCapability {
  version: typeof CONFIDENTIAL_INTENTS_CAPABILITY_VERSION;
  provider: 'near_confidential_intents';
  environment: 'near_private_shard';
  privateShardNetwork: string;
  privateIntentsContract: string;
  privateSettlementAccount: string;
  deploymentMode: 'customer_approved_keyless_contract';
  settlementVisibility: 'private';
  publicRecord: 'commitments_only';
  settlementCodeSha256Hex: string;
  providerInterfaceSha256Hex: string;
  validatorPolicySha256Hex: string;
  bridgeAttestationPolicySha256Hex: string;
  disclosurePolicySha256Hex: string;
  disclosureReceiptSchemaSha256Hex: string;
  settlementAccessKeys: [];
  edictAccessKeys: [];
  customerApproved: true;
  immutableActiveOrders: true;
  externalAuditStatus:
    | 'required_before_customer_funds'
    | 'independent_audit_evidence_attached';
  externalAuditEvidence?: ConfidentialIntentsAuditEvidence;
  canaryStatus: 'required' | 'passed';
  canaryReceiptSha256Hex?: string;
  capabilitySha256Hex: string;
}

export interface ConfidentialIntentsBindingOptions {
  resolutionTimeoutMs?: number;
  livenessFallback?: LivenessFallback;
  /** Defaults to fail_closed so an outage cannot silently publish the order. */
  privacyFallback?: ConfidentialityFallback;
  /** Required when privacyFallback expressly permits public settlement. */
  publicFallbackAdapterRef?: string;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

function nonEmpty(value: unknown, label: string, problems: string[]): value is string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    problems.push(`${label} must be a non-empty string`);
    return false;
  }
  return true;
}

function sha256(value: unknown, label: string, problems: string[]): value is string {
  if (typeof value !== 'string' || !SHA256_HEX.test(value) || /^0+$/.test(value)) {
    problems.push(`${label} must be non-zero lowercase sha256 hex`);
    return false;
  }
  return true;
}

function privacyScope(capability: ConfidentialIntentsCapability): Record<string, unknown> {
  return {
    version: capability.version,
    provider: capability.provider,
    environment: capability.environment,
    privateShardNetwork: capability.privateShardNetwork,
    privateIntentsContract: capability.privateIntentsContract,
    privateSettlementAccount: capability.privateSettlementAccount,
    deploymentMode: capability.deploymentMode,
    settlementVisibility: capability.settlementVisibility,
    publicRecord: capability.publicRecord,
    settlementCodeSha256Hex: capability.settlementCodeSha256Hex,
    providerInterfaceSha256Hex: capability.providerInterfaceSha256Hex,
    validatorPolicySha256Hex: capability.validatorPolicySha256Hex,
    bridgeAttestationPolicySha256Hex: capability.bridgeAttestationPolicySha256Hex,
    disclosurePolicySha256Hex: capability.disclosurePolicySha256Hex,
    disclosureReceiptSchemaSha256Hex: capability.disclosureReceiptSchemaSha256Hex,
    settlementAccessKeys: capability.settlementAccessKeys,
    edictAccessKeys: capability.edictAccessKeys,
    customerApproved: capability.customerApproved,
    immutableActiveOrders: capability.immutableActiveOrders,
  };
}

export function confidentialIntentsAuditScopeDigest(
  capability: ConfidentialIntentsCapability,
): string {
  return digest(privacyScope(capability));
}

export function confidentialIntentsCapabilityDigest(
  capability:
    | Omit<ConfidentialIntentsCapability, 'capabilitySha256Hex'>
    | ConfidentialIntentsCapability,
): string {
  const { capabilitySha256Hex: _ignored, ...payload } =
    capability as ConfidentialIntentsCapability;
  return digest(payload);
}

export function validateConfidentialIntentsCapability(value: unknown): string[] {
  const problems: string[] = [];
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return ['capability must be an object'];
  }
  for (const key of Object.keys(value)) {
    if (!CAPABILITY_KEYS.has(key)) problems.push(`capability.${key} is an unknown key`);
  }
  const capability = value as ConfidentialIntentsCapability;
  if (capability.version !== CONFIDENTIAL_INTENTS_CAPABILITY_VERSION) {
    problems.push('capability version is unsupported');
  }
  if (capability.provider !== 'near_confidential_intents') {
    problems.push('provider must be near_confidential_intents');
  }
  if (capability.environment !== 'near_private_shard') {
    problems.push('environment must be near_private_shard');
  }
  nonEmpty(capability.privateShardNetwork, 'privateShardNetwork', problems);
  nonEmpty(capability.privateIntentsContract, 'privateIntentsContract', problems);
  nonEmpty(capability.privateSettlementAccount, 'privateSettlementAccount', problems);
  if (capability.deploymentMode !== 'customer_approved_keyless_contract') {
    problems.push('deploymentMode must be customer_approved_keyless_contract');
  }
  if (capability.settlementVisibility !== 'private') {
    problems.push('settlementVisibility must be private');
  }
  if (capability.publicRecord !== 'commitments_only') {
    problems.push('publicRecord must be commitments_only');
  }
  for (const field of [
    'settlementCodeSha256Hex',
    'providerInterfaceSha256Hex',
    'validatorPolicySha256Hex',
    'bridgeAttestationPolicySha256Hex',
    'disclosurePolicySha256Hex',
    'disclosureReceiptSchemaSha256Hex',
  ] as const) {
    sha256(capability[field], field, problems);
  }
  if (!Array.isArray(capability.settlementAccessKeys) || capability.settlementAccessKeys.length !== 0) {
    problems.push('settlementAccessKeys must be an empty array');
  }
  if (!Array.isArray(capability.edictAccessKeys) || capability.edictAccessKeys.length !== 0) {
    problems.push('edictAccessKeys must be an empty array');
  }
  if (capability.customerApproved !== true) problems.push('customerApproved must be true');
  if (capability.immutableActiveOrders !== true) problems.push('immutableActiveOrders must be true');
  if (
    capability.externalAuditStatus !== 'required_before_customer_funds'
    && capability.externalAuditStatus !== 'independent_audit_evidence_attached'
  ) {
    problems.push('externalAuditStatus is unsupported');
  }
  if (capability.canaryStatus !== 'required' && capability.canaryStatus !== 'passed') {
    problems.push('canaryStatus is unsupported');
  }
  if (capability.canaryStatus === 'passed') {
    sha256(capability.canaryReceiptSha256Hex, 'canaryReceiptSha256Hex', problems);
  } else if (capability.canaryReceiptSha256Hex !== undefined) {
    problems.push('canaryReceiptSha256Hex must be absent until the canary passes');
  }

  const audit = capability.externalAuditEvidence;
  if (capability.externalAuditStatus === 'independent_audit_evidence_attached') {
    if (audit === undefined) {
      problems.push('externalAuditEvidence is required when audit status is attached');
    } else if (typeof audit !== 'object' || audit === null || Array.isArray(audit)) {
      problems.push('externalAuditEvidence must be an object');
    } else {
      for (const key of Object.keys(audit)) {
        if (!AUDIT_EVIDENCE_KEYS.has(key)) {
          problems.push(`externalAuditEvidence.${key} is an unknown key`);
        }
      }
      nonEmpty(audit.auditor, 'externalAuditEvidence.auditor', problems);
      nonEmpty(audit.reportUri, 'externalAuditEvidence.reportUri', problems);
      sha256(audit.reportSha256Hex, 'externalAuditEvidence.reportSha256Hex', problems);
      if (typeof audit.completedOn !== 'string' || !DATE.test(audit.completedOn)) {
        problems.push('externalAuditEvidence.completedOn must be YYYY-MM-DD');
      }
      if (audit.auditedScopeSha256Hex !== confidentialIntentsAuditScopeDigest(capability)) {
        problems.push('external audit evidence does not cover the privacy and custody scope');
      }
    }
  } else if (audit !== undefined) {
    problems.push('externalAuditEvidence requires attached audit status');
  }

  if (!sha256(capability.capabilitySha256Hex, 'capabilitySha256Hex', problems)) {
    return problems;
  }
  if (confidentialIntentsCapabilityDigest(capability) !== capability.capabilitySha256Hex) {
    problems.push('capability digest is invalid');
  }
  return problems;
}

export function confidentialIntentsAdapterRef(
  capability: ConfidentialIntentsCapability,
): string {
  const problems = validateConfidentialIntentsCapability(capability);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
  return `${CONFIDENTIAL_INTENTS_ADAPTER_VERSION}:${capability.capabilitySha256Hex}`;
}

/**
 * Convert audited, canary-proven private-shard evidence into the signed Edict
 * settlement boundary. This never submits an intent or receives a signing key.
 */
export function confidentialIntentsSettlementBinding(
  capability: ConfidentialIntentsCapability,
  options: ConfidentialIntentsBindingOptions = {},
): SettlementBinding {
  const problems = validateConfidentialIntentsCapability(capability);
  if (capability.externalAuditStatus !== 'independent_audit_evidence_attached') {
    problems.push('independent external audit evidence is required before customer funds');
  }
  if (capability.canaryStatus !== 'passed') {
    problems.push('a private-shard mainnet canary is required before customer funds');
  }
  if (problems.length > 0) throw new TypeError(problems.join('; '));

  const binding: SettlementBinding = {
    custodyMode: 'M2_external_escrow',
    fundsController: 'customer_contract',
    adapterRef: `${CONFIDENTIAL_INTENTS_ADAPTER_VERSION}:${capability.capabilitySha256Hex}`,
    edictOperatorCanTransfer: false,
    edictOperatorCanFreeze: false,
    edictOperatorIsRequiredSigner: false,
    resolutionTimeoutMs: options.resolutionTimeoutMs ?? 72 * 60 * 60 * 1_000,
    livenessFallback: options.livenessFallback ?? 'controller_resolution',
    confidentiality: {
      mode: 'confidential_settlement',
      capabilitySha256: capability.capabilitySha256Hex,
      disclosurePolicySha256: capability.disclosurePolicySha256Hex,
      fallback: options.privacyFallback ?? 'fail_closed',
      ...(options.publicFallbackAdapterRef !== undefined
        ? { publicFallbackAdapterRef: options.publicFallbackAdapterRef }
        : {}),
    },
  };
  const bindingProblems = validateSettlementBinding(binding);
  if (bindingProblems.length > 0) throw new TypeError(bindingProblems.join('; '));
  return binding;
}
