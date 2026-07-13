import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CONFIDENTIAL_INTENTS_CAPABILITY_VERSION,
  confidentialIntentsAdapterRef,
  confidentialIntentsAuditScopeDigest,
  confidentialIntentsCapabilityDigest,
  confidentialIntentsSettlementBinding,
  validateConfidentialIntentsCapability,
  type ConfidentialIntentsCapability,
} from './confidential.js';

const HASH_A = '11'.repeat(32);
const HASH_B = '22'.repeat(32);
const HASH_C = '33'.repeat(32);
const HASH_D = '44'.repeat(32);
const HASH_E = '55'.repeat(32);
const HASH_F = '66'.repeat(32);
const HASH_G = '77'.repeat(32);
const HASH_H = '88'.repeat(32);

function capability(options: {
  audited?: boolean;
  canary?: boolean;
} = {}): ConfidentialIntentsCapability {
  const audited = options.audited ?? true;
  const canary = options.canary ?? true;
  const base = {
    version: CONFIDENTIAL_INTENTS_CAPABILITY_VERSION,
    provider: 'near_confidential_intents' as const,
    environment: 'near_private_shard' as const,
    privateShardNetwork: 'provider-issued-network-id',
    privateIntentsContract: 'provider-issued-private-intents-contract',
    privateSettlementAccount: 'protect.customer.private',
    deploymentMode: 'customer_approved_keyless_contract' as const,
    settlementVisibility: 'private' as const,
    publicRecord: 'commitments_only' as const,
    settlementCodeSha256Hex: HASH_A,
    providerInterfaceSha256Hex: HASH_B,
    validatorPolicySha256Hex: HASH_C,
    bridgeAttestationPolicySha256Hex: HASH_D,
    disclosurePolicySha256Hex: HASH_E,
    disclosureReceiptSchemaSha256Hex: HASH_F,
    settlementAccessKeys: [] as [],
    edictAccessKeys: [] as [],
    customerApproved: true as const,
    immutableActiveOrders: true as const,
    externalAuditStatus: audited
      ? 'independent_audit_evidence_attached' as const
      : 'required_before_customer_funds' as const,
    canaryStatus: canary ? 'passed' as const : 'required' as const,
    ...(canary ? { canaryReceiptSha256Hex: HASH_G } : {}),
  };
  const auditScope = confidentialIntentsAuditScopeDigest({
    ...base,
    capabilitySha256Hex: HASH_H,
  });
  const unsigned = {
    ...base,
    ...(audited ? {
      externalAuditEvidence: {
        auditor: 'Independent Security LLP',
        reportUri: 'https://auditor.example/reports/edict-confidential-v1',
        reportSha256Hex: HASH_H,
        completedOn: '2030-01-31',
        auditedScopeSha256Hex: auditScope,
      },
    } : {}),
  };
  return {
    ...unsigned,
    capabilitySha256Hex: confidentialIntentsCapabilityDigest(unsigned),
  };
}

test('audited capability produces a fail-closed confidential settlement binding', () => {
  const value = capability();
  assert.deepEqual(validateConfidentialIntentsCapability(value), []);
  assert.match(confidentialIntentsAdapterRef(value), new RegExp(`${value.capabilitySha256Hex}$`));

  const binding = confidentialIntentsSettlementBinding(value);
  assert.equal(binding.custodyMode, 'M2_external_escrow');
  assert.equal(binding.fundsController, 'customer_contract');
  assert.equal(binding.edictOperatorCanTransfer, false);
  assert.deepEqual(binding.confidentiality, {
    mode: 'confidential_settlement',
    capabilitySha256: value.capabilitySha256Hex,
    disclosurePolicySha256: HASH_E,
    fallback: 'fail_closed',
  });
});

test('capability and audit-scope tampering fail closed', () => {
  const value = capability();
  const tampered = { ...value, publicRecord: 'full' as 'commitments_only' };
  assert.match(validateConfidentialIntentsCapability(tampered).join('; '), /commitments_only/);
  assert.throws(() => confidentialIntentsSettlementBinding(tampered), /commitments_only/);

  const wrongAudit = {
    ...value,
    externalAuditEvidence: { ...value.externalAuditEvidence!, auditedScopeSha256Hex: HASH_A },
  };
  wrongAudit.capabilitySha256Hex = confidentialIntentsCapabilityDigest(wrongAudit);
  assert.match(validateConfidentialIntentsCapability(wrongAudit).join('; '), /does not cover/);

  assert.match(
    validateConfidentialIntentsCapability({ ...value, privacyMarketingClaim: 'anonymous' }).join('; '),
    /unknown key/,
  );
  assert.match(
    validateConfidentialIntentsCapability({
      ...value,
      externalAuditEvidence: null,
    }).join('; '),
    /must be an object/,
  );
});

test('unaudited or uncanaried capability cannot accept customer funds', () => {
  assert.throws(
    () => confidentialIntentsSettlementBinding(capability({ audited: false })),
    /independent external audit evidence/,
  );
  assert.throws(
    () => confidentialIntentsSettlementBinding(capability({ canary: false })),
    /mainnet canary/,
  );
});

test('public fallback must be an explicit signed choice', () => {
  assert.throws(
    () => confidentialIntentsSettlementBinding(capability(), {
      privacyFallback: 'allow_public_settlement',
    }),
    /publicFallbackAdapterRef/,
  );
  const binding = confidentialIntentsSettlementBinding(capability(), {
    privacyFallback: 'allow_public_settlement',
    publicFallbackAdapterRef: 'near-intents:v1:audited-public-fallback',
  });
  assert.equal(binding.confidentiality?.fallback, 'allow_public_settlement');
  assert.equal(
    binding.confidentiality?.publicFallbackAdapterRef,
    'near-intents:v1:audited-public-fallback',
  );
});
