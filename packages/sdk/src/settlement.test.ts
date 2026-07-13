import { test } from 'node:test';
import assert from 'node:assert/strict';

import type { FinalVerdict } from '@edict/core';
import {
  deploymentManifestDigest,
  type DeploymentManifest,
  intentsDeploymentManifestDigest,
  type IntentsDeploymentManifest,
} from '@edict/near-deployer';
import { nearIntentsAdapterRef, nearIntentsRoute } from '@edict/near-intents';
import { createEdict, isFinalVerdict } from './client.js';
import { CustodyBoundaryError } from './errors.js';
import {
  buildSettlementDirective,
  customerContractSettlementFromManifest,
  nearIntentsSettlementFromManifest,
  verifySettlementDirective,
} from './settlement.js';

const EXPECTED_SHA = 'a'.repeat(64);
const ACTUAL_SHA = 'b'.repeat(64);

async function decidedProtection() {
  const edict = createEdict({ mode: 'sandbox' });
  edict.escrow.deposit('wallet:buyer', 1_000);
  const protection = await edict.protectPayment({
    paymentId: 'pay_self_custody_1',
    requester: 'wallet:buyer',
    worker: 'wallet:worker',
    promise: 'Deliver artifact.bin; it represents 100% of the protected payment.',
    amountUsd: 250,
    deadlineUnixMs: 1_850_000_000_000,
    currency: { asset: 'USDC', rail: 'acme-payments' },
    acceptanceCriteria: [{
      id: 'AC-1',
      statement: 'artifact.bin matches the pinned checksum and represents 100% of the payment.',
      machineCheck: { kind: 'hash_equals', params: { path: 'artifact.bin', sha256: EXPECTED_SHA } },
    }],
  });
  await edict.deliver(protection, {
    artifactHashes: [{ path: 'artifact.bin', sha256: ACTUAL_SHA, mediaType: 'application/octet-stream' }],
    deliveredAtUnixMs: 1_800_000_000_000,
  });
  const verdict = await edict.dispute(protection, {
    openedAtUnixMs: 1_800_000_100_000,
    submissions: { requester: 'The checksum does not match.' },
  });
  assert.ok(isFinalVerdict(verdict));
  const record = edict.getRecord(protection);
  assert.ok(record.caseObject);
  return { mandate: record.mandate, caseObject: record.caseObject, verdict };
}

test('buildSettlementDirective emits pure customer-rail instructions without Edict custody', async () => {
  const { mandate, caseObject, verdict } = await decidedProtection();
  const directive = buildSettlementDirective(mandate, caseObject, verdict);
  assert.equal(directive.version, 'edict-settlement-1');
  assert.equal(directive.settlement.custodyMode, 'M2_external_escrow');
  assert.equal(directive.settlement.fundsController, 'payment_rail');
  assert.equal(directive.settlement.adapterRef, 'rail:acme-payments');
  assert.equal(directive.settlement.edictOperatorCanTransfer, false);
  assert.equal(directive.settlement.edictOperatorCanFreeze, false);
  assert.equal(directive.settlement.edictOperatorIsRequiredSigner, false);
  assert.equal(directive.settlement.livenessFallback, 'controller_resolution');
  assert.equal(directive.railRef.rail, 'acme-payments');
  assert.deepEqual(directive.action, { kind: 'allocate', requesterBps: 10_000, workerBps: 0 });
  assert.match(directive.verdictSha256, /^[0-9a-f]{64}$/);
});

test('buildSettlementDirective rejects custody drift before a customer adapter sees it', async () => {
  const { mandate, caseObject, verdict } = await decidedProtection();
  assert.throws(
    () => buildSettlementDirective(
      mandate,
      { ...caseObject, custodyMode: 'M1_native_escrow' },
      verdict,
    ),
    CustodyBoundaryError,
  );
  assert.throws(
    () => buildSettlementDirective(
      mandate,
      { ...caseObject, railRef: { ...caseObject.railRef, adapterRef: 'rail:attacker' } },
      verdict,
    ),
    CustodyBoundaryError,
  );
  assert.throws(
    () => buildSettlementDirective(
      { ...mandate, settlement: undefined },
      caseObject,
      verdict,
    ),
    CustodyBoundaryError,
  );
});

test('buildSettlementDirective never turns an advisory verdict into a payment instruction', async () => {
  const { mandate, caseObject, verdict } = await decidedProtection();
  const advisory = {
    ...verdict,
    final: false,
    quality: { ...verdict.quality, escalated: true, escalationReason: 'low_confidence' },
  } as unknown as FinalVerdict;
  assert.throws(() => buildSettlementDirective(mandate, caseObject, advisory));
});

test('verifySettlementDirective accepts the exact handoff and rejects changed economics', async () => {
  const { mandate, caseObject, verdict } = await decidedProtection();
  const directive = buildSettlementDirective(mandate, caseObject, verdict);
  assert.doesNotThrow(() => verifySettlementDirective(mandate, caseObject, verdict, directive));

  const tampered = structuredClone(directive);
  tampered.action = { kind: 'allocate', requesterBps: 0, workerBps: 10_000 };
  assert.throws(
    () => verifySettlementDirective(mandate, caseObject, verdict, tampered),
    CustodyBoundaryError,
  );
});

function deploymentManifest(): DeploymentManifest {
  const settlementCode = 'ab'.repeat(32);
  const factoryCode = 'bc'.repeat(32);
  const value: Omit<DeploymentManifest, 'manifestSha256Hex'> = {
    version: 'edict-customer-deployment-1',
    chain: 'near',
    network: 'mainnet',
    settlementAccount: 'acme.v1.factory.edict.near',
    factoryAccount: 'v1.factory.edict.near',
    adapterRef: 'near:acme.v1.factory.edict.near:edict-customer-settlement-v1',
    contractVersion: 'edict-customer-settlement-v1',
    globalCodeSha256Hex: settlementCode,
    globalCodeHashBase58: 'settlement-code-hash',
    factoryCodeSha256Hex: factoryCode,
    factoryCodeHashBase58: 'factory-code-hash',
    customerGovernance: 'governance.acme.near',
    removalAccount: 'pool.acme.near',
    verifierPolicySha256Hex: 'cd'.repeat(32),
    settlementAccessKeys: [],
    factoryAccessKeys: [],
    edictAccessKeys: [],
    immutable: true,
    nativeNearOnly: true,
    externalAuditStatus: 'independent_audit_evidence_attached',
    externalAuditEvidence: {
      auditor: 'Independent Security Labs',
      reportUri: 'https://auditor.example/edict-v1.pdf',
      reportSha256Hex: 'de'.repeat(32),
      completedOn: '2026-08-01',
      settlementCodeSha256Hex: settlementCode,
      factoryCodeSha256Hex: factoryCode,
    },
    verifiedBlockHash: 'final-block-hash',
    verifiedBlockHeight: 123_456,
    verifiedAtUnixMs: 1_800_000_000_000,
  };
  return { ...value, manifestSha256Hex: deploymentManifestDigest(value) };
}

test('manifest handoff requires keyless chain facts and build-specific audit evidence', () => {
  const manifest = deploymentManifest();
  const binding = customerContractSettlementFromManifest(manifest);
  assert.equal(binding.adapterRef, manifest.adapterRef);
  assert.equal(binding.fundsController, 'customer_contract');
  assert.equal(binding.edictOperatorCanTransfer, false);

  const unaudited: DeploymentManifest = {
    ...manifest,
    externalAuditStatus: 'required_before_customer_funds',
    externalAuditEvidence: undefined,
  };
  unaudited.manifestSha256Hex = deploymentManifestDigest(unaudited);
  assert.throws(
    () => customerContractSettlementFromManifest(unaudited),
    /external audit evidence is required/,
  );

  const tampered = { ...manifest, globalCodeSha256Hex: '00'.repeat(32) };
  assert.throws(
    () => customerContractSettlementFromManifest(tampered),
    CustodyBoundaryError,
  );

  const redirected = { ...manifest, adapterRef: 'near:attacker.near:edict-customer-settlement-v1' };
  redirected.manifestSha256Hex = deploymentManifestDigest(redirected);
  assert.throws(
    () => customerContractSettlementFromManifest(redirected),
    /adapter or contract version/,
  );
});

function intentsDeploymentManifest(): IntentsDeploymentManifest {
  const settlementCode = '12'.repeat(32);
  const factoryCode = '23'.repeat(32);
  const intentsCode = '34'.repeat(32);
  const settlementAccount = 'acme.intents-factory.edict.near';
  const settlementTokenId = 'nep141:usdc.omft.near';
  const removalAccount = 'pool.acme.near';
  const adapterRef = nearIntentsAdapterRef(nearIntentsRoute({
    settlementAccount,
    settlementAsset: settlementTokenId,
    removalIntentsAccount: removalAccount,
  }));
  const value: Omit<IntentsDeploymentManifest, 'manifestSha256Hex'> = {
    version: 'edict-intents-customer-deployment-1',
    chain: 'near',
    network: 'mainnet',
    settlementAccount,
    factoryAccount: 'intents-factory.edict.near',
    adapterRef,
    contractVersion: 'edict-customer-settlement-intents-v1',
    globalCodeSha256Hex: settlementCode,
    globalCodeHashBase58: 'settlement-code-hash',
    factoryCodeSha256Hex: factoryCode,
    factoryCodeHashBase58: 'factory-code-hash',
    customerGovernance: 'governance.acme.near',
    removalAccount,
    verifierPolicySha256Hex: '45'.repeat(32),
    settlementAccessKeys: [],
    factoryAccessKeys: [],
    edictAccessKeys: [],
    immutable: true,
    nativeNearOnly: false,
    keylessIntentsAccount: true,
    intentsContract: 'intents.near',
    intentsVerifierCodeSha256Hex: intentsCode,
    intentsVerifierCodeHashBase58: 'intents-code-hash',
    intentsAuthByPredecessorEnabled: true,
    intentsSettlementAccountLocked: false,
    intentsExecutionPaused: false,
    intentsTransfersPaused: false,
    settlementTokenId,
    maxOrders: 1_000,
    externalAuditStatus: 'independent_audit_evidence_attached',
    externalAuditEvidence: {
      auditor: 'Independent Security Labs',
      reportUri: 'https://auditor.example/edict-intents-v1.pdf',
      reportSha256Hex: '56'.repeat(32),
      completedOn: '2026-08-01',
      settlementCodeSha256Hex: settlementCode,
      factoryCodeSha256Hex: factoryCode,
      intentsVerifierCodeSha256Hex: intentsCode,
    },
    verifiedBlockHash: 'final-block-hash',
    verifiedBlockHeight: 654_321,
    verifiedAtUnixMs: 1_800_000_000_000,
  };
  return { ...value, manifestSha256Hex: intentsDeploymentManifestDigest(value) };
}

test('Intents manifest handoff fails closed on audit, adapter or upstream-auth drift', () => {
  const manifest = intentsDeploymentManifest();
  const binding = nearIntentsSettlementFromManifest(manifest);
  assert.equal(binding.adapterRef, manifest.adapterRef);
  assert.equal(binding.fundsController, 'customer_contract');
  assert.equal(binding.edictOperatorCanTransfer, false);

  const unaudited: IntentsDeploymentManifest = {
    ...manifest,
    externalAuditStatus: 'required_before_customer_funds',
    externalAuditEvidence: undefined,
  };
  unaudited.manifestSha256Hex = intentsDeploymentManifestDigest(unaudited);
  assert.throws(() => nearIntentsSettlementFromManifest(unaudited), /external audit evidence is required/);

  const disabled = { ...manifest, intentsAuthByPredecessorEnabled: false as true };
  disabled.manifestSha256Hex = intentsDeploymentManifestDigest(disabled);
  assert.throws(() => nearIntentsSettlementFromManifest(disabled), /upstream authentication/);

  const redirected = { ...manifest, removalAccount: 'attacker.near' };
  redirected.manifestSha256Hex = intentsDeploymentManifestDigest(redirected);
  assert.throws(() => nearIntentsSettlementFromManifest(redirected), /adapter does not match/);
});
