/**
 * Pure settlement-directive construction.
 *
 * Edict decides and signs an outcome; it never applies the outcome to funds.
 * The customer-hosted wallet, contract or payment rail independently verifies
 * this directive and moves assets using credentials Edict never receives.
 */

import type {
  CaseObject,
  FinalVerdict,
  LivenessFallback,
  OrderMandate,
  SettlementAction,
  SettlementBinding,
  SettlementDirective,
} from '@edict/core';
import { assertExecutableVerdict, validateSettlementBinding } from '@edict/core';
import { canonicalOrderMandateHash, canonicalize, sha256Hex } from '@edict/evidence';
import {
  CUSTOMER_SETTLEMENT_VERSION,
  INTENTS_CUSTOMER_SETTLEMENT_VERSION,
  adapterRef as nearAdapterRef,
  deploymentManifestDigest,
  type DeploymentManifest,
  intentsDeploymentManifestDigest,
  type IntentsDeploymentManifest,
} from '@edict/near-deployer';
import {
  NEAR_INTENTS_MAINNET_CONTRACT,
  nearIntentsAdapterRef,
  nearIntentsRoute,
  nearIntentsSettlementBinding,
} from '@edict/near-intents';
import { CustodyBoundaryError } from './errors.js';

export interface CustomerContractSettlementOptions {
  resolutionTimeoutMs?: number;
  livenessFallback?: LivenessFallback;
}

export interface ManifestSettlementOptions extends CustomerContractSettlementOptions {
  /** Testnet is intentionally opt-in; production bindings default to mainnet. */
  allowTestnet?: boolean;
}

export interface AtomicSettlementAllocation {
  requesterPrincipalAtomic: string;
  workerPrincipalAtomic: string;
  bondRefundAtomic: string;
  bondToCounterpartyAtomic: string;
  bondToRemovalAtomic: string;
}

const MAX_U128 = (1n << 128n) - 1n;

function atomic(value: string, label: string): bigint {
  if (!/^\d+$/.test(value)) throw new TypeError(`${label} must be an unsigned atomic-unit integer`);
  const parsed = BigInt(value);
  if (parsed > MAX_U128) throw new TypeError(`${label} exceeds the uint128 settlement limit`);
  return parsed;
}

/** Exact integer allocation used by customer adapters and the NEAR contract. */
export function allocateAtomicSettlement(input: {
  principalAtomic: string;
  bondAtomic: string;
  requesterBps: number;
  disputant: 'requester' | 'worker';
}): AtomicSettlementAllocation {
  if (!Number.isInteger(input.requesterBps) || input.requesterBps < 0 || input.requesterBps > 10_000) {
    throw new TypeError('requesterBps must be an integer in [0, 10000]');
  }
  const principal = atomic(input.principalAtomic, 'principalAtomic');
  const bond = atomic(input.bondAtomic, 'bondAtomic');
  const requesterBps = BigInt(input.requesterBps);
  const requesterPrincipal = principal * requesterBps / 10_000n;
  const workerPrincipal = principal - requesterPrincipal;
  const disputantBps = input.disputant === 'requester' ? requesterBps : 10_000n - requesterBps;
  const bondRefund = bond * disputantBps / 10_000n;
  const forfeited = bond - bondRefund;
  const bondToCounterparty = forfeited / 2n;
  const bondToRemoval = forfeited - bondToCounterparty;
  return {
    requesterPrincipalAtomic: requesterPrincipal.toString(),
    workerPrincipalAtomic: workerPrincipal.toString(),
    bondRefundAtomic: bondRefund.toString(),
    bondToCounterpartyAtomic: bondToCounterparty.toString(),
    bondToRemovalAtomic: bondToRemoval.toString(),
  };
}

/** Build the one-time binding for a customer-owned settlement contract. */
export function customerContractSettlement(
  adapterRef: string,
  options: CustomerContractSettlementOptions = {},
): SettlementBinding {
  const binding: SettlementBinding = {
    custodyMode: 'M2_external_escrow',
    fundsController: 'customer_contract',
    adapterRef,
    edictOperatorCanTransfer: false,
    edictOperatorCanFreeze: false,
    edictOperatorIsRequiredSigner: false,
    resolutionTimeoutMs: options.resolutionTimeoutMs ?? 72 * 60 * 60 * 1_000,
    livenessFallback: options.livenessFallback ?? 'controller_resolution',
  };
  const problems = validateSettlementBinding(binding);
  if (problems.length > 0) throw new CustodyBoundaryError(problems);
  return binding;
}

/**
 * Build the production binding from a chain-verified deployment manifest.
 * This path fails closed until build-specific independent-audit evidence is
 * attached. It verifies evidence binding, not auditor competence or findings.
 */
export function customerContractSettlementFromManifest(
  manifest: DeploymentManifest,
  options: ManifestSettlementOptions = {},
): SettlementBinding {
  const problems: string[] = [];
  if (manifest.version !== 'edict-customer-deployment-1' || manifest.chain !== 'near') {
    problems.push('deployment manifest is not an Edict NEAR customer deployment');
  }
  if (manifest.network !== 'mainnet' && options.allowTestnet !== true) {
    problems.push('production settlement requires a mainnet deployment manifest');
  }
  if (manifest.immutable !== true) problems.push('settlement deployment is not immutable');
  if (manifest.nativeNearOnly !== true) problems.push('settlement asset mode is unexpected');
  if (
    manifest.contractVersion !== CUSTOMER_SETTLEMENT_VERSION
    || manifest.adapterRef !== nearAdapterRef(manifest.settlementAccount)
  ) {
    problems.push('settlement adapter or contract version does not match the verified account');
  }
  if (
    !Array.isArray(manifest.settlementAccessKeys)
    || !Array.isArray(manifest.edictAccessKeys)
    || manifest.settlementAccessKeys.length !== 0
    || manifest.edictAccessKeys.length !== 0
  ) {
    problems.push('settlement deployment exposes an access key');
  }
  if (
    manifest.factoryAccount !== undefined
    && (!Array.isArray(manifest.factoryAccessKeys) || manifest.factoryAccessKeys.length !== 0)
  ) {
    problems.push('deployment factory exposes an access key');
  }
  if (manifest.externalAuditStatus !== 'independent_audit_evidence_attached') {
    problems.push('independent external audit evidence is required before customer funds');
  }
  const audit = manifest.externalAuditEvidence;
  if (audit === undefined) {
    problems.push('external audit evidence is missing');
  } else {
    if (audit.settlementCodeSha256Hex !== manifest.globalCodeSha256Hex) {
      problems.push('external audit evidence does not cover the deployed settlement artifact');
    }
    if (
      manifest.factoryCodeSha256Hex !== undefined
      && audit.factoryCodeSha256Hex !== manifest.factoryCodeSha256Hex
    ) {
      problems.push('external audit evidence does not cover the deployed factory artifact');
    }
  }
  if (deploymentManifestDigest(manifest) !== manifest.manifestSha256Hex) {
    problems.push('deployment manifest digest is invalid');
  }
  if (problems.length > 0) throw new CustodyBoundaryError(problems);

  return customerContractSettlement(manifest.adapterRef, options);
}

/** Build a production cross-chain binding from a finalized, audited Intents manifest. */
export function nearIntentsSettlementFromManifest(
  manifest: IntentsDeploymentManifest,
  options: CustomerContractSettlementOptions = {},
): SettlementBinding {
  const problems: string[] = [];
  if (manifest.version !== 'edict-intents-customer-deployment-1' || manifest.chain !== 'near') {
    problems.push('deployment manifest is not an Edict NEAR Intents customer deployment');
  }
  if (manifest.network !== 'mainnet') problems.push('NEAR Intents settlement is mainnet only');
  if (manifest.immutable !== true) problems.push('Intents settlement deployment is not immutable');
  if (manifest.nativeNearOnly !== false || manifest.keylessIntentsAccount !== true) {
    problems.push('Intents settlement asset or account mode is unexpected');
  }
  if (
    manifest.contractVersion !== INTENTS_CUSTOMER_SETTLEMENT_VERSION
    || manifest.intentsContract !== NEAR_INTENTS_MAINNET_CONTRACT
    || manifest.intentsAuthByPredecessorEnabled !== true
    || manifest.intentsSettlementAccountLocked !== false
    || manifest.intentsExecutionPaused !== false
    || manifest.intentsTransfersPaused !== false
  ) {
    problems.push('Intents settlement contract or upstream authentication is not conforming');
  }
  let expectedAdapterRef: string | undefined;
  try {
    expectedAdapterRef = nearIntentsAdapterRef(nearIntentsRoute({
      settlementAccount: manifest.settlementAccount,
      settlementAsset: manifest.settlementTokenId,
      removalIntentsAccount: manifest.removalAccount,
    }));
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  if (expectedAdapterRef !== undefined && manifest.adapterRef !== expectedAdapterRef) {
    problems.push('Intents adapter does not match the verified account, asset and removal identity');
  }
  if (
    !Array.isArray(manifest.settlementAccessKeys)
    || !Array.isArray(manifest.edictAccessKeys)
    || manifest.settlementAccessKeys.length !== 0
    || manifest.edictAccessKeys.length !== 0
  ) {
    problems.push('Intents settlement deployment exposes an access key');
  }
  if (
    manifest.factoryAccount !== undefined
    && (!Array.isArray(manifest.factoryAccessKeys) || manifest.factoryAccessKeys.length !== 0)
  ) {
    problems.push('Intents deployment factory exposes an access key');
  }
  if (manifest.externalAuditStatus !== 'independent_audit_evidence_attached') {
    problems.push('independent external audit evidence is required before customer funds');
  }
  const audit = manifest.externalAuditEvidence;
  if (audit === undefined) {
    problems.push('external audit evidence is missing');
  } else {
    if (audit.settlementCodeSha256Hex !== manifest.globalCodeSha256Hex) {
      problems.push('external audit evidence does not cover the deployed Intents settlement artifact');
    }
    if (
      manifest.factoryCodeSha256Hex !== undefined
      && audit.factoryCodeSha256Hex !== manifest.factoryCodeSha256Hex
    ) {
      problems.push('external audit evidence does not cover the deployed Intents factory artifact');
    }
    if (audit.intentsVerifierCodeSha256Hex !== manifest.intentsVerifierCodeSha256Hex) {
      problems.push('external audit evidence does not cover the pinned Intents Verifier artifact');
    }
  }
  if (intentsDeploymentManifestDigest(manifest) !== manifest.manifestSha256Hex) {
    problems.push('Intents deployment manifest digest is invalid');
  }
  if (problems.length > 0) throw new CustodyBoundaryError(problems);

  return nearIntentsSettlementBinding(nearIntentsRoute({
    settlementAccount: manifest.settlementAccount,
    settlementAsset: manifest.settlementTokenId,
    removalIntentsAccount: manifest.removalAccount,
  }), options);
}

function actionFor(verdict: FinalVerdict): SettlementAction {
  switch (verdict.ruling.kind) {
    case 'requester_wins':
      return { kind: 'allocate', requesterBps: 10_000, workerBps: 0 };
    case 'worker_wins':
      return { kind: 'allocate', requesterBps: 0, workerBps: 10_000 };
    case 'split':
      return {
        kind: 'allocate',
        requesterBps: verdict.ruling.requesterBps,
        workerBps: 10_000 - verdict.ruling.requesterBps,
      };
    case 'redo':
      return { kind: 'hold_for_redo', newDeadlineUnixMs: verdict.ruling.newDeadlineUnixMs };
    case 'categorical':
    case 'scalar':
      return { kind: 'record_only' };
  }
}

/**
 * Derive a customer-actionable instruction from the exact signed mandate and
 * final verdict. The function performs no I/O and has no custody capability.
 */
export function buildSettlementDirective(
  mandate: OrderMandate,
  caseObject: CaseObject,
  verdict: FinalVerdict,
): SettlementDirective {
  const problems: string[] = [];
  if (mandate.version !== 'edict-om-2') {
    problems.push('production settlement requires edict-om-2');
  }
  if (mandate.settlement === undefined) {
    problems.push('the signed mandate has no settlement binding');
  } else {
    problems.push(...validateSettlementBinding(mandate.settlement, 'mandate.settlement'));
    if (caseObject.custodyMode !== mandate.settlement.custodyMode) {
      problems.push(
        `case custodyMode ${caseObject.custodyMode} does not match signed mode ${mandate.settlement.custodyMode}`,
      );
    }
    if (caseObject.railRef.rail !== mandate.currency.rail) {
      problems.push(
        `case rail ${caseObject.railRef.rail} does not match signed currency rail ${mandate.currency.rail}`,
      );
    }
    if (caseObject.railRef['adapterRef'] !== undefined &&
        caseObject.railRef['adapterRef'] !== mandate.settlement.adapterRef) {
      problems.push('case adapterRef does not match the signed customer-hosted adapter');
    }
  }
  const mandateHash = canonicalOrderMandateHash(mandate);
  if (caseObject.orderMandateHash !== mandateHash) {
    problems.push(`case orderMandateHash does not match the supplied mandate (${mandateHash})`);
  }
  if (verdict.caseId !== caseObject.caseId) {
    problems.push(`verdict caseId ${verdict.caseId} does not match case ${caseObject.caseId}`);
  }
  if (problems.length > 0) throw new CustodyBoundaryError(problems);

  assertExecutableVerdict(verdict, caseObject.decisionSpace);
  return {
    version: 'edict-settlement-1',
    caseId: caseObject.caseId,
    orderMandateHash: mandateHash,
    verdictSha256: sha256Hex(canonicalize(verdict)),
    issuedAtUnixMs: verdict.issuedAtUnixMs,
    settlement: structuredClone(mandate.settlement!),
    railRef: structuredClone(caseObject.railRef),
    outcome: structuredClone(verdict.ruling),
    action: actionFor(verdict),
  };
}

/**
 * Rebuild and compare a directive before a customer-hosted executor applies
 * it. This catches transport tampering and prevents an authenticated webhook
 * from becoming a bearer instruction.
 */
export function verifySettlementDirective(
  mandate: OrderMandate,
  caseObject: CaseObject,
  verdict: FinalVerdict,
  received: SettlementDirective,
): void {
  const expected = buildSettlementDirective(mandate, caseObject, verdict);
  if (canonicalize(expected) !== canonicalize(received)) {
    throw new CustodyBoundaryError([
      'received settlement directive does not match the locally rebuilt directive',
    ]);
  }
}
