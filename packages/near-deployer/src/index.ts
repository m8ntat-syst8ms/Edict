/**
 * NEAR deployment plans and post-deployment verification for Edict's keyless
 * customer settlement contract. This package constructs data only. It never
 * accepts, stores or uses a customer private key.
 */
import { createHash } from 'node:crypto';
import bs58 from 'bs58';
import {
  NEAR_INTENTS_MAINNET_CONTRACT,
  nearIntentsAdapterRef,
  nearIntentsRoute,
} from '@edict/near-intents';

export const CUSTOMER_SETTLEMENT_VERSION = 'edict-customer-settlement-v1';
export const DEPLOYMENT_FACTORY_VERSION = 'edict-deployment-factory-v1';
export const INTENTS_CUSTOMER_SETTLEMENT_VERSION = 'edict-customer-settlement-intents-v1';
export const INTENTS_DEPLOYMENT_FACTORY_VERSION = 'edict-intents-deployment-factory-v1';
export const MAINNET_RPC = 'https://free.rpc.fastnear.com';
export const TESTNET_RPC = 'https://test.rpc.fastnear.com';

export interface VerifierSignerConfig {
  signing_address: string;
  operator_id: string;
  edict_controlled: boolean;
  attestation_sha256: number[];
}

export interface VerifierPolicyConfig {
  scheme: 'ecdsa_secp256k1_eth';
  quorum: number;
  signers: VerifierSignerConfig[];
}

export interface CustomerSettlementConfig {
  customer_governance: string;
  removal_account: string;
  verifier_policy: VerifierPolicyConfig;
}

export interface IntentsSettlementConfig {
  customer: CustomerSettlementConfig;
  intents_contract: string;
  settlement_token_id: string;
  max_orders: number;
}

export interface ArtifactIdentity {
  sha256Hex: string;
  codeHashBase58: string;
  byteLength: number;
}

export interface ExternalAuditEvidence {
  auditor: string;
  reportUri: string;
  reportSha256Hex: string;
  completedOn: string;
  settlementCodeSha256Hex: string;
  factoryCodeSha256Hex?: string;
}

export interface IntentsExternalAuditEvidence extends ExternalAuditEvidence {
  /** Exact upstream Verifier code whose behavior and assumptions the audit reviewed. */
  intentsVerifierCodeSha256Hex: string;
}

export type NearDeploymentAction =
  | { type: 'create_account' }
  | { type: 'transfer'; depositYocto: string }
  | { type: 'deploy_global_contract'; mode: 'code_hash'; wasmBase64: string }
  | { type: 'use_global_contract'; codeHashBase58: string }
  | {
      type: 'function_call';
      methodName: string;
      args: Record<string, unknown>;
      gas: string;
      attachedDepositYocto: string;
    };

export interface DirectDeploymentPlan {
  version: 'edict-near-direct-deployment-1';
  kind: 'customer_parent_transaction';
  signerId: string;
  receiverId: string;
  adapterRef: string;
  actions: NearDeploymentAction[];
  guarantees: {
    addsAccessKey: false;
    immutableGlobalCodeByHash: true;
    customerSignsLocally: true;
  };
}

export interface GlobalContractPublishPlan {
  version: 'edict-near-global-publish-1';
  kind: 'global_contract_publish_transaction';
  signerId: string;
  receiverId: string;
  artifact: ArtifactIdentity;
  actions: NearDeploymentAction[];
  guarantees: {
    contentAddressedBySha256: true;
    publisherCannotReplaceCodeAtHash: true;
    containsNoCustomerFunds: true;
  };
}

export interface FactoryBootstrapPlan {
  version: 'edict-near-factory-bootstrap-1';
  kind: 'keyless_factory_bootstrap_transaction';
  signerId: string;
  receiverId: string;
  factoryCodeSha256Hex: string;
  settlementCodeSha256Hex: string;
  actions: NearDeploymentAction[];
  guarantees: {
    addsAccessKey: false;
    adminlessFactory: true;
    bothCodeHashesImmutable: true;
  };
}

export interface FactoryDeploymentPlan {
  version: 'edict-near-factory-deployment-1';
  kind: 'locked_factory_call';
  signerId: string;
  receiverId: string;
  expectedInstanceAccount: string;
  adapterRef: string;
  actions: NearDeploymentAction[];
  guarantees: {
    customerGovernanceMatchesSigner: true;
    factoryReceivesNoPrincipal: true;
    childAddsAccessKey: false;
  };
}

export interface IntentsDirectDeploymentPlan {
  version: 'edict-near-intents-direct-deployment-1';
  kind: 'customer_parent_transaction';
  signerId: string;
  receiverId: string;
  adapterRef: string;
  actions: NearDeploymentAction[];
  guarantees: {
    addsAccessKey: false;
    immutableGlobalCodeByHash: true;
    customerSignsLocally: true;
    intentsMainnetOnly: true;
  };
}

export interface IntentsFactoryDeploymentPlan {
  version: 'edict-near-intents-factory-deployment-1';
  kind: 'locked_factory_call';
  signerId: string;
  receiverId: string;
  expectedInstanceAccount: string;
  adapterRef: string;
  actions: NearDeploymentAction[];
  guarantees: {
    customerGovernanceMatchesSigner: true;
    factoryReceivesNoPrincipal: true;
    childAddsAccessKey: false;
    intentsMainnetOnly: true;
  };
}

export type NearNetwork = 'mainnet' | 'testnet';

export interface DeploymentManifest {
  version: 'edict-customer-deployment-1';
  chain: 'near';
  network: NearNetwork;
  settlementAccount: string;
  factoryAccount?: string;
  adapterRef: string;
  contractVersion: string;
  globalCodeSha256Hex: string;
  globalCodeHashBase58: string;
  factoryCodeSha256Hex?: string;
  factoryCodeHashBase58?: string;
  customerGovernance: string;
  removalAccount: string;
  verifierPolicySha256Hex: string;
  settlementAccessKeys: [];
  factoryAccessKeys?: [];
  edictAccessKeys: [];
  immutable: true;
  nativeNearOnly: true;
  externalAuditStatus: 'required_before_customer_funds' | 'independent_audit_evidence_attached';
  externalAuditEvidence?: ExternalAuditEvidence;
  verifiedBlockHash: string;
  verifiedBlockHeight: number;
  verifiedAtUnixMs: number;
  manifestSha256Hex: string;
}

export interface VerifyDeploymentOptions {
  network: NearNetwork;
  settlementAccount: string;
  expectedCodeSha256Hex: string;
  expectedConfig: CustomerSettlementConfig;
  factoryAccount?: string;
  expectedFactoryCodeSha256Hex?: string;
  rpcUrl?: string;
  fetchImpl?: typeof fetch;
  nowUnixMs?: number;
  externalAuditEvidence?: ExternalAuditEvidence;
}

export interface IntentsDeploymentManifest {
  version: 'edict-intents-customer-deployment-1';
  chain: 'near';
  network: 'mainnet';
  settlementAccount: string;
  factoryAccount?: string;
  adapterRef: string;
  contractVersion: string;
  globalCodeSha256Hex: string;
  globalCodeHashBase58: string;
  factoryCodeSha256Hex?: string;
  factoryCodeHashBase58?: string;
  customerGovernance: string;
  removalAccount: string;
  verifierPolicySha256Hex: string;
  settlementAccessKeys: [];
  factoryAccessKeys?: [];
  edictAccessKeys: [];
  immutable: true;
  nativeNearOnly: false;
  keylessIntentsAccount: true;
  intentsContract: typeof NEAR_INTENTS_MAINNET_CONTRACT;
  intentsVerifierCodeSha256Hex: string;
  intentsVerifierCodeHashBase58: string;
  intentsAuthByPredecessorEnabled: true;
  intentsSettlementAccountLocked: false;
  intentsExecutionPaused: false;
  intentsTransfersPaused: false;
  settlementTokenId: string;
  maxOrders: number;
  externalAuditStatus: 'required_before_customer_funds' | 'independent_audit_evidence_attached';
  externalAuditEvidence?: IntentsExternalAuditEvidence;
  verifiedBlockHash: string;
  verifiedBlockHeight: number;
  verifiedAtUnixMs: number;
  manifestSha256Hex: string;
}

export interface VerifyIntentsDeploymentOptions {
  network: 'mainnet';
  settlementAccount: string;
  expectedCodeSha256Hex: string;
  expectedIntentsVerifierCodeSha256Hex: string;
  expectedConfig: IntentsSettlementConfig;
  factoryAccount?: string;
  expectedFactoryCodeSha256Hex?: string;
  rpcUrl?: string;
  fetchImpl?: typeof fetch;
  nowUnixMs?: number;
  externalAuditEvidence?: IntentsExternalAuditEvidence;
}

export interface IntentsRuntimeStatus {
  version: 'edict-intents-runtime-status-1';
  settlementAccount: string;
  intentsContract: typeof NEAR_INTENTS_MAINNET_CONTRACT;
  intentsVerifierCodeSha256Hex: string;
  intentsAuthByPredecessorEnabled: true;
  intentsSettlementAccountLocked: false;
  intentsExecutionPaused: false;
  intentsTransfersPaused: false;
  verifiedBlockHash: string;
  verifiedBlockHeight: number;
  verifiedAtUnixMs: number;
}

export interface VerifyIntentsRuntimeOptions {
  manifest: IntentsDeploymentManifest;
  rpcUrl?: string;
  fetchImpl?: typeof fetch;
  nowUnixMs?: number;
}

const ACCOUNT_ID = /^(?=.{2,64}$)[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const INTENTS_ASSET_ID = /^nep141:(.+)$/;
const OPERATOR_ID = /^[A-Za-z0-9._:/-]{1,64}$/;
const ETH_ADDRESS = /^0x[0-9a-f]{40}$/;

function isBytes32(value: unknown, nonzero = true): value is number[] {
  return Array.isArray(value)
    && value.length === 32
    && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)
    && (!nonzero || value.some((byte) => byte !== 0));
}

function normalizeHex32(value: string, label: string): string {
  const normalized = value.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new TypeError(`${label} must be exactly 64 hex characters`);
  }
  return normalized;
}

function normalizeExternalAuditEvidence(
  evidence: ExternalAuditEvidence,
  expectedSettlementCodeHex: string,
  expectedFactoryCodeHex?: string,
): ExternalAuditEvidence {
  if (typeof evidence.auditor !== 'string' || evidence.auditor.trim().length < 2) {
    throw new TypeError('external audit evidence must identify the independent auditor');
  }
  if (
    typeof evidence.reportUri !== 'string'
    || !/^(https:\/\/|ipfs:\/\/)/.test(evidence.reportUri)
  ) {
    throw new TypeError('external audit reportUri must use https:// or ipfs://');
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(evidence.completedOn)) {
    throw new TypeError('external audit completedOn must be YYYY-MM-DD');
  }
  const reportSha256Hex = normalizeHex32(evidence.reportSha256Hex, 'external audit reportSha256Hex');
  const settlementCodeSha256Hex = normalizeHex32(
    evidence.settlementCodeSha256Hex,
    'external audit settlementCodeSha256Hex',
  );
  if (settlementCodeSha256Hex !== expectedSettlementCodeHex) {
    throw new TypeError('external audit evidence covers a different settlement artifact');
  }
  let factoryCodeSha256Hex: string | undefined;
  if (expectedFactoryCodeHex !== undefined) {
    if (evidence.factoryCodeSha256Hex === undefined) {
      throw new TypeError('external audit evidence must cover the deployment factory artifact');
    }
    factoryCodeSha256Hex = normalizeHex32(
      evidence.factoryCodeSha256Hex,
      'external audit factoryCodeSha256Hex',
    );
    if (factoryCodeSha256Hex !== expectedFactoryCodeHex) {
      throw new TypeError('external audit evidence covers a different deployment factory artifact');
    }
  } else if (evidence.factoryCodeSha256Hex !== undefined) {
    factoryCodeSha256Hex = normalizeHex32(
      evidence.factoryCodeSha256Hex,
      'external audit factoryCodeSha256Hex',
    );
  }
  return {
    auditor: evidence.auditor.trim(),
    reportUri: evidence.reportUri,
    reportSha256Hex,
    completedOn: evidence.completedOn,
    settlementCodeSha256Hex,
    ...(factoryCodeSha256Hex !== undefined ? { factoryCodeSha256Hex } : {}),
  };
}

function normalizeIntentsExternalAuditEvidence(
  evidence: IntentsExternalAuditEvidence,
  expectedSettlementCodeHex: string,
  expectedIntentsVerifierCodeHex: string,
  expectedFactoryCodeHex?: string,
): IntentsExternalAuditEvidence {
  const base = normalizeExternalAuditEvidence(
    evidence,
    expectedSettlementCodeHex,
    expectedFactoryCodeHex,
  );
  const intentsVerifierCodeSha256Hex = normalizeHex32(
    evidence.intentsVerifierCodeSha256Hex,
    'external audit intentsVerifierCodeSha256Hex',
  );
  if (intentsVerifierCodeSha256Hex !== expectedIntentsVerifierCodeHex) {
    throw new TypeError('external audit evidence covers a different Intents Verifier artifact');
  }
  return { ...base, intentsVerifierCodeSha256Hex };
}

export function validateCustomerSettlementConfig(config: unknown): string[] {
  const errors: string[] = [];
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    return ['config must be an object'];
  }
  const value = config as Partial<CustomerSettlementConfig>;
  if (typeof value.customer_governance !== 'string' || !ACCOUNT_ID.test(value.customer_governance)) {
    errors.push('customer_governance must be a canonical NEAR account id');
  }
  if (typeof value.removal_account !== 'string' || !ACCOUNT_ID.test(value.removal_account)) {
    errors.push('removal_account must be a canonical NEAR account id');
  }
  const policy = value.verifier_policy;
  if (policy === undefined || policy === null || typeof policy !== 'object') {
    errors.push('verifier_policy is required');
    return errors;
  }
  if (policy.scheme !== 'ecdsa_secp256k1_eth') {
    errors.push('verifier_policy.scheme must be ecdsa_secp256k1_eth');
  }
  if (!Number.isInteger(policy.quorum) || policy.quorum < 2) {
    errors.push('verifier_policy.quorum must be an integer of at least 2');
  }
  if (!Array.isArray(policy.signers) || policy.signers.length < 2 || policy.signers.length > 16) {
    errors.push('verifier_policy.signers must contain 2..16 entries');
    return errors;
  }
  const addresses = new Set<string>();
  const operators = new Set<string>();
  let previous = '';
  let edictControlled = 0;
  for (const [index, rawSigner] of policy.signers.entries()) {
    const path = `verifier_policy.signers[${index}]`;
    if (rawSigner === null || typeof rawSigner !== 'object' || Array.isArray(rawSigner)) {
      errors.push(`${path} must be an object`);
      continue;
    }
    const signer = rawSigner as VerifierSignerConfig;
    if (!ETH_ADDRESS.test(signer.signing_address)) {
      errors.push(`${path}.signing_address must be normalized lowercase 0x hex`);
    } else if (addresses.has(signer.signing_address)) {
      errors.push(`${path}.signing_address is duplicated`);
    }
    addresses.add(signer.signing_address);
    if (!OPERATOR_ID.test(signer.operator_id)) {
      errors.push(`${path}.operator_id is invalid`);
    } else if (operators.has(signer.operator_id)) {
      errors.push(`${path}.operator_id is duplicated`);
    }
    operators.add(signer.operator_id);
    if (previous !== '' && previous >= signer.operator_id) {
      errors.push('verifier_policy.signers must be strictly sorted by operator_id');
    }
    previous = signer.operator_id;
    if (typeof signer.edict_controlled !== 'boolean') {
      errors.push(`${path}.edict_controlled must be boolean`);
    } else if (signer.edict_controlled) {
      edictControlled += 1;
    }
    if (!isBytes32(signer.attestation_sha256)) {
      errors.push(`${path}.attestation_sha256 must be a nonzero 32-byte array`);
    }
  }
  if (Number.isInteger(policy.quorum)) {
    if (policy.quorum > policy.signers.length) {
      errors.push('verifier_policy.quorum exceeds signer count');
    }
    if (policy.signers.length - edictControlled < policy.quorum) {
      errors.push('quorum must remain satisfiable without Edict-controlled signers');
    }
    if (edictControlled >= policy.quorum) {
      errors.push('Edict-controlled signers must not satisfy quorum alone');
    }
  }
  return errors;
}

export function assertValidCustomerSettlementConfig(
  config: CustomerSettlementConfig,
): void {
  const errors = validateCustomerSettlementConfig(config);
  if (errors.length > 0) throw new TypeError(errors.join('; '));
}

export function validateIntentsSettlementConfig(config: unknown): string[] {
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    return ['config must be an object'];
  }
  const value = config as Partial<IntentsSettlementConfig>;
  const errors = validateCustomerSettlementConfig(value.customer);
  if (value.intents_contract !== NEAR_INTENTS_MAINNET_CONTRACT) {
    errors.push(`intents_contract must be ${NEAR_INTENTS_MAINNET_CONTRACT}`);
  }
  const assetMatch = typeof value.settlement_token_id === 'string'
    ? INTENTS_ASSET_ID.exec(value.settlement_token_id)
    : null;
  if (assetMatch === null || !ACCOUNT_ID.test(assetMatch[1]!)) {
    errors.push('settlement_token_id must be nep141:<canonical NEAR account id>');
  }
  if (!Number.isInteger(value.max_orders) || value.max_orders! < 1 || value.max_orders! > 100_000) {
    errors.push('max_orders must be an integer in [1, 100000]');
  }
  if (value.customer !== undefined) {
    if (value.customer.customer_governance === value.customer.removal_account) {
      errors.push('customer governance and removal account must differ');
    }
    if (
      value.customer.customer_governance === value.intents_contract
      || value.customer.removal_account === value.intents_contract
    ) {
      errors.push('intents contract cannot be a customer beneficiary');
    }
  }
  return errors;
}

export function assertValidIntentsSettlementConfig(config: IntentsSettlementConfig): void {
  const errors = validateIntentsSettlementConfig(config);
  if (errors.length > 0) throw new TypeError(errors.join('; '));
}

function intentsAdapterRef(settlementAccount: string, config: IntentsSettlementConfig): string {
  return nearIntentsAdapterRef(nearIntentsRoute({
    settlementAccount,
    settlementAsset: config.settlement_token_id,
    removalIntentsAccount: config.customer.removal_account,
  }));
}

export function identifyWasm(wasm: Uint8Array): ArtifactIdentity {
  if (!(wasm instanceof Uint8Array) || wasm.length === 0) {
    throw new TypeError('wasm must be a non-empty Uint8Array');
  }
  const digest = createHash('sha256').update(wasm).digest();
  return {
    sha256Hex: digest.toString('hex'),
    codeHashBase58: bs58.encode(digest),
    byteLength: wasm.length,
  };
}

export function adapterRef(settlementAccount: string): string {
  if (!ACCOUNT_ID.test(settlementAccount)) throw new TypeError('invalid settlement account');
  return `near:${settlementAccount}:${CUSTOMER_SETTLEMENT_VERSION}`;
}

function assertImmediateSubaccount(parent: string, child: string, label: string): void {
  if (!ACCOUNT_ID.test(parent) || !ACCOUNT_ID.test(child)) {
    throw new TypeError(`${label} and its parent must be canonical NEAR account ids`);
  }
  const suffix = `.${parent}`;
  if (!child.endsWith(suffix) || child.slice(0, -suffix.length).includes('.')) {
    throw new TypeError(`${label} must be an immediate subaccount of ${parent}`);
  }
}

function assertYocto(value: string, label: string): void {
  if (!/^[1-9]\d*$/.test(value)) throw new TypeError(`${label} must be a positive yoctoNEAR integer string`);
}

export function buildDirectDeploymentPlan(input: {
  signerId: string;
  instanceAccount: string;
  globalCodeSha256Hex: string;
  instanceBalanceYocto: string;
  config: CustomerSettlementConfig;
}): DirectDeploymentPlan {
  assertValidCustomerSettlementConfig(input.config);
  if (input.signerId !== input.config.customer_governance) {
    throw new TypeError('signerId must equal config.customer_governance');
  }
  assertImmediateSubaccount(input.signerId, input.instanceAccount, 'instanceAccount');
  assertYocto(input.instanceBalanceYocto, 'instanceBalanceYocto');
  const codeHex = normalizeHex32(input.globalCodeSha256Hex, 'globalCodeSha256Hex');
  return {
    version: 'edict-near-direct-deployment-1',
    kind: 'customer_parent_transaction',
    signerId: input.signerId,
    receiverId: input.instanceAccount,
    adapterRef: adapterRef(input.instanceAccount),
    actions: [
      { type: 'create_account' },
      { type: 'transfer', depositYocto: input.instanceBalanceYocto },
      { type: 'use_global_contract', codeHashBase58: bs58.encode(Buffer.from(codeHex, 'hex')) },
      {
        type: 'function_call',
        methodName: 'new',
        args: { config: structuredClone(input.config) },
        gas: '100000000000000',
        attachedDepositYocto: '0',
      },
    ],
    guarantees: {
      addsAccessKey: false,
      immutableGlobalCodeByHash: true,
      customerSignsLocally: true,
    },
  };
}

export function buildIntentsDirectDeploymentPlan(input: {
  signerId: string;
  instanceAccount: string;
  globalCodeSha256Hex: string;
  instanceBalanceYocto: string;
  config: IntentsSettlementConfig;
}): IntentsDirectDeploymentPlan {
  assertValidIntentsSettlementConfig(input.config);
  if (input.signerId !== input.config.customer.customer_governance) {
    throw new TypeError('signerId must equal config.customer.customer_governance');
  }
  assertImmediateSubaccount(input.signerId, input.instanceAccount, 'instanceAccount');
  assertYocto(input.instanceBalanceYocto, 'instanceBalanceYocto');
  const codeHex = normalizeHex32(input.globalCodeSha256Hex, 'globalCodeSha256Hex');
  return {
    version: 'edict-near-intents-direct-deployment-1',
    kind: 'customer_parent_transaction',
    signerId: input.signerId,
    receiverId: input.instanceAccount,
    adapterRef: intentsAdapterRef(input.instanceAccount, input.config),
    actions: [
      { type: 'create_account' },
      { type: 'transfer', depositYocto: input.instanceBalanceYocto },
      { type: 'use_global_contract', codeHashBase58: bs58.encode(Buffer.from(codeHex, 'hex')) },
      {
        type: 'function_call',
        methodName: 'new',
        args: { config: structuredClone(input.config) },
        gas: '100000000000000',
        attachedDepositYocto: '0',
      },
    ],
    guarantees: {
      addsAccessKey: false,
      immutableGlobalCodeByHash: true,
      customerSignsLocally: true,
      intentsMainnetOnly: true,
    },
  };
}

/** Publish immutable code once. The publisher controls its account, not the hash. */
export function buildGlobalContractPublishPlan(input: {
  publisherAccount: string;
  wasm: Uint8Array;
}): GlobalContractPublishPlan {
  if (!ACCOUNT_ID.test(input.publisherAccount)) throw new TypeError('publisherAccount is invalid');
  const artifact = identifyWasm(input.wasm);
  return {
    version: 'edict-near-global-publish-1',
    kind: 'global_contract_publish_transaction',
    signerId: input.publisherAccount,
    receiverId: input.publisherAccount,
    artifact,
    actions: [{
      type: 'deploy_global_contract',
      mode: 'code_hash',
      wasmBase64: Buffer.from(input.wasm).toString('base64'),
    }],
    guarantees: {
      contentAddressedBySha256: true,
      publisherCannotReplaceCodeAtHash: true,
      containsNoCustomerFunds: true,
    },
  };
}

/** Create, fund, install and initialize the version-fixed factory with no key. */
export function buildFactoryBootstrapPlan(input: {
  parentAccount: string;
  factoryAccount: string;
  factoryGlobalCodeSha256Hex: string;
  settlementGlobalCodeSha256Hex: string;
  factoryBalanceYocto: string;
  minimumInstanceBalanceYocto: string;
}): FactoryBootstrapPlan {
  assertImmediateSubaccount(input.parentAccount, input.factoryAccount, 'factoryAccount');
  assertYocto(input.factoryBalanceYocto, 'factoryBalanceYocto');
  assertYocto(input.minimumInstanceBalanceYocto, 'minimumInstanceBalanceYocto');
  const factoryCode = normalizeHex32(input.factoryGlobalCodeSha256Hex, 'factoryGlobalCodeSha256Hex');
  const settlementCode = normalizeHex32(
    input.settlementGlobalCodeSha256Hex,
    'settlementGlobalCodeSha256Hex',
  );
  return {
    version: 'edict-near-factory-bootstrap-1',
    kind: 'keyless_factory_bootstrap_transaction',
    signerId: input.parentAccount,
    receiverId: input.factoryAccount,
    factoryCodeSha256Hex: factoryCode,
    settlementCodeSha256Hex: settlementCode,
    actions: [
      { type: 'create_account' },
      { type: 'transfer', depositYocto: input.factoryBalanceYocto },
      {
        type: 'use_global_contract',
        codeHashBase58: bs58.encode(Buffer.from(factoryCode, 'hex')),
      },
      {
        type: 'function_call',
        methodName: 'new',
        args: {
          global_code_sha256: [...Buffer.from(settlementCode, 'hex')],
          minimum_instance_balance: input.minimumInstanceBalanceYocto,
        },
        gas: '100000000000000',
        attachedDepositYocto: '0',
      },
    ],
    guarantees: {
      addsAccessKey: false,
      adminlessFactory: true,
      bothCodeHashesImmutable: true,
    },
  };
}

export function buildFactoryDeploymentPlan(input: {
  factoryAccount: string;
  slug: string;
  requiredDepositYocto: string;
  config: CustomerSettlementConfig;
}): FactoryDeploymentPlan {
  assertValidCustomerSettlementConfig(input.config);
  if (!ACCOUNT_ID.test(input.factoryAccount)) throw new TypeError('factoryAccount is invalid');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])$/.test(input.slug)) {
    throw new TypeError('slug must contain 2..32 lowercase letters, digits or internal hyphens');
  }
  assertYocto(input.requiredDepositYocto, 'requiredDepositYocto');
  const instance = `${input.slug}.${input.factoryAccount}`;
  if (!ACCOUNT_ID.test(instance)) throw new TypeError('derived instance account is invalid');
  return {
    version: 'edict-near-factory-deployment-1',
    kind: 'locked_factory_call',
    signerId: input.config.customer_governance,
    receiverId: input.factoryAccount,
    expectedInstanceAccount: instance,
    adapterRef: adapterRef(instance),
    actions: [{
      type: 'function_call',
      methodName: 'create_instance',
      args: { slug: input.slug, config: structuredClone(input.config) },
      gas: '180000000000000',
      attachedDepositYocto: input.requiredDepositYocto,
    }],
    guarantees: {
      customerGovernanceMatchesSigner: true,
      factoryReceivesNoPrincipal: true,
      childAddsAccessKey: false,
    },
  };
}

export function buildIntentsFactoryDeploymentPlan(input: {
  factoryAccount: string;
  slug: string;
  requiredDepositYocto: string;
  config: IntentsSettlementConfig;
}): IntentsFactoryDeploymentPlan {
  assertValidIntentsSettlementConfig(input.config);
  if (!ACCOUNT_ID.test(input.factoryAccount)) throw new TypeError('factoryAccount is invalid');
  if (!/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])$/.test(input.slug)) {
    throw new TypeError('slug must contain 2..32 lowercase letters, digits or internal hyphens');
  }
  assertYocto(input.requiredDepositYocto, 'requiredDepositYocto');
  const instance = `${input.slug}.${input.factoryAccount}`;
  if (!ACCOUNT_ID.test(instance)) throw new TypeError('derived instance account is invalid');
  return {
    version: 'edict-near-intents-factory-deployment-1',
    kind: 'locked_factory_call',
    signerId: input.config.customer.customer_governance,
    receiverId: input.factoryAccount,
    expectedInstanceAccount: instance,
    adapterRef: intentsAdapterRef(instance, input.config),
    actions: [{
      type: 'function_call',
      methodName: 'create_instance',
      args: { slug: input.slug, config: structuredClone(input.config) },
      gas: '180000000000000',
      attachedDepositYocto: input.requiredDepositYocto,
    }],
    guarantees: {
      customerGovernanceMatchesSigner: true,
      factoryReceivesNoPrincipal: true,
      childAddsAccessKey: false,
      intentsMainnetOnly: true,
    },
  };
}

interface RpcEnvelope<T> {
  result?: T;
  error?: { message?: string; data?: unknown };
}

async function rpcCall<T>(
  rpcUrl: string,
  fetchImpl: typeof fetch,
  method: string,
  params: Record<string, unknown>,
): Promise<T> {
  const response = await fetchImpl(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'edict-deployment-verify', method, params }),
  });
  if (!response.ok) throw new Error(`NEAR RPC HTTP ${response.status}`);
  const envelope = await response.json() as RpcEnvelope<T>;
  if (envelope.error !== undefined || envelope.result === undefined) {
    throw new Error(`NEAR RPC ${method} failed: ${envelope.error?.message ?? 'missing result'}`);
  }
  return envelope.result;
}

async function rpcQuery<T>(
  rpcUrl: string,
  fetchImpl: typeof fetch,
  params: Record<string, unknown>,
): Promise<T> {
  return rpcCall<T>(rpcUrl, fetchImpl, 'query', params);
}

async function viewCall<T>(
  rpcUrl: string,
  fetchImpl: typeof fetch,
  accountId: string,
  methodName: string,
  blockId: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  const result = await rpcQuery<{ result: number[] }>(rpcUrl, fetchImpl, {
    request_type: 'call_function',
    block_id: blockId,
    account_id: accountId,
    method_name: methodName,
    args_base64: Buffer.from(JSON.stringify(args), 'utf8').toString('base64'),
  });
  return JSON.parse(Buffer.from(result.result).toString('utf8')) as T;
}

async function queryIntentsRuntimeHealth(input: {
  rpcUrl: string;
  fetchImpl: typeof fetch;
  blockId: string;
  settlementAccount: string;
  expectedIntentsCodeBase58: string;
}): Promise<{
  authByPredecessor: true;
  accountLocked: false;
  intentsPaused: false;
  transfersPaused: false;
}> {
  const verifierAccount = await rpcQuery<{ code_hash: string }>(input.rpcUrl, input.fetchImpl, {
    request_type: 'view_account',
    block_id: input.blockId,
    account_id: NEAR_INTENTS_MAINNET_CONTRACT,
  });
  if (verifierAccount.code_hash !== input.expectedIntentsCodeBase58) {
    throw new Error(
      `Intents Verifier code hash mismatch: expected ${input.expectedIntentsCodeBase58}, got ${verifierAccount.code_hash}`,
    );
  }
  const [authByPredecessor, accountLocked, intentsPaused, transfersPaused] = await Promise.all([
    viewCall<boolean>(
      input.rpcUrl,
      input.fetchImpl,
      NEAR_INTENTS_MAINNET_CONTRACT,
      'is_auth_by_predecessor_id_enabled',
      input.blockId,
      { account_id: input.settlementAccount },
    ),
    viewCall<boolean>(
      input.rpcUrl,
      input.fetchImpl,
      NEAR_INTENTS_MAINNET_CONTRACT,
      'is_account_locked',
      input.blockId,
      { account_id: input.settlementAccount },
    ),
    viewCall<boolean>(
      input.rpcUrl,
      input.fetchImpl,
      NEAR_INTENTS_MAINNET_CONTRACT,
      'pa_is_paused',
      input.blockId,
      { key: 'intents' },
    ),
    viewCall<boolean>(
      input.rpcUrl,
      input.fetchImpl,
      NEAR_INTENTS_MAINNET_CONTRACT,
      'pa_is_paused',
      input.blockId,
      { key: 'mt_transfer' },
    ),
  ]);
  if (authByPredecessor !== true) {
    throw new Error('Intents predecessor authorization is disabled for the settlement account');
  }
  if (accountLocked !== false) throw new Error('Intents settlement balance is locked upstream');
  if (intentsPaused !== false) throw new Error('Intents execution is paused upstream');
  if (transfersPaused !== false) throw new Error('Intents transfers are paused upstream');
  return {
    authByPredecessor: true,
    accountLocked: false,
    intentsPaused: false,
    transfersPaused: false,
  };
}

function bytesToHex(value: unknown, label: string): string {
  if (!isBytes32(value, false)) throw new Error(`${label} is not a 32-byte array`);
  return Buffer.from(value).toString('hex');
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`)
      .join(',')}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError('manifest contains a non-JSON value');
  return encoded;
}

export function deploymentManifestDigest(
  manifest: Omit<DeploymentManifest, 'manifestSha256Hex'> | DeploymentManifest,
): string {
  const { manifestSha256Hex: _ignored, ...payload } = manifest as DeploymentManifest;
  return createHash('sha256')
    .update('EDICT_CUSTOMER_DEPLOYMENT_MANIFEST_V1\0', 'utf8')
    .update(canonical(payload), 'utf8')
    .digest('hex');
}

export async function verifySettlementDeployment(
  options: VerifyDeploymentOptions,
): Promise<DeploymentManifest> {
  if (options.network !== 'mainnet' && options.network !== 'testnet') {
    throw new TypeError('network must be mainnet or testnet');
  }
  assertValidCustomerSettlementConfig(options.expectedConfig);
  if (!ACCOUNT_ID.test(options.settlementAccount)) throw new TypeError('settlementAccount is invalid');
  if (options.factoryAccount !== undefined && !ACCOUNT_ID.test(options.factoryAccount)) {
    throw new TypeError('factoryAccount is invalid');
  }
  if (options.factoryAccount === undefined && options.expectedFactoryCodeSha256Hex !== undefined) {
    throw new TypeError('factoryAccount is required when an expected factory code hash is supplied');
  }
  if (options.factoryAccount !== undefined && options.expectedFactoryCodeSha256Hex === undefined) {
    throw new TypeError('expectedFactoryCodeSha256Hex is required when verifying a factory deployment');
  }
  const expectedCodeHex = normalizeHex32(options.expectedCodeSha256Hex, 'expectedCodeSha256Hex');
  const expectedCodeBase58 = bs58.encode(Buffer.from(expectedCodeHex, 'hex'));
  const fetchImpl = options.fetchImpl ?? fetch;
  const rpcUrl = options.rpcUrl ?? (options.network === 'mainnet' ? MAINNET_RPC : TESTNET_RPC);

  const finalBlock = await rpcCall<{ header: { hash: string; height: number } }>(
    rpcUrl,
    fetchImpl,
    'block',
    { finality: 'final' },
  );
  if (
    typeof finalBlock.header?.hash !== 'string'
    || finalBlock.header.hash.length === 0
    || !Number.isSafeInteger(finalBlock.header.height)
    || finalBlock.header.height < 0
  ) {
    throw new Error('NEAR RPC returned a malformed final block');
  }
  const blockId = finalBlock.header.hash;

  const account = await rpcQuery<{ code_hash: string }>(rpcUrl, fetchImpl, {
    request_type: 'view_account',
    block_id: blockId,
    account_id: options.settlementAccount,
  });
  if (account.code_hash !== expectedCodeBase58) {
    throw new Error(`settlement code hash mismatch: expected ${expectedCodeBase58}, got ${account.code_hash}`);
  }
  const access = await rpcQuery<{ keys: unknown[] }>(rpcUrl, fetchImpl, {
    request_type: 'view_access_key_list',
    block_id: blockId,
    account_id: options.settlementAccount,
  });
  if (!Array.isArray(access.keys) || access.keys.length !== 0) {
    throw new Error('settlement account is not keyless');
  }
  const config = await viewCall<{
    contract_version: string;
    customer_governance: string;
    removal_account: string;
    verifier_policy: VerifierPolicyConfig;
    verifier_policy_sha256: number[];
    native_near_only: boolean;
  }>(rpcUrl, fetchImpl, options.settlementAccount, 'get_config', blockId);
  if (config.contract_version !== CUSTOMER_SETTLEMENT_VERSION || config.native_near_only !== true) {
    throw new Error('settlement contract version or asset mode is unexpected');
  }
  const actualConfig: CustomerSettlementConfig = {
    customer_governance: config.customer_governance,
    removal_account: config.removal_account,
    verifier_policy: config.verifier_policy,
  };
  assertValidCustomerSettlementConfig(actualConfig);
  if (canonical(actualConfig) !== canonical(options.expectedConfig)) {
    throw new Error('on-chain customer settlement config does not match the requested config');
  }

  let factoryAccessKeys: [] | undefined;
  let factoryCodeSha256Hex: string | undefined;
  let factoryCodeHashBase58: string | undefined;
  if (options.factoryAccount !== undefined) {
    factoryCodeSha256Hex = normalizeHex32(
      options.expectedFactoryCodeSha256Hex!,
      'expectedFactoryCodeSha256Hex',
    );
    factoryCodeHashBase58 = bs58.encode(Buffer.from(factoryCodeSha256Hex, 'hex'));
    const factoryAccount = await rpcQuery<{ code_hash: string }>(rpcUrl, fetchImpl, {
      request_type: 'view_account',
      block_id: blockId,
      account_id: options.factoryAccount,
    });
    if (factoryAccount.code_hash !== factoryCodeHashBase58) {
      throw new Error(
        `factory code hash mismatch: expected ${factoryCodeHashBase58}, got ${factoryAccount.code_hash}`,
      );
    }
    const factoryAccess = await rpcQuery<{ keys: unknown[] }>(rpcUrl, fetchImpl, {
      request_type: 'view_access_key_list',
      block_id: blockId,
      account_id: options.factoryAccount,
    });
    if (!Array.isArray(factoryAccess.keys) || factoryAccess.keys.length !== 0) {
      throw new Error('deployment factory account is not keyless');
    }
    const factoryConfig = await viewCall<{
      factory_version: string;
      settlement_contract_version: string;
      global_code_sha256: number[];
      adminless: boolean;
    }>(rpcUrl, fetchImpl, options.factoryAccount, 'get_config', blockId);
    if (
      factoryConfig.factory_version !== DEPLOYMENT_FACTORY_VERSION
      || factoryConfig.settlement_contract_version !== CUSTOMER_SETTLEMENT_VERSION
      || factoryConfig.adminless !== true
      || bytesToHex(factoryConfig.global_code_sha256, 'factory global code hash') !== expectedCodeHex
    ) {
      throw new Error('deployment factory configuration is not conforming');
    }
    const deployment = await viewCall<{
      instance_account: string;
      customer_governance: string;
      global_code_sha256: number[];
      status: string;
    } | null>(rpcUrl, fetchImpl, options.factoryAccount, 'get_deployment', blockId, {
      instance_account: options.settlementAccount,
    });
    if (
      deployment === null
      ||
      deployment.instance_account !== options.settlementAccount
      || deployment.customer_governance !== options.expectedConfig.customer_governance
      || deployment.status !== 'active'
      || bytesToHex(deployment.global_code_sha256, 'deployment global code hash') !== expectedCodeHex
    ) {
      throw new Error('factory deployment record is not active or does not match the customer');
    }
    factoryAccessKeys = [];
  }

  const externalAuditEvidence = options.externalAuditEvidence === undefined
    ? undefined
    : normalizeExternalAuditEvidence(
      options.externalAuditEvidence,
      expectedCodeHex,
      factoryCodeSha256Hex,
    );

  const unsignedManifest: Omit<DeploymentManifest, 'manifestSha256Hex'> = {
    version: 'edict-customer-deployment-1',
    chain: 'near',
    network: options.network,
    settlementAccount: options.settlementAccount,
    ...(options.factoryAccount !== undefined ? { factoryAccount: options.factoryAccount } : {}),
    adapterRef: adapterRef(options.settlementAccount),
    contractVersion: config.contract_version,
    globalCodeSha256Hex: expectedCodeHex,
    globalCodeHashBase58: expectedCodeBase58,
    ...(factoryCodeSha256Hex !== undefined ? { factoryCodeSha256Hex } : {}),
    ...(factoryCodeHashBase58 !== undefined ? { factoryCodeHashBase58 } : {}),
    customerGovernance: config.customer_governance,
    removalAccount: config.removal_account,
    verifierPolicySha256Hex: bytesToHex(config.verifier_policy_sha256, 'verifier policy hash'),
    settlementAccessKeys: [],
    ...(factoryAccessKeys !== undefined ? { factoryAccessKeys } : {}),
    edictAccessKeys: [],
    immutable: true,
    nativeNearOnly: true,
    externalAuditStatus: externalAuditEvidence === undefined
      ? 'required_before_customer_funds'
      : 'independent_audit_evidence_attached',
    ...(externalAuditEvidence !== undefined ? { externalAuditEvidence } : {}),
    verifiedBlockHash: blockId,
    verifiedBlockHeight: finalBlock.header.height,
    verifiedAtUnixMs: options.nowUnixMs ?? Date.now(),
  };
  return {
    ...unsignedManifest,
    manifestSha256Hex: deploymentManifestDigest(unsignedManifest),
  };
}

export function intentsDeploymentManifestDigest(
  manifest: Omit<IntentsDeploymentManifest, 'manifestSha256Hex'> | IntentsDeploymentManifest,
): string {
  const { manifestSha256Hex: _ignored, ...payload } = manifest as IntentsDeploymentManifest;
  return createHash('sha256')
    .update('EDICT_INTENTS_CUSTOMER_DEPLOYMENT_MANIFEST_V1\0', 'utf8')
    .update(canonical(payload), 'utf8')
    .digest('hex');
}

/**
 * Verify the separate mainnet-only Intents settlement line at one finalized
 * block. The upstream Verifier hash and predecessor authorization are part of
 * the result because both are required for claim liveness.
 */
export async function verifyIntentsSettlementDeployment(
  options: VerifyIntentsDeploymentOptions,
): Promise<IntentsDeploymentManifest> {
  if (options.network !== 'mainnet') {
    throw new TypeError('NEAR Intents deployment verification is mainnet only');
  }
  assertValidIntentsSettlementConfig(options.expectedConfig);
  if (!ACCOUNT_ID.test(options.settlementAccount)) throw new TypeError('settlementAccount is invalid');
  if (options.factoryAccount !== undefined && !ACCOUNT_ID.test(options.factoryAccount)) {
    throw new TypeError('factoryAccount is invalid');
  }
  if (options.factoryAccount === undefined && options.expectedFactoryCodeSha256Hex !== undefined) {
    throw new TypeError('factoryAccount is required when an expected factory code hash is supplied');
  }
  if (options.factoryAccount !== undefined && options.expectedFactoryCodeSha256Hex === undefined) {
    throw new TypeError('expectedFactoryCodeSha256Hex is required when verifying a factory deployment');
  }

  const expectedCodeHex = normalizeHex32(options.expectedCodeSha256Hex, 'expectedCodeSha256Hex');
  const expectedCodeBase58 = bs58.encode(Buffer.from(expectedCodeHex, 'hex'));
  const expectedIntentsCodeHex = normalizeHex32(
    options.expectedIntentsVerifierCodeSha256Hex,
    'expectedIntentsVerifierCodeSha256Hex',
  );
  const expectedIntentsCodeBase58 = bs58.encode(Buffer.from(expectedIntentsCodeHex, 'hex'));
  const fetchImpl = options.fetchImpl ?? fetch;
  const rpcUrl = options.rpcUrl ?? MAINNET_RPC;

  const finalBlock = await rpcCall<{ header: { hash: string; height: number } }>(
    rpcUrl,
    fetchImpl,
    'block',
    { finality: 'final' },
  );
  if (
    typeof finalBlock.header?.hash !== 'string'
    || finalBlock.header.hash.length === 0
    || !Number.isSafeInteger(finalBlock.header.height)
    || finalBlock.header.height < 0
  ) {
    throw new Error('NEAR RPC returned a malformed final block');
  }
  const blockId = finalBlock.header.hash;

  const settlementAccount = await rpcQuery<{ code_hash: string }>(rpcUrl, fetchImpl, {
    request_type: 'view_account',
    block_id: blockId,
    account_id: options.settlementAccount,
  });
  if (settlementAccount.code_hash !== expectedCodeBase58) {
    throw new Error(
      `Intents settlement code hash mismatch: expected ${expectedCodeBase58}, got ${settlementAccount.code_hash}`,
    );
  }
  const settlementAccess = await rpcQuery<{ keys: unknown[] }>(rpcUrl, fetchImpl, {
    request_type: 'view_access_key_list',
    block_id: blockId,
    account_id: options.settlementAccount,
  });
  if (!Array.isArray(settlementAccess.keys) || settlementAccess.keys.length !== 0) {
    throw new Error('Intents settlement account is not keyless');
  }

  const config = await viewCall<{
    contract_version: string;
    customer_governance: string;
    removal_account: string;
    intents_contract: string;
    settlement_token_id: string;
    max_orders: number;
    verifier_policy: VerifierPolicyConfig;
    verifier_policy_sha256: number[];
    native_near_only: boolean;
    keyless_intents_account: boolean;
  }>(rpcUrl, fetchImpl, options.settlementAccount, 'get_config', blockId);
  if (
    config.contract_version !== INTENTS_CUSTOMER_SETTLEMENT_VERSION
    || config.native_near_only !== false
    || config.keyless_intents_account !== true
  ) {
    throw new Error('Intents settlement contract version or asset mode is unexpected');
  }
  const actualConfig: IntentsSettlementConfig = {
    customer: {
      customer_governance: config.customer_governance,
      removal_account: config.removal_account,
      verifier_policy: config.verifier_policy,
    },
    intents_contract: config.intents_contract,
    settlement_token_id: config.settlement_token_id,
    max_orders: config.max_orders,
  };
  assertValidIntentsSettlementConfig(actualConfig);
  if (canonical(actualConfig) !== canonical(options.expectedConfig)) {
    throw new Error('on-chain Intents settlement config does not match the requested config');
  }

  await queryIntentsRuntimeHealth({
    rpcUrl,
    fetchImpl,
    blockId,
    settlementAccount: options.settlementAccount,
    expectedIntentsCodeBase58,
  });

  let factoryAccessKeys: [] | undefined;
  let factoryCodeSha256Hex: string | undefined;
  let factoryCodeHashBase58: string | undefined;
  if (options.factoryAccount !== undefined) {
    factoryCodeSha256Hex = normalizeHex32(
      options.expectedFactoryCodeSha256Hex!,
      'expectedFactoryCodeSha256Hex',
    );
    factoryCodeHashBase58 = bs58.encode(Buffer.from(factoryCodeSha256Hex, 'hex'));
    const factoryAccount = await rpcQuery<{ code_hash: string }>(rpcUrl, fetchImpl, {
      request_type: 'view_account',
      block_id: blockId,
      account_id: options.factoryAccount,
    });
    if (factoryAccount.code_hash !== factoryCodeHashBase58) {
      throw new Error(
        `Intents factory code hash mismatch: expected ${factoryCodeHashBase58}, got ${factoryAccount.code_hash}`,
      );
    }
    const factoryAccess = await rpcQuery<{ keys: unknown[] }>(rpcUrl, fetchImpl, {
      request_type: 'view_access_key_list',
      block_id: blockId,
      account_id: options.factoryAccount,
    });
    if (!Array.isArray(factoryAccess.keys) || factoryAccess.keys.length !== 0) {
      throw new Error('Intents deployment factory account is not keyless');
    }
    const factoryConfig = await viewCall<{
      factory_version: string;
      settlement_contract_version: string;
      global_code_sha256: number[];
      adminless: boolean;
      near_intents: boolean;
    }>(rpcUrl, fetchImpl, options.factoryAccount, 'get_config', blockId);
    if (
      factoryConfig.factory_version !== INTENTS_DEPLOYMENT_FACTORY_VERSION
      || factoryConfig.settlement_contract_version !== INTENTS_CUSTOMER_SETTLEMENT_VERSION
      || factoryConfig.adminless !== true
      || factoryConfig.near_intents !== true
      || bytesToHex(factoryConfig.global_code_sha256, 'Intents factory global code hash') !== expectedCodeHex
    ) {
      throw new Error('Intents deployment factory configuration is not conforming');
    }
    const deployment = await viewCall<{
      instance_account: string;
      customer_governance: string;
      global_code_sha256: number[];
      status: string;
    } | null>(rpcUrl, fetchImpl, options.factoryAccount, 'get_deployment', blockId, {
      instance_account: options.settlementAccount,
    });
    if (
      deployment === null
      || deployment.instance_account !== options.settlementAccount
      || deployment.customer_governance !== options.expectedConfig.customer.customer_governance
      || deployment.status !== 'active'
      || bytesToHex(deployment.global_code_sha256, 'Intents deployment global code hash') !== expectedCodeHex
    ) {
      throw new Error('Intents factory deployment record is not active or does not match the customer');
    }
    factoryAccessKeys = [];
  }

  const externalAuditEvidence = options.externalAuditEvidence === undefined
    ? undefined
    : normalizeIntentsExternalAuditEvidence(
      options.externalAuditEvidence,
      expectedCodeHex,
      expectedIntentsCodeHex,
      factoryCodeSha256Hex,
    );
  const unsignedManifest: Omit<IntentsDeploymentManifest, 'manifestSha256Hex'> = {
    version: 'edict-intents-customer-deployment-1',
    chain: 'near',
    network: 'mainnet',
    settlementAccount: options.settlementAccount,
    ...(options.factoryAccount !== undefined ? { factoryAccount: options.factoryAccount } : {}),
    adapterRef: intentsAdapterRef(options.settlementAccount, actualConfig),
    contractVersion: config.contract_version,
    globalCodeSha256Hex: expectedCodeHex,
    globalCodeHashBase58: expectedCodeBase58,
    ...(factoryCodeSha256Hex !== undefined ? { factoryCodeSha256Hex } : {}),
    ...(factoryCodeHashBase58 !== undefined ? { factoryCodeHashBase58 } : {}),
    customerGovernance: config.customer_governance,
    removalAccount: config.removal_account,
    verifierPolicySha256Hex: bytesToHex(config.verifier_policy_sha256, 'verifier policy hash'),
    settlementAccessKeys: [],
    ...(factoryAccessKeys !== undefined ? { factoryAccessKeys } : {}),
    edictAccessKeys: [],
    immutable: true,
    nativeNearOnly: false,
    keylessIntentsAccount: true,
    intentsContract: NEAR_INTENTS_MAINNET_CONTRACT,
    intentsVerifierCodeSha256Hex: expectedIntentsCodeHex,
    intentsVerifierCodeHashBase58: expectedIntentsCodeBase58,
    intentsAuthByPredecessorEnabled: true,
    intentsSettlementAccountLocked: false,
    intentsExecutionPaused: false,
    intentsTransfersPaused: false,
    settlementTokenId: config.settlement_token_id,
    maxOrders: config.max_orders,
    externalAuditStatus: externalAuditEvidence === undefined
      ? 'required_before_customer_funds'
      : 'independent_audit_evidence_attached',
    ...(externalAuditEvidence !== undefined ? { externalAuditEvidence } : {}),
    verifiedBlockHash: blockId,
    verifiedBlockHeight: finalBlock.header.height,
    verifiedAtUnixMs: options.nowUnixMs ?? Date.now(),
  };
  return {
    ...unsignedManifest,
    manifestSha256Hex: intentsDeploymentManifestDigest(unsignedManifest),
  };
}

/** Recheck mutable upstream Intents liveness assumptions immediately before funding. */
export async function verifyIntentsRuntime(
  options: VerifyIntentsRuntimeOptions,
): Promise<IntentsRuntimeStatus> {
  const manifest = options.manifest;
  if (
    manifest.version !== 'edict-intents-customer-deployment-1'
    || manifest.network !== 'mainnet'
    || manifest.intentsContract !== NEAR_INTENTS_MAINNET_CONTRACT
  ) {
    throw new TypeError('manifest is not a mainnet Edict Intents deployment');
  }
  if (intentsDeploymentManifestDigest(manifest) !== manifest.manifestSha256Hex) {
    throw new TypeError('Intents deployment manifest digest is invalid');
  }
  if (!ACCOUNT_ID.test(manifest.settlementAccount)) {
    throw new TypeError('manifest settlementAccount is invalid');
  }
  const verifierCodeHex = normalizeHex32(
    manifest.intentsVerifierCodeSha256Hex,
    'manifest intentsVerifierCodeSha256Hex',
  );
  const verifierCodeBase58 = bs58.encode(Buffer.from(verifierCodeHex, 'hex'));
  if (verifierCodeBase58 !== manifest.intentsVerifierCodeHashBase58) {
    throw new TypeError('manifest Intents Verifier code hash encodings disagree');
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const rpcUrl = options.rpcUrl ?? MAINNET_RPC;
  const finalBlock = await rpcCall<{ header: { hash: string; height: number } }>(
    rpcUrl,
    fetchImpl,
    'block',
    { finality: 'final' },
  );
  if (
    typeof finalBlock.header?.hash !== 'string'
    || finalBlock.header.hash.length === 0
    || !Number.isSafeInteger(finalBlock.header.height)
    || finalBlock.header.height < 0
  ) {
    throw new Error('NEAR RPC returned a malformed final block');
  }
  await queryIntentsRuntimeHealth({
    rpcUrl,
    fetchImpl,
    blockId: finalBlock.header.hash,
    settlementAccount: manifest.settlementAccount,
    expectedIntentsCodeBase58: verifierCodeBase58,
  });
  return {
    version: 'edict-intents-runtime-status-1',
    settlementAccount: manifest.settlementAccount,
    intentsContract: NEAR_INTENTS_MAINNET_CONTRACT,
    intentsVerifierCodeSha256Hex: verifierCodeHex,
    intentsAuthByPredecessorEnabled: true,
    intentsSettlementAccountLocked: false,
    intentsExecutionPaused: false,
    intentsTransfersPaused: false,
    verifiedBlockHash: finalBlock.header.hash,
    verifiedBlockHeight: finalBlock.header.height,
    verifiedAtUnixMs: options.nowUnixMs ?? Date.now(),
  };
}
