import assert from 'node:assert/strict';
import { test } from 'node:test';
import bs58 from 'bs58';
import {
  CUSTOMER_SETTLEMENT_VERSION,
  DEPLOYMENT_FACTORY_VERSION,
  INTENTS_CUSTOMER_SETTLEMENT_VERSION,
  INTENTS_DEPLOYMENT_FACTORY_VERSION,
  adapterRef,
  buildDirectDeploymentPlan,
  buildFactoryBootstrapPlan,
  buildFactoryDeploymentPlan,
  buildGlobalContractPublishPlan,
  buildIntentsDirectDeploymentPlan,
  buildIntentsFactoryDeploymentPlan,
  deploymentManifestDigest,
  identifyWasm,
  intentsDeploymentManifestDigest,
  validateCustomerSettlementConfig,
  validateIntentsSettlementConfig,
  verifyIntentsSettlementDeployment,
  verifyIntentsRuntime,
  verifySettlementDeployment,
  type CustomerSettlementConfig,
  type IntentsSettlementConfig,
} from './index.js';

const CODE_HEX = 'ab'.repeat(32);
const CODE_BASE58 = bs58.encode(Buffer.from(CODE_HEX, 'hex'));
const FACTORY_CODE_HEX = 'bc'.repeat(32);
const FACTORY_CODE_BASE58 = bs58.encode(Buffer.from(FACTORY_CODE_HEX, 'hex'));
const INTENTS_CODE_HEX = 'de'.repeat(32);
const INTENTS_CODE_BASE58 = bs58.encode(Buffer.from(INTENTS_CODE_HEX, 'hex'));
const BLOCK_HASH = bs58.encode(Buffer.from('cd'.repeat(32), 'hex'));

function signer(operator: string, suffix: number, edictControlled: boolean) {
  return {
    signing_address: `0x${suffix.toString(16).padStart(40, '0')}`,
    operator_id: operator,
    edict_controlled: edictControlled,
    attestation_sha256: Array<number>(32).fill(suffix),
  };
}

function config(): CustomerSettlementConfig {
  return {
    customer_governance: 'governance.customer.near',
    removal_account: 'pool.customer.near',
    verifier_policy: {
      scheme: 'ecdsa_secp256k1_eth',
      quorum: 2,
      signers: [
        signer('edict', 1, true),
        signer('independent-a', 2, false),
        signer('independent-b', 3, false),
      ],
    },
  };
}

function intentsConfig(): IntentsSettlementConfig {
  return {
    customer: config(),
    intents_contract: 'intents.near',
    settlement_token_id: 'nep141:usdc.omft.near',
    max_orders: 1_000,
  };
}

test('configuration validation preserves an independent quorum', () => {
  assert.deepEqual(validateCustomerSettlementConfig(config()), []);
  const unsafe = config();
  unsafe.verifier_policy.quorum = 1;
  assert.match(validateCustomerSettlementConfig(unsafe).join('; '), /at least 2/);

  const edictQuorum = config();
  edictQuorum.verifier_policy.signers[1]!.edict_controlled = true;
  assert.match(
    validateCustomerSettlementConfig(edictQuorum).join('; '),
    /Edict-controlled signers must not satisfy quorum alone/,
  );

  const unsorted = config();
  unsorted.verifier_policy.signers.reverse();
  assert.match(validateCustomerSettlementConfig(unsorted).join('; '), /strictly sorted/);
});

test('artifact identity pins both sha256 encodings', () => {
  const identity = identifyWasm(Uint8Array.from([0, 1, 2, 3]));
  assert.equal(identity.sha256Hex, '054edec1d0211f624fed0cbca9d4f9400b0e491c43742af2c5b0abebf0c990d8');
  assert.equal(Buffer.from(bs58.decode(identity.codeHashBase58)).toString('hex'), identity.sha256Hex);
  assert.equal(identity.byteLength, 4);
});

test('global publication is content-addressed and factory bootstrap adds no key', () => {
  const publication = buildGlobalContractPublishPlan({
    publisherAccount: 'publisher.edict.near',
    wasm: Uint8Array.from([0, 1, 2, 3]),
  });
  assert.equal(publication.actions[0]!.type, 'deploy_global_contract');
  assert.equal(publication.guarantees.publisherCannotReplaceCodeAtHash, true);

  const bootstrap = buildFactoryBootstrapPlan({
    parentAccount: 'edict.near',
    factoryAccount: 'v1.edict.near',
    factoryGlobalCodeSha256Hex: FACTORY_CODE_HEX,
    settlementGlobalCodeSha256Hex: CODE_HEX,
    factoryBalanceYocto: '500000000000000000000000',
    minimumInstanceBalanceYocto: '500000000000000000000000',
  });
  assert.deepEqual(bootstrap.actions.map(({ type }) => type), [
    'create_account',
    'transfer',
    'use_global_contract',
    'function_call',
  ]);
  assert.equal(bootstrap.guarantees.addsAccessKey, false);
  assert.equal(JSON.stringify(bootstrap).includes('add_key'), false);
});

test('direct deployment is one customer-signed keyless action batch', () => {
  const plan = buildDirectDeploymentPlan({
    signerId: 'governance.customer.near',
    instanceAccount: 'settlement.governance.customer.near',
    globalCodeSha256Hex: CODE_HEX,
    instanceBalanceYocto: '500000000000000000000000',
    config: config(),
  });
  assert.deepEqual(plan.actions.map(({ type }) => type), [
    'create_account',
    'transfer',
    'use_global_contract',
    'function_call',
  ]);
  assert.equal(plan.adapterRef, adapterRef(plan.receiverId));
  assert.equal(plan.guarantees.addsAccessKey, false);
  assert.throws(() => buildDirectDeploymentPlan({
    signerId: 'governance.customer.near',
    instanceAccount: 'nested.settlement.governance.customer.near',
    globalCodeSha256Hex: CODE_HEX,
    instanceBalanceYocto: '1',
    config: config(),
  }), /immediate subaccount/);
});

test('factory deployment is a standard call with no credential or principal field', () => {
  const plan = buildFactoryDeploymentPlan({
    factoryAccount: 'v1.factory.edict.near',
    slug: 'acme-settlement',
    requiredDepositYocto: '500100000000000000000000',
    config: config(),
  });
  assert.equal(plan.expectedInstanceAccount, 'acme-settlement.v1.factory.edict.near');
  assert.equal(plan.actions.length, 1);
  assert.equal(plan.actions[0]!.type, 'function_call');
  assert.equal(plan.guarantees.factoryReceivesNoPrincipal, true);
  assert.equal(JSON.stringify(plan).includes('private'), false);
  assert.equal(JSON.stringify(plan).includes('secret'), false);
});

test('Intents plans pin mainnet Verifier, asset and keyless customer deployment', () => {
  assert.deepEqual(validateIntentsSettlementConfig(intentsConfig()), []);
  const invalid = intentsConfig();
  invalid.intents_contract = 'substitute.near';
  assert.match(validateIntentsSettlementConfig(invalid).join('; '), /must be intents.near/);

  const direct = buildIntentsDirectDeploymentPlan({
    signerId: 'governance.customer.near',
    instanceAccount: 'intents.governance.customer.near',
    globalCodeSha256Hex: CODE_HEX,
    instanceBalanceYocto: '1000000000000000000000000',
    config: intentsConfig(),
  });
  assert.equal(direct.version, 'edict-near-intents-direct-deployment-1');
  assert.equal(direct.guarantees.intentsMainnetOnly, true);
  assert.match(direct.adapterRef, /^near-intents:v1:/);
  assert.equal(JSON.stringify(direct).includes('add_key'), false);

  const factory = buildIntentsFactoryDeploymentPlan({
    factoryAccount: 'intents-factory.edict.near',
    slug: 'protected',
    requiredDepositYocto: '1001000000000000000000000',
    config: intentsConfig(),
  });
  assert.equal(factory.expectedInstanceAccount, 'protected.intents-factory.edict.near');
  assert.equal(factory.signerId, 'governance.customer.near');
  assert.equal(factory.guarantees.factoryReceivesNoPrincipal, true);
});

function rpcFetch(options: { settlementKeys?: unknown[]; codeHash?: string } = {}): typeof fetch {
  return (async (_input: string | URL | Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as {
      method: string;
      params: Record<string, unknown>;
    };
    let result: unknown;
    if (request.method === 'block') {
      result = { header: { hash: BLOCK_HASH, height: 123_456 } };
    } else if (request.params.request_type === 'view_account') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      result = {
        code_hash: request.params.account_id === 'v1.factory.edict.near'
          ? FACTORY_CODE_BASE58
          : (options.codeHash ?? CODE_BASE58),
      };
    } else if (request.params.request_type === 'view_access_key_list') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      result = {
        keys: request.params.account_id === 'settlement.v1.factory.edict.near'
          ? (options.settlementKeys ?? [])
          : [],
      };
    } else if (request.params.request_type === 'call_function') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      const methodName = request.params.method_name;
      const accountId = request.params.account_id;
      let value: unknown;
      if (accountId === 'settlement.v1.factory.edict.near' && methodName === 'get_config') {
        value = {
          contract_version: CUSTOMER_SETTLEMENT_VERSION,
          customer_governance: config().customer_governance,
          removal_account: config().removal_account,
          verifier_policy: config().verifier_policy,
          verifier_policy_sha256: Array<number>(32).fill(9),
          native_near_only: true,
        };
      } else if (methodName === 'get_config') {
        value = {
          factory_version: DEPLOYMENT_FACTORY_VERSION,
          settlement_contract_version: CUSTOMER_SETTLEMENT_VERSION,
          global_code_sha256: Array<number>(32).fill(0xab),
          adminless: true,
        };
      } else if (methodName === 'get_deployment') {
        value = {
          instance_account: 'settlement.v1.factory.edict.near',
          customer_governance: config().customer_governance,
          global_code_sha256: Array<number>(32).fill(0xab),
          status: 'active',
        };
      } else {
        throw new Error(`unexpected view ${String(accountId)}.${String(methodName)}`);
      }
      result = { result: [...Buffer.from(JSON.stringify(value), 'utf8')] };
    } else {
      throw new Error(`unexpected RPC request ${JSON.stringify(request)}`);
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 'test', result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

function intentsRpcFetch(options: {
  settlementKeys?: unknown[];
  predecessorAuth?: boolean;
  intentsCodeHash?: string;
  accountLocked?: boolean;
  intentsPaused?: boolean;
  transfersPaused?: boolean;
} = {}): typeof fetch {
  return (async (_input: string | URL | Request, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as {
      method: string;
      params: Record<string, unknown>;
    };
    let result: unknown;
    if (request.method === 'block') {
      result = { header: { hash: BLOCK_HASH, height: 987_654 } };
    } else if (request.params.request_type === 'view_account') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      const accountId = request.params.account_id;
      result = {
        code_hash: accountId === 'intents.near'
          ? (options.intentsCodeHash ?? INTENTS_CODE_BASE58)
          : accountId === 'intents-factory.edict.near'
            ? FACTORY_CODE_BASE58
            : CODE_BASE58,
      };
    } else if (request.params.request_type === 'view_access_key_list') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      result = {
        keys: request.params.account_id === 'protected.intents-factory.edict.near'
          ? (options.settlementKeys ?? [])
          : [],
      };
    } else if (request.params.request_type === 'call_function') {
      assert.equal(request.params.block_id, BLOCK_HASH);
      const accountId = request.params.account_id;
      const methodName = request.params.method_name;
      let value: unknown;
      if (accountId === 'protected.intents-factory.edict.near' && methodName === 'get_config') {
        value = {
          contract_version: INTENTS_CUSTOMER_SETTLEMENT_VERSION,
          customer_governance: config().customer_governance,
          removal_account: config().removal_account,
          intents_contract: 'intents.near',
          settlement_token_id: intentsConfig().settlement_token_id,
          max_orders: intentsConfig().max_orders,
          order_count: 0,
          verifier_policy: config().verifier_policy,
          verifier_policy_sha256: Array<number>(32).fill(9),
          native_near_only: false,
          keyless_intents_account: true,
        };
      } else if (accountId === 'intents.near' && methodName === 'is_auth_by_predecessor_id_enabled') {
        const args = JSON.parse(Buffer.from(String(request.params.args_base64), 'base64').toString('utf8')) as {
          account_id: string;
        };
        assert.equal(args.account_id, 'protected.intents-factory.edict.near');
        value = options.predecessorAuth ?? true;
      } else if (accountId === 'intents.near' && methodName === 'is_account_locked') {
        value = options.accountLocked ?? false;
      } else if (accountId === 'intents.near' && methodName === 'pa_is_paused') {
        const args = JSON.parse(Buffer.from(String(request.params.args_base64), 'base64').toString('utf8')) as {
          key: string;
        };
        value = args.key === 'intents'
          ? (options.intentsPaused ?? false)
          : (options.transfersPaused ?? false);
      } else if (accountId === 'intents-factory.edict.near' && methodName === 'get_config') {
        value = {
          factory_version: INTENTS_DEPLOYMENT_FACTORY_VERSION,
          settlement_contract_version: INTENTS_CUSTOMER_SETTLEMENT_VERSION,
          global_code_sha256: Array<number>(32).fill(0xab),
          adminless: true,
          near_intents: true,
        };
      } else if (accountId === 'intents-factory.edict.near' && methodName === 'get_deployment') {
        value = {
          instance_account: 'protected.intents-factory.edict.near',
          customer_governance: config().customer_governance,
          global_code_sha256: Array<number>(32).fill(0xab),
          status: 'active',
        };
      } else {
        throw new Error(`unexpected Intents view ${String(accountId)}.${String(methodName)}`);
      }
      result = { result: [...Buffer.from(JSON.stringify(value), 'utf8')] };
    } else {
      throw new Error(`unexpected RPC request ${JSON.stringify(request)}`);
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 'test', result }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
}

test('deployment verification binds all facts to one final block and hashes the manifest', async () => {
  const manifest = await verifySettlementDeployment({
    network: 'testnet',
    settlementAccount: 'settlement.v1.factory.edict.near',
    factoryAccount: 'v1.factory.edict.near',
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedCodeSha256Hex: CODE_HEX,
    expectedConfig: config(),
    fetchImpl: rpcFetch(),
    nowUnixMs: 1_800_000_000_000,
  });
  assert.equal(manifest.settlementAccessKeys.length, 0);
  assert.equal(manifest.factoryAccessKeys?.length, 0);
  assert.equal(manifest.edictAccessKeys.length, 0);
  assert.equal(manifest.verifiedBlockHash, BLOCK_HASH);
  assert.equal(manifest.verifiedBlockHeight, 123_456);
  assert.equal(manifest.immutable, true);
  assert.equal(manifest.externalAuditStatus, 'required_before_customer_funds');
  assert.equal(manifest.manifestSha256Hex, deploymentManifestDigest(manifest));
});

test('deployment verification fails closed on an access key or code mismatch', async () => {
  const base = {
    network: 'mainnet' as const,
    settlementAccount: 'settlement.v1.factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedConfig: config(),
  };
  await assert.rejects(
    verifySettlementDeployment({ ...base, fetchImpl: rpcFetch({ settlementKeys: [{}] }) }),
    /not keyless/,
  );
  await assert.rejects(
    verifySettlementDeployment({ ...base, fetchImpl: rpcFetch({ codeHash: '11111111111111111111111111111111' }) }),
    /code hash mismatch/,
  );
});

test('audit evidence is build-specific and becomes part of the manifest digest', async () => {
  const evidence = {
    auditor: 'Independent Security Labs',
    reportUri: 'https://auditor.example/edict-v1.pdf',
    reportSha256Hex: 'de'.repeat(32),
    completedOn: '2026-08-01',
    settlementCodeSha256Hex: CODE_HEX,
    factoryCodeSha256Hex: FACTORY_CODE_HEX,
  };
  const manifest = await verifySettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'settlement.v1.factory.edict.near',
    factoryAccount: 'v1.factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedConfig: config(),
    fetchImpl: rpcFetch(),
    externalAuditEvidence: evidence,
  });
  assert.equal(manifest.externalAuditStatus, 'independent_audit_evidence_attached');
  assert.deepEqual(manifest.externalAuditEvidence, evidence);
  assert.equal(manifest.manifestSha256Hex, deploymentManifestDigest(manifest));

  await assert.rejects(verifySettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'settlement.v1.factory.edict.near',
    factoryAccount: 'v1.factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedConfig: config(),
    fetchImpl: rpcFetch(),
    externalAuditEvidence: { ...evidence, settlementCodeSha256Hex: '00'.repeat(32) },
  }), /different settlement artifact/);
});

test('Intents deployment verification pins upstream code and predecessor authorization', async () => {
  const manifest = await verifyIntentsSettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'protected.intents-factory.edict.near',
    factoryAccount: 'intents-factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
    expectedConfig: intentsConfig(),
    fetchImpl: intentsRpcFetch(),
    nowUnixMs: 1_800_000_000_000,
  });
  assert.equal(manifest.nativeNearOnly, false);
  assert.equal(manifest.keylessIntentsAccount, true);
  assert.equal(manifest.intentsContract, 'intents.near');
  assert.equal(manifest.intentsAuthByPredecessorEnabled, true);
  assert.equal(manifest.intentsSettlementAccountLocked, false);
  assert.equal(manifest.intentsExecutionPaused, false);
  assert.equal(manifest.intentsTransfersPaused, false);
  assert.equal(manifest.settlementTokenId, 'nep141:usdc.omft.near');
  assert.equal(manifest.externalAuditStatus, 'required_before_customer_funds');
  assert.equal(manifest.manifestSha256Hex, intentsDeploymentManifestDigest(manifest));

  await assert.rejects(
    verifyIntentsSettlementDeployment({
      network: 'mainnet',
      settlementAccount: 'protected.intents-factory.edict.near',
      expectedCodeSha256Hex: CODE_HEX,
      expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
      expectedConfig: intentsConfig(),
      fetchImpl: intentsRpcFetch({ predecessorAuth: false }),
    }),
    /predecessor authorization is disabled/,
  );
  await assert.rejects(
    verifyIntentsSettlementDeployment({
      network: 'mainnet',
      settlementAccount: 'protected.intents-factory.edict.near',
      expectedCodeSha256Hex: CODE_HEX,
      expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
      expectedConfig: intentsConfig(),
      fetchImpl: intentsRpcFetch({ intentsCodeHash: CODE_BASE58 }),
    }),
    /Verifier code hash mismatch/,
  );
});

test('Intents runtime guard detects mutable upstream drift immediately before funding', async () => {
  const manifest = await verifyIntentsSettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'protected.intents-factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
    expectedConfig: intentsConfig(),
    fetchImpl: intentsRpcFetch(),
  });
  const status = await verifyIntentsRuntime({
    manifest,
    fetchImpl: intentsRpcFetch(),
    nowUnixMs: 1_800_000_000_000,
  });
  assert.equal(status.intentsAuthByPredecessorEnabled, true);
  assert.equal(status.intentsSettlementAccountLocked, false);
  assert.equal(status.intentsExecutionPaused, false);
  assert.equal(status.intentsTransfersPaused, false);

  await assert.rejects(
    verifyIntentsRuntime({ manifest, fetchImpl: intentsRpcFetch({ accountLocked: true }) }),
    /balance is locked/,
  );
  await assert.rejects(
    verifyIntentsRuntime({ manifest, fetchImpl: intentsRpcFetch({ intentsPaused: true }) }),
    /execution is paused/,
  );
  await assert.rejects(
    verifyIntentsRuntime({ manifest, fetchImpl: intentsRpcFetch({ transfersPaused: true }) }),
    /transfers are paused/,
  );
});

test('Intents audit evidence must cover Edict, factory and upstream Verifier artifacts', async () => {
  const evidence = {
    auditor: 'Independent Security Labs',
    reportUri: 'https://auditor.example/edict-intents-v1.pdf',
    reportSha256Hex: 'ef'.repeat(32),
    completedOn: '2026-08-01',
    settlementCodeSha256Hex: CODE_HEX,
    factoryCodeSha256Hex: FACTORY_CODE_HEX,
    intentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
  };
  const manifest = await verifyIntentsSettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'protected.intents-factory.edict.near',
    factoryAccount: 'intents-factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
    expectedConfig: intentsConfig(),
    fetchImpl: intentsRpcFetch(),
    externalAuditEvidence: evidence,
  });
  assert.equal(manifest.externalAuditStatus, 'independent_audit_evidence_attached');
  assert.deepEqual(manifest.externalAuditEvidence, evidence);

  await assert.rejects(verifyIntentsSettlementDeployment({
    network: 'mainnet',
    settlementAccount: 'protected.intents-factory.edict.near',
    factoryAccount: 'intents-factory.edict.near',
    expectedCodeSha256Hex: CODE_HEX,
    expectedFactoryCodeSha256Hex: FACTORY_CODE_HEX,
    expectedIntentsVerifierCodeSha256Hex: INTENTS_CODE_HEX,
    expectedConfig: intentsConfig(),
    fetchImpl: intentsRpcFetch(),
    externalAuditEvidence: { ...evidence, intentsVerifierCodeSha256Hex: '00'.repeat(32) },
  }), /different Intents Verifier artifact/);
});
