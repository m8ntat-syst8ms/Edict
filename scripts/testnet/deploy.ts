/** Deploy and verify the current keyless native NEAR testnet stack. */
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import bs58 from 'bs58';
import {
  CREDENTIALS_DIR,
  NEAR,
  REPO_ROOT,
  RPC_URL,
  accounts,
  bytesToNumberArray,
  credentialFile,
  nearCall,
  nearCommand,
  suffix,
  viewBalance,
  viewFunction,
} from './common.js';

const FACTORY_BALANCE = 5n * NEAR;
const INSTANCE_BALANCE = 1n * NEAR;
const FACTORY_SLUG = 'm2';
const INSTANCE_SLUG = 'protect';
const REMOVAL_ACCOUNT = 'cfe1355f332ae784c34546a05fc3ba0e416efcf4f8541be449d2f3b57c88cfdc';
const SETTLEMENT_WASM = join(
  REPO_ROOT,
  'contracts/near/target/wasm32-unknown-unknown/release/edict_customer_settlement.wasm',
);
const FACTORY_WASM = join(
  REPO_ROOT,
  'contracts/near/target/wasm32-unknown-unknown/release/edict_deployment_factory.wasm',
);
const MANIFEST_PATH = join(REPO_ROOT, 'scripts/testnet/deployment.json');

interface DemoSignerFile {
  address: string;
  attestationPlaceholderSha256Hex: string;
}

async function rpcQuery(params: Record<string, unknown>): Promise<any> {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'edict-native-deploy', method: 'query', params }),
  });
  const body = await response.json() as { result?: unknown; error?: { cause?: { name?: string }; message?: string } };
  if (body.error !== undefined) throw Object.assign(new Error(body.error.message ?? 'NEAR RPC query failed'), { rpcError: body.error });
  return body.result;
}

async function accountExists(accountId: string): Promise<boolean> {
  try {
    await rpcQuery({ request_type: 'view_account', finality: 'final', account_id: accountId });
    return true;
  } catch (error) {
    const name = (error as { rpcError?: { cause?: { name?: string } } }).rpcError?.cause?.name;
    if (name === 'UNKNOWN_ACCOUNT') return false;
    throw error;
  }
}

async function accountEvidence(accountId: string): Promise<{
  codeSha256Hex: string;
  accessKeyCount: number;
  blockHeight: number;
}> {
  const [code, keys] = await Promise.all([
    rpcQuery({ request_type: 'view_code', finality: 'final', account_id: accountId }),
    rpcQuery({ request_type: 'view_access_key_list', finality: 'final', account_id: accountId }),
  ]) as [{ code_base64: string; block_height: number }, { keys: unknown[] }];
  return {
    codeSha256Hex: createHash('sha256').update(Buffer.from(code.code_base64, 'base64')).digest('hex'),
    accessKeyCount: keys.keys.length,
    blockHeight: code.block_height,
  };
}

async function artifact(path: string): Promise<{ sha256Hex: string; base58: string }> {
  const bytes = await readFile(path);
  const digest = createHash('sha256').update(bytes).digest();
  return { sha256Hex: digest.toString('hex'), base58: bs58.encode(digest) };
}

async function signer(name: string): Promise<DemoSignerFile> {
  return JSON.parse(await readFile(join(CREDENTIALS_DIR, name), 'utf8')) as DemoSignerFile;
}

function transactionHash(result: ReturnType<typeof nearCommand>, label: string): string {
  if (result.txHash === null) throw new Error(`${label} succeeded but its transaction hash was not found`);
  return result.txHash;
}

const accountSet = accounts();
const publisher = accountSet.requester;
const factoryAccount = `${FACTORY_SLUG}.${publisher}`;
const settlementAccount = `${INSTANCE_SLUG}.${factoryAccount}`;
const [settlementArtifact, factoryArtifact, edictSigner, operatorA, operatorB] = await Promise.all([
  artifact(SETTLEMENT_WASM),
  artifact(FACTORY_WASM),
  signer('demo-signer-a.json'),
  signer('demo-signer-a2.json'),
  signer('demo-signer-b.json'),
]);
const verifierPolicy = {
  scheme: 'ecdsa_secp256k1_eth',
  quorum: 2,
  signers: [
    {
      signing_address: edictSigner.address.toLowerCase(),
      operator_id: 'edict-staging',
      edict_controlled: true,
      attestation_sha256: bytesToNumberArray(Buffer.from(edictSigner.attestationPlaceholderSha256Hex, 'hex')),
    },
    {
      signing_address: operatorA.address.toLowerCase(),
      operator_id: 'staging-operator-a',
      edict_controlled: false,
      attestation_sha256: bytesToNumberArray(Buffer.from(operatorA.attestationPlaceholderSha256Hex, 'hex')),
    },
    {
      signing_address: operatorB.address.toLowerCase(),
      operator_id: 'staging-operator-b',
      edict_controlled: false,
      attestation_sha256: bytesToNumberArray(Buffer.from(operatorB.attestationPlaceholderSha256Hex, 'hex')),
    },
  ],
};
const customerConfig = {
  customer_governance: publisher,
  removal_account: REMOVAL_ACCOUNT,
  verifier_policy: verifierPolicy,
};

let settlementPublishTx: string | undefined;
let factoryBootstrapTx: string | undefined;
let instanceCreateTx: string | undefined;
const balanceBefore = await viewBalance(publisher);

if (!await accountExists(factoryAccount)) {
  settlementPublishTx = transactionHash(nearCommand([
    'transaction', 'construct-transaction', publisher,
    'receiver-id', publisher,
    'add-action', 'deploy-global-contract', SETTLEMENT_WASM,
    'as-global-hash', 'skip',
    'network-config', 'testnet',
    'sign-with-access-key-file', credentialFile(publisher),
    'send',
  ]), 'settlement global publication');
  factoryBootstrapTx = transactionHash(nearCommand([
    'transaction', 'construct-transaction', publisher,
    'receiver-id', factoryAccount,
    'add-action', 'create-account',
    'add-action', 'transfer', `${FACTORY_BALANCE} yoctoNEAR`,
    'add-action', 'deploy-contract', 'use-file', FACTORY_WASM,
    'with-init-call', 'new', 'json-args', JSON.stringify({
      global_code_sha256: bytesToNumberArray(Buffer.from(settlementArtifact.sha256Hex, 'hex')),
      minimum_instance_balance: INSTANCE_BALANCE.toString(),
    }),
    'prepaid-gas', '100 Tgas',
    'attached-deposit', '0 NEAR',
    'skip',
    'network-config', 'testnet',
    'sign-with-access-key-file', credentialFile(publisher),
    'send',
  ]), 'factory bootstrap');
}

const factoryConfig = await viewFunction<{
  factory_version: string;
  settlement_contract_version: string;
  global_code_sha256: number[];
  minimum_instance_balance: string;
  adminless: boolean;
}>(factoryAccount, 'get_config', {});
if (Buffer.from(factoryConfig.global_code_sha256).toString('hex') !== settlementArtifact.sha256Hex
    || factoryConfig.minimum_instance_balance !== INSTANCE_BALANCE.toString()
    || factoryConfig.adminless !== true) {
  throw new Error('deployed native factory configuration does not match the staged artifacts');
}

if (!await accountExists(settlementAccount)) {
  const required = await viewFunction<string>(factoryAccount, 'required_deployment_deposit', {});
  const create = nearCall({
    contract: factoryAccount,
    method: 'create_instance',
    args: { slug: INSTANCE_SLUG, config: customerConfig },
    gas: '200 Tgas',
    deposit: `${required} yoctoNEAR`,
    signAs: publisher,
  });
  instanceCreateTx = create.txHash ?? undefined;
  for (let attempt = 0; attempt < 30 && !await accountExists(settlementAccount); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
}
if (!await accountExists(settlementAccount)) throw new Error('native settlement instance was not created');

const [factoryEvidence, settlementEvidence, settlementConfig, deploymentRecord, balanceAfter] = await Promise.all([
  accountEvidence(factoryAccount),
  accountEvidence(settlementAccount),
  viewFunction<any>(settlementAccount, 'get_config', {}),
  viewFunction<any>(factoryAccount, 'get_deployment', { instance_account: settlementAccount }),
  viewBalance(publisher),
]);
if (factoryEvidence.codeSha256Hex !== factoryArtifact.sha256Hex || factoryEvidence.accessKeyCount !== 0) {
  throw new Error('native factory is not the expected keyless artifact');
}
if (settlementEvidence.codeSha256Hex !== settlementArtifact.sha256Hex || settlementEvidence.accessKeyCount !== 0) {
  throw new Error('native settlement is not the expected keyless artifact');
}
if (deploymentRecord?.status !== 'active' || settlementConfig.customer_governance !== publisher) {
  throw new Error('native settlement deployment is not active or customer-bound');
}

const manifest = {
  version: 'edict-native-testnet-1',
  generatedAt: new Date().toISOString(),
  network: 'testnet',
  deploymentSuffix: suffix(),
  warning: 'Unaudited NEAR Testnet deployment with simulated signer operators. Do not use customer funds.',
  accounts: {
    publisher,
    customerGovernance: publisher,
    worker: accountSet.worker,
    removal: REMOVAL_ACCOUNT,
    factory: factoryAccount,
    settlement: settlementAccount,
  },
  artifacts: {
    settlementSha256Hex: settlementArtifact.sha256Hex,
    settlementCodeHashBase58: settlementArtifact.base58,
    factorySha256Hex: factoryArtifact.sha256Hex,
    factoryCodeHashBase58: factoryArtifact.base58,
  },
  transactions: {
    settlementPublish: settlementPublishTx ?? null,
    factoryPublish: null,
    factoryBootstrap: factoryBootstrapTx ?? null,
    instanceCreate: instanceCreateTx ?? null,
  },
  verification: {
    factoryAccessKeys: factoryEvidence.accessKeyCount,
    settlementAccessKeys: settlementEvidence.accessKeyCount,
    factoryAdminless: factoryConfig.adminless,
    factoryDeploymentMode: 'direct_code_on_keyless_account',
    deploymentStatus: deploymentRecord.status,
    nativeNearOnly: settlementConfig.native_near_only,
    verifierPolicySha256Hex: Buffer.from(settlementConfig.verifier_policy_sha256).toString('hex'),
    blockHeight: Math.max(factoryEvidence.blockHeight, settlementEvidence.blockHeight),
  },
  testnetSpendYocto: (balanceBefore - balanceAfter).toString(),
};
await writeFile(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(JSON.stringify(manifest, null, 2));
