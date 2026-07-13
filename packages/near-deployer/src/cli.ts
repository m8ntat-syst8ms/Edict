#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  buildDirectDeploymentPlan,
  buildFactoryBootstrapPlan,
  buildFactoryDeploymentPlan,
  buildGlobalContractPublishPlan,
  buildIntentsDirectDeploymentPlan,
  buildIntentsFactoryDeploymentPlan,
  identifyWasm,
  verifyIntentsSettlementDeployment,
  verifySettlementDeployment,
  type CustomerSettlementConfig,
  type ExternalAuditEvidence,
  type IntentsExternalAuditEvidence,
  type IntentsSettlementConfig,
  type NearNetwork,
} from './index.js';

const HELP = `Usage:
  edict-near-deploy artifact --wasm <path>
  edict-near-deploy plan-publish --publisher <account> --wasm <path>
  edict-near-deploy plan-bootstrap-factory --parent <account> --factory <account> --factory-code-hash <hex> --code-hash <hex> --balance <yoctoNEAR> --instance-balance <yoctoNEAR>
  edict-near-deploy plan-direct --config <path> --signer <account> --instance <account> --code-hash <hex> --balance <yoctoNEAR>
  edict-near-deploy plan-factory --config <path> --factory <account> --slug <slug> --deposit <yoctoNEAR>
  edict-near-deploy verify --config <path> --account <account> --code-hash <hex> --network <mainnet|testnet> [--factory <account> --factory-code-hash <hex>] [--audit-evidence <path>] [--rpc <url>]
  edict-near-deploy plan-intents-direct --config <path> --signer <account> --instance <account> --code-hash <hex> --balance <yoctoNEAR>
  edict-near-deploy plan-intents-factory --config <path> --factory <account> --slug <slug> --deposit <yoctoNEAR>
  edict-near-deploy verify-intents --config <path> --account <account> --code-hash <hex> --intents-code-hash <hex> --network mainnet [--factory <account> --factory-code-hash <hex>] [--audit-evidence <path>] [--rpc <url>]

This tool reads public configuration and artifacts only. Wallet approval and
transaction signing happen outside this process; it has no private-key option.`;

function required(values: Record<string, string | boolean | undefined>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`--${name} is required`);
  }
  return value;
}

function readConfig(path: string): CustomerSettlementConfig {
  return JSON.parse(readFileSync(path, 'utf8')) as CustomerSettlementConfig;
}

function readIntentsConfig(path: string): IntentsSettlementConfig {
  return JSON.parse(readFileSync(path, 'utf8')) as IntentsSettlementConfig;
}

async function main(): Promise<void> {
  const parsed = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      help: { type: 'boolean', short: 'h' },
      wasm: { type: 'string' },
      config: { type: 'string' },
      signer: { type: 'string' },
      parent: { type: 'string' },
      publisher: { type: 'string' },
      instance: { type: 'string' },
      factory: { type: 'string' },
      slug: { type: 'string' },
      account: { type: 'string' },
      'code-hash': { type: 'string' },
      'factory-code-hash': { type: 'string' },
      'intents-code-hash': { type: 'string' },
      balance: { type: 'string' },
      'instance-balance': { type: 'string' },
      deposit: { type: 'string' },
      network: { type: 'string' },
      rpc: { type: 'string' },
      'audit-evidence': { type: 'string' },
    },
  });
  if (parsed.values.help === true || parsed.positionals.length === 0) {
    process.stdout.write(`${HELP}\n`);
    return;
  }
  if (parsed.positionals.length !== 1) throw new TypeError('provide exactly one command');
  const values = parsed.values as Record<string, string | boolean | undefined>;
  const command = parsed.positionals[0];
  let output: unknown;

  if (command === 'artifact') {
    output = identifyWasm(readFileSync(required(values, 'wasm')));
  } else if (command === 'plan-publish') {
    output = buildGlobalContractPublishPlan({
      publisherAccount: required(values, 'publisher'),
      wasm: readFileSync(required(values, 'wasm')),
    });
  } else if (command === 'plan-bootstrap-factory') {
    output = buildFactoryBootstrapPlan({
      parentAccount: required(values, 'parent'),
      factoryAccount: required(values, 'factory'),
      factoryGlobalCodeSha256Hex: required(values, 'factory-code-hash'),
      settlementGlobalCodeSha256Hex: required(values, 'code-hash'),
      factoryBalanceYocto: required(values, 'balance'),
      minimumInstanceBalanceYocto: required(values, 'instance-balance'),
    });
  } else if (command === 'plan-direct') {
    output = buildDirectDeploymentPlan({
      config: readConfig(required(values, 'config')),
      signerId: required(values, 'signer'),
      instanceAccount: required(values, 'instance'),
      globalCodeSha256Hex: required(values, 'code-hash'),
      instanceBalanceYocto: required(values, 'balance'),
    });
  } else if (command === 'plan-factory') {
    output = buildFactoryDeploymentPlan({
      config: readConfig(required(values, 'config')),
      factoryAccount: required(values, 'factory'),
      slug: required(values, 'slug'),
      requiredDepositYocto: required(values, 'deposit'),
    });
  } else if (command === 'plan-intents-direct') {
    output = buildIntentsDirectDeploymentPlan({
      config: readIntentsConfig(required(values, 'config')),
      signerId: required(values, 'signer'),
      instanceAccount: required(values, 'instance'),
      globalCodeSha256Hex: required(values, 'code-hash'),
      instanceBalanceYocto: required(values, 'balance'),
    });
  } else if (command === 'plan-intents-factory') {
    output = buildIntentsFactoryDeploymentPlan({
      config: readIntentsConfig(required(values, 'config')),
      factoryAccount: required(values, 'factory'),
      slug: required(values, 'slug'),
      requiredDepositYocto: required(values, 'deposit'),
    });
  } else if (command === 'verify') {
    const network = required(values, 'network');
    if (network !== 'mainnet' && network !== 'testnet') {
      throw new TypeError('--network must be mainnet or testnet');
    }
    output = await verifySettlementDeployment({
      network: network as NearNetwork,
      settlementAccount: required(values, 'account'),
      expectedCodeSha256Hex: required(values, 'code-hash'),
      expectedConfig: readConfig(required(values, 'config')),
      ...(typeof values.factory === 'string' ? { factoryAccount: values.factory } : {}),
      ...(typeof values['factory-code-hash'] === 'string'
        ? { expectedFactoryCodeSha256Hex: values['factory-code-hash'] }
        : {}),
      ...(typeof values.rpc === 'string' ? { rpcUrl: values.rpc } : {}),
      ...(typeof values['audit-evidence'] === 'string'
        ? {
            externalAuditEvidence: JSON.parse(
              readFileSync(values['audit-evidence'], 'utf8'),
            ) as ExternalAuditEvidence,
          }
        : {}),
    });
  } else if (command === 'verify-intents') {
    const network = required(values, 'network');
    if (network !== 'mainnet') throw new TypeError('--network must be mainnet for NEAR Intents');
    output = await verifyIntentsSettlementDeployment({
      network: 'mainnet',
      settlementAccount: required(values, 'account'),
      expectedCodeSha256Hex: required(values, 'code-hash'),
      expectedIntentsVerifierCodeSha256Hex: required(values, 'intents-code-hash'),
      expectedConfig: readIntentsConfig(required(values, 'config')),
      ...(typeof values.factory === 'string' ? { factoryAccount: values.factory } : {}),
      ...(typeof values['factory-code-hash'] === 'string'
        ? { expectedFactoryCodeSha256Hex: values['factory-code-hash'] }
        : {}),
      ...(typeof values.rpc === 'string' ? { rpcUrl: values.rpc } : {}),
      ...(typeof values['audit-evidence'] === 'string'
        ? {
            externalAuditEvidence: JSON.parse(
              readFileSync(values['audit-evidence'], 'utf8'),
            ) as IntentsExternalAuditEvidence,
          }
        : {}),
    });
  } else {
    throw new TypeError(`unknown command: ${command}`);
  }

  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`edict-near-deploy: ${message}\n`);
  process.exitCode = 1;
});
