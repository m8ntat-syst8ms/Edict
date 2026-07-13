/** Run the resumable, native NEAR Edict Protect testnet product. */
import {
  createHash,
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  type KeyObject,
} from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { MockProvider, ethPersonalBytesDigest } from '@edict/arbiter';
import {
  canonicalDeliveryManifestHash,
  canonicalize,
  sha256Hex,
  type DeliveryManifest,
} from '@edict/evidence';
import { adapterRef } from '@edict/near-deployer';
import { startProtectApp } from '@edict/protect-app';
import {
  EncryptedFileEvidenceVault,
  JsonlProtectionEventStore,
  NearJsonRpcViewClient,
  NearNativeConnector,
  ProtectionRuntime,
  protectionRuntimeServerUrl,
  registrationFromProtectResult,
  signedActionMessage,
  startProtectionRuntimeServer,
  type ExecutionSignatureCollector,
  type PermissionlessRelayer,
  type ProtectionEvent,
  type ProtectionRegistration,
  type RelayPlan,
  type RuntimeVerifierPolicy,
  type SignedActionEnvelope,
  type SignedActionName,
  type SignedActionPayloadMap,
} from '@edict/protection-runtime';
import {
  SANDBOX_MOCK_SEATS,
  createEdict,
  customerContractSettlement,
  standardProfile,
  type ProtectionProfile,
} from '@edict/sdk';
import {
  CREDENTIALS_DIR,
  REPO_ROOT,
  RPC_URL,
  explorerTx,
  nearCall,
  nearRpc,
  viewFunction,
} from './common.js';

const HOUR = 60 * 60 * 1_000;
const DAY = 24 * HOUR;
const PRINCIPAL_ATOMIC = '50000000000000000000000';
const DISPUTE_BOND_BPS = 500;
const CONNECTOR_ID = 'near-native-testnet';
const DATA_DIR = join(CREDENTIALS_DIR, 'runtime');
const CONTEXT_PATH = join(DATA_DIR, 'seed-context.json');
const LIVE_STATE_PATH = join(DATA_DIR, 'live-state.json');
const PUBLIC_PRODUCT_PATH = join(REPO_ROOT, 'scripts/testnet/product-run.json');
const DEPLOYMENT_PATH = join(REPO_ROOT, 'scripts/testnet/deployment.json');

interface DeploymentManifest {
  version: string;
  network: 'testnet';
  deploymentSuffix: string;
  warning: string;
  accounts: {
    publisher: string;
    customerGovernance: string;
    worker: string;
    removal: string;
    factory: string;
    settlement: string;
  };
  artifacts: {
    settlementSha256Hex: string;
    factorySha256Hex: string;
  };
  verification: { verifierPolicySha256Hex: string };
}

interface DemoSignerFile {
  address: string;
  privateKeyHex: string;
  attestationPlaceholderSha256Hex: string;
}

interface PartyKeyMaterial {
  publicHex: string;
  privateKeyPkcs8Base64: string;
}

interface ScenarioContext {
  kind: 'accepted' | 'disputed';
  registration: ProtectionRegistration;
  requesterKey: PartyKeyMaterial;
  workerKey: PartyKeyMaterial;
  manifest: DeliveryManifest;
  transactions: Partial<Record<'fund' | 'deliver' | 'accept' | 'openDispute', string>>;
}

interface SeedContext {
  version: 'edict-native-product-seed-1';
  settlementAccount: string;
  createdAtUnixMs: number;
  scenarios: ScenarioContext[];
}

interface NativeOrderView {
  state: string;
  delivery?: { manifest_sha256: number[] | string } | null;
  dispute?: { case_id_sha256: number[] | string } | null;
}

async function deployedCodeEvidence(accountId: string): Promise<{
  codeSha256Hex: string;
  accessKeyCount: number;
}> {
  const [code, keys] = await Promise.all([
    nearRpc('query', { request_type: 'view_code', finality: 'final', account_id: accountId }),
    nearRpc('query', { request_type: 'view_access_key_list', finality: 'final', account_id: accountId }),
  ]) as [{ code_base64: string }, { keys: unknown[] }];
  return {
    codeSha256Hex: createHash('sha256').update(Buffer.from(code.code_base64, 'base64')).digest('hex'),
    accessKeyCount: keys.keys.length,
  };
}

function keyMaterial(): PartyKeyMaterial {
  const pair = generateKeyPairSync('ed25519');
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  return {
    publicHex: publicDer.subarray(-32).toString('hex'),
    privateKeyPkcs8Base64: privateDer.toString('base64'),
  };
}

function privateKey(material: PartyKeyMaterial): KeyObject {
  return createPrivateKey({
    key: Buffer.from(material.privateKeyPkcs8Base64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

function signed<A extends SignedActionName>(
  key: PartyKeyMaterial,
  role: 'requester' | 'worker',
  protectionId: string,
  action: A,
  payload: SignedActionPayloadMap[A],
  nonce: string,
): SignedActionEnvelope<A> {
  const issuedAtUnixMs = Date.now();
  const unsigned: SignedActionEnvelope<A> = {
    version: 'edict-protect-signed-action-1',
    action,
    protectionId,
    signer: `ed25519:${key.publicHex}`,
    role,
    nonce,
    issuedAtUnixMs,
    expiresAtUnixMs: issuedAtUnixMs + 10 * 60_000,
    scheme: 'ed25519',
    publicKey: key.publicHex,
    payload,
    signature: '',
  };
  return {
    ...unsigned,
    signature: nodeSign(null, Buffer.from(signedActionMessage(unsigned)), privateKey(key)).toString('hex'),
  };
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function secretHex(name: string, byteLength: number): Promise<string> {
  const path = join(DATA_DIR, name);
  try {
    const value = (await readFile(path, 'utf8')).trim();
    if (new RegExp(`^[0-9a-f]{${byteLength * 2}}$`).test(value)) return value;
    throw new Error(`${path} has an invalid secret length`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const value = randomBytes(byteLength).toString('hex');
  await mkdir(DATA_DIR, { recursive: true, mode: 0o700 });
  await writeFile(path, `${value}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  return value;
}

function testnetProfile(): ProtectionProfile {
  const profile = standardProfile();
  profile.name = 'edict-protect-native-near-testnet';
  profile.version = '1.0.0';
  profile.legalPolicy.policyId = 'edict-protect-native-near-testnet-v1';
  profile.legalPolicy.challengeWindowMs = 2 * HOUR;
  profile.defaults.acceptanceWindowMs = 6 * HOUR;
  return profile;
}

async function signerPolicy(): Promise<{
  policy: RuntimeVerifierPolicy;
  executionSigners: DemoSignerFile[];
}> {
  const descriptors = [
    { file: 'demo-signer-a.json', operatorId: 'edict-staging', edictControlled: true },
    { file: 'demo-signer-a2.json', operatorId: 'staging-operator-a', edictControlled: false },
    { file: 'demo-signer-b.json', operatorId: 'staging-operator-b', edictControlled: false },
  ];
  const files = await Promise.all(descriptors.map((entry) =>
    readJson<DemoSignerFile>(join(CREDENTIALS_DIR, entry.file))));
  return {
    policy: {
      scheme: 'ecdsa_secp256k1_eth',
      quorum: 2,
      signers: descriptors.map((entry, index) => ({
        signingAddress: files[index]!.address.toLowerCase(),
        operatorId: entry.operatorId,
        edictControlled: entry.edictControlled,
        attestationSha256Hex: files[index]!.attestationPlaceholderSha256Hex,
      })),
    },
    executionSigners: [files[1]!, files[2]!],
  };
}

function executionSignature(privateKeyHex: string, executionDigestHex: string): string {
  const digest = ethPersonalBytesDigest(Buffer.from(executionDigestHex, 'hex'));
  const signature = secp256k1.sign(digest, Buffer.from(privateKeyHex, 'hex'), {
    format: 'recovered',
    prehash: false,
  });
  return `0x${Buffer.concat([
    Buffer.from(signature.slice(1)),
    Buffer.from([signature[0]! + 27]),
  ]).toString('hex')}`;
}

async function createSeedContext(
  deployment: DeploymentManifest,
  verifierPolicy: RuntimeVerifierPolicy,
): Promise<SeedContext> {
  const createdAtUnixMs = Date.now();
  const profile = testnetProfile();
  const settlement = customerContractSettlement(adapterRef(deployment.accounts.settlement), {
    resolutionTimeoutMs: 3 * DAY,
    livenessFallback: 'refund_requester',
  });
  const client = createEdict({ mode: 'live', profile, settlement });

  const scenarios: ScenarioContext[] = [];
  for (const [index, kind] of (['accepted', 'disputed'] as const).entries()) {
    const requesterKey = keyMaterial();
    const workerKey = keyMaterial();
    const expectedHash = (index === 0 ? 'a' : 'b').repeat(64);
    const deliveredHash = (index === 0 ? 'a' : 'c').repeat(64);
    const result = await client.protectPayment({
      paymentId: `native-testnet-${kind}-v1`,
      requester: `ed25519:${requesterKey.publicHex}`,
      worker: `ed25519:${workerKey.publicHex}`,
      promise: kind === 'accepted'
        ? 'Deliver the signed reconciliation report with the committed checksum.'
        : 'Deliver the signed risk report with the exact committed checksum.',
      acceptanceCriteria: [{
        id: 'AC-1',
        statement: 'The delivered report must match the committed checksum.',
        machineCheck: { kind: 'hash_equals', params: { path: 'result.json', sha256: expectedHash } },
      }],
      amountUsd: kind === 'accepted' ? 25 : 40,
      deadlineUnixMs: createdAtUnixMs + 7 * DAY + index * HOUR,
      currency: { asset: 'NEAR', rail: 'near-native-testnet' },
    });
    const registration = registrationFromProtectResult(result, {
      profile,
      nativeNear: {
        version: 'edict-native-near-runtime-1',
        connectorId: CONNECTOR_ID,
        network: 'testnet',
        settlementAccount: deployment.accounts.settlement,
        settlementAsset: 'native:near',
        requesterAccount: deployment.accounts.publisher,
        workerAccount: deployment.accounts.worker,
        principalAtomic: PRINCIPAL_ATOMIC,
        challengeWindowMs: profile.legalPolicy.challengeWindowMs,
        resolutionTimeoutMs: settlement.resolutionTimeoutMs,
        disputeBondBps: DISPUTE_BOND_BPS,
        verifierPolicySha256Hex: deployment.verification.verifierPolicySha256Hex,
        verifierPolicy,
      },
      integrationRef: 'near-native-testnet-staging',
    });
    const manifest: DeliveryManifest = {
      artifactHashes: [{ path: 'result.json', sha256: deliveredHash, mediaType: 'application/json' }],
      formatClaims: ['application/json'],
      workerAgentId: registration.mandate.worker.agentId,
      orderMandateHash: registration.mandateHash,
      deliveredAtUnixMs: createdAtUnixMs + 1_000 + index,
    };
    scenarios.push({ kind, registration, requesterKey, workerKey, manifest, transactions: {} });
  }
  const context: SeedContext = {
    version: 'edict-native-product-seed-1',
    settlementAccount: deployment.accounts.settlement,
    createdAtUnixMs,
    scenarios,
  };
  await writePrivateJson(CONTEXT_PATH, context);
  return context;
}

async function loadOrCreateContext(
  deployment: DeploymentManifest,
  verifierPolicy: RuntimeVerifierPolicy,
): Promise<SeedContext> {
  try {
    const context = await readJson<SeedContext>(CONTEXT_PATH);
    if (context.version !== 'edict-native-product-seed-1'
        || context.settlementAccount !== deployment.accounts.settlement) {
      throw new Error('persisted product context targets another deployment');
    }
    return context;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    return createSeedContext(deployment, verifierPolicy);
  }
}

async function orderOf(settlement: string, protectionId: string): Promise<NativeOrderView | null> {
  return viewFunction(settlement, 'get_order', {
    order_mandate_sha256: [...Buffer.from(protectionId, 'hex')],
  });
}

function stateOf(order: NativeOrderView): string {
  return order.state.toLowerCase();
}

async function recordTransaction(
  context: SeedContext,
  scenario: ScenarioContext,
  key: keyof ScenarioContext['transactions'],
  transactionHash: string | null,
): Promise<void> {
  if (transactionHash === null) throw new Error(`${scenario.kind} ${key} returned no transaction hash`);
  scenario.transactions[key] = transactionHash;
  await writePrivateJson(CONTEXT_PATH, context);
}

async function ensureApprovals(runtime: ProtectionRuntime, scenario: ScenarioContext): Promise<void> {
  const projection = await runtime.getProtection(scenario.registration.mandateHash);
  if (!projection.requesterApproved) {
    await runtime.handleSignedAction(signed(
      scenario.requesterKey,
      'requester',
      scenario.registration.mandateHash,
      'approve_protection',
      { reference: `${scenario.kind}:requester:testnet` },
      `${scenario.kind}-requester-approval-v1`,
    ));
  }
  if (!projection.workerApproved) {
    await runtime.handleSignedAction(signed(
      scenario.workerKey,
      'worker',
      scenario.registration.mandateHash,
      'approve_protection',
      { reference: `${scenario.kind}:worker:testnet` },
      `${scenario.kind}-worker-approval-v1`,
    ));
  }
}

async function ensureDeliveryEvidence(runtime: ProtectionRuntime, scenario: ScenarioContext): Promise<string> {
  const manifestSha256 = canonicalDeliveryManifestHash(scenario.manifest);
  const events = await runtime.listEvents(scenario.registration.mandateHash);
  const attached = events.some((event) => event.type === 'evidence_attached'
    && event.payload.kind === 'delivery_manifest'
    && event.payload.sha256 === manifestSha256);
  if (!attached) {
    await runtime.handleSignedAction(signed(
      scenario.workerKey,
      'worker',
      scenario.registration.mandateHash,
      'attach_evidence',
      { kind: 'delivery_manifest', plaintext: canonicalize(scenario.manifest) },
      `${scenario.kind}-delivery-manifest-v1`,
    ));
  }
  return manifestSha256;
}

async function ensureScenario(
  runtime: ProtectionRuntime,
  deployment: DeploymentManifest,
  context: SeedContext,
  scenario: ScenarioContext,
): Promise<void> {
  const registration = scenario.registration;
  const protectionId = registration.mandateHash;
  const binding = registration.nativeNear!;
  await runtime.register(registration);
  await ensureApprovals(runtime, scenario);

  let order = await orderOf(binding.settlementAccount, protectionId);
  if (order === null) {
    const storageDeposit = await viewFunction<string>(binding.settlementAccount, 'order_storage_deposit', {});
    const settlementBindingSha256 = sha256Hex(canonicalize(registration.mandate.settlement));
    const result = nearCall({
      contract: binding.settlementAccount,
      method: 'fund',
      args: {
        args: {
          order_mandate_sha256: [...Buffer.from(protectionId, 'hex')],
          settlement_binding_sha256: [...Buffer.from(settlementBindingSha256, 'hex')],
          worker: binding.workerAccount,
          principal: binding.principalAtomic,
          deadline_ms: registration.mandate.deadlineUnixMs,
          acceptance_window_ms: registration.mandate.acceptanceWindowMs,
          challenge_window_ms: binding.challengeWindowMs,
          resolution_timeout_ms: binding.resolutionTimeoutMs,
          liveness_fallback: registration.mandate.settlement!.livenessFallback,
          permitted_rulings: registration.mandate.decisionSpace.kind === 'escrow_branches'
            ? registration.mandate.decisionSpace.permitted
            : [],
          dispute_bond_bps: binding.disputeBondBps,
        },
      },
      gas: '100 Tgas',
      deposit: `${BigInt(binding.principalAtomic) + BigInt(storageDeposit)} yoctoNEAR`,
      signAs: binding.requesterAccount,
    });
    await recordTransaction(context, scenario, 'fund', result.txHash);
    order = await orderOf(binding.settlementAccount, protectionId);
  }
  if (order === null) throw new Error(`${scenario.kind} order was not funded`);
  await runtime.pollConnectors();

  const manifestSha256 = await ensureDeliveryEvidence(runtime, scenario);
  if (stateOf(order) === 'funded') {
    const result = nearCall({
      contract: binding.settlementAccount,
      method: 'deliver',
      args: {
        order_mandate_sha256: [...Buffer.from(protectionId, 'hex')],
        manifest_sha256: [...Buffer.from(manifestSha256, 'hex')],
      },
      gas: '80 Tgas',
      signAs: binding.workerAccount,
    });
    await recordTransaction(context, scenario, 'deliver', result.txHash);
    order = await orderOf(binding.settlementAccount, protectionId);
  }
  if (order === null) throw new Error(`${scenario.kind} order disappeared after delivery`);
  await runtime.pollConnectors();

  if (scenario.kind === 'accepted') {
    if (stateOf(order) === 'delivered') {
      const result = nearCall({
        contract: binding.settlementAccount,
        method: 'accept',
        args: { order_mandate_sha256: [...Buffer.from(protectionId, 'hex')] },
        gas: '100 Tgas',
        signAs: binding.requesterAccount,
      });
      await recordTransaction(context, scenario, 'accept', result.txHash);
    } else if (stateOf(order) !== 'settled') {
      throw new Error(`accepted scenario has unexpected on-chain state ${order.state}`);
    }
  } else if (stateOf(order) === 'delivered') {
    const events = await runtime.listEvents(protectionId);
    let challenge = events.find(
      (event): event is ProtectionEvent<'challenge_requested'> => event.type === 'challenge_requested',
    );
    if (challenge === undefined) {
      const requested = await runtime.handleSignedAction(signed(
        scenario.requesterKey,
        'requester',
        protectionId,
        'open_challenge',
        {
          statement: 'The report is missing the promised result, failed verification, is broken, incomplete, wrong, corrupted, mismatched, unusable and in breach. Refund requested.',
        },
        'disputed-open-challenge-v1',
      ));
      if (requested.event.type !== 'challenge_requested') {
        throw new Error('runtime did not create the challenge request');
      }
      challenge = requested.event;
    }
    const action = challenge.payload.action as {
      kind?: string;
      contractId?: string;
      methodName?: string;
      args?: unknown;
      depositYocto?: string;
    };
    if (action.kind !== 'near_function_call'
        || action.contractId !== binding.settlementAccount
        || action.methodName !== 'open_dispute'
        || typeof action.depositYocto !== 'string') {
      throw new Error('runtime returned an invalid native challenge action');
    }
    const result = nearCall({
      contract: binding.settlementAccount,
      method: action.methodName,
      args: action.args,
      gas: '100 Tgas',
      deposit: `${action.depositYocto} yoctoNEAR`,
      signAs: binding.requesterAccount,
    });
    await recordTransaction(context, scenario, 'openDispute', result.txHash);
  } else if (stateOf(order) !== 'disputed' && stateOf(order) !== 'settled') {
    throw new Error(`disputed scenario has unexpected on-chain state ${order.state}`);
  }
  await runtime.pollConnectors();

  const projection = await runtime.getProtection(protectionId);
  if (scenario.kind === 'accepted' && projection.state !== 'settled') {
    throw new Error(`accepted scenario did not reach settled state (${projection.state})`);
  }
  if (scenario.kind === 'disputed'
      && projection.state !== 'settlement_ready'
      && projection.state !== 'settled') {
    throw new Error(`disputed scenario did not reach a relayable decision (${projection.state})`);
  }
  if (deployment.accounts.settlement !== binding.settlementAccount) {
    throw new Error('scenario settlement binding drifted from the deployment');
  }
}

function gasForCli(raw: string): string {
  const gas = BigInt(raw);
  const tgas = 1_000_000_000_000n;
  return gas % tgas === 0n ? `${gas / tgas} Tgas` : `${gas} gas`;
}

function testnetRelayer(settlementAccount: string, relayerAccount: string): PermissionlessRelayer {
  const allowed = new Set(['claim_timeout', 'submit_ruling', 'execute_liveness_fallback', 'withdraw_claim']);
  return {
    async relay(plan: RelayPlan) {
      if (plan.kind !== 'near_function_call') throw new Error('native testnet relayer accepts NEAR function calls only');
      if (plan.contractId !== settlementAccount || !allowed.has(plan.methodName)) {
        throw new Error('relay plan is outside the pinned native settlement contract surface');
      }
      const result = nearCall({
        contract: plan.contractId,
        method: plan.methodName,
        args: plan.args,
        gas: gasForCli(plan.gas),
        deposit: `${plan.depositYocto} yoctoNEAR`,
        signAs: relayerAccount,
      });
      if (result.txHash === null) throw new Error('permissionless relay returned no transaction hash');
      return { transactionHash: result.txHash };
    },
  };
}

async function productState(
  runtime: ProtectionRuntime,
  deployment: DeploymentManifest,
  context: SeedContext,
  runtimeUrl: string,
  appUrl: string,
): Promise<Record<string, unknown>> {
  const projections = await runtime.listProtections();
  const latestUpdateUnixMs = projections.reduce(
    (latest, projection) => Math.max(latest, projection.updatedAtUnixMs),
    context.createdAtUnixMs,
  );
  return {
    version: 'edict-native-testnet-product-1',
    generatedAt: new Date(latestUpdateUnixMs).toISOString(),
    network: 'NEAR testnet',
    warning: 'Unaudited NEAR Testnet deployment with deterministic model seats and simulated signer operators. Do not use customer funds.',
    deployment: {
      factory: deployment.accounts.factory,
      settlement: deployment.accounts.settlement,
      relayer: `edict-relay-${deployment.deploymentSuffix}.testnet`,
      settlementExplorer: `https://testnet.nearblocks.io/address/${deployment.accounts.settlement}`,
      factoryExplorer: `https://testnet.nearblocks.io/address/${deployment.accounts.factory}`,
      factoryAccessKeys: 0,
      settlementAccessKeys: 0,
    },
    services: { runtimeUrl, appUrl },
    flows: context.scenarios.map((scenario) => {
      const projection = projections.find((candidate) =>
        candidate.protectionId === scenario.registration.mandateHash);
      const relayPlans = new Map(projection?.events.flatMap((event) =>
        event.type === 'relay_ready' ? [[event.payload.plan.planId, event.payload.plan]] : []) ?? []);
      const relayTransactions = projection?.events.flatMap((event) => {
        if (event.type !== 'relay_submitted') return [];
        const plan = relayPlans.get(event.payload.planId);
        return [{
          method: plan?.kind === 'near_function_call' ? plan.methodName : plan?.kind ?? 'unknown',
          hash: event.payload.transactionHash,
          explorer: explorerTx(event.payload.transactionHash),
        }];
      });
      const settlementPlan = projection?.relayPlans.find((plan) =>
        plan.kind === 'near_function_call' && plan.methodName === 'submit_ruling');
      return {
        kind: scenario.kind,
        protectionId: scenario.registration.mandateHash,
        state: projection?.state,
        title: projection?.title,
        latestRuling: projection?.latestVerdict?.ruling,
        challengeWindowEndsAtUnixMs: settlementPlan?.eligibleAtUnixMs,
        transactions: Object.fromEntries(Object.entries(scenario.transactions).map(([key, hash]) => [
          key,
          { hash, explorer: explorerTx(hash) },
        ])),
        relayTransactions: relayTransactions ?? [],
      };
    }),
    guarantees: {
      edictHoldsCustomerFunds: false,
      edictHoldsCustomerKeys: false,
      settlementContractHasAccessKeys: false,
      relayerCanRedirectPayouts: false,
    },
  };
}

const deployment = await readJson<DeploymentManifest>(DEPLOYMENT_PATH);
if (deployment.version !== 'edict-native-testnet-1' || deployment.network !== 'testnet') {
  throw new Error('scripts/testnet/deployment.json is not the current native testnet deployment');
}
const { policy, executionSigners } = await signerPolicy();
const relayerAccount = `edict-relay-${deployment.deploymentSuffix}.testnet`;
const [factoryEvidence, settlementEvidence] = await Promise.all([
  deployedCodeEvidence(deployment.accounts.factory),
  deployedCodeEvidence(deployment.accounts.settlement),
]);
if (factoryEvidence.codeSha256Hex !== deployment.artifacts.factorySha256Hex
    || settlementEvidence.codeSha256Hex !== deployment.artifacts.settlementSha256Hex
    || factoryEvidence.accessKeyCount !== 0
    || settlementEvidence.accessKeyCount !== 0) {
  throw new Error('native testnet code identity or keyless deployment boundary no longer matches the manifest');
}
const onChainConfig = await viewFunction<{
  verifier_policy_sha256: number[];
  verifier_policy: { signers: Array<{ signing_address: string }> };
}>(deployment.accounts.settlement, 'get_config', {});
if (Buffer.from(onChainConfig.verifier_policy_sha256).toString('hex')
    !== deployment.verification.verifierPolicySha256Hex) {
  throw new Error('on-chain verifier policy hash no longer matches the deployment manifest');
}
const chainAddresses = onChainConfig.verifier_policy.signers.map((signer) => signer.signing_address.toLowerCase());
if (canonicalize(chainAddresses) !== canonicalize(policy.signers.map((signer) => signer.signingAddress))) {
  throw new Error('local testnet signer files no longer match the immutable on-chain verifier policy');
}

const context = await loadOrCreateContext(deployment, policy);
const vaultKey = Buffer.from(await secretHex('evidence-key.hex', 32), 'hex');
const apiToken = `native-testnet-${await secretHex('runtime-api-token.hex', 32)}`;
const providers = new Map<string, MockProvider>();
for (const seat of SANDBOX_MOCK_SEATS) providers.set(seat.providerId, new MockProvider(seat.providerId));
const executionSignatures: ExecutionSignatureCollector = {
  async collect(request) {
    return executionSigners.map((signer) => ({
      signing_address: signer.address.toLowerCase(),
      signature: executionSignature(signer.privateKeyHex, request.executionDigestHex),
    }));
  },
};
const runtime = new ProtectionRuntime({
  eventStore: new JsonlProtectionEventStore(join(DATA_DIR, 'events.jsonl')),
  evidenceVault: new EncryptedFileEvidenceVault(join(DATA_DIR, 'evidence'), vaultKey),
  connectors: [new NearNativeConnector(CONNECTOR_ID, new NearJsonRpcViewClient(RPC_URL))],
  adjudicator: { providers, archiveDir: join(DATA_DIR, 'arbiter') },
  executionSignatures,
  relayer: testnetRelayer(deployment.accounts.settlement, relayerAccount),
  autoRelay: true,
});
await runtime.initialize();
for (const scenario of context.scenarios) {
  await ensureScenario(runtime, deployment, context, scenario);
}

const runtimePort = Number(process.env.EDICT_TESTNET_RUNTIME_PORT ?? '4890');
const appPort = Number(process.env.EDICT_TESTNET_APP_PORT ?? '4885');
const runtimeServer = await startProtectionRuntimeServer(runtime, { port: runtimePort, apiTokens: [apiToken] });
const runtimeUrl = protectionRuntimeServerUrl(runtimeServer);
const appServer = await startProtectApp({
  port: appPort,
  dataDir: join(DATA_DIR, 'protect-app'),
  runtimeBaseUrl: runtimeUrl,
  runtimeApiToken: apiToken,
  environmentLabel: 'NEAR testnet',
});
const appUrl = `http://127.0.0.1:${appPort}`;

async function refreshState(): Promise<void> {
  await runtime.pollConnectors();
  const state = await productState(runtime, deployment, context, runtimeUrl, appUrl);
  await Promise.all([
    writePrivateJson(LIVE_STATE_PATH, state),
    writeFile(PUBLIC_PRODUCT_PATH, `${JSON.stringify(state, null, 2)}\n`, 'utf8'),
  ]);
}

await refreshState();

let refreshing = false;
const timer = setInterval(() => {
  if (refreshing) return;
  refreshing = true;
  void refreshState()
    .catch((error: unknown) => console.error(`[edict-testnet] poll failed: ${(error as Error).message}`))
    .finally(() => { refreshing = false; });
}, 15_000);

async function shutdown(): Promise<void> {
  clearInterval(timer);
  await Promise.all([
    new Promise<void>((resolve) => runtimeServer.close(() => resolve())),
    new Promise<void>((resolve) => appServer.close(() => resolve())),
  ]);
}
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => { void shutdown().finally(() => process.exit(0)); });
}

console.log(JSON.stringify({
  product: 'Edict Protect',
  environment: 'NEAR Testnet Preview',
  appUrl,
  runtimeUrl,
  settlementAccount: deployment.accounts.settlement,
  protections: (await runtime.listProtections()).map((projection) => ({
    protectionId: projection.protectionId,
    state: projection.state,
  })),
}, null, 2));
