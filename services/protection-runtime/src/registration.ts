import {
  tierForValueUsd,
  validateEvidenceCommitment,
  validateOrderMandate,
  validateSettlementBinding,
  type ValueTier,
} from '@edict/core';
import {
  canonicalOrderMandateHash,
  canonicalize,
  sha256Hex,
} from '@edict/evidence';
import {
  disputeBondAtomic,
  nearIntentsAdapterRef,
} from '@edict/near-intents';
import { adapterRef as nativeNearAdapterRef } from '@edict/near-deployer';
import { profileHash, validateProfile } from '@edict/sdk';
import {
  NATIVE_NEAR_RUNTIME_BINDING_VERSION,
  PROTECTION_REGISTRATION_VERSION,
  type ProtectionRegistration,
  type RuntimeVerifierPolicy,
} from './types.js';
import {
  runtimeVerifierPolicySha256,
  validateRuntimeVerifierPolicy,
} from './verifierPolicy.js';

const SHA256 = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ATOMIC = /^(0|[1-9][0-9]*)$/;
const ACCOUNT_ID = /^(?=.{2,64}$)[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const MAX_U128 = (1n << 128n) - 1n;
const INTENTS_USDC_ASSET = 'nep141:usdc.omft.near';
const REGISTRATION_KEYS = [
  'version', 'mandate', 'mandateHash', 'legalPolicyHash', 'profile', 'profileHash',
  'evidenceCommitments', 'intents', 'nativeNear', 'integrationRef', 'standingChallengeAuthorization',
] as const;
const INTENTS_KEYS = [
  'connectorId', 'route', 'requesterIntentsAccount', 'workerIntentsAccount', 'principalAtomic',
  'challengeWindowMs', 'resolutionTimeoutMs', 'disputeBondBps', 'verifierPolicySha256Hex', 'verifierPolicy',
] as const;
const NATIVE_KEYS = [
  'version', 'connectorId', 'network', 'settlementAccount', 'settlementAsset', 'requesterAccount',
  'workerAccount', 'principalAtomic', 'challengeWindowMs', 'resolutionTimeoutMs', 'disputeBondBps',
  'verifierPolicySha256Hex', 'verifierPolicy',
] as const;
const STANDING_AUTHORIZATION_KEYS = [
  'version', 'party', 'triggerKinds', 'caseId', 'caseIdSha256', 'bondAtomic', 'expiresAtUnixMs',
  'signedIntentSha256', 'signedIntent',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(
  problems: string[],
  value: Record<string, unknown>,
  path: string,
  allowed: readonly string[],
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) problems.push(`${path}.${key} is not supported`);
  }
}

function microUsdcFor(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return undefined;
  const fixed = value.toFixed(6);
  if (Number(fixed) !== value) return undefined;
  const [whole, fractional = ''] = fixed.split('.');
  return (BigInt(whole!) * 1_000_000n + BigInt(fractional.padEnd(6, '0'))).toString();
}

function tierForRegistration(valueUsd: number, thresholds?: { aMaxUsd: number; bMaxUsd: number }): ValueTier | undefined {
  const candidates = tierForValueUsd(valueUsd);
  if (candidates.length === 0) return undefined;
  const selected = thresholds ?? { aMaxUsd: 10, bMaxUsd: 1_000 };
  const preferred: ValueTier = valueUsd <= selected.aMaxUsd ? 'A' : valueUsd <= selected.bMaxUsd ? 'B' : 'C';
  return candidates.includes(preferred) ? preferred : candidates[0];
}

export function validateProtectionRegistration(registration: unknown): string[] {
  const problems: string[] = [];
  if (typeof registration !== 'object' || registration === null || Array.isArray(registration)) {
    return ['registration must be an object'];
  }
  const value = registration as ProtectionRegistration;
  rejectUnknownKeys(problems, registration as Record<string, unknown>, 'registration', REGISTRATION_KEYS);
  if (value.version !== PROTECTION_REGISTRATION_VERSION) problems.push('unsupported registration version');
  if (!SHA256.test(value.mandateHash)) problems.push('mandateHash must be lowercase sha256 hex');
  if (!SHA256.test(value.legalPolicyHash)) problems.push('legalPolicyHash must be lowercase sha256 hex');
  if (!SHA256.test(value.profileHash)) problems.push('profileHash must be lowercase sha256 hex');
  if (value.integrationRef !== undefined
      && (typeof value.integrationRef !== 'string'
        || value.integrationRef.trim().length === 0
        || value.integrationRef.length > 256)) {
    problems.push('integrationRef must be a non-empty string of at most 256 characters');
  }
  const mandateProblems = validateOrderMandate(value.mandate, 'mandate');
  problems.push(...mandateProblems);
  try {
    if (canonicalOrderMandateHash(value.mandate) !== value.mandateHash) {
      problems.push('mandateHash does not match the canonical mandate');
    }
  } catch (error) {
    problems.push(`mandate is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (value.mandate?.version !== 'edict-om-2' || value.mandate.legalPolicy === undefined) {
    problems.push('runtime protections require an edict-om-2 mandate with a Legal Policy');
  } else {
    try {
      if (sha256Hex(canonicalize(value.mandate.legalPolicy)) !== value.legalPolicyHash) {
        problems.push('legalPolicyHash does not match the signed Legal Policy');
      }
    } catch (error) {
      problems.push(`signed Legal Policy is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  const profileProblems = validateProfile(value.profile);
  problems.push(...profileProblems.map((problem) => `profile: ${problem}`));
  if (profileProblems.length === 0 && profileHash(value.profile) !== value.profileHash) {
    problems.push('profileHash does not match the Protection Profile');
  }
  if (profileProblems.length === 0 && mandateProblems.length === 0
      && canonicalize(value.profile.legalPolicy) !== canonicalize(value.mandate.legalPolicy)) {
    problems.push('Protection Profile Legal Policy does not match the signed mandate Legal Policy');
  }
  if (profileProblems.length === 0) {
    const seats = value.profile.juryPolicy.seats;
    if (!Array.isArray(seats) || seats.length === 0) {
      problems.push('runtime registrations require an explicit immutable jury seat roster');
    } else {
      const perProvider = new Map<string, number>();
      for (const seat of seats) perProvider.set(seat.providerId, (perProvider.get(seat.providerId) ?? 0) + 1);
      const tier = typeof value.mandate?.priceUsd === 'number'
        ? tierForRegistration(value.mandate.priceUsd, value.profile.tierThresholds)
        : undefined;
      if (tier === 'C') {
        if (perProvider.size < 3) problems.push('tier C runtime registrations require at least 3 distinct jury providers');
        for (const [providerId, count] of perProvider) {
          if (count * 2 > seats.length) {
            problems.push(`tier C runtime jury provider ${providerId} cannot hold a majority of seats`);
          }
        }
      }
    }
  }
  if (value.mandate?.settlement === undefined) {
    problems.push('mandate settlement binding is required');
  } else {
    problems.push(...validateSettlementBinding(value.mandate.settlement).map((problem) => `mandate.${problem}`));
    if (value.mandate.settlement.edictOperatorCanTransfer !== false
        || value.mandate.settlement.edictOperatorCanFreeze !== false
        || value.mandate.settlement.edictOperatorIsRequiredSigner !== false) {
      problems.push('mandate grants Edict a custody or liveness power');
    }
  }
  if (!Array.isArray(value.evidenceCommitments)) {
    problems.push('evidenceCommitments must be an array');
  } else {
    const commitmentKeys = new Set<string>();
    value.evidenceCommitments.forEach((entry, index) => {
      problems.push(...validateEvidenceCommitment(entry, `evidenceCommitments[${index}]`));
      if (!isRecord(entry)) return;
      const key = `${String(entry.kind)}:${String(entry.sha256)}`;
      if (commitmentKeys.has(key)) problems.push(`evidenceCommitments[${index}] duplicates ${key}`);
      commitmentKeys.add(key);
    });
    const hasCommitment = (kind: string, sha256: string): boolean => value.evidenceCommitments.some((entry) =>
      isRecord(entry) && entry.kind === kind && entry.sha256 === sha256);
    if (!hasCommitment('order_mandate', value.mandateHash)) {
      problems.push('evidenceCommitments must contain the canonical order mandate');
    }
    if (!hasCommitment('legal_policy', value.legalPolicyHash)) {
      problems.push('evidenceCommitments must contain the signed Legal Policy');
    }
    const customerPolicyRef = value.mandate?.legalPolicy?.customerPolicyPack;
    if (customerPolicyRef !== undefined && !hasCommitment('customer_policy_pack', customerPolicyRef.sha256)) {
      problems.push('evidenceCommitments must contain the signed Customer Policy Pack');
    }
    for (const [role, party] of [
      ['requester', value.mandate?.requester],
      ['worker', value.mandate?.worker],
    ] as const) {
      const credential = party?.authorityCredentialRef;
      if (credential !== undefined && !hasCommitment('authority_credential', credential.sha256)) {
        problems.push(`evidenceCommitments must contain the ${role} authority credential`);
      }
    }
  }

  const intents = value.intents;
  const nativeNear = value.nativeNear;
  if ((intents === undefined) === (nativeNear === undefined)) {
    return [...problems, 'exactly one of intents or nativeNear binding is required'];
  }
  if (intents !== undefined && !isRecord(intents)) {
    return [...problems, 'intents binding must be an object'];
  }
  if (nativeNear !== undefined && !isRecord(nativeNear)) {
    return [...problems, 'nativeNear binding must be an object'];
  }
  if (isRecord(intents)) rejectUnknownKeys(problems, intents, 'intents', INTENTS_KEYS);
  if (isRecord(nativeNear)) rejectUnknownKeys(problems, nativeNear, 'nativeNear', NATIVE_KEYS);

  let prefix: 'intents' | 'nativeNear';
  let connectorId: string;
  let requesterAccount: string;
  let workerAccount: string;
  let principalAtomic: string;
  let challengeWindowMs: number;
  let resolutionTimeoutMs: number;
  let disputeBondBps: number;
  let verifierPolicySha256Hex: string;
  let verifierPolicy: RuntimeVerifierPolicy;
  if (intents !== undefined) {
    prefix = 'intents';
    connectorId = intents.connectorId;
    requesterAccount = intents.requesterIntentsAccount;
    workerAccount = intents.workerIntentsAccount;
    principalAtomic = intents.principalAtomic;
    challengeWindowMs = intents.challengeWindowMs;
    resolutionTimeoutMs = intents.resolutionTimeoutMs;
    disputeBondBps = intents.disputeBondBps;
    verifierPolicySha256Hex = intents.verifierPolicySha256Hex;
    verifierPolicy = intents.verifierPolicy;
    try {
      const adapterRef = nearIntentsAdapterRef(intents.route);
      if (value.mandate?.settlement?.adapterRef !== adapterRef) {
        problems.push('signed settlement adapter does not match the NEAR Intents route');
      }
    } catch (error) {
      problems.push(`intents.route is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (intents.route?.settlementAsset !== INTENTS_USDC_ASSET) {
      problems.push(`runtime Intents v1 settlement asset must be ${INTENTS_USDC_ASSET}`);
    }
    if (value.mandate?.currency?.asset !== 'USDC') {
      problems.push('runtime Intents v1 mandate currency asset must be USDC');
    }
    const expectedPrincipal = microUsdcFor(value.mandate?.priceUsd);
    if (expectedPrincipal === undefined) {
      problems.push('runtime Intents v1 mandate priceUsd must have at most 6 decimal places');
    } else if (principalAtomic !== expectedPrincipal) {
      problems.push('intents.principalAtomic must equal the signed mandate value in micro-USDC');
    }
  } else {
    prefix = 'nativeNear';
    connectorId = nativeNear!.connectorId;
    requesterAccount = nativeNear!.requesterAccount;
    workerAccount = nativeNear!.workerAccount;
    principalAtomic = nativeNear!.principalAtomic;
    challengeWindowMs = nativeNear!.challengeWindowMs;
    resolutionTimeoutMs = nativeNear!.resolutionTimeoutMs;
    disputeBondBps = nativeNear!.disputeBondBps;
    verifierPolicySha256Hex = nativeNear!.verifierPolicySha256Hex;
    verifierPolicy = nativeNear!.verifierPolicy;
    if (nativeNear!.version !== NATIVE_NEAR_RUNTIME_BINDING_VERSION) {
      problems.push('nativeNear.version is unsupported');
    }
    if (nativeNear!.network !== 'mainnet' && nativeNear!.network !== 'testnet') {
      problems.push('nativeNear.network must be mainnet or testnet');
    } else if (nativeNear!.network === 'mainnet') {
      problems.push('testnet-preview runtime permits native NEAR on testnet only; mainnet requires an audited valuation binding');
    }
    if (typeof nativeNear!.settlementAccount !== 'string' || !ACCOUNT_ID.test(nativeNear!.settlementAccount)) {
      problems.push('nativeNear.settlementAccount must be a canonical NEAR account');
    } else if (value.mandate?.settlement?.adapterRef !== nativeNearAdapterRef(nativeNear!.settlementAccount)) {
      problems.push('signed settlement adapter does not match the native NEAR contract');
    }
    if (nativeNear!.settlementAsset !== 'native:near') {
      problems.push('nativeNear.settlementAsset must be native:near');
    }
  }

  if (typeof connectorId !== 'string' || connectorId.trim().length === 0) {
    problems.push(`${prefix}.connectorId must be non-empty`);
  }
  if (typeof requesterAccount !== 'string' || !ACCOUNT_ID.test(requesterAccount)) problems.push(`${prefix} requester account is invalid`);
  if (typeof workerAccount !== 'string' || !ACCOUNT_ID.test(workerAccount)) problems.push(`${prefix} worker account is invalid`);
  if (requesterAccount === workerAccount) problems.push(`${prefix} requester and worker must differ`);
  if (typeof principalAtomic !== 'string' || !ATOMIC.test(principalAtomic) || principalAtomic === '0') {
    problems.push(`${prefix}.principalAtomic must be a positive atomic-unit integer`);
  } else if (BigInt(principalAtomic) > MAX_U128) {
    problems.push(`${prefix}.principalAtomic exceeds uint128`);
  } else {
    try {
      disputeBondAtomic(principalAtomic, disputeBondBps);
    } catch (error) {
      problems.push(`${prefix} dispute Bond is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (!Number.isSafeInteger(challengeWindowMs)
      || challengeWindowMs < 2 * 60 * 60 * 1_000
      || challengeWindowMs > 24 * 60 * 60 * 1_000) {
    problems.push(`${prefix}.challengeWindowMs must be between 2 and 24 hours`);
  }
  if (value.mandate?.legalPolicy !== undefined
      && challengeWindowMs !== value.mandate.legalPolicy.challengeWindowMs) {
    problems.push(`${prefix} challenge window does not match the signed Legal Policy`);
  }
  if (!Number.isSafeInteger(resolutionTimeoutMs) || resolutionTimeoutMs <= challengeWindowMs) {
    problems.push(`${prefix}.resolutionTimeoutMs must exceed the challenge window`);
  }
  if (value.mandate?.settlement !== undefined
      && resolutionTimeoutMs !== value.mandate.settlement.resolutionTimeoutMs) {
    problems.push(`${prefix} resolution timeout does not match the signed settlement binding`);
  }
  if (!Number.isInteger(disputeBondBps) || disputeBondBps < 500 || disputeBondBps > 1_000) {
    problems.push(`${prefix}.disputeBondBps must be between 500 and 1000`);
  }
  if (!SHA256.test(verifierPolicySha256Hex) || /^0+$/.test(verifierPolicySha256Hex)) {
    problems.push(`${prefix}.verifierPolicySha256Hex must be non-zero sha256 hex`);
  }
  const verifierProblems = validateRuntimeVerifierPolicy(verifierPolicy, `${prefix}.verifierPolicy`);
  problems.push(...verifierProblems);
  if (verifierProblems.length === 0
      && runtimeVerifierPolicySha256(verifierPolicy) !== verifierPolicySha256Hex) {
    problems.push(`${prefix}.verifierPolicySha256Hex does not match verifierPolicy Borsh bytes`);
  }

  const authorization = value.standingChallengeAuthorization;
  if (authorization !== undefined) {
    if (!isRecord(authorization)) return [...problems, 'standing challenge authorization must be an object'];
    rejectUnknownKeys(problems, authorization, 'standingChallengeAuthorization', STANDING_AUTHORIZATION_KEYS);
    if (intents === undefined) problems.push('standing challenge authorization is currently NEAR Intents only');
    if (authorization.version !== 'edict-standing-challenge-1') problems.push('standing authorization version is unsupported');
    if (authorization.party !== 'requester') {
      problems.push('objective-failure standing authorization must be signed by the requester');
    }
    if (!Array.isArray(authorization.triggerKinds)
        || authorization.triggerKinds.length !== 1
        || authorization.triggerKinds[0] !== 'objective_failure') {
      problems.push('standing authorization triggerKinds must be exactly [objective_failure]');
    }
    if (!Number.isSafeInteger(authorization.expiresAtUnixMs) || authorization.expiresAtUnixMs <= 0) {
      problems.push('standing authorization expiry is invalid');
    } else if (typeof value.mandate?.deadlineUnixMs === 'number'
        && authorization.expiresAtUnixMs <= value.mandate.deadlineUnixMs) {
      problems.push('standing authorization must remain valid through the delivery deadline');
    }
    if (typeof authorization.caseId !== 'string' || !UUID_V4.test(authorization.caseId)
        || !SHA256.test(authorization.caseIdSha256)
        || sha256Hex(authorization.caseId) !== authorization.caseIdSha256) {
      problems.push('standing authorization caseId preimage does not match caseIdSha256');
    }
    if (typeof authorization.bondAtomic !== 'string'
        || !ATOMIC.test(authorization.bondAtomic) || authorization.bondAtomic === '0') {
      problems.push('standing authorization Bond must be a positive atomic-unit integer');
    }
    if (!SHA256.test(authorization.signedIntentSha256)) problems.push('standing signedIntentSha256 is invalid');
    if (!isRecord(authorization.signedIntent)) {
      problems.push('standing signed intent must be a JSON object');
    } else try {
      if (sha256Hex(canonicalize(authorization.signedIntent)) !== authorization.signedIntentSha256) {
        problems.push('standing signed intent hash does not match its bytes');
      }
    } catch (error) {
      problems.push(`standing signed intent is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
      if (authorization.bondAtomic !== disputeBondAtomic(principalAtomic, disputeBondBps)) {
        problems.push('standing authorization Bond is not the exact contract-required amount');
      }
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
  }
  return problems;
}

export function assertValidProtectionRegistration(
  registration: unknown,
): asserts registration is ProtectionRegistration {
  const problems = validateProtectionRegistration(registration);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
}
