import type { NearIntentsRoute } from '@edict/near-intents';
import type {
  ProtectionRegistration,
  RuntimeVerifierPolicy,
} from './types.js';

export interface RuntimeSettlementBinding {
  kind: 'near_intents' | 'near_native';
  connectorId: string;
  settlementAccount: string;
  settlementAsset: string;
  requesterAccount: string;
  workerAccount: string;
  principalAtomic: string;
  challengeWindowMs: number;
  resolutionTimeoutMs: number;
  disputeBondBps: number;
  verifierPolicySha256Hex: string;
  verifierPolicy: RuntimeVerifierPolicy;
  intentsRoute?: NearIntentsRoute;
}

/** Normalize the two shipped NEAR rails without erasing their distinct funding semantics. */
export function runtimeSettlementBinding(
  registration: ProtectionRegistration,
): RuntimeSettlementBinding {
  const intents = registration.intents;
  const nativeNear = registration.nativeNear;
  if ((intents === undefined) === (nativeNear === undefined)) {
    throw new TypeError('protection registration must contain exactly one runtime settlement binding');
  }
  if (intents !== undefined) {
    return {
      kind: 'near_intents',
      connectorId: intents.connectorId,
      settlementAccount: intents.route.settlementAccount,
      settlementAsset: intents.route.settlementAsset,
      requesterAccount: intents.requesterIntentsAccount,
      workerAccount: intents.workerIntentsAccount,
      principalAtomic: intents.principalAtomic,
      challengeWindowMs: intents.challengeWindowMs,
      resolutionTimeoutMs: intents.resolutionTimeoutMs,
      disputeBondBps: intents.disputeBondBps,
      verifierPolicySha256Hex: intents.verifierPolicySha256Hex,
      verifierPolicy: intents.verifierPolicy,
      intentsRoute: intents.route,
    };
  }
  return {
    kind: 'near_native',
    connectorId: nativeNear!.connectorId,
    settlementAccount: nativeNear!.settlementAccount,
    settlementAsset: nativeNear!.settlementAsset,
    requesterAccount: nativeNear!.requesterAccount,
    workerAccount: nativeNear!.workerAccount,
    principalAtomic: nativeNear!.principalAtomic,
    challengeWindowMs: nativeNear!.challengeWindowMs,
    resolutionTimeoutMs: nativeNear!.resolutionTimeoutMs,
    disputeBondBps: nativeNear!.disputeBondBps,
    verifierPolicySha256Hex: nativeNear!.verifierPolicySha256Hex,
    verifierPolicy: nativeNear!.verifierPolicy,
  };
}
