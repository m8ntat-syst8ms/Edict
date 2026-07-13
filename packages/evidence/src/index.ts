export {
  canonicalize,
  sha256Hex,
  sha256Canonical,
  normalizeSha256,
  GENESIS_HEAD,
  appendToChain,
  HashChain,
} from './hash.js';

export {
  canonicalOrderMandateHash,
  verifyOrderMandateHash,
  flattenOrderMandate,
  buildEip712TypedData,
  buildNep413Payload,
} from './orderMandate.js';
export type { FlattenedOrderMandate, Eip712TypedData, Nep413Payload } from './orderMandate.js';

export {
  assertValidDeliveryManifest,
  canonicalDeliveryManifestHash,
  validateDeliveryManifest,
  verifyDeliveryManifestHash,
  buildEvidenceCommitment,
} from './deliveryManifest.js';
export type { ArtifactHash, DeliveryManifest } from './deliveryManifest.js';

export { runMachineChecks, validateStructuralSchema } from './acceptance.js';
export type { MachineCheckStatus, MachineCheckResult, MachineCheckReport } from './acceptance.js';
