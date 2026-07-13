/**
 * Delivery manifests + evidence commitments (spec C5).
 *
 * A DeliveryManifest is the worker's signed claim of WHAT was delivered:
 * artifact hashes, format claims, and when. It is evidence of delivery, not
 * proof of acceptance — the requester's receipt is likewise not acceptance
 * (burden defaults, evidence policy). The manifest type is local to this package
 * on purpose: `@edict/core` only ever sees its canonical hash
 * (`CaseObject.deliveryManifestHash`) and its EvidenceCommitment.
 */

import type { EvidenceCommitment, EvidenceKind } from '@edict/core';
import { canonicalize, normalizeSha256, sha256Canonical, sha256Hex } from './hash.js';

// ---------------------------------------------------------------------------
// Manifest type (LOCAL to @edict/evidence — not a core schema)
// ---------------------------------------------------------------------------

export interface ArtifactHash {
  /** Delivery-relative path or logical artifact name, e.g. "report.pdf". */
  path: string;
  /** sha256 (lowercase hex) over the raw artifact bytes. */
  sha256: string;
  /** IANA media type claimed by the worker, e.g. "application/pdf". */
  mediaType: string;
}

export interface DeliveryManifest {
  artifactHashes: ArtifactHash[];
  /** Free-form format/spec claims, e.g. "pdf/a-3b", "utf-8", "en-GB". */
  formatClaims: string[];
  /** Rail-scoped agent id of the delivering worker (matches PartyRef.agentId). */
  workerAgentId: string;
  /** canonicalOrderMandateHash of the mandate this delivery answers. */
  orderMandateHash: string;
  deliveredAtUnixMs: number;
}

const MANIFEST_KEYS = [
  'artifactHashes',
  'formatClaims',
  'workerAgentId',
  'orderMandateHash',
  'deliveredAtUnixMs',
] as const;
const ARTIFACT_KEYS = ['path', 'sha256', 'mediaType'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function unknownKeys(value: Record<string, unknown>, allowed: readonly string[], path: string): string[] {
  return Object.keys(value)
    .filter((key) => !allowed.includes(key))
    .map((key) => `${path}.${key}: unknown field`);
}

/** Validate the closed, signed delivery-manifest wire shape. */
export function validateDeliveryManifest(value: unknown): string[] {
  if (!isRecord(value)) return ['deliveryManifest: must be an object'];
  const problems = unknownKeys(value, MANIFEST_KEYS, 'deliveryManifest');

  if (!Array.isArray(value.artifactHashes)) {
    problems.push('deliveryManifest.artifactHashes: must be an array');
  } else {
    const paths = new Set<string>();
    value.artifactHashes.forEach((artifact, index) => {
      const path = `deliveryManifest.artifactHashes[${index}]`;
      if (!isRecord(artifact)) {
        problems.push(`${path}: must be an object`);
        return;
      }
      problems.push(...unknownKeys(artifact, ARTIFACT_KEYS, path));
      if (typeof artifact.path !== 'string' || artifact.path.length === 0 || artifact.path.length > 1_024
          || /[\u0000-\u001f]/.test(artifact.path)) {
        problems.push(`${path}.path: must be a non-empty string of at most 1024 characters without controls`);
      } else if (paths.has(artifact.path)) {
        problems.push(`${path}.path: duplicate artifact path ${artifact.path}`);
      } else {
        paths.add(artifact.path);
      }
      if (typeof artifact.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(artifact.sha256)) {
        problems.push(`${path}.sha256: must be lowercase sha256 hex`);
      }
      if (typeof artifact.mediaType !== 'string' || artifact.mediaType.length === 0
          || artifact.mediaType.length > 255 || /[\u0000-\u001f]/.test(artifact.mediaType)) {
        problems.push(`${path}.mediaType: must be a non-empty string of at most 255 characters without controls`);
      }
    });
  }

  if (!Array.isArray(value.formatClaims)
      || value.formatClaims.some((claim) => typeof claim !== 'string' || claim.length > 2_048 || /[\u0000-\u001f]/.test(claim))) {
    problems.push('deliveryManifest.formatClaims: must be an array of strings of at most 2048 characters without controls');
  }
  if (typeof value.workerAgentId !== 'string' || value.workerAgentId.length === 0
      || value.workerAgentId.length > 512 || /[\u0000-\u001f]/.test(value.workerAgentId)) {
    problems.push('deliveryManifest.workerAgentId: must be a non-empty string of at most 512 characters without controls');
  }
  if (typeof value.orderMandateHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.orderMandateHash)) {
    problems.push('deliveryManifest.orderMandateHash: must be lowercase sha256 hex');
  }
  if (!Number.isSafeInteger(value.deliveredAtUnixMs) || (value.deliveredAtUnixMs as number) <= 0) {
    problems.push('deliveryManifest.deliveredAtUnixMs: must be a positive unix-ms integer');
  }
  return problems;
}

export function assertValidDeliveryManifest(value: unknown): asserts value is DeliveryManifest {
  const problems = validateDeliveryManifest(value);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
}

// ---------------------------------------------------------------------------
// Canonical hash
// ---------------------------------------------------------------------------

/**
 * sha256 (lowercase hex) over the canonical JSON of the full manifest.
 * This is the value referenced by `CaseObject.deliveryManifestHash` and by
 * `delivery_manifest` evidence commitments.
 */
export function canonicalDeliveryManifestHash(manifest: DeliveryManifest): string {
  return sha256Canonical(manifest);
}

/** Verify a manifest against an expected sha256 (case-insensitive, optional 0x). */
export function verifyDeliveryManifestHash(manifest: DeliveryManifest, expectedSha256: string): boolean {
  const expected = normalizeSha256(expectedSha256);
  if (expected === null) return false;
  return canonicalDeliveryManifestHash(manifest) === expected;
}

// ---------------------------------------------------------------------------
// Evidence commitments
// ---------------------------------------------------------------------------

/**
 * Build a core EvidenceCommitment for a piece of evidence.
 *
 * - `Uint8Array` input is hashed over its raw bytes (artifacts, sealed blobs).
 * - Any other input is hashed over its canonical JSON (mandates, manifests,
 *   receipts) so independent parties reproduce the same sha256 regardless of
 *   key ordering.
 * - `authenticated` is ALWAYS false here: a commitment merely pins content.
 *   It becomes authenticated only after signature / zkTLS / attestation
 *   verification upstream, which is outside this helper's knowledge.
 */
export function buildEvidenceCommitment(
  kind: EvidenceKind,
  bytesOrObj: Uint8Array | unknown,
  submitter: EvidenceCommitment['submitter'],
  uri?: string,
): EvidenceCommitment {
  const sha256 =
    bytesOrObj instanceof Uint8Array ? sha256Hex(bytesOrObj) : sha256Hex(canonicalize(bytesOrObj));
  const commitment: EvidenceCommitment = {
    kind,
    sha256,
    submitter,
    authenticated: false,
  };
  if (uri !== undefined) commitment.uri = uri;
  return commitment;
}
