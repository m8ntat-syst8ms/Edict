/**
 * Provider-proof verification for the attestation gate. Non-mock proofs must
 * pass cryptographic verification before their seats can count.
 *
 * The signed envelope (documented in the README provider matrix) is
 * scheme-dependent:
 *
 *     default:      `${modelId}:${requestSha256}:${responseSha256}`
 *     *_bodyhashes: `${requestSha256}:${responseSha256}`
 *
 * Schemes:
 * - `ecdsa_secp256k1_eth` (NEAR AI Cloud): the signature is an Ethereum
 *   personal-message signature over the envelope — the signed digest is
 *   keccak256("\x19Ethereum Signed Message:\n" + byteLen(envelope) + envelope).
 *   The signer address is RECOVERED from the 65-byte r||s||v signature
 *   (v ∈ {0,1,27,28}; the v-first layout is also accepted) and must equal
 *   `proof.signingAddress` case-insensitively AND, when the config provides
 *   a signer allowlist for the provider, be allowlisted.
 * - `ecdsa_secp256k1_eth_bodyhashes` (Phala Cloud / RedPill ACI gateway,
 *   legacy signature profile): identical recovery, but over the bodyhash
 *   envelope `${requestSha256}:${responseSha256}` — the model is bound
 *   through the request bytes. Evidence (2026-07-09): the ACI gateway's
 *   `GET /v1/signature/{chat_id}` returns `text` =
 *   `"<sha256(request body)>:<sha256(response wire bytes)>"` signed with
 *   `ethereum_personal_message_hash` → secp256k1 recoverable r||s||v
 *   (v = recid+27) — pinned by the gateway source the LIVE attestation's
 *   `source_provenance` names (Dstack-TEE/private-ai-gateway@58b027d,
 *   src/dstack.rs `sign_legacy_message` + src/aggregator/service/helpers.rs
 *   `legacy_signature_text`), and the live `GET /v1/aci/attestation` keyset
 *   publishes ecdsa-secp256k1 + ed25519 receipt keys (NOT P-256; see
 *   services/arbiter/evidence/redpill-aci-2026-07-09/). Not yet re-verified
 *   against a live RedPill completion — the on-disk PHALA_API_KEY is a Phala
 *   Cloud management key the inference gateway rejects (HTTP 401).
 * - `ed25519`: verified via node:crypto over the raw UTF-8 envelope bytes;
 *   `signingAddress` is the 32-byte raw ed25519 public key (hex, 0x optional).
 * - `ecdsa_p256`: verified via node:crypto as ECDSA-SHA256 over the raw
 *   UTF-8 envelope bytes; `signingAddress` is the uncompressed 65-byte P-256
 *   point (hex) or an SPKI DER (hex). DER and raw (ieee-p1363) signature
 *   encodings are both accepted. No known provider emits this scheme today —
 *   the 2026-07-09 evidence disproved the earlier assumption that Phala ACI
 *   receipts were P-256; the code remains as a generic verifier only.
 * - `none_mock`: always fails here — it is exempt from the gate ONLY when
 *   requireProofs=false, in which case this function is never called.
 *
 * Beyond the signature, a proof must carry a non-empty `attestationRef`
 * (the attestation bundle archived at inference time) and a
 * `fetchedAtUnixMs` within a configurable freshness window of the reference
 * time (default 24h; the reference is an INJECTED now or the case's
 * openedAtUnixMs — never the wall clock — so deterministic paths stay
 * deterministic).
 *
 * Failed verification = seat exclusion (the existing
 * insufficient_attested_seats escalation path in aggregate.ts).
 *
 * Dependency note: @noble/curves (+ @noble/hashes for keccak256) is the ONE
 * authorized runtime dependency exception (audited, zero-dep) — node:crypto
 * has no secp256k1 recovery or keccak.
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import type { ProviderProof } from '@edict/core';

/** Default proof freshness window: 24 hours. */
export const DEFAULT_PROOF_FRESHNESS_MS = 24 * 60 * 60 * 1000;

/** Per-run proof verification policy (ArbiterConfig.proofPolicy). */
export interface ProofPolicy {
  /**
   * providerId → allowed signer identities (eth addresses / raw public keys,
   * hex, 0x optional, case-insensitive). When a provider has an entry, a
   * verified proof must ALSO be signed by an allowlisted identity.
   */
  signerAllowlist?: Record<string, string[]>;
  /** Freshness window for proof.fetchedAtUnixMs (ms). Default 24h. */
  freshnessMs?: number;
  /**
   * Injected "now" the freshness window is measured against. Defaults to the
   * case's openedAtUnixMs at the call site — NEVER the wall clock, so the
   * same case verifies the same way forever.
   */
  nowUnixMs?: number;
}

export type ProofVerification = { ok: true } | { ok: false; reason: string };

export interface VerifyProofOptions {
  /** Seat's pinned modelId; a proof for a different model is rejected. */
  expectedModelId?: string;
  /** Captured request/response hashes of the completion this proof must cover. */
  expectedRequestSha256?: string;
  expectedResponseSha256?: string;
  /** Reference time for the freshness window (case openedAt or injected now). */
  referenceUnixMs: number;
  freshnessMs?: number;
  signerAllowlist?: Record<string, string[]>;
}

/** The default signed envelope (README provider matrix). */
export function proofEnvelope(
  proof: Pick<ProviderProof, 'modelId' | 'requestSha256' | 'responseSha256'>,
): string {
  return `${proof.modelId}:${proof.requestSha256}:${proof.responseSha256}`;
}

/**
 * The ACI legacy-signature envelope (`ecdsa_secp256k1_eth_bodyhashes`):
 * `"<request body sha256>:<response wire sha256>"`, exactly the `text` field
 * the gateway's `GET /v1/signature/{chat_id}` returns. The model is bound
 * through the request bytes (the request body carries `"model"`).
 */
export function proofEnvelopeBodyHashes(
  proof: Pick<ProviderProof, 'requestSha256' | 'responseSha256'>,
): string {
  return `${proof.requestSha256}:${proof.responseSha256}`;
}

/** Ethereum personal-message digest of arbitrary bytes. */
export function ethPersonalBytesDigest(message: Uint8Array): Uint8Array {
  const body = Buffer.from(message);
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${body.length}`, 'utf8');
  return keccak_256(Buffer.concat([prefix, body]));
}

/** Ethereum personal-message digest of a UTF-8 string. */
export function ethPersonalMessageDigest(message: string): Uint8Array {
  return ethPersonalBytesDigest(Buffer.from(message, 'utf8'));
}

// ---------------------------------------------------------------------------
// Hex / key helpers
// ---------------------------------------------------------------------------

function strip0x(s: string): string {
  return s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
}

function hexToBytes(s: string): Uint8Array | null {
  const h = strip0x(s.trim());
  if (h.length === 0 || h.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(h)) return null;
  return Uint8Array.from(Buffer.from(h, 'hex'));
}

/** Case-insensitive signer identity comparison over normalized hex. */
function sameSigner(a: string, b: string): boolean {
  return strip0x(a.trim()).toLowerCase() === strip0x(b.trim()).toLowerCase();
}

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const SPKI_P256_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

function ed25519KeyFromHex(signingAddress: string): KeyObject | null {
  const raw = hexToBytes(signingAddress);
  if (raw === null || raw.length !== 32) return null;
  try {
    return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

function p256KeyFromAddress(signingAddress: string): KeyObject | null {
  if (signingAddress.includes('BEGIN')) {
    try {
      return createPublicKey(signingAddress);
    } catch {
      return null;
    }
  }
  const bytes = hexToBytes(signingAddress);
  if (bytes === null) return null;
  try {
    if (bytes.length === 65 && bytes[0] === 0x04) {
      return createPublicKey({ key: Buffer.concat([SPKI_P256_PREFIX, bytes]), format: 'der', type: 'spki' });
    }
    return createPublicKey({ key: Buffer.from(bytes), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

/** keccak256(pubkey[1..])[-20:] as a 0x-prefixed lowercase address. */
function ethAddressOfUncompressed(pub65: Uint8Array): string {
  return `0x${Buffer.from(keccak_256(pub65.slice(1)).slice(-20)).toString('hex')}`;
}

/**
 * Recover the Ethereum address from a 65-byte personal-message signature.
 * Accepts r||s||v (Ethereum convention, v ∈ {0,1,27,28}) and the v-first
 * layout; returns null when the signature is malformed/unrecoverable.
 */
export function recoverEthAddress(signatureHex: string, digest: Uint8Array): string | null {
  const sig = hexToBytes(signatureHex);
  if (sig === null || sig.length !== 65) return null;
  const candidates: Array<{ rs: Uint8Array; v: number }> = [];
  const last = sig[64]!;
  const first = sig[0]!;
  if (last === 0 || last === 1 || last === 27 || last === 28) {
    candidates.push({ rs: sig.slice(0, 64), v: last >= 27 ? last - 27 : last });
  }
  if (candidates.length === 0 && (first === 0 || first === 1 || first === 27 || first === 28)) {
    candidates.push({ rs: sig.slice(1), v: first >= 27 ? first - 27 : first });
  }
  for (const { rs, v } of candidates) {
    try {
      const pub = secp256k1.Signature.fromBytes(rs, 'compact').addRecoveryBit(v).recoverPublicKey(digest);
      return ethAddressOfUncompressed(pub.toBytes(false));
    } catch {
      // fall through to the next candidate layout
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// verifyProviderProof
// ---------------------------------------------------------------------------

/**
 * Verify one per-inference proof (module doc above). Returns `{ ok: true }`
 * or `{ ok: false, reason }`; the reason becomes the seat's exclusion record.
 * Pure of wall clock: freshness is measured against `opts.referenceUnixMs`.
 */
export function verifyProviderProof(proof: ProviderProof, opts: VerifyProofOptions): ProofVerification {
  const fail = (reason: string): ProofVerification => ({ ok: false, reason });

  if (proof.signatureScheme === 'none_mock') {
    return fail("mock signature scheme 'none_mock' (exempt only when requireProofs=false)");
  }
  if (typeof proof.signature !== 'string' || proof.signature.length === 0) {
    return fail('proof carries no signature');
  }
  if (proof.signatureScheme === undefined) {
    return fail('proof carries no signature scheme');
  }
  if (opts.expectedModelId !== undefined && proof.modelId !== opts.expectedModelId) {
    return fail(`proof modelId "${proof.modelId}" does not match the seat's pinned model "${opts.expectedModelId}"`);
  }
  if (opts.expectedRequestSha256 !== undefined && proof.requestSha256 !== opts.expectedRequestSha256) {
    return fail('proof requestSha256 does not match the captured request bytes');
  }
  if (opts.expectedResponseSha256 !== undefined && proof.responseSha256 !== opts.expectedResponseSha256) {
    return fail('proof responseSha256 does not match the captured response bytes');
  }
  if (typeof proof.attestationRef !== 'string' || proof.attestationRef.length === 0) {
    return fail('proof carries no attestationRef (attestation bundle must be archived at inference time)');
  }
  const freshnessMs = opts.freshnessMs ?? DEFAULT_PROOF_FRESHNESS_MS;
  if (
    typeof proof.fetchedAtUnixMs !== 'number' ||
    !Number.isFinite(proof.fetchedAtUnixMs) ||
    Math.abs(proof.fetchedAtUnixMs - opts.referenceUnixMs) > freshnessMs
  ) {
    return fail(
      `proof is stale: fetchedAtUnixMs ${String(proof.fetchedAtUnixMs)} is outside the ±${freshnessMs}ms freshness window around ${opts.referenceUnixMs}`,
    );
  }
  if (typeof proof.signingAddress !== 'string' || proof.signingAddress.length === 0) {
    return fail('proof carries no signingAddress');
  }

  // Scheme-dependent envelope: the ACI legacy profile signs the bodyhash
  // pair; every other scheme signs the model-prefixed default envelope.
  const envelope =
    proof.signatureScheme === 'ecdsa_secp256k1_eth_bodyhashes'
      ? proofEnvelopeBodyHashes(proof)
      : proofEnvelope(proof);

  let verifiedSigner: string;
  switch (proof.signatureScheme) {
    case 'ecdsa_secp256k1_eth':
    case 'ecdsa_secp256k1_eth_bodyhashes': {
      const digest = ethPersonalMessageDigest(envelope);
      const recovered = recoverEthAddress(proof.signature, digest);
      if (recovered === null) {
        return fail('secp256k1 signature is malformed or unrecoverable (expected 65-byte r||s||v personal-message signature)');
      }
      if (!sameSigner(recovered, proof.signingAddress)) {
        return fail(`recovered signer ${recovered} does not match proof.signingAddress ${proof.signingAddress}`);
      }
      verifiedSigner = recovered;
      break;
    }
    case 'ed25519': {
      const key = ed25519KeyFromHex(proof.signingAddress);
      if (key === null) return fail('signingAddress is not a 32-byte raw ed25519 public key (hex)');
      const sig = hexToBytes(proof.signature);
      if (sig === null || sig.length !== 64) return fail('ed25519 signature must be 64 bytes (hex)');
      let ok = false;
      try {
        ok = cryptoVerify(null, Buffer.from(envelope, 'utf8'), key, Buffer.from(sig));
      } catch {
        ok = false;
      }
      if (!ok) return fail('ed25519 signature does not verify over the proof envelope');
      verifiedSigner = proof.signingAddress;
      break;
    }
    case 'ecdsa_p256': {
      // Generic P-256 verifier — no known provider emits this scheme
      // (2026-07-09 evidence: Phala ACI keys are secp256k1/ed25519, not
      // P-256; see module doc).
      const key = p256KeyFromAddress(proof.signingAddress);
      if (key === null) return fail('signingAddress is not an uncompressed P-256 point / SPKI DER (hex) or PEM');
      const sig = hexToBytes(proof.signature);
      if (sig === null) return fail('ecdsa_p256 signature is not valid hex');
      let ok = false;
      try {
        ok = cryptoVerify('sha256', Buffer.from(envelope, 'utf8'), key, Buffer.from(sig));
      } catch {
        ok = false;
      }
      if (!ok && sig.length === 64) {
        try {
          ok = cryptoVerify(
            'sha256',
            Buffer.from(envelope, 'utf8'),
            { key, dsaEncoding: 'ieee-p1363' },
            Buffer.from(sig),
          );
        } catch {
          ok = false;
        }
      }
      if (!ok) return fail('ecdsa_p256 signature does not verify over the proof envelope');
      verifiedSigner = proof.signingAddress;
      break;
    }
    default:
      return fail(`unknown signature scheme "${String(proof.signatureScheme)}"`);
  }

  const allowlist = opts.signerAllowlist?.[proof.providerId];
  if (allowlist !== undefined && !allowlist.some((a) => sameSigner(a, verifiedSigner))) {
    return fail(
      `signer ${verifiedSigner} is not in the configured allowlist for provider "${proof.providerId}"`,
    );
  }
  return { ok: true };
}
