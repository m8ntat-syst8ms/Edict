/**
 * Per-inference proof signing — the EXACT format the arbiter already
 * verifies for NEAR AI Cloud seats (services/arbiter/src/pipeline/
 * proofVerify.ts, scheme `ecdsa_secp256k1_eth`):
 *
 *   envelope  = `${model_id}:${sha256(request bytes)}:${sha256(response bytes)}`
 *   digest    = keccak256("\x19Ethereum Signed Message:\n" + len(envelope) + envelope)
 *   signature = secp256k1 recoverable over digest, encoded r||s||v with
 *               v = recovery_id + 27, hex with 0x prefix (65 bytes)
 *
 * `verifyProviderProof` recovers the Ethereum address from the signature and
 * requires it to equal the published signing address (and, when configured,
 * to be in EDICT_SIGNER_ALLOWLIST_EDICT_NODE / the on-chain attestation
 * registry).
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hexToBytes } from './util.js';

export const SIGNING_SCHEME = 'ecdsa_secp256k1_eth' as const;
/** Human-readable envelope spec, published in the attestation report. */
export const SIGNING_ENVELOPE_FORMAT = '{model_id}:{sha256(request)}:{sha256(response)}';

export function proofEnvelope(modelId: string, requestSha256: string, responseSha256: string): string {
  return `${modelId}:${requestSha256}:${responseSha256}`;
}

/** Ethereum personal-message digest of a UTF-8 string (mirrors arbiter proofVerify). */
export function ethPersonalMessageDigest(message: string): Uint8Array {
  const body = Buffer.from(message, 'utf8');
  const prefix = Buffer.from(`\x19Ethereum Signed Message:\n${body.length}`, 'utf8');
  return keccak_256(Buffer.concat([prefix, body]));
}

/** keccak256(uncompressed_pubkey[1..])[-20:] as a 0x-prefixed lowercase address. */
export function ethAddressOfPrivateKey(privateKey: Uint8Array): string {
  const pub = secp256k1.getPublicKey(privateKey, false);
  return `0x${Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex')}`;
}

/**
 * Sign the proof envelope as an Ethereum personal message. Returns the
 * 65-byte `r||s||v` signature (v = recid + 27) as 0x-hex — byte-for-byte the
 * layout `recoverEthAddress` in the arbiter accepts.
 */
export function signEnvelopeEth(privateKey: Uint8Array, envelope: string): string {
  const digest = ethPersonalMessageDigest(envelope);
  // @noble/curves 2.x 'recovered' format: recovery byte FIRST, then r||s.
  const recovered = secp256k1.sign(digest, privateKey, { format: 'recovered', prehash: false });
  const v = recovered[0]! + 27;
  const rs = Buffer.from(recovered.subarray(1));
  return `0x${Buffer.concat([rs, Buffer.from([v])]).toString('hex')}`;
}

/**
 * Recover the signer address from an r||s||v personal-message signature —
 * used for the node's own post-sign self-check and in tests. Returns null on
 * malformed signatures.
 */
export function recoverEthAddress(signatureHex: string, digest: Uint8Array): string | null {
  const sig = hexToBytes(signatureHex);
  if (sig === null || sig.length !== 65) return null;
  const last = sig[64]!;
  if (last !== 0 && last !== 1 && last !== 27 && last !== 28) return null;
  const v = last >= 27 ? last - 27 : last;
  try {
    const pub = secp256k1.Signature.fromBytes(sig.slice(0, 64), 'compact')
      .addRecoveryBit(v)
      .recoverPublicKey(digest)
      .toBytes(false);
    return `0x${Buffer.from(keccak_256(pub.slice(1)).slice(-20)).toString('hex')}`;
  } catch {
    return null;
  }
}
