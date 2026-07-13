import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { ethPersonalMessageDigest, recoverEthAddress } from '@edict/arbiter';
import { canonicalize, sha256Hex } from '@edict/evidence';
import {
  SIGNED_ACTION_VERSION,
  type SignedActionEnvelope,
  type SignedActionName,
} from './types.js';

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface SignedActionVerification {
  ok: boolean;
  reason?: string;
  digestSha256: string;
  normalizedSigner?: string;
}

export interface SignedActionVerifier {
  verify(envelope: SignedActionEnvelope, nowUnixMs?: number): Promise<SignedActionVerification>;
}

export function signedActionMessage<A extends SignedActionName>(
  envelope: SignedActionEnvelope<A>,
): string {
  const { signature: _signature, ...unsigned } = envelope;
  return `EDICT_PROTECT_MESSAGE_V1\n${canonicalize(unsigned)}`;
}

function decode(value: string): Buffer | undefined {
  const stripped = value.startsWith('0x') ? value.slice(2) : value;
  if (/^[0-9a-fA-F]+$/.test(stripped) && stripped.length % 2 === 0) return Buffer.from(stripped, 'hex');
  try {
    const decoded = Buffer.from(value, 'base64');
    return decoded.length > 0 ? decoded : undefined;
  } catch {
    return undefined;
  }
}

export function normalizedPartyIdentity(value: string): string {
  const trimmed = value.trim();
  const eth = /(0x[0-9a-fA-F]{40})$/.exec(trimmed);
  if (eth !== null) return eth[1]!.toLowerCase();
  return trimmed.toLowerCase();
}

export function signerMatchesParty(signer: string, partyAgentId: string): boolean {
  return normalizedPartyIdentity(signer) === normalizedPartyIdentity(partyAgentId);
}

export class BuiltInSignedActionVerifier implements SignedActionVerifier {
  constructor(readonly maximumLifetimeMs = 15 * 60 * 1_000) {}

  async verify(envelope: SignedActionEnvelope, nowUnixMs = Date.now()): Promise<SignedActionVerification> {
    const message = signedActionMessage(envelope);
    const digestSha256 = sha256Hex(message);
    const fail = (reason: string): SignedActionVerification => ({ ok: false, reason, digestSha256 });
    if (envelope.version !== SIGNED_ACTION_VERSION) return fail('unsupported signed-action version');
    if (!Number.isSafeInteger(envelope.issuedAtUnixMs) || !Number.isSafeInteger(envelope.expiresAtUnixMs)) {
      return fail('signed-action timestamps must be unix-ms integers');
    }
    if (envelope.expiresAtUnixMs <= envelope.issuedAtUnixMs) return fail('signed action expires before it is issued');
    if (envelope.expiresAtUnixMs - envelope.issuedAtUnixMs > this.maximumLifetimeMs) {
      return fail('signed action lifetime exceeds policy');
    }
    if (nowUnixMs < envelope.issuedAtUnixMs - 60_000) return fail('signed action is not yet valid');
    if (nowUnixMs > envelope.expiresAtUnixMs) return fail('signed action has expired');
    if (envelope.nonce.trim().length < 8 || envelope.nonce.length > 200) return fail('signed action nonce is invalid');

    if (envelope.scheme === 'eip191') {
      const recovered = recoverEthAddress(envelope.signature, ethPersonalMessageDigest(message));
      if (recovered === null) return fail('EIP-191 signature is malformed or unrecoverable');
      if (normalizedPartyIdentity(recovered) !== normalizedPartyIdentity(envelope.signer)) {
        return fail('EIP-191 signature does not match signer');
      }
      return { ok: true, digestSha256, normalizedSigner: recovered.toLowerCase() };
    }

    if (envelope.scheme === 'ed25519') {
      if (envelope.publicKey === undefined) return fail('ed25519 publicKey is required');
      const key = decode(envelope.publicKey);
      const signature = decode(envelope.signature);
      if (key === undefined || key.length !== 32) return fail('ed25519 publicKey must be 32 bytes');
      if (signature === undefined || signature.length !== 64) return fail('ed25519 signature must be 64 bytes');
      let publicKey;
      try {
        publicKey = createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, key]),
          format: 'der',
          type: 'spki',
        });
      } catch {
        return fail('ed25519 publicKey could not be decoded');
      }
      if (!verifySignature(null, Buffer.from(message, 'utf8'), publicKey, signature)) {
        return fail('ed25519 signature is invalid');
      }
      const publicIdentity = key.toString('hex');
      const signerIdentity = normalizedPartyIdentity(envelope.signer).replace(/^ed25519:/, '');
      if (signerIdentity !== publicIdentity && normalizedPartyIdentity(envelope.signer) !== publicIdentity) {
        return fail('ed25519 publicKey does not match signer');
      }
      return { ok: true, digestSha256, normalizedSigner: publicIdentity };
    }

    return fail('custom signature scheme requires an injected verifier');
  }
}
