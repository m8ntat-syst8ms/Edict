import type { InferenceProvider, JurySeatSpec } from '@edict/core';
import type { ProofPolicy } from './pipeline/proofVerify.js';
import { MockProvider } from './providers/mock.js';

/** Configuration for one adjudication run (re-exported from the package root). */
export interface ArbiterConfig {
  seats: JurySeatSpec[];
  /** providerId -> provider. Keys must match seat.providerId values. */
  providers: Map<string, InferenceProvider>;
  /** Proofs, attestations, juror outputs and the verdict are archived here. */
  archiveDir: string;
  /**
   * Attestation execution gate. When true, a seat whose
   * per-inference proof cannot be fetched, or whose proof fails cryptographic
   * verification (see pipeline/proofVerify.ts: signature
   * recovery/verification over the `${modelId}:${requestSha256}:${responseSha256}`
   * envelope, signer identity + optional allowlist, non-empty attestationRef,
   * freshness window), is excluded from the majority calculation; if
   * exclusions drop counted seats below quorum (a majority of configured
   * seats) the verdict escalates with
   * escalationReason 'insufficient_attested_seats'.
   *
   * Default: true when ANY seat's provider is non-mock; false when every
   * provider is the deterministic MockProvider (offline runs). The 'none_mock'
   * scheme is exempt from the gate ONLY when requireProofs resolves to false.
   */
  requireProofs?: boolean;
  /**
   * Per-pass juror completion budget (max_tokens). Default 1024
   * (JUROR_MAX_TOKENS). Reasoning-style models spend tokens on <think>
   * preambles before the strict-JSON verdict and can exhaust the default
   * budget (observed: 8/8 parse failures at 1024 on Qwen3.5-122B-A10B);
   * raise this for such seats. parseJurorOutput strips think/reasoning
   * blocks before strict parsing either way.
   */
  jurorMaxTokens?: number;
  /**
   * Proof-verification policy: per-provider signer
   * allowlist, freshness window (default 24h), and the injected reference
   * "now" the window is measured against (default: the case's
   * openedAtUnixMs — never the wall clock, so deterministic paths stay
   * deterministic). Only consulted under requireProofs.
   */
  proofPolicy?: ProofPolicy;
}

/** Resolve the effective requireProofs value (see ArbiterConfig.requireProofs). */
export function effectiveRequireProofs(config: ArbiterConfig): boolean {
  if (config.requireProofs !== undefined) return config.requireProofs;
  for (const provider of config.providers.values()) {
    if (!(provider instanceof MockProvider)) return true;
  }
  return false;
}

/** Env var prefix for provider signer allowlists in live/attested runs. */
export const SIGNER_ALLOWLIST_ENV_PREFIX = 'EDICT_SIGNER_ALLOWLIST_';

/** ProviderId -> env var name, e.g. "nearai" -> EDICT_SIGNER_ALLOWLIST_NEARAI. */
export function signerAllowlistEnvName(providerId: string): string {
  const suffix = providerId.replace(/[^A-Za-z0-9]/g, '_').toUpperCase();
  return `${SIGNER_ALLOWLIST_ENV_PREFIX}${suffix}`;
}

/**
 * Parse comma/whitespace-separated signer allowlists from env. Use for real
 * attested provider ids only; mock substitutions do not need allowlists.
 */
export function requireSignerAllowlistFromEnv(
  providerIds: Iterable<string>,
  env: Record<string, string | undefined> = process.env,
): Record<string, string[]> {
  const signerAllowlist: Record<string, string[]> = {};
  const missing: string[] = [];
  for (const providerId of [...new Set(providerIds)].sort()) {
    const envName = signerAllowlistEnvName(providerId);
    const raw = env[envName];
    const signers = raw?.split(/[,\s]+/).map((s) => s.trim()).filter((s) => s.length > 0) ?? [];
    if (signers.length === 0) {
      missing.push(`${providerId} (${envName})`);
      continue;
    }
    signerAllowlist[providerId] = signers;
  }
  if (missing.length > 0) {
    throw new Error(
      `missing signer allowlist for attested provider(s): ${missing.join(', ')}. ` +
        `Set ${SIGNER_ALLOWLIST_ENV_PREFIX}<PROVIDER_ID>=0x...[,0x...] so recovered proof signers are bound to known receipt keys.`,
    );
  }
  return signerAllowlist;
}
