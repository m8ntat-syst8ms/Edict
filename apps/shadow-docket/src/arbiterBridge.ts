/**
 * Bridge to @edict/arbiter.
 *
 * The docket imports the arbiter STATICALLY and is compile-time typed against
 * its real public API:
 *   adjudicate(caseObj: CaseObject, evidencePlaintext: Record<string,string>,
 *              config: ArbiterConfig): Promise<VerdictObject>
 *   ArbiterConfig = { seats, providers: Map<providerId, InferenceProvider>, archiveDir }
 *   MockProvider(id, opts?) — deterministic offline provider
 *   NearAiProvider({ archiveDir, apiKey?, baseUrl? }) for providerId "nearai"
 *   PhalaProvider({ archiveDir, apiKey?, baseUrl? }) for providerId "phala"
 *   EdictNodeProvider({ archiveDir, apiKey?, baseUrl? }) for providerId "edict-node"
 *
 * mode 'mock' (default) is fully offline: the real arbiter pipeline over
 * deterministic MockProviders. mode 'env' constructs real attested providers
 * from environment keys (see services/arbiter/.env.example), substituting a
 * MockProvider (with a warning) for any seat whose key is absent.
 *
 * The separate built-in baseline (./baselineArbiter.js) is NOT wired in here
 * any more — it remains available as an explicit harness-credibility baseline
 * for tests, never a silent fallback.
 */
import type { InferenceProvider, JurySeatSpec } from '@edict/core';
import {
  adjudicate,
  MockProvider,
  NearAiProvider,
  PhalaProvider,
  EdictNodeProvider,
  requireSignerAllowlistFromEnv,
  type ArbiterConfig,
} from '@edict/arbiter';

export type ProviderMode = 'mock' | 'env';

export interface ResolvedArbiter {
  adjudicate: typeof adjudicate;
  config: ArbiterConfig;
  /** Human-readable provenance for report headers. */
  source: string;
}

/** One deterministic MockProvider per distinct providerId in the roster. */
function buildMockProviderMap(seats: JurySeatSpec[]): Map<string, InferenceProvider> {
  const providers = new Map<string, InferenceProvider>();
  for (const seat of seats) {
    if (!providers.has(seat.providerId)) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  return providers;
}

/**
 * Mirror the arbiter CLI's env mapping: providerId "nearai" → NearAiProvider
 * when NEARAI_API_KEY is set, "phala" → PhalaProvider when PHALA_API_KEY is
 * set, and "edict-node" → EdictNodeProvider when EDICT_NODE_BASE_URL is set;
 * anything else (or missing config) falls back to the deterministic
 * MockProvider with a warning, so runs never silently mix rails.
 */
function buildEnvProviderMap(seats: JurySeatSpec[], archiveDir: string): Map<string, InferenceProvider> {
  const providers = new Map<string, InferenceProvider>();
  for (const seat of seats) {
    if (providers.has(seat.providerId)) continue;
    let provider: InferenceProvider | undefined;
    if (seat.providerId === 'nearai' && process.env.NEARAI_API_KEY) {
      provider = new NearAiProvider({
        archiveDir,
        apiKey: process.env.NEARAI_API_KEY,
        ...(process.env.NEARAI_BASE_URL ? { baseUrl: process.env.NEARAI_BASE_URL } : {}),
      });
    } else if (seat.providerId === 'phala' && process.env.PHALA_API_KEY) {
      provider = new PhalaProvider({
        archiveDir,
        apiKey: process.env.PHALA_API_KEY,
        ...(process.env.PHALA_BASE_URL ? { baseUrl: process.env.PHALA_BASE_URL } : {}),
      });
    } else if (seat.providerId === 'edict-node' && process.env.EDICT_NODE_BASE_URL) {
      provider = new EdictNodeProvider({
        archiveDir,
        baseUrl: process.env.EDICT_NODE_BASE_URL,
        ...(process.env.EDICT_NODE_API_KEY ? { apiKey: process.env.EDICT_NODE_API_KEY } : {}),
      });
    }
    if (!provider) {
      if (seat.providerId === 'nearai' || seat.providerId === 'phala' || seat.providerId === 'edict-node') {
        console.error(`shadow-docket: no API key for provider "${seat.providerId}" — substituting deterministic MockProvider`);
      }
      provider = new MockProvider(seat.providerId);
    }
    providers.set(seat.providerId, provider);
  }
  return providers;
}

/** Resolve the adjudicator + config for a run. */
export function resolveArbiter(
  seats: JurySeatSpec[],
  mode: ProviderMode,
  archiveDir: string,
): ResolvedArbiter {
  if (mode === 'env') {
    const providers = buildEnvProviderMap(seats, archiveDir);
    const realProviderIds = [...providers.entries()]
      .filter(([, provider]) => !(provider instanceof MockProvider))
      .map(([providerId]) => providerId);
    const signerAllowlist =
      realProviderIds.length > 0 ? requireSignerAllowlistFromEnv(realProviderIds) : undefined;
    return {
      adjudicate,
      config: {
        seats,
        providers,
        archiveDir,
        // Live runs are attested runs: proofs REQUIRED (a mock substituted
        // for a missing key can never pass the gate — its seat is excluded),
        // and the proof-freshness reference is the run start, injected ONCE
        // so verification never reads the wall clock per case.
        requireProofs: true,
        proofPolicy: {
          nowUnixMs: Date.now(),
          ...(signerAllowlist !== undefined ? { signerAllowlist } : {}),
        },
      },
      source: '@edict/arbiter (env providers)',
    };
  }
  return {
    adjudicate,
    config: { seats, providers: buildMockProviderMap(seats), archiveDir },
    source: '@edict/arbiter (mock providers)',
  };
}
