#!/usr/bin/env node
/**
 * edict-arbiter CLI.
 *
 *   edict-arbiter adjudicate --case case.json --evidence ./evidence-dir \
 *     --seats seats.json [--out verdict.json] [--archive ./arbiter-archive]
 *
 * Evidence dir: each regular file is read and keyed by the sha256 of its
 * ACTUAL BYTES — filenames are never trusted. A file whose hash matches no
 * evidence commitment in the case object is an error (unknown evidence is
 * rejected at the boundary, not silently ignored).
 *
 * Providers are constructed from the seats file: providerId "nearai" uses
 * NEAR AI Cloud when NEARAI_API_KEY is set, "phala" uses Phala Cloud ACI
 * when PHALA_API_KEY is set, and "edict-node" uses the configured self-hosted
 * node when EDICT_NODE_BASE_URL is set; anything else — or missing config — falls back
 * to the deterministic offline MockProvider (with a warning).
 */
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import type { InferenceProvider, JurySeatSpec, CaseObject } from '@edict/core';
import { adjudicate, requireSignerAllowlistFromEnv } from './index.js';
import { NearAiProvider } from './providers/nearai.js';
import { PhalaProvider } from './providers/phala.js';
import { EdictNodeProvider } from './providers/edictNode.js';
import { MockProvider } from './providers/mock.js';
import { sha256Hex } from './util.js';

function usage(): never {
  console.error(
    [
      'usage: edict-arbiter adjudicate --case <case.json> --evidence <dir> --seats <seats.json>',
      '                                [--out <verdict.json>] [--archive <dir>]',
      '',
      'env: NEARAI_API_KEY + EDICT_SIGNER_ALLOWLIST_NEARAI, PHALA_API_KEY + EDICT_SIGNER_ALLOWLIST_PHALA',
      '     EDICT_NODE_BASE_URL [+ EDICT_NODE_API_KEY] + EDICT_SIGNER_ALLOWLIST_EDICT_NODE',
      '     (mock providers substituted when provider keys are absent)',
    ].join('\n'),
  );
  process.exit(2);
}

/** Tiny .env loader (cwd only, never overrides existing env). No deps. */
async function loadDotEnv(): Promise<void> {
  try {
    const txt = await readFile('.env', 'utf8');
    for (const line of txt.split('\n')) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (m && m[1] !== undefined && process.env[m[1]] === undefined) {
        process.env[m[1]] = (m[2] ?? '').replace(/^["']|["']$/g, '');
      }
    }
  } catch {
    /* no .env file — fine */
  }
}

/**
 * Load evidence plaintext keyed by the sha256 of the ACTUAL file bytes.
 * Filenames are never trusted (a file named `<hash>.txt` is keyed by what it
 * hashes to, not what it claims to be). Files whose computed hash matches no
 * commitment in the case object are hard errors.
 */
async function loadEvidenceDir(dir: string, caseObj: CaseObject): Promise<Record<string, string>> {
  const committed = new Set(caseObj.evidence.map((c) => c.sha256));
  const out: Record<string, string> = {};
  const problems: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isFile() || e.name.startsWith('.')) continue;
    const bytes = await readFile(join(dir, e.name));
    const hash = sha256Hex(bytes);
    if (!committed.has(hash)) {
      problems.push(
        `${e.name}: file bytes hash to ${hash.slice(0, 12)}…, which matches no evidence commitment in the case object`,
      );
      continue;
    }
    out[hash] = bytes.toString('utf8');
  }
  if (problems.length > 0) {
    throw new Error(`evidence dir ${dir} contains uncommitted evidence:\n- ${problems.join('\n- ')}`);
  }
  return out;
}

function buildProviders(seats: JurySeatSpec[], archiveDir: string): Map<string, InferenceProvider> {
  const providers = new Map<string, InferenceProvider>();
  for (const seat of seats) {
    if (providers.has(seat.providerId)) continue;
    let provider: InferenceProvider;
    if (seat.providerId === 'nearai' && process.env.NEARAI_API_KEY) {
      provider = new NearAiProvider({ archiveDir });
    } else if (seat.providerId === 'phala' && process.env.PHALA_API_KEY) {
      provider = new PhalaProvider({ archiveDir });
    } else if (seat.providerId === 'edict-node' && process.env.EDICT_NODE_BASE_URL) {
      provider = new EdictNodeProvider({ archiveDir });
    } else {
      if (seat.providerId === 'nearai' || seat.providerId === 'phala' || seat.providerId === 'edict-node') {
        console.error(
          `[edict-arbiter] no API key for provider "${seat.providerId}" — substituting deterministic MockProvider (offline mode)`,
        );
      }
      provider = new MockProvider(seat.providerId);
    }
    providers.set(seat.providerId, provider);
  }
  return providers;
}

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  if (command !== 'adjudicate') usage();

  const { values } = parseArgs({
    args: rest,
    options: {
      case: { type: 'string' },
      evidence: { type: 'string' },
      seats: { type: 'string' },
      out: { type: 'string' },
      archive: { type: 'string' },
    },
  });
  if (!values.case || !values.evidence || !values.seats) usage();

  await loadDotEnv();

  const caseObj = JSON.parse(await readFile(values.case, 'utf8')) as CaseObject;
  const seatsRaw = JSON.parse(await readFile(values.seats, 'utf8')) as
    | JurySeatSpec[]
    | { seats: JurySeatSpec[] };
  const seats = Array.isArray(seatsRaw) ? seatsRaw : seatsRaw.seats;
  if (!Array.isArray(seats)) {
    throw new Error(`${values.seats}: expected a JurySeatSpec[] or { "seats": [...] }`);
  }
  const evidencePlaintext = await loadEvidenceDir(values.evidence, caseObj);
  const archiveDir = resolve(values.archive ?? './arbiter-archive');
  const providers = buildProviders(seats, archiveDir);
  const realProviderIds = [...providers.entries()]
    .filter(([, provider]) => !(provider instanceof MockProvider))
    .map(([providerId]) => providerId);
  const signerAllowlist =
    realProviderIds.length > 0 ? requireSignerAllowlistFromEnv(realProviderIds) : undefined;

  const verdict = await adjudicate(caseObj, evidencePlaintext, {
    seats,
    providers,
    archiveDir,
    ...(signerAllowlist !== undefined
      ? { proofPolicy: { signerAllowlist, nowUnixMs: Date.now() } }
      : {}),
  });
  const json = JSON.stringify(verdict, null, 2);
  if (values.out) {
    await writeFile(values.out, json, 'utf8');
    console.error(`[edict-arbiter] verdict written to ${values.out} (archive: ${archiveDir})`);
  } else {
    console.log(json);
  }
}

main().catch((err: unknown) => {
  console.error(`[edict-arbiter] error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
