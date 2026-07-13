/**
 * ProtectionProfile store — JSON files under `<dataDir>/profiles/<name>/<version>.json`.
 *
 * Versions are IMMUTABLE: re-saving the same name+version with byte-different
 * canonical content is a conflict (HTTP 409 at the API layer); re-saving the
 * identical profile is an idempotent no-op. Every save computes and stores the
 * `profileHash` (sha256 over canonical JSON — @edict/sdk `profileHash`), so a
 * verdict is always attributable to the exact policy version it ran under.
 */

import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { profileHash, validateProfile, type ProtectionProfile } from '@edict/sdk';

/** What gets written to disk (and returned by get/list). */
export interface StoredProfile {
  name: string;
  version: string;
  profileHash: string;
  savedAtUnixMs: number;
  profile: ProtectionProfile;
}

export interface ProfileListEntry {
  name: string;
  version: string;
  profileHash: string;
  savedAtUnixMs: number;
}

export type SaveResult =
  | { status: 'created'; stored: StoredProfile }
  | { status: 'unchanged'; stored: StoredProfile }
  | { status: 'conflict'; name: string; version: string; existingHash: string; incomingHash: string }
  | { status: 'invalid'; problems: string[] };

/** File-system-safe profile name/version segments (also blocks traversal). */
const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function segmentProblems(name: unknown, version: unknown): string[] {
  const problems: string[] = [];
  if (typeof name !== 'string' || !SEGMENT_RE.test(name) || name === '.' || name === '..') {
    problems.push('profile.name: must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} (file-system-safe)');
  }
  if (typeof version !== 'string' || !SEGMENT_RE.test(version) || version === '.' || version === '..') {
    problems.push('profile.version: must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} (file-system-safe)');
  }
  return problems;
}

export class ProfileStore {
  /** `<dataDir>/profiles` */
  private readonly root: string;

  constructor(root: string) {
    this.root = root;
  }

  /** Validate + persist. Immutable versions: same content is idempotent, different content conflicts. */
  async save(candidate: unknown): Promise<SaveResult> {
    const problems = validateProfile(candidate);
    if (problems.length > 0) return { status: 'invalid', problems };
    const profile = candidate as ProtectionProfile;
    const segProblems = segmentProblems(profile.name, profile.version);
    if (segProblems.length > 0) return { status: 'invalid', problems: segProblems };

    const incomingHash = profileHash(profile);
    const existing = await this.get(profile.name, profile.version);
    if (existing !== undefined) {
      if (existing.profileHash === incomingHash) return { status: 'unchanged', stored: existing };
      return {
        status: 'conflict',
        name: profile.name,
        version: profile.version,
        existingHash: existing.profileHash,
        incomingHash,
      };
    }

    const stored: StoredProfile = {
      name: profile.name,
      version: profile.version,
      profileHash: incomingHash,
      savedAtUnixMs: Date.now(),
      profile,
    };
    const dir = join(this.root, profile.name);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, `${profile.version}.json`), JSON.stringify(stored, null, 2), 'utf8');
    return { status: 'created', stored };
  }

  /** Read one stored version. Returns undefined on unknown name/version (or unsafe segments). */
  async get(name: string, version: string): Promise<StoredProfile | undefined> {
    if (segmentProblems(name, version).length > 0) return undefined;
    let raw: string;
    try {
      raw = await readFile(join(this.root, name, `${version}.json`), 'utf8');
    } catch {
      return undefined;
    }
    try {
      const parsed = JSON.parse(raw) as StoredProfile;
      if (validateProfile(parsed.profile).length > 0) return undefined; // tampered on disk
      return parsed;
    } catch {
      return undefined;
    }
  }

  /** All saved versions with hashes, sorted by name then version. */
  async list(): Promise<ProfileListEntry[]> {
    let names: string[];
    try {
      names = (await readdir(this.root, { withFileTypes: true }))
        .filter((e) => e.isDirectory())
        .map((e) => e.name)
        .sort();
    } catch {
      return []; // store dir not created yet — nothing saved
    }
    const entries: ProfileListEntry[] = [];
    for (const name of names) {
      let files: string[];
      try {
        files = (await readdir(join(this.root, name))).filter((f) => f.endsWith('.json')).sort();
      } catch {
        continue;
      }
      for (const file of files) {
        const stored = await this.get(name, file.slice(0, -'.json'.length));
        if (stored === undefined) continue;
        entries.push({
          name: stored.name,
          version: stored.version,
          profileHash: stored.profileHash,
          savedAtUnixMs: stored.savedAtUnixMs,
        });
      }
    }
    return entries;
  }
}
