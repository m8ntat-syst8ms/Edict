#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tracked = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: root })
  .toString('utf8')
  .split('\0')
  .filter((file) => file.length > 0 && existsSync(resolve(root, file)));

const forbiddenPaths = [
  /^apps\/shadow-docket\/(?:holdout|private-cases|private-results|reports)\//,
  /^services\/arbiter\/(?:private-tests|production)\//,
  /^config\/(?:customers|production)\//,
  /(?:^|\/)\.env(?!\.example$)(?:\.|$)/,
  /(?:^|\/)\.credentials\//,
  /\.seats\.production\.json$/,
  /\.signing-policy\.json$/,
];

const violations = tracked.filter((file) => forbiddenPaths.some((pattern) => pattern.test(file)));
if (violations.length > 0) {
  throw new Error(`private or operational files are tracked:\n${violations.map((file) => `- ${file}`).join('\n')}`);
}

const manifestPath = resolve(root, 'apps/shadow-docket/PUBLIC_FIXTURES.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
if (manifest.classification !== 'illustrative_only' || manifest.qualificationEligible !== false) {
  throw new Error('PUBLIC_FIXTURES.json must classify the public corpus as non-qualifying illustration');
}

const casePrefix = 'apps/shadow-docket/cases/';
const committedCases = [...new Set(
  tracked
    .filter((file) => file.startsWith(casePrefix))
    .map((file) => file.slice(casePrefix.length).split('/')[0])
    .filter(Boolean),
)].sort();
const declaredCases = [...manifest.cases].sort();
if (JSON.stringify(committedCases) !== JSON.stringify(declaredCases)) {
  throw new Error(
    `public fixture manifest mismatch\ntracked: ${committedCases.join(', ')}\ndeclared: ${declaredCases.join(', ')}`,
  );
}

const privateTags = new Set(['adversarial', 'prompt_injection', 'qualification', 'holdout']);
for (const slug of committedCases) {
  const groundTruthPath = resolve(root, casePrefix, slug, 'groundtruth.json');
  const groundTruth = JSON.parse(readFileSync(groundTruthPath, 'utf8'));
  const leakedTags = (groundTruth.tags ?? []).filter((tag) => privateTags.has(tag));
  if (groundTruth.expectInjectionFlag === true || leakedTags.length > 0) {
    throw new Error(`${slug} contains private qualification or adversarial markers`);
  }
}

console.log(`public boundary OK: ${committedCases.length} illustrative fixtures; no private paths tracked`);
