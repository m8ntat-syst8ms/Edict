/**
 * Placement-rule and case-shape validation tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { InferenceProvider, JurySeatSpec } from '@edict/core';
import { adjudicate, CaseValidationError, MockProvider, type ArbiterConfig } from './index.js';
import { makeFixture } from './fixtures.js';

function configFor(seats: JurySeatSpec[]): ArbiterConfig {
  const providers = new Map<string, InferenceProvider>();
  for (const seat of seats) {
    if (!providers.has(seat.providerId)) providers.set(seat.providerId, new MockProvider(seat.providerId));
  }
  return { seats, providers, archiveDir: mkdtempSync(join(tmpdir(), 'edict-arbiter-validate-')) };
}

const seat = (providerId: string, family: string, n: number): JurySeatSpec => ({
  seatId: `${providerId}:${family}-${n}`,
  providerId,
  modelId: `${family}-model-${n}`,
  modelFamily: family,
});

test('placement : tier B permits a provider majority across >= 2 distinct providers', async () => {
  // 2-operator 3-seat roster (mock-a holds 2 of 3) — VALID at tier B.
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-a', 'beta', 2), seat('mock-b', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture(); // default tier B
  const verdict = await adjudicate(caseObj, evidencePlaintext, configFor(seats));
  assert.equal(verdict.votes.length, 3, 'tier B 2-operator jury must adjudicate');
});

test('placement : tiers A/B require >= 2 distinct providers', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-a', 'beta', 2), seat('mock-a', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture();
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) =>
      err instanceof CaseValidationError && /tier B requires >= 2 distinct providers/.test(err.message),
  );
});

test('placement : tier C requires at least 3 distinct providers', async () => {
  // The same 2-operator 3-seat roster that is VALID at tier B fails tier C.
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-a', 'beta', 2), seat('mock-b', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture({ tier: 'C', valueUsd: 5000 });
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) => err instanceof CaseValidationError && /tier C requires >= 3 distinct providers/.test(err.message),
  );
});

test('placement : tier C additionally forbids a provider majority', async () => {
  // 3 distinct providers, but mock-a holds 3 of 5 seats.
  const seats = [
    seat('mock-a', 'alpha', 1),
    seat('mock-a', 'beta', 2),
    seat('mock-a', 'gamma', 3),
    seat('mock-b', 'delta', 4),
    seat('mock-c', 'epsilon', 5),
  ];
  const { caseObj, evidencePlaintext } = makeFixture({ tier: 'C', valueUsd: 5000 });
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) => err instanceof CaseValidationError && /majority at tier C/.test(err.message),
  );
});

test('placement : tier C passes with 3 distinct providers and no majority', async () => {
  const seats = [
    seat('mock-a', 'alpha', 1),
    seat('mock-a', 'beta', 2),
    seat('mock-b', 'gamma', 3),
    seat('mock-b', 'delta', 4),
    seat('mock-c', 'epsilon', 5),
  ];
  const { caseObj, evidencePlaintext } = makeFixture({ tier: 'C', valueUsd: 5000 });
  const verdict = await adjudicate(caseObj, evidencePlaintext, configFor(seats));
  assert.equal(verdict.votes.length, 5, 'compliant tier C jury must adjudicate');
});

test('placement: duplicate model families across seats are rejected', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-b', 'alpha', 2), seat('mock-c', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture();
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) => err instanceof CaseValidationError && /duplicate modelFamily/.test(err.message),
  );
});

test('case shape: an empty escrow decision space is rejected (core structural check)', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-b', 'beta', 2), seat('mock-c', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture({ permittedRulings: [] });
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) =>
      err instanceof CaseValidationError && /decisionSpace\.permitted: must be a non-empty array/.test(err.message),
  );
});

test('case shape: warn-level advisories (public_resolution SHOULD be public) do NOT fail validation', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-b', 'beta', 2), seat('mock-c', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture({
    caseId: 'warn-sealed-pubres',
    caseType: 'public_resolution',
    publicity: 'sealed', // core emits warn:case.publicity — advisory only
    decisionSpace: { kind: 'categorical', outcomes: ['YES', 'NO', 'INVALID'], invalidOutcome: 'INVALID' },
  });
  const verdict = await adjudicate(caseObj, evidencePlaintext, configFor(seats));
  assert.equal(verdict.votes.length, 3, 'sealed public_resolution case must still adjudicate');
});

test('case shape: orderMandateHash without a matching order_mandate commitment is rejected', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-b', 'beta', 2), seat('mock-c', 'gamma', 3)];
  const { caseObj, evidencePlaintext } = makeFixture({ mandateCommitmentMatches: false });
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, configFor(seats)),
    (err: unknown) =>
      err instanceof CaseValidationError && /no matching order_mandate evidence commitment/.test(err.message),
  );
});

test('case shape: seat with unregistered provider is rejected', async () => {
  const seats = [seat('mock-a', 'alpha', 1), seat('mock-b', 'beta', 2), seat('mock-c', 'gamma', 3)];
  const config = configFor(seats);
  config.providers.delete('mock-c');
  const { caseObj, evidencePlaintext } = makeFixture();
  await assert.rejects(
    adjudicate(caseObj, evidencePlaintext, config),
    (err: unknown) => err instanceof CaseValidationError && /not registered/.test(err.message),
  );
});
