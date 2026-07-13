/**
 * Terminology module (product interface translation table): userFacing lookups,
 * lifecycleState mapping over ProtectionRecord shapes (status + disposition
 * + reviewState), the status palette, and plain-English outcomes.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  LIFECYCLE_STATES,
  TERMINOLOGY,
  lifecycleState,
  plainOutcome,
  statusColor,
  userFacing,
  type LifecycleState,
} from './terminology.js';
import { createEdict } from './client.js';
import { defaultProfile } from './profile.js';

// ---------------------------------------------------------------------------
// userFacing — the binding translation table
// ---------------------------------------------------------------------------

test('userFacing: every user-facing row translates (case-insensitive), unknown terms pass through', () => {
  assert.equal(userFacing('CaseObject'), 'Dispute');
  assert.equal(userFacing('OrderMandate'), 'Transaction terms');
  assert.equal(userFacing('order mandate'), 'Transaction terms');
  assert.equal(userFacing('ProtectionProfile'), 'Protection policy');
  assert.equal(userFacing('VerdictObject'), 'Decision');
  assert.equal(userFacing('verdict'), 'Decision');
  assert.equal(userFacing('Jury seats'), 'Review panel');
  assert.equal(userFacing('Provider proofs'), 'Verification');
  assert.equal(userFacing('Escalation'), 'Appeal / human review');
  assert.equal(userFacing('Decision space'), 'Possible outcomes');
  assert.equal(userFacing('Evidence commitments'), 'Evidence record');
  // Unknown internal terms pass through unchanged (template safety).
  assert.equal(userFacing('Settlement'), 'Settlement');
  // The table itself never contains protocol jargon on the user-facing side.
  for (const v of Object.values(TERMINOLOGY)) {
    assert.doesNotMatch(v, /mandate|verdict|jury|attestation|case/i, v);
  }
});

// ---------------------------------------------------------------------------
// lifecycleState — the status rail
// ---------------------------------------------------------------------------

test('lifecycleState: plain status mapping (Draft/Protected/Delivered/Accepted/Settled)', () => {
  assert.equal(lifecycleState(undefined), 'Draft');
  assert.equal(lifecycleState({}), 'Draft');
  assert.equal(lifecycleState({ status: 'protected' }), 'Protected');
  assert.equal(lifecycleState({ status: 'delivered' }), 'Delivered');
  assert.equal(lifecycleState({ status: 'accepted' }), 'Accepted');
  assert.equal(lifecycleState({ status: 'settled' }), 'Settled');
});

test('lifecycleState: disputed refines by review state, escalation route and decision', () => {
  // A human has the case → Under Review (queued or appealed).
  assert.equal(lifecycleState({ status: 'disputed', reviewState: 'queued' }), 'Under Review');
  assert.equal(lifecycleState({ status: 'disputed', reviewState: 'appealed' }), 'Under Review');
  // Escalated verdict, no human elected → Escalated.
  assert.equal(
    lifecycleState({
      status: 'disputed',
      disposition: { route: 'programmatic_fallback' },
      verdict: { final: false, quality: { escalated: true } },
    }),
    'Escalated',
  );
  // A final decision exists (incl. after human resolution) → Decided.
  assert.equal(
    lifecycleState({ status: 'disputed', verdict: { final: true, quality: { escalated: false } } }),
    'Decided',
  );
  assert.equal(
    lifecycleState({
      status: 'disputed',
      reviewState: 'resolved',
      verdict: { final: true, quality: { escalated: false } },
    }),
    'Decided',
  );
  // Dispute raised, nothing decided yet.
  assert.equal(lifecycleState({ status: 'disputed' }), 'Disputed');
});

test('lifecycleState: a ProtectionRecord maps without adaptation (SDK sandbox round-trip)', async () => {
  const edict = createEdict({
    mode: 'sandbox',
    profile: defaultProfile(),
    archiveDir: join(tmpdir(), 'edict-terminology-test-archive'),
  });
  edict.escrow.deposit('agent:alice', 10_000);
  edict.escrow.deposit('agent:bob', 1_000);
  const p = await edict.protect({
    requester: { agentId: 'agent:alice', principalKybRef: 'kyb:alice' },
    worker: { agentId: 'agent:bob', principalKybRef: 'kyb:bob' },
    description: 'Deliver dataset.bin matching the pinned checksum committed in this mandate.',
    acceptanceCriteria: [
      {
        id: 'AC-1',
        statement: 'dataset.bin matches its pinned checksum.',
        machineCheck: { kind: 'hash_equals', params: { path: 'dataset.bin', sha256: 'a'.repeat(64) } },
      },
    ],
    priceUsd: 500,
    deadlineUnixMs: 1_750_000_000_000,
    overrides: { nonce: 'nonce-terminology' },
  });
  assert.equal(lifecycleState(edict.getRecord(p)), 'Protected');
  await edict.dispute(p, { submissions: {}, openedAtUnixMs: 1_750_100_000_000 });
  assert.equal(lifecycleState(edict.getRecord(p)), 'Decided'); // deterministic final, appealable
  const rec = edict.getRecord(p);
  assert.equal(rec.disposition!.route, 'appealable');
  await edict.appeal(p, 'worker');
  assert.equal(lifecycleState(edict.getRecord(p)), 'Under Review');
  edict.resolveHumanReview(p, { ruling: { kind: 'requester_wins' }, reviewerRef: 'bench:t' });
  assert.equal(lifecycleState(edict.getRecord(p)), 'Decided');
});

// ---------------------------------------------------------------------------
// statusColor — the user-facing palette
// ---------------------------------------------------------------------------

test('statusColor: the status palette covers every rail state', () => {
  assert.equal(statusColor('Protected'), '#1d4ed8'); // blue
  assert.equal(statusColor('Delivered'), '#64748b'); // neutral
  assert.equal(statusColor('Disputed'), '#b45309'); // amber
  assert.equal(statusColor('Under Review'), '#4f46e5'); // indigo
  assert.equal(statusColor('Settled'), '#15803d'); // final/settled green
  assert.equal(statusColor('Decided'), '#15803d');
  assert.equal(statusColor('Accepted'), '#15803d');
  assert.equal(statusColor('Escalated'), '#ea580c'); // orange
  assert.equal(statusColor('Failed'), '#b91c1c'); // failed/blocked red
  for (const state of LIFECYCLE_STATES) {
    assert.match(statusColor(state as LifecycleState), /^#[0-9a-f]{6}$/);
  }
});

// ---------------------------------------------------------------------------
// plainOutcome — plain-English decisions
// ---------------------------------------------------------------------------

test('plainOutcome: escrow branches read as plain English per case shape', () => {
  assert.equal(plainOutcome({ kind: 'requester_wins' }), 'Buyer wins');
  assert.equal(plainOutcome({ kind: 'worker_wins' }), 'Worker wins');
  assert.equal(plainOutcome({ kind: 'requester_wins' }, 'public_resolution'), 'Challenger wins');
  assert.equal(plainOutcome({ kind: 'worker_wins' }, 'public_resolution'), 'Proposer wins');
  assert.equal(plainOutcome({ kind: 'requester_wins' }, 'claim'), 'Claimant wins');
  assert.equal(plainOutcome({ kind: 'worker_wins' }, 'claim'), 'Underwriter wins');
  assert.equal(
    plainOutcome({ kind: 'split', requesterBps: 2_500 }),
    'Split payment (25% to buyer / 75% to worker)',
  );
  assert.equal(
    plainOutcome({ kind: 'redo', newDeadlineUnixMs: Date.UTC(2026, 7, 1) }),
    'Redo work (new deadline 2026-08-01)',
  );
});

test('plainOutcome: categorical labels and scalar quantum phrasing', () => {
  assert.equal(plainOutcome({ kind: 'categorical', outcome: 'YES' }), 'YES');
  assert.equal(plainOutcome({ kind: 'scalar', value: 1_200 }), 'Amount awarded: 1200');
});
