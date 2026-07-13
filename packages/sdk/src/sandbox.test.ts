/**
 * SandboxEscrow: full ledger lifecycle, every payout branch, dispute-bond
 * economics (loser-pays with half-burn) and the FinalVerdict settle guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { FinalVerdict, LegalProfile, Outcome, VerdictObject } from '@edict/core';
import { ExecutableVerdictError } from '@edict/core';
import { SandboxEscrow } from './sandbox.js';
import {
  EscalatedVerdictError,
  EscrowStateError,
  InsufficientFundsError,
  UnsupportedRulingError,
} from './errors.js';

const LEGAL: LegalProfile = {
  governingLaw: 'england_wales',
  seat: 'london',
  rules: 'edict-drr-v0.1',
  enforcementTier: 'E1',
};

function mkVerdict(caseId: string, ruling: Outcome, final: boolean): VerdictObject {
  return {
    caseId,
    ruling,
    final,
    reasoningSha256: '0'.repeat(64),
    votes: [],
    quality: {
      majority: 'unanimous',
      swapFlipRate: 0,
      injectionFlags: [],
      escalated: !final,
      ...(final ? {} : { escalationReason: 'swap_flip_rate' }),
    },
    legalProfile: LEGAL,
    issuedAtUnixMs: 1_750_000_000_000,
  };
}

const fv = (caseId: string, ruling: Outcome): FinalVerdict => mkVerdict(caseId, ruling, true) as FinalVerdict;

function setup(): SandboxEscrow {
  const escrow = new SandboxEscrow();
  escrow.deposit('req', 1_000);
  escrow.deposit('work', 100);
  return escrow;
}

function fundDisputed(escrow: SandboxEscrow, by: 'requester' | 'worker', caseId: string): void {
  escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 500 });
  escrow.deliver('e1', 1_750_000_000_000);
  escrow.dispute('e1', by, { caseId });
}

test('accept path: worker is paid in full', () => {
  const escrow = setup();
  escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 500 });
  assert.equal(escrow.balanceOf('req'), 500);
  escrow.deliver('e1');
  escrow.accept('e1');
  assert.equal(escrow.balanceOf('work'), 600);
  assert.equal(escrow.record('e1')!.status, 'accepted');
  // Nothing burned, nothing bonded on the happy path.
  assert.equal(escrow.burnedTotalUsd(), 0);
});

test('fund: insufficient balance and duplicate ids are rejected', () => {
  const escrow = new SandboxEscrow();
  escrow.deposit('req', 100);
  assert.throws(
    () => escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 500 }),
    InsufficientFundsError,
  );
  escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 100 });
  assert.throws(
    () => escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 1 }),
    EscrowStateError,
  );
});

test('state machine: accept needs delivered; deliver needs funded/redo', () => {
  const escrow = setup();
  escrow.fund({ escrowId: 'e1', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 500 });
  assert.throws(() => escrow.accept('e1'), EscrowStateError);
  escrow.deliver('e1');
  assert.throws(() => escrow.deliver('e1'), EscrowStateError);
  assert.throws(() => escrow.accept('unknown'), EscrowStateError);
});

test('dispute: posts a 5% bond from the disputant', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const rec = escrow.record('e1')!;
  assert.equal(rec.status, 'disputed');
  assert.equal(rec.bondUsd, 25); // 5% of 500
  assert.equal(escrow.balanceOf('req'), 475); // 1000 - 500 - 25
  // A worker with no bond funds cannot dispute.
  const poor = new SandboxEscrow();
  poor.deposit('req', 500);
  poor.fund({ escrowId: 'e2', requesterAgentId: 'req', workerAgentId: 'work', amountUsd: 500 });
  assert.throws(() => poor.dispute('e2', 'worker'), InsufficientFundsError);
});

test('settle requester_wins: winning disputant gets a full bond refund', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const rec = escrow.settle(fv('case-1', { kind: 'requester_wins' }));
  assert.equal(rec.status, 'settled');
  assert.deepEqual(rec.settlement, {
    ruling: { kind: 'requester_wins' },
    requesterPayoutUsd: 500,
    workerPayoutUsd: 0,
    bondRefundUsd: 25,
    bondBurnedUsd: 0,
    bondToCounterpartyUsd: 0,
  });
  assert.equal(escrow.balanceOf('req'), 1_000);
  assert.equal(escrow.balanceOf('work'), 100);
  assert.equal(escrow.burnedTotalUsd(), 0);
});

test('settle worker_wins vs a losing requester-disputant: loser pays, half burns', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  escrow.settle(fv('case-1', { kind: 'worker_wins' }));
  const s = escrow.record('e1')!.settlement!;
  assert.equal(s.workerPayoutUsd, 500);
  assert.equal(s.bondRefundUsd, 0);
  assert.equal(s.bondBurnedUsd, 12.5);
  assert.equal(s.bondToCounterpartyUsd, 12.5);
  assert.equal(escrow.balanceOf('req'), 475); // lost escrow + bond
  assert.equal(escrow.balanceOf('work'), 612.5); // 100 + 500 + 12.5
  assert.equal(escrow.burnedTotalUsd(), 12.5);
});

test('settle split(7500): payouts and bond refund are pro-rata to the winning share', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  escrow.settle(fv('case-1', { kind: 'split', requesterBps: 7_500 }));
  const s = escrow.record('e1')!.settlement!;
  assert.equal(s.requesterPayoutUsd, 375);
  assert.equal(s.workerPayoutUsd, 125);
  assert.equal(s.bondRefundUsd, 18.75); // 75% of the 25 bond
  assert.equal(s.bondBurnedUsd, 3.125);
  assert.equal(s.bondToCounterpartyUsd, 3.125);
  assert.equal(escrow.balanceOf('req'), 868.75); // 1000 - 500 - 25 + 375 + 18.75
  assert.equal(escrow.balanceOf('work'), 228.125); // 100 + 125 + 3.125
  assert.equal(escrow.burnedTotalUsd(), 3.125);
});

test('settle redo: bond stays held, then acceptance allocates it on the final outcome', () => {
  const escrow = setup();
  fundDisputed(escrow, 'worker', 'case-1');
  const rec = escrow.settle(fv('case-1', { kind: 'redo', newDeadlineUnixMs: 1_750_300_000_000 }));
  assert.equal(rec.status, 'redo');
  assert.equal(rec.settlement!.newDeadlineUnixMs, 1_750_300_000_000);
  assert.equal(rec.settlement!.bondRefundUsd, 0);
  assert.equal(rec.settlement!.bondHeldUsd, 25);
  assert.equal(rec.bondUsd, 25);
  assert.equal(rec.rounds.length, 1);
  assert.equal(escrow.balanceOf('work'), 75); // bond remains held
  assert.equal(escrow.balanceOf('req'), 500); // escrow still locked
  // The redo escrow accepts a fresh delivery and can be released.
  escrow.deliver('e1');
  escrow.accept('e1');
  assert.equal(escrow.balanceOf('work'), 600);
  assert.equal(escrow.record('e1')!.rounds.length, 2);
});

test('settle guards: unknown case, non-disputed state, double settle', () => {
  const escrow = setup();
  assert.throws(() => escrow.settle(fv('nope', { kind: 'requester_wins' })), EscrowStateError);
  fundDisputed(escrow, 'requester', 'case-1');
  escrow.settle(fv('case-1', { kind: 'requester_wins' }));
  assert.throws(() => escrow.settle(fv('case-1', { kind: 'requester_wins' })), EscrowStateError);
});

test('settle: non-escrow rulings are not executable here', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  assert.throws(
    () => escrow.settle(fv('case-1', { kind: 'categorical', outcome: 'YES' })),
    UnsupportedRulingError,
  );
});

test('FinalVerdict guard: escalated verdicts can neither compile nor execute', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const escalated = mkVerdict('case-1', { kind: 'requester_wins' }, false);
  assert.throws(
    () => {
      // @ts-expect-error — a plain VerdictObject (final: boolean) is NOT assignable
      // to FinalVerdict (final: true); the sandbox rejects it at compile time.
      escrow.settle(escalated);
    },
    (err: unknown) => err instanceof EscalatedVerdictError && (err as EscalatedVerdictError).caseId === 'case-1',
  );
  // A cast cannot smuggle it past the runtime guard either.
  assert.throws(() => escrow.settle(escalated as FinalVerdict), EscalatedVerdictError);
  assert.equal(escrow.record('e1')!.status, 'disputed'); // ledger untouched
});

// ---------------------------------------------------------------------------
// Executable-verdict gate — the core assertExecutableVerdict gate inside settle()
// ---------------------------------------------------------------------------

test('settle: final=true but quality.escalated=true is rejected by the executable-verdict gate', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const inconsistent = mkVerdict('case-1', { kind: 'requester_wins' }, true);
  inconsistent.quality.escalated = true; // pipeline-bug shape a cast could smuggle in
  assert.throws(
    () => escrow.settle(inconsistent as FinalVerdict),
    (err: unknown) => err instanceof ExecutableVerdictError && /quality\.escalated=true/.test((err as Error).message),
  );
  assert.equal(escrow.record('e1')!.status, 'disputed'); // ledger untouched
});

test('settle: attack-severity injection flags on a final verdict are rejected (no silent execution)', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const flagged = fv('case-1', { kind: 'requester_wins' });
  flagged.quality.injectionFlags.push('attack:instruction_override:party_submission:worker:deadbeef');
  assert.throws(
    () => escrow.settle(flagged),
    (err: unknown) => err instanceof ExecutableVerdictError && /attack-severity/.test((err as Error).message),
  );
  assert.equal(escrow.record('e1')!.status, 'disputed');
});

test('settle: an out-of-vocabulary escrow ruling (split bps out of range) is rejected in-space', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  assert.throws(
    () => escrow.settle(fv('case-1', { kind: 'split', requesterBps: 11_000 })),
    (err: unknown) => err instanceof ExecutableVerdictError,
  );
  assert.equal(escrow.record('e1')!.status, 'disputed');
});

test('settle: note-level flags do not block execution (happy path through the gate)', () => {
  const escrow = setup();
  fundDisputed(escrow, 'requester', 'case-1');
  const noted = fv('case-1', { kind: 'requester_wins' });
  noted.quality.injectionFlags.push('note:imperative_advocacy', 'deterministic:non_delivery_after_deadline');
  const rec = escrow.settle(noted);
  assert.equal(rec.status, 'settled');
});
