/**
 * Sandbox escrow simulation — an in-memory ledger implementing the
 * pre-committed payout branches, dispute bonds and loser-pays-with-half-burn
 * bond economics. No chain and no real assets are involved. It simulates what
 * a customer-hosted wallet, contract or payment rail may do after verifying an
 * Edict SettlementDirective; it is never a hosted Edict balance or live rail.
 *
 * Non-custodial invariant preserved: `settle` only ever executes a ruling
 * that lies within the escrow branch vocabulary, and ONLY from a
 * `FinalVerdict` — the type-level `final: true` refinement makes passing an
 * escalated verdict a compile error, and the runtime guard throws
 * {@link EscalatedVerdictError} on any cast that smuggles one through.
 *
 * Bond economics (documented contract):
 * - `dispute` posts a bond of `disputeBondFraction` × escrow amount
 *   (default 5%) from the disputant's balance.
 * - At settlement the disputant's WINNING SHARE of the escrow determines the
 *   bond refund pro-rata: requester_wins → share 1 for a requester-disputant
 *   (full refund) and 0 for a worker-disputant (full forfeit); split(bps)
 *   refunds proportionally.
 * - The forfeited part is split half/half: one half is BURNED (removed from
 *   the ledger — spam deterrence), the other half is paid to the
 *   counterparty (loser-pays).
 * - `redo` has no loser yet: the original bond remains held, the escrow stays
 *   locked, and the record returns to a re-deliverable state. The same
 *   disputant reopens round 2 without posting a second bond; v0 permits one
 *   redo. Acceptance or the final ruling then allocates the held bond.
 */

import type { DecisionSpace, FinalVerdict } from '@edict/core';
import { assertExecutableVerdict } from '@edict/core';
import {
  EscalatedVerdictError,
  EscrowStateError,
  InsufficientFundsError,
  UnsupportedRulingError,
} from './errors.js';

/**
 * The sandbox escrow's own decision space: it can execute any of the four
 * pre-committed payout branches. `settle` validates the incoming ruling
 * against this space via the core `assertExecutableVerdict` guard (the
 * case-specific space was already enforced when the arbiter issued the
 * verdict; `EdictClient.settle` re-checks it when the case is known).
 */
const SANDBOX_ESCROW_SPACE: DecisionSpace = {
  kind: 'escrow_branches',
  permitted: ['requester_wins', 'worker_wins', 'split', 'redo'],
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EscrowPartyRole = 'requester' | 'worker';

export type EscrowStatus = 'funded' | 'delivered' | 'accepted' | 'disputed' | 'redo' | 'settled';

export interface EscrowSettlement {
  ruling: FinalVerdict['ruling'];
  requesterPayoutUsd: number;
  workerPayoutUsd: number;
  bondRefundUsd: number;
  bondBurnedUsd: number;
  bondToCounterpartyUsd: number;
  /** Non-zero only for redo: the original Bond remains locked for round 2. */
  bondHeldUsd?: number;
  /** Present only for `redo` rulings. */
  newDeadlineUnixMs?: number;
}

export interface EscrowRound {
  number: number;
  caseId?: string;
  openedAtUnixMs?: number;
  deliveredAtUnixMs?: number;
  resolution?: FinalVerdict['ruling'] | { kind: 'accepted' };
  resolvedAtUnixMs?: number;
  bondHeldAfterUsd?: number;
}

export interface EscrowRecord {
  escrowId: string;
  requesterAgentId: string;
  workerAgentId: string;
  amountUsd: number;
  status: EscrowStatus;
  /** Bond currently posted (0 unless status is 'disputed'). */
  bondUsd: number;
  disputedBy?: EscrowPartyRole;
  /** CaseObject.caseId this escrow's dispute is bound to (settle looks it up). */
  caseId?: string;
  deliveredAtUnixMs?: number;
  settlement?: EscrowSettlement;
  /** Append-only dispute/redo audit trail. */
  rounds: EscrowRound[];
  /** v0 permits at most one redo. */
  redoCount: number;
}

export interface SandboxEscrowOptions {
  /** Dispute bond as a fraction of the escrow amount. Default 0.05 (5%). */
  disputeBondFraction?: number;
}

export const DEFAULT_DISPUTE_BOND_FRACTION = 0.05;

/** Round to micro-USD so ledger arithmetic never accumulates float noise. */
function r6(x: number): number {
  return Math.round(x * 1e6) / 1e6;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

export class SandboxEscrow {
  private readonly balances = new Map<string, number>();
  private readonly records = new Map<string, EscrowRecord>();
  private readonly byCaseId = new Map<string, string>(); // caseId -> escrowId
  private burned = 0;
  private readonly bondFraction: number;

  constructor(opts: SandboxEscrowOptions = {}) {
    const f = opts.disputeBondFraction ?? DEFAULT_DISPUTE_BOND_FRACTION;
    if (!Number.isFinite(f) || f < 0 || f >= 1) {
      throw new RangeError(`disputeBondFraction must be in [0, 1), got ${f}`);
    }
    this.bondFraction = f;
  }

  /** Credit a sandbox balance. Returns the new balance. */
  deposit(agentId: string, amountUsd: number): number {
    if (typeof agentId !== 'string' || agentId.length === 0) throw new TypeError('agentId must be a non-empty string');
    if (!Number.isFinite(amountUsd) || amountUsd <= 0) throw new RangeError(`deposit amount must be > 0, got ${amountUsd}`);
    const next = r6(this.balanceOf(agentId) + amountUsd);
    this.balances.set(agentId, next);
    return next;
  }

  balanceOf(agentId: string): number {
    return this.balances.get(agentId) ?? 0;
  }

  /** Total USD removed from the ledger by bond half-burns. */
  burnedTotalUsd(): number {
    return this.burned;
  }

  record(escrowId: string): EscrowRecord | undefined {
    const rec = this.records.get(escrowId);
    return rec !== undefined ? structuredClone(rec) : undefined;
  }

  /** Lock `amountUsd` from the requester's balance into a new escrow. */
  fund(input: {
    escrowId: string;
    requesterAgentId: string;
    workerAgentId: string;
    amountUsd: number;
  }): EscrowRecord {
    const { escrowId, requesterAgentId, workerAgentId, amountUsd } = input;
    if (!Number.isFinite(amountUsd) || amountUsd <= 0) {
      throw new RangeError(`escrow amount must be > 0, got ${amountUsd}`);
    }
    if (this.records.has(escrowId)) {
      throw new EscrowStateError(`escrow ${escrowId} already exists`);
    }
    const available = this.balanceOf(requesterAgentId);
    if (available < amountUsd) {
      throw new InsufficientFundsError(requesterAgentId, amountUsd, available);
    }
    this.balances.set(requesterAgentId, r6(available - amountUsd));
    const rec: EscrowRecord = {
      escrowId,
      requesterAgentId,
      workerAgentId,
      amountUsd,
      status: 'funded',
      bondUsd: 0,
      rounds: [],
      redoCount: 0,
    };
    this.records.set(escrowId, rec);
    return structuredClone(rec);
  }

  /** Worker marks delivery (funded or post-redo escrows). */
  deliver(escrowId: string, deliveredAtUnixMs?: number): EscrowRecord {
    const rec = this.require(escrowId);
    if (rec.status !== 'funded' && rec.status !== 'redo') {
      throw new EscrowStateError(`escrow ${escrowId} is '${rec.status}' — deliver() needs 'funded' or 'redo'`);
    }
    rec.status = 'delivered';
    rec.deliveredAtUnixMs = deliveredAtUnixMs ?? Date.now();
    return structuredClone(rec);
  }

  /** Requester accepts (or the acceptance window auto-releases): pay the worker in full. */
  accept(escrowId: string): EscrowRecord {
    const rec = this.require(escrowId);
    if (rec.status !== 'delivered') {
      throw new EscrowStateError(`escrow ${escrowId} is '${rec.status}' — accept() needs 'delivered'`);
    }
    this.credit(rec.workerAgentId, rec.amountUsd);
    if (rec.bondUsd > 0) {
      const bond = this.allocateBond(rec, 0);
      rec.settlement = {
        ruling: { kind: 'worker_wins' },
        requesterPayoutUsd: 0,
        workerPayoutUsd: rec.amountUsd,
        ...bond,
      };
      rec.rounds.push({
        number: rec.rounds.length + 1,
        deliveredAtUnixMs: rec.deliveredAtUnixMs,
        resolution: { kind: 'accepted' },
        resolvedAtUnixMs: Date.now(),
        bondHeldAfterUsd: 0,
      });
    }
    rec.status = 'accepted';
    return structuredClone(rec);
  }

  /** Open a dispute: the disputant posts the bond; the case id binds the verdict. */
  dispute(escrowId: string, by: EscrowPartyRole, opts: { caseId?: string } = {}): EscrowRecord {
    const rec = this.require(escrowId);
    if (rec.status !== 'funded' && rec.status !== 'delivered' && rec.status !== 'redo') {
      throw new EscrowStateError(
        `escrow ${escrowId} is '${rec.status}' — dispute() needs 'funded', 'delivered' or 'redo'`,
      );
    }
    const disputantId = by === 'requester' ? rec.requesterAgentId : rec.workerAgentId;
    if (rec.bondUsd > 0) {
      if (rec.disputedBy !== by) {
        throw new EscrowStateError(
          `escrow ${escrowId} holds the round-1 bond from '${rec.disputedBy}' — only that party may reopen round 2`,
        );
      }
    } else {
      const bond = r6(rec.amountUsd * this.bondFraction);
      const available = this.balanceOf(disputantId);
      if (available < bond) throw new InsufficientFundsError(disputantId, bond, available);
      this.balances.set(disputantId, r6(available - bond));
      rec.bondUsd = bond;
      rec.disputedBy = by;
    }
    rec.status = 'disputed';
    if (opts.caseId !== undefined) this.bindCase(escrowId, opts.caseId);
    rec.rounds.push({
      number: rec.rounds.length + 1,
      ...(opts.caseId !== undefined ? { caseId: opts.caseId } : {}),
      openedAtUnixMs: Date.now(),
      deliveredAtUnixMs: rec.deliveredAtUnixMs,
    });
    return structuredClone(rec);
  }

  /** Bind (or rebind) a case id to an escrow so `settle(verdict)` can find it. */
  bindCase(escrowId: string, caseId: string): void {
    const rec = this.require(escrowId);
    if (rec.caseId !== undefined) this.byCaseId.delete(rec.caseId);
    rec.caseId = caseId;
    this.byCaseId.set(caseId, escrowId);
  }

  /**
   * Execute a FINAL verdict's payout branch plus the bond economics.
   *
   * Compile-time: only `FinalVerdict` (final: true) is accepted. Runtime
   * defence in depth: a verdict whose `final` flag is not `true` throws
   * {@link EscalatedVerdictError} before touching the ledger, and the core
   * `assertExecutableVerdict` guard re-checks everything the type promises
   * (not escalated, ruling within the escrow branch space, no
   * attack-severity injection flags) before any balance moves.
   */
  settle(verdict: FinalVerdict): EscrowRecord {
    if (verdict.final !== true) {
      throw new EscalatedVerdictError(
        verdict.caseId,
        (verdict as { quality?: { escalationReason?: string } }).quality?.escalationReason,
      );
    }
    const ruling = verdict.ruling;
    if (ruling.kind === 'categorical' || ruling.kind === 'scalar') {
      throw new UnsupportedRulingError(ruling.kind);
    }
    // Apply the executable-verdict gate before creating a directive.
    // consistency, outcome-in-space, attack-flag screen — fails closed
    // BEFORE the ledger is touched.
    assertExecutableVerdict(verdict, SANDBOX_ESCROW_SPACE);

    const escrowId = this.byCaseId.get(verdict.caseId);
    if (escrowId === undefined) {
      throw new EscrowStateError(`no escrow is bound to case ${verdict.caseId} — dispute()/bindCase() first`);
    }
    const rec = this.require(escrowId);
    if (rec.status !== 'disputed') {
      throw new EscrowStateError(`escrow ${escrowId} is '${rec.status}' — settle() needs 'disputed'`);
    }
    if (ruling.kind === 'redo') {
      if (rec.redoCount >= 1) throw new EscrowStateError(`escrow ${escrowId} already used its single permitted redo`);
      // No loser yet: HOLD the original bond and allow one re-delivery round.
      const settlement: EscrowSettlement = {
        ruling,
        requesterPayoutUsd: 0,
        workerPayoutUsd: 0,
        bondRefundUsd: 0,
        bondBurnedUsd: 0,
        bondToCounterpartyUsd: 0,
        bondHeldUsd: rec.bondUsd,
        newDeadlineUnixMs: ruling.newDeadlineUnixMs,
      };
      rec.settlement = settlement;
      rec.redoCount += 1;
      this.resolveCurrentRound(rec, ruling, rec.bondUsd);
      rec.status = 'redo';
      return structuredClone(rec);
    }

    const requesterShare =
      ruling.kind === 'requester_wins' ? 1 : ruling.kind === 'worker_wins' ? 0 : ruling.requesterBps / 10_000;

    const requesterPayout = r6(rec.amountUsd * requesterShare);
    const workerPayout = r6(rec.amountUsd - requesterPayout);
    this.credit(rec.requesterAgentId, requesterPayout);
    this.credit(rec.workerAgentId, workerPayout);
    const bond = this.allocateBond(rec, requesterShare);

    rec.settlement = {
      ruling,
      requesterPayoutUsd: requesterPayout,
      workerPayoutUsd: workerPayout,
      ...bond,
    };
    this.resolveCurrentRound(rec, ruling, 0);
    rec.status = 'settled';
    return structuredClone(rec);
  }

  private credit(agentId: string, amountUsd: number): void {
    if (amountUsd === 0) return;
    this.balances.set(agentId, r6(this.balanceOf(agentId) + amountUsd));
  }

  private allocateBond(
    rec: EscrowRecord,
    requesterShare: number,
  ): Pick<EscrowSettlement, 'bondRefundUsd' | 'bondBurnedUsd' | 'bondToCounterpartyUsd'> {
    const disputedBy = rec.disputedBy ?? 'requester';
    const disputantId = disputedBy === 'requester' ? rec.requesterAgentId : rec.workerAgentId;
    const counterpartyId = disputedBy === 'requester' ? rec.workerAgentId : rec.requesterAgentId;
    const disputantShare = disputedBy === 'requester' ? requesterShare : 1 - requesterShare;
    const bondRefundUsd = r6(rec.bondUsd * disputantShare);
    const forfeited = r6(rec.bondUsd - bondRefundUsd);
    const bondBurnedUsd = r6(forfeited / 2);
    const bondToCounterpartyUsd = r6(forfeited - bondBurnedUsd);
    this.credit(disputantId, bondRefundUsd);
    this.credit(counterpartyId, bondToCounterpartyUsd);
    this.burned = r6(this.burned + bondBurnedUsd);
    rec.bondUsd = 0;
    rec.disputedBy = undefined;
    return { bondRefundUsd, bondBurnedUsd, bondToCounterpartyUsd };
  }

  private resolveCurrentRound(
    rec: EscrowRecord,
    resolution: FinalVerdict['ruling'],
    bondHeldAfterUsd: number,
  ): void {
    const round = rec.rounds.at(-1);
    if (round === undefined || round.resolution !== undefined) {
      throw new EscrowStateError(`escrow ${rec.escrowId} has no open dispute round to resolve`);
    }
    round.resolution = structuredClone(resolution);
    round.resolvedAtUnixMs = Date.now();
    round.bondHeldAfterUsd = bondHeldAfterUsd;
  }

  private require(escrowId: string): EscrowRecord {
    const rec = this.records.get(escrowId);
    if (rec === undefined) throw new EscrowStateError(`unknown escrow ${escrowId}`);
    return rec;
  }
}
