/**
 * Offline Edict Protect end-to-end product demonstration:
 *
 *   an agent buys a digital service over an x402-style payment
 *   → the service returns incomplete output
 *   → the protected transaction is shown
 *   → evidence was already captured
 *   → a deterministic check catches the missing artifact
 *   → decision: buyer wins
 *   → the refund executes
 *   → the audit drawer shows the hashes and proofs.
 *
 * The demonstration uses customer-facing language until its final audit view.
 * It runs the same @edict/sdk sandbox pipeline as the customer app and
 * quickstart: linting, evidence commitments, deterministic checks, an offline
 * mock jury, and the settlement guard.
 *
 * Run from the repo root:  npm run demo
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  createEdict,
  isFinalVerdict,
  lifecycleState,
  plainOutcome,
  presetByKey,
  statusColor,
  LIFECYCLE_STATES,
} from '@edict/sdk';
import { runMachineChecks } from '@edict/evidence';

// ---------------------------------------------------------------------------
// Narration helpers
// ---------------------------------------------------------------------------

const t0 = Date.now();
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
const short = (h: string) => `${h.slice(0, 10)}…`;
const usd = (n: number) => `$${n.toFixed(2)}`;

function banner(n: number, title: string): void {
  console.log('');
  console.log(`━━━ ${n}. ${title} ${'━'.repeat(Math.max(2, 62 - title.length))}`);
}
function say(...lines: string[]): void {
  for (const l of lines) console.log(`  ${l}`);
}

// ---------------------------------------------------------------------------
// Cast: a buyer agent and a data service, on an x402-style payment rail
// ---------------------------------------------------------------------------

const BUYER = { agentId: 'agent:acme-procurement', principalKybRef: 'kyb:acme-corp' };
const SELLER = { agentId: 'agent:dataworks-service', principalKybRef: 'kyb:dataworks-llc' };
const PRICE_USD = 120;

// The digital good the buyer is paying for: a two-file pricing dataset.
// The buyer pins the exact bytes it expects for the dataset up front.
const EXPECTED_DATASET = 'sku,region,price_usd\nA-100,eu,41.90\nA-100,us,39.00\nB-220,eu,18.75\n';
const EXPECTED_DATASET_SHA = sha256(EXPECTED_DATASET);
const METHOD_NOTES = '# Methodology\nCollected 2026-07-08 from public price pages; normalized to USD.\n';
const METHOD_NOTES_SHA = sha256(METHOD_NOTES);

async function main(): Promise<void> {
  console.log('EDICT — protected transactions for agent commerce (sandbox demo)');
  console.log('Scenario: an agent buys a $120 pricing dataset from a data service.');

  // The Basic protection policy — one of the three hash-committed presets
  // ("Small automated tasks. Fast checks, no human review." — the right fit
  // for a $120 machine-checkable dataset purchase).
  const preset = presetByKey('basic')!;
  const archiveDir = mkdtempSync(join(tmpdir(), 'edict-demo-audit-'));
  const edict = createEdict({ mode: 'sandbox', profile: preset.profile, archiveDir });

  // ── 1. The agent pays for a digital service ────────────────────────────────
  banner(1, 'An agent buys a digital service (x402-style payment)');
  edict.escrow.deposit(BUYER.agentId, 200);
  const order = await edict.protect({
    requester: BUYER,
    worker: SELLER,
    description:
      'Deliver the Q3 competitor pricing dataset for SKUs A-100 and B-220 (EU + US), ' +
      'as dataset.csv matching the pinned checksum, plus methodology notes in notes.md.',
    acceptanceCriteria: [
      {
        id: 'AC-1',
        statement: 'dataset.csv is delivered and matches the checksum pinned at purchase.',
        machineCheck: { kind: 'hash_equals', params: { path: 'dataset.csv', sha256: EXPECTED_DATASET_SHA } },
      },
      {
        id: 'AC-2',
        statement: 'notes.md is delivered and documents the collection methodology.',
        machineCheck: { kind: 'contains', params: { path: 'notes.md', needle: 'Methodology' } },
      },
    ],
    priceUsd: PRICE_USD,
    deadlineUnixMs: Date.now() + 86_400_000,
  });
  say(
    `Payment sent: ${usd(PRICE_USD)} USDC, x402-style — the HTTP payment header carries`,
    `the protection reference ${short(order.mandateHash)} so the money and the terms travel together.`,
    `The transaction terms (what "done" means, in 2 checkable criteria) were agreed`,
    `and locked before any money moved. Funds sit in the sandbox holding account.`,
    `Protection policy: "${preset.title}" (policy fingerprint ${short(order.profileHash)}).`,
  );

  // ── 2. The service returns incomplete output ───────────────────────────────
  banner(2, 'The service returns incomplete output');
  await edict.deliver(order, {
    artifactHashes: [{ path: 'notes.md', sha256: METHOD_NOTES_SHA, mediaType: 'text/markdown' }],
    formatClaims: ['text/markdown'],
  });
  say(
    'The service delivers… one file. notes.md arrives; dataset.csv — the thing',
    'the buyer actually paid for — is missing from the delivery.',
    'No human is watching. This is exactly the failure agent payments can\'t handle today.',
  );

  // ── 3. The protected transaction ───────────────────────────────────────────
  banner(3, 'The protected transaction');
  const rec = edict.getRecord(order);
  const state = lifecycleState(rec);
  const rail = LIFECYCLE_STATES.filter((s) => s !== 'Escalated')
    .map((s) => (s === state ? `[${s}]` : s))
    .join(' → ');
  say(
    `Status rail: ${rail}`,
    `Current status: ${state} (rendered ${statusColor(state)})`,
    `Terms: ${usd(PRICE_USD)} · 2 acceptance criteria · delivery deadline in 24h · outcome set:`,
    `buyer wins / seller wins / split / redo — all agreed before payment.`,
  );

  // ── 4. Evidence was already captured ───────────────────────────────────────
  banner(4, 'Evidence: already captured, nothing to chase');
  const disputeText =
    'dataset.csv is missing from the delivery; AC-1 cannot be satisfied. Refund requested.';
  say('The evidence record was built as the transaction happened — not reconstructed after:');
  say(`  • Transaction terms — sealed at purchase (${short(order.mandateHash)})`);
  say(`  • Delivery record — sealed at delivery (${short(rec.manifestHash!)})`);
  say(`  • Buyer's dispute note — sealed at filing (${short(sha256(disputeText))})`);
  say('Neither side can rewrite history: every item is fingerprinted the moment it exists.');

  // ── 5. The deterministic check catches the missing artifact ────────────────
  banner(5, 'Automated checks run first — and catch it');
  const report = runMachineChecks(
    rec.mandate,
    rec.manifest!,
    new Map([['notes.md', new TextEncoder().encode(METHOD_NOTES)]]),
  );
  for (const r of report.results) {
    say(`  [${r.criterionId}] ${r.status.toUpperCase().padEnd(4)} — ${r.detail}`);
  }
  say(
    `Checks: ${report.passed} passed, ${report.failed} failed.`,
    'AC-1 fails on facts alone: the promised file is simply not in the delivery.',
    'No opinion involved yet — this class of dispute costs nothing to decide.',
  );

  // ── 6. The decision ────────────────────────────────────────────────────────
  banner(6, 'The dispute is filed and decided');
  const verdict = await edict.dispute(order, { submissions: { requester: disputeText } });
  const decided = lifecycleState(edict.getRecord(order));
  const decisionPath = verdict.votes.length === 0
    ? [
        'The failed objective check is conclusive, so the deterministic layer resolves it',
        'without paying for a model jury.',
      ]
    : [
        'The failed check narrows the facts, but the mixed-criterion remedy still needs judgment.',
        `${verdict.votes.length} independent reviewers each judge twice with the parties swapped, so neither side gets the good seat.`,
      ];
  say(
    `The buyer's agent files the dispute (posting a ${usd(rec.mandate.priceUsd * 0.05)} good-faith bond).`,
    ...decisionPath,
    '',
    `Decision: ${plainOutcome(verdict.ruling)} — unanimous, no flip when positions swapped.`,
    `Status: ${decided}.`,
  );

  // ── 7. Settlement executes ─────────────────────────────────────────────────
  banner(7, 'The refund executes');
  if (!isFinalVerdict(verdict)) throw new Error('demo invariant: expected a final decision');
  const settled = edict.settle(verdict);
  const s = settled.settlement!;
  say(
    `Settlement (sandbox ledger): buyer refunded ${usd(s.requesterPayoutUsd)} + ${usd(s.bondRefundUsd)} bond back;`,
    `seller receives ${usd(s.workerPayoutUsd)}. Status: ${lifecycleState(edict.getRecord(order))}.`,
    '',
    'The full path has also executed on NEAR Testnet through the keyless settlement contract:',
    '  settlement       https://testnet.nearblocks.io/address/protect.m2.edict-req-ggrb91.testnet',
    '  fund             https://testnet.nearblocks.io/txns/ACvHhp66xp1jqZWEPpp6M18P38HPmUJrqesoFQ3zNrLg',
    '  deliver          https://testnet.nearblocks.io/txns/GmGCErJ5gsotmkDTxfobeDrjLpLEj6B5FbhPNKt8PLTj',
    '  open dispute     https://testnet.nearblocks.io/txns/6RkeZrYR2N9Ws65HHTan7KsvaD7htKnuy1W98K9uHcYe',
    '  submit ruling    https://testnet.nearblocks.io/txns/3hSukXVWQQnmXP2MLCoScWLGiBk7psVHQeCZvMva4NKy',
    '  withdraw claim   https://testnet.nearblocks.io/txns/A8yMskugjiDgRJbUWwd2myvzwnFupTxBDtL5d4TFBn5B',
    '  (the signed challenge clock, exact digest, immutable quorum and fixed recipient were rechecked on-chain;',
    '   the model seats and signer keys in this testnet run are test-only.)',
  );

  // ── 8. The audit drawer ────────────────────────────────────────────────────
  banner(8, 'Audit mode — technical record');
  const audit = edict.getRecord(order);
  const c = audit.caseObject;
  const v = audit.verdict;
  if (c === undefined || v === undefined) throw new Error('demo invariant: adjudication record is missing');
  say(
    `CaseObject          ${c.caseId} (tier ${c.tier}, ${c.caseType}, custody ${c.custodyMode})`,
    `OrderMandate hash   ${order.mandateHash}`,
    `DeliveryManifest    ${audit.manifestHash!}`,
    `ProtectionProfile   ${order.profileHash} (preset "${preset.title}", hash-committed)`,
    `Reasoning sha256    ${v.reasoningSha256}`,
    `Evidence commitments (${c.evidence.length}):`,
  );
  for (const e of c.evidence) {
    say(`    • ${e.kind.padEnd(18)} ${e.sha256}  [${e.submitter}${e.authenticated ? ', authenticated' : ''}]`);
  }
  const seats = v.votes.map((vt) => `${vt.seat.providerId}/${vt.seat.modelFamily}`).join(', ');
  say(
    v.votes.length === 0
      ? 'Decision path       deterministic machine-check short circuit (no model calls)'
      : `Decision path       ${v.votes.length}-seat jury (${seats})`,
    `Quality             majority=${v.quality.majority}, swapFlipRate=${v.quality.swapFlipRate}, ` +
      `injectionFlags=[${v.quality.injectionFlags.join(', ')}], escalated=${v.quality.escalated}`,
    `Verdict             final=${v.final}, ruling=${JSON.stringify(v.ruling)}`,
    `Proof policy        requireProofs=${preset.profile.juryPolicy.requireProofs} (Basic preset — sandbox mock seats; ` +
      'production rosters require reviewed TEE signer allowlists and attestation policies)',
    `Audit bundle        ${archiveDir} (per-pass request/response captures, reasoning, verdict JSON)`,
    '',
    'With production TEE operators, this drawer also carries ECDSA proofs recovered',
    'to attested signers. The testnet links demonstrate the same digest/quorum',
    'contract checks with explicitly test-only keys.',
  );

  console.log('');
  console.log(`Done in ${((Date.now() - t0) / 1000).toFixed(2)}s — the whole dispute cost fractions of a cent to resolve.`);
}

main().catch((err) => {
  console.error('demo failed:', err);
  process.exitCode = 1;
});
