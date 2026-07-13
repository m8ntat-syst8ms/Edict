/**
 * Deterministic test/demo fixtures. Not a test file itself — imported by the
 * *.test.ts suites and usable for generating CLI example inputs.
 */
import type {
  CaseObject,
  CaseType,
  DecisionSpace,
  EscrowRulingKind,
  EvidenceCommitment,
  LegalProfile,
  OrderMandate,
  PartyRef,
  Publicity,
  ValueTier,
} from '@edict/core';
import { sha256Hex } from './util.js';

export interface FixtureOptions {
  caseId?: string;
  tier?: ValueTier;
  valueUsd?: number;
  /** Case shape. Defaults: bilateral / sealed (public_resolution defaults to public). */
  caseType?: CaseType;
  publicity?: Publicity;
  /** Full decision space; overrides permittedRulings when given. */
  decisionSpace?: DecisionSpace;
  /** Escrow shorthand: builds an escrow_branches space with these branches. */
  permittedRulings?: EscrowRulingKind[];
  /** Enumerated MAE events written into the order mandate. */
  maeEvents?: string[];
  requesterSubmission?: string;
  workerSubmission?: string;
  manifestText?: string;
  /** When false the order_mandate commitment hash is corrupted (for validate tests). */
  mandateCommitmentMatches?: boolean;
}

export interface Fixture {
  caseObj: CaseObject;
  evidencePlaintext: Record<string, string>;
}

/**
 * Deterministic uuid-v4-shaped id derived from a human-readable label (the
 * core validator requires caseId to be a uuid v4; tests want stable,
 * meaningfully-named cases). Same label → same uuid.
 */
export function fixtureUuid(label: string): string {
  const h = sha256Hex(`edict-fixture:${label}`);
  return (
    `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-` +
    `${'89ab'[parseInt(h[16]!, 16) % 4]}${h.slice(17, 20)}-${h.slice(20, 32)}`
  );
}

export const WORKER_FAVORING_SUBMISSION =
  'Worker submission: all ten pages were delivered on time. The translation was completed, ' +
  'verified against the agreed glossary, and passed every review check. The client confirmed ' +
  'receipt of the files, which were uploaded as agreed. Work completed and delivered in full.';

export const REQUESTER_FAVORING_SUBMISSION =
  'Requester submission: the delivery is missing three pages, the formatting is broken, the ' +
  'glossary check failed, and the work is incomplete and late. This is a breach of the mandate; ' +
  'the output is unusable and I request a refund.';

export const NEUTRAL_REQUESTER_SUBMISSION =
  'Requester submission: please review the record and decide per the mandate.';

export function makeFixture(opts: FixtureOptions = {}): Fixture {
  const legalProfile: LegalProfile = {
    governingLaw: 'england_wales',
    seat: 'london',
    rules: 'edict-drr-v0.1',
    enforcementTier: 'E1',
  };
  const requester: PartyRef = { agentId: 'agent:req-1', principalKybRef: 'kyb:req-principal' };
  const worker: PartyRef = { agentId: 'agent:work-1', principalKybRef: 'kyb:work-principal' };
  const caseType: CaseType = opts.caseType ?? 'bilateral';
  const publicity: Publicity = opts.publicity ?? (caseType === 'public_resolution' ? 'public' : 'sealed');
  const decisionSpace: DecisionSpace = opts.decisionSpace ?? {
    kind: 'escrow_branches',
    permitted: opts.permittedRulings ?? ['requester_wins', 'worker_wins', 'split', 'redo'],
  };

  const mandate: OrderMandate = {
    version: 'edict-om-1',
    requester,
    worker,
    description: 'Translate ten pages of technical documentation into German.',
    acceptanceCriteria: [
      { id: 'AC-1', statement: 'All ten pages are translated.' },
      { id: 'AC-2', statement: 'Delivery occurs before the deadline.' },
    ],
    priceUsd: opts.valueUsd ?? 500,
    currency: { asset: 'USDC', rail: 'test-rail' },
    deadlineUnixMs: 1_750_000_000_000,
    acceptanceWindowMs: 86_400_000,
    legalProfile,
    decisionSpace,
    maeEvents: opts.maeEvents ?? [],
    nonce: 'nonce-fixture-1',
  };
  const mandateText = JSON.stringify(mandate);
  const mandateHash = sha256Hex(mandateText);

  const manifestText =
    opts.manifestText ?? 'Manifest: 10 artifacts, format=pdf, artifactRoot=deadbeef, signedBy=worker.';
  const manifestHash = sha256Hex(manifestText);

  const requesterSubmission = opts.requesterSubmission ?? NEUTRAL_REQUESTER_SUBMISSION;
  const workerSubmission = opts.workerSubmission ?? WORKER_FAVORING_SUBMISSION;
  const reqSubHash = sha256Hex(requesterSubmission);
  const workSubHash = sha256Hex(workerSubmission);

  const evidence: EvidenceCommitment[] = [
    {
      kind: 'order_mandate',
      sha256: opts.mandateCommitmentMatches === false ? sha256Hex('some-other-mandate') : mandateHash,
      submitter: 'system',
      authenticated: true,
    },
    { kind: 'delivery_manifest', sha256: manifestHash, submitter: 'worker', authenticated: true },
    { kind: 'party_submission', sha256: reqSubHash, submitter: 'requester', authenticated: false },
    { kind: 'party_submission', sha256: workSubHash, submitter: 'worker', authenticated: false },
  ];

  const caseObj: CaseObject = {
    caseId: fixtureUuid(opts.caseId ?? 'case-fixture-0001'),
    caseType,
    publicity,
    requester,
    worker,
    orderMandateHash: mandateHash,
    deliveryManifestHash: manifestHash,
    evidence,
    valueUsd: opts.valueUsd ?? 500,
    tier: opts.tier ?? 'B',
    custodyMode: 'M2_external_escrow',
    railRef: { rail: 'test-rail' },
    legalProfile,
    openedAtUnixMs: 1_750_000_000_000,
    decisionSpace,
  };

  const evidencePlaintext: Record<string, string> = {
    // When the order_mandate commitment is deliberately corrupted, the real
    // mandate bytes match no commitment — the boundary would reject them as
    // unknown evidence, so the fixture (correctly) cannot provide them.
    ...(opts.mandateCommitmentMatches === false ? {} : { [mandateHash]: mandateText }),
    [manifestHash]: manifestText,
    [reqSubHash]: requesterSubmission,
    [workSubHash]: workerSubmission,
  };

  return { caseObj, evidencePlaintext };
}
