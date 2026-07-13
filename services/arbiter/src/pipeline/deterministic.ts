/**
 * Deterministic machine-check layer. Runs after evidence
 * commitment verification and BEFORE the jury.
 *
 * Parses the committed order mandate and delivery manifest, runs
 * `runMachineChecks` from @edict/evidence, and applies a short-circuit
 * ladder. Every rule below is pure: no wall clock ("now" is the case's
 * openedAtUnixMs), no model calls, same case → same analysis.
 *
 *  (a) NON-DELIVERY: no delivery manifest committed anywhere in the case AND
 *      openedAt > mandate deadline → requester_wins (if permitted).
 *  (b) FORGED / INCONSISTENT DELIVERY → requester_wins (if permitted):
 *      - committed delivery-manifest plaintext failed hash verification
 *        (`evidence_hash_mismatch:delivery_manifest` from the integrity layer),
 *      - the manifest's mandate binding contradicts the case (its
 *        orderMandateHash matches neither the case's orderMandateHash nor the
 *        canonical mandate hash, or its jobNonce ≠ the mandate nonce),
 *      - a hash_equals acceptance criterion where the manifest LISTS the
 *        artifact with a sha256 different from the mandated checksum — an
 *        affirmative false conformance claim. (An artifact merely absent from
 *        the manifest is partial/non-delivery, NOT forgery: it fails the
 *        check but is left to the jury.)
 *  (c) PAYMENT-RECEIPT equality checks: a committed payment receipt whose
 *      binding field (jobNonce / orderMandateHash) fails equality against
 *      this mandate deterministically evidences a DIFFERENT engagement; it is
 *      disregarded and recorded as a finding. Only receipts that are
 *      deterministically disposed of this way allow rule (d) to fire — a
 *      receipt that binds to this mandate (or cannot be checked) is a live
 *      settlement question for the jury.
 *  (d) FULL DETERMINISTIC CONFORMANCE: manifest bound to the mandate, every
 *      acceptance criterion carries a machine check, all of them pass, and no
 *      unresolved payment receipt → worker_wins (if permitted).
 *  (e) otherwise NOT dispositive: the per-criterion report is attached to the
 *      evidence frame as a DETERMINISTIC FINDINGS section the jury must weigh.
 *
 *  (f) CLAIM-COMPONENT QUANTUM (claim cases deciding a bounded_scalar space
 *      — the documented claim-component convention, see the services/arbiter
 *      README): an acceptance criterion MAY carry a numeric
 *      `machineCheck.params.payableUsd` declaring the component's
 *      contribution to the claim quantum. The deterministic layer evaluates
 *      each criterion against the COMMITTED evidence:
 *      - `payableUsd > 0` + `hash_equals` with `expectedSha256`/`sha256`:
 *        the component is PAYABLE iff an AUTHENTICATED evidence commitment
 *        with that sha256 exists on the case (optionally restricted by
 *        `params.evidenceKind`). This is the only dispositive component
 *        check in v0: the mandate pre-commits the exact bytes-hash, so
 *        presence of the authenticated commitment is deterministic.
 *      - `payableUsd === 0`: a COMMITTED EXCLUSION — machine-decided by
 *        construction (the mandate's own terms bind the component to zero
 *        regardless of proof); contributes 0.
 *      - anything else (no payableUsd, malformed payableUsd, or a payable
 *        component whose check kind is not hash_equals) is NOT machine-
 *        decidable and leaves a live quantum question for the jury.
 *      Deterministic quantum = Σ payableUsd over PASSING components, clamped
 *      to [space.min, space.max]. When EVERY criterion is machine-decidable
 *      the case short-circuits to a deterministic scalar verdict (rule
 *      'deterministic_claim_quantum', still subject to the shared
 *      escalation/finality gate in ../index.ts); otherwise the per-component
 *      results and the PARTIAL quantum sum are attached to the DETERMINISTIC
 *      FINDINGS section and the jury decides.
 *
 * SHORT-CIRCUIT GUARD: dispositive short-circuits (a)/(b)/(d)
 * apply ONLY to bilateral cases deciding an escrow_branches space — those
 * rules encode bilateral delivery-dispute semantics and their rulings are
 * escrow branches. public_resolution cases (and non-escrow bilateral cases)
 * skip straight to the jury: the machine checks still run and their findings
 * are attached to the evidence frame (with flags), but nothing
 * short-circuits. Claim cases deciding a bounded_scalar space additionally
 * run rule (f) above.
 *
 * If a short-circuit ruling is not among the escrow space's permitted
 * branches the analysis records it as a blocked finding and the case falls
 * through to the jury.
 *
 * Interop notes (kept deterministic and documented):
 * - hash_equals params accept the aliases `artifactName`→path and
 *   `expectedSha256`→sha256 alongside the canonical `{ path, sha256 }`.
 * - manifests are accepted in canonical @edict/evidence shape
 *   (`artifactHashes`) or the venue shape `edict-dm-1` (`artifacts[]` with
 *   name/sha256/format + jobNonce). The raw manifest text is appended to
 *   formatClaims so `contains` checks aimed at the manifest can search it.
 * - `contains` checks that target non-manifest evidence (params.evidenceKind
 *   ≠ 'delivery_manifest') are evaluated against the COMMITTED, verified
 *   plaintext of that evidence kind (optionally filtered by params.submitter).
 *   They produce jury-weight findings ONLY and never enable rule (d):
 *   adversarial text can contain planted magic strings, so a pass on
 *   party-supplied evidence must never be dispositive for the worker. When the
 *   target evidence is sealed the check is SKIPPED, never failed (burden
 *   default: ambiguity against the drafter).
 */
import type {
  AcceptanceCriterion,
  CaseObject,
  CustomerRuleOfDecision,
  EscrowRulingKind,
  OrderMandate,
  Outcome,
  Ruling,
} from '@edict/core';
import { validateCustomerPolicyPack } from '@edict/core';
import {
  canonicalOrderMandateHash,
  normalizeSha256,
  runMachineChecks,
  sha256Canonical,
  type DeliveryManifest,
  type MachineCheckReport,
  type MachineCheckResult,
} from '@edict/evidence';
import type { VerifiedEvidence } from './evidenceIntegrity.js';
import { screenText } from './injectionScreen.js';
import { clamp } from '../util.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type ShortCircuitRule =
  | 'non_delivery_after_deadline'
  | 'forged_delivery_manifest'
  | 'deterministic_conformance'
  | 'deterministic_claim_quantum';

export interface DeterministicShortCircuit {
  /** Escrow Ruling for rules (a/b/d); a scalar Outcome for rule (f). */
  ruling: Outcome;
  rule: ShortCircuitRule;
  detail: string;
  /** Deterministic flags to surface on the verdict (injectionFlags-style). */
  flags: string[];
}

/** One evaluated claim component (rule (f) — the payableUsd convention). */
export interface ClaimComponentResult {
  criterionId: string;
  /** The declared payableUsd (absent when missing/malformed). */
  payableUsd?: number;
  /**
   * pass      — payable: authenticated committed evidence matches the hash;
   * fail      — not payable: no matching authenticated commitment;
   * excluded  — payableUsd === 0, a committed exclusion (decided, pays 0);
   * undecidable — no/malformed payableUsd or a non-dispositive check kind:
   *               the jury must weigh this component.
   */
  status: 'pass' | 'fail' | 'excluded' | 'undecidable';
  detail: string;
}

export interface DeterministicAnalysis {
  /** Per-criterion machine-check report (present when mandate+manifest parsed). */
  report?: MachineCheckReport;
  /** Parsed order-mandate view (present when the committed mandate plaintext parsed). */
  parsedMandate?: ParsedMandate;
  /** DETERMINISTIC FINDINGS frame section for the jury (rule (e); also carries blocked findings). */
  findingsSection?: string;
  /** Set when a rule (a/b/d/f) fired AND its ruling is permitted. */
  shortCircuit?: DeterministicShortCircuit;
  /** Set when a rule fired but its ruling is NOT permitted (jury proceeds with the finding). */
  blocked?: { rule: ShortCircuitRule; wantedKind: Ruling['kind']; detail: string };
  /** Rule (f): per-component evaluation on claim/bounded_scalar cases with payableUsd criteria. */
  claimComponents?: ClaimComponentResult[];
  /** Deterministic flags regardless of path (superset of shortCircuit.flags). */
  flags: string[];
}

// ---------------------------------------------------------------------------
// Tolerant parsing / normalization
// ---------------------------------------------------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Quote + length-cap a party-derived string before interpolating it into findings text. */
function fmt(s: string | undefined): string {
  if (s === undefined) return '(absent)';
  return JSON.stringify(s.length > 80 ? `${s.slice(0, 77)}…` : s);
}

function parseJson(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined) return undefined;
  try {
    const v: unknown = JSON.parse(text);
    return isRecord(v) ? v : undefined;
  } catch {
    return undefined;
  }
}

export interface ParsedMandate {
  raw: Record<string, unknown>;
  nonce?: string;
  deadlineUnixMs?: number;
  criteria: AcceptanceCriterion[];
  /** canonical hash of the raw mandate object (for manifest binding). */
  canonicalHash?: string;
  /** Enumerated Material Adverse Exception events (qualified code deference). */
  maeEvents?: string[];
  /** Rules from a valid, authenticated Policy Pack bound by the signed Legal Policy. */
  customerRules?: CustomerRuleOfDecision[];
}

function parseCustomerRules(
  caseObj: CaseObject,
  verified: VerifiedEvidence,
  mandate: ParsedMandate,
): CustomerRuleOfDecision[] | undefined {
  const legalPolicy = isRecord(mandate.raw.legalPolicy) ? mandate.raw.legalPolicy : undefined;
  if (legalPolicy === undefined || caseObj.legalPolicyHash === undefined) return undefined;
  if (sha256Canonical(legalPolicy) !== caseObj.legalPolicyHash) return undefined;
  const packRef = isRecord(legalPolicy.customerPolicyPack) ? legalPolicy.customerPolicyPack : undefined;
  if (packRef === undefined || typeof packRef.sha256 !== 'string') return undefined;
  const commitment = caseObj.evidence.find(
    (e) => e.kind === 'customer_policy_pack' && e.sha256 === packRef.sha256 && e.authenticated,
  );
  if (commitment === undefined) return undefined;
  const raw = parseJson(verified.plaintext[commitment.sha256]);
  if (raw === undefined || validateCustomerPolicyPack(raw).length > 0) return undefined;
  return structuredClone(raw.rulesOfDecision as CustomerRuleOfDecision[]);
}

function parseMandate(text: string | undefined): ParsedMandate | undefined {
  const raw = parseJson(text);
  if (raw === undefined) return undefined;
  const criteria: AcceptanceCriterion[] = Array.isArray(raw.acceptanceCriteria)
    ? raw.acceptanceCriteria.filter(
        (c): c is AcceptanceCriterion =>
          isRecord(c) && typeof c.id === 'string' && typeof c.statement === 'string',
      )
    : [];
  let canonicalHash: string | undefined;
  try {
    canonicalHash = canonicalOrderMandateHash(raw as unknown as OrderMandate);
  } catch {
    canonicalHash = undefined;
  }
  const out: ParsedMandate = { raw, criteria };
  if (Array.isArray(raw.maeEvents)) {
    out.maeEvents = raw.maeEvents.filter((e): e is string => typeof e === 'string');
  }
  if (typeof raw.nonce === 'string' && raw.nonce.length > 0) out.nonce = raw.nonce;
  if (typeof raw.deadlineUnixMs === 'number' && Number.isSafeInteger(raw.deadlineUnixMs)) {
    out.deadlineUnixMs = raw.deadlineUnixMs;
  }
  if (canonicalHash !== undefined) out.canonicalHash = canonicalHash;
  return out;
}

type Binding = 'bound' | 'contradiction' | 'indeterminate';

interface ParsedManifest {
  manifest: DeliveryManifest;
  binding: Binding;
  bindingDetail: string;
}

/** Normalize canonical or edict-dm-1 manifests; determine mandate binding. */
function parseManifest(
  caseObj: CaseObject,
  om: ParsedMandate | undefined,
  text: string | undefined,
): ParsedManifest | undefined {
  const raw = parseJson(text);
  if (raw === undefined) return undefined;

  const artifactHashes: DeliveryManifest['artifactHashes'] = [];
  const formatClaims: string[] = [];
  const entries = Array.isArray(raw.artifactHashes)
    ? raw.artifactHashes
    : Array.isArray(raw.artifacts)
      ? raw.artifacts
      : [];
  for (const a of entries) {
    if (!isRecord(a)) continue;
    const path = typeof a.path === 'string' ? a.path : typeof a.name === 'string' ? a.name : undefined;
    const sha = typeof a.sha256 === 'string' ? a.sha256 : undefined;
    if (path === undefined || sha === undefined) continue;
    const mediaType =
      typeof a.mediaType === 'string' ? a.mediaType : typeof a.format === 'string' ? a.format : 'application/octet-stream';
    artifactHashes.push({ path, sha256: sha, mediaType });
    formatClaims.push(mediaType);
  }
  if (Array.isArray(raw.formatClaims)) {
    for (const c of raw.formatClaims) if (typeof c === 'string') formatClaims.push(c);
  }
  if (typeof raw.notes === 'string') formatClaims.push(raw.notes);
  // Let `contains` checks aimed at the manifest search its full committed text.
  if (text !== undefined) formatClaims.push(text);

  // --- mandate binding -------------------------------------------------------
  const omhRaw = typeof raw.orderMandateHash === 'string' ? raw.orderMandateHash : undefined;
  const omh = omhRaw !== undefined ? normalizeSha256(omhRaw) : null;
  const omhMatches =
    omh !== null && (omh === caseObj.orderMandateHash || (om?.canonicalHash !== undefined && omh === om.canonicalHash));
  const jobNonce = typeof raw.jobNonce === 'string' ? raw.jobNonce : undefined;
  const nonceComparable = jobNonce !== undefined && om?.nonce !== undefined;
  const nonceMatches = nonceComparable && jobNonce === om.nonce;

  let binding: Binding;
  let bindingDetail: string;
  if ((omhRaw !== undefined && !omhMatches) || (nonceComparable && !nonceMatches)) {
    binding = 'contradiction';
    bindingDetail =
      omhRaw !== undefined && !omhMatches
        ? `manifest.orderMandateHash ${fmt(omhRaw.slice(0, 12))}… matches neither the case orderMandateHash nor the canonical mandate hash`
        : `manifest jobNonce ${fmt(jobNonce)} ≠ mandate nonce ${fmt(om?.nonce)}`;
  } else if (omhMatches || nonceMatches) {
    binding = 'bound';
    bindingDetail = omhMatches ? 'orderMandateHash match' : 'jobNonce match';
  } else {
    binding = 'indeterminate';
    bindingDetail = 'manifest carries no checkable mandate binding (no orderMandateHash / jobNonce pair)';
  }

  const manifest: DeliveryManifest = {
    artifactHashes,
    formatClaims,
    workerAgentId: typeof raw.workerAgentId === 'string' ? raw.workerAgentId : caseObj.worker.agentId,
    // runMachineChecks derives mandateBound from this field; encode our
    // binding determination so the report is consistent with it.
    orderMandateHash: binding === 'bound' && om?.canonicalHash !== undefined ? om.canonicalHash : '0'.repeat(64),
    deliveredAtUnixMs: typeof raw.deliveredAtUnixMs === 'number' ? raw.deliveredAtUnixMs : Number.NaN,
  };
  return { manifest, binding, bindingDetail };
}

/** hash_equals param aliases: artifactName→path, expectedSha256→sha256. */
function normalizeCriteria(criteria: AcceptanceCriterion[]): AcceptanceCriterion[] {
  return criteria.map((c) => {
    if (c.machineCheck?.kind !== 'hash_equals') return c;
    const p = c.machineCheck.params ?? {};
    const path = typeof p.path === 'string' ? p.path : typeof p.artifactName === 'string' ? p.artifactName : undefined;
    const sha = typeof p.sha256 === 'string' ? p.sha256 : typeof p.expectedSha256 === 'string' ? p.expectedSha256 : undefined;
    return {
      ...c,
      machineCheck: {
        kind: 'hash_equals' as const,
        params: { ...p, ...(path !== undefined ? { path } : {}), ...(sha !== undefined ? { sha256: sha } : {}) },
      },
    };
  });
}

/** contains-checks aimed at non-manifest evidence (jury-weight only). */
function targetsNonManifestEvidence(c: AcceptanceCriterion): boolean {
  if (c.machineCheck?.kind !== 'contains') return false;
  const ek = c.machineCheck.params?.evidenceKind;
  return typeof ek === 'string' && ek !== 'delivery_manifest';
}

/**
 * Evaluate a `contains` check against committed evidence of the targeted
 * kind (optionally filtered by submitter). Deterministic string presence:
 * pass if ANY verified plaintext of that kind contains the needle; fail only
 * when EVERY committed item of that kind is available and none contains it;
 * skipped when the target is sealed or the params are malformed.
 */
function evaluateEvidenceContains(
  criterion: AcceptanceCriterion,
  caseObj: CaseObject,
  verified: VerifiedEvidence,
): { status: 'pass' | 'fail' | 'skipped'; detail: string } {
  const params = criterion.machineCheck?.params ?? {};
  const needle = typeof params.needle === 'string' && params.needle.length > 0 ? params.needle : undefined;
  const kind = typeof params.evidenceKind === 'string' ? params.evidenceKind : undefined;
  const submitter = typeof params.submitter === 'string' ? params.submitter : undefined;
  if (needle === undefined || kind === undefined) {
    return { status: 'skipped', detail: 'malformed params: need { needle, evidenceKind, submitter? }' };
  }
  const target = `${kind}${submitter !== undefined ? ` from ${submitter}` : ''}`;
  const commitments = caseObj.evidence.filter(
    (e) => e.kind === kind && (submitter === undefined || e.submitter === submitter),
  );
  if (commitments.length === 0) {
    return { status: 'fail', detail: `no ${target} evidence was committed at all — nothing can contain ${JSON.stringify(needle)}` };
  }
  const texts = commitments
    .map((c) => verified.plaintext[c.sha256])
    .filter((t): t is string => t !== undefined);
  if (texts.some((t) => t.includes(needle))) {
    return { status: 'pass', detail: `committed ${target} evidence contains ${JSON.stringify(needle)}` };
  }
  if (texts.length < commitments.length) {
    return { status: 'skipped', detail: `some ${target} evidence is sealed; cannot rule out ${JSON.stringify(needle)}` };
  }
  return { status: 'fail', detail: `no committed ${target} evidence contains ${JSON.stringify(needle)}` };
}

// ---------------------------------------------------------------------------
// Claim components (rule (f) — the payableUsd convention)
// ---------------------------------------------------------------------------

/**
 * Evaluate one claim's acceptance criteria under the claim-component
 * convention (module doc, rule (f)). Deterministic: decided purely from the
 * case's evidence COMMITMENTS (the mandate pre-commits the exact component
 * hash, so an authenticated commitment carrying it is the committed payment
 * evidence — sealed plaintext does not change the hash).
 */
function evaluateClaimComponents(criteria: AcceptanceCriterion[], caseObj: CaseObject): ClaimComponentResult[] {
  return criteria.map((c) => {
    const params = c.machineCheck?.params ?? {};
    const rawPayable = params.payableUsd;
    if (rawPayable === undefined) {
      return {
        criterionId: c.id,
        status: 'undecidable' as const,
        detail: 'no payableUsd declared — this component is outside the deterministic quantum algebra; the jury weighs it',
      };
    }
    if (typeof rawPayable !== 'number' || !Number.isFinite(rawPayable) || rawPayable < 0) {
      return {
        criterionId: c.id,
        status: 'undecidable' as const,
        detail: `malformed payableUsd ${fmt(String(rawPayable))} — must be a finite number >= 0; the jury weighs this component`,
      };
    }
    if (rawPayable === 0) {
      return {
        criterionId: c.id,
        payableUsd: 0,
        status: 'excluded' as const,
        detail: 'committed exclusion (payableUsd=0): the mandate’s own terms bind this component to zero regardless of proof',
      };
    }
    if (c.machineCheck?.kind !== 'hash_equals') {
      return {
        criterionId: c.id,
        payableUsd: rawPayable,
        status: 'undecidable' as const,
        detail: `payable component uses check kind ${fmt(c.machineCheck?.kind)} — only hash_equals against a committed authenticated evidence hash is dispositive in v0; the jury weighs it`,
      };
    }
    const shaRaw =
      typeof params.expectedSha256 === 'string'
        ? params.expectedSha256
        : typeof params.sha256 === 'string'
          ? params.sha256
          : undefined;
    const expected = shaRaw !== undefined ? normalizeSha256(shaRaw) : null;
    if (expected === null) {
      return {
        criterionId: c.id,
        payableUsd: rawPayable,
        status: 'undecidable' as const,
        detail: 'malformed hash_equals params: need expectedSha256 (or sha256) as 64-hex; the jury weighs this component',
      };
    }
    const kindFilter = typeof params.evidenceKind === 'string' ? params.evidenceKind : undefined;
    const commitments = caseObj.evidence.filter(
      (e) => normalizeSha256(e.sha256) === expected && (kindFilter === undefined || e.kind === kindFilter),
    );
    if (commitments.length === 0) {
      return {
        criterionId: c.id,
        payableUsd: rawPayable,
        status: 'fail' as const,
        detail: `no ${kindFilter ?? 'evidence'} commitment on the case carries the committed component hash ${expected.slice(0, 12)}… — component not payable`,
      };
    }
    if (!commitments.some((e) => e.authenticated)) {
      return {
        criterionId: c.id,
        payableUsd: rawPayable,
        status: 'fail' as const,
        detail: `evidence commitment ${expected.slice(0, 12)}… exists but is not authenticated — the convention requires AUTHENTICATED payment evidence; component not payable`,
      };
    }
    return {
      criterionId: c.id,
      payableUsd: rawPayable,
      status: 'pass' as const,
      detail: `authenticated ${commitments.find((e) => e.authenticated)!.kind} commitment matches the committed component hash ${expected.slice(0, 12)}… — ${rawPayable} USD payable`,
    };
  });
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

export function analyzeDeterministic(caseObj: CaseObject, verified: VerifiedEvidence): DeterministicAnalysis {
  const flags: string[] = [...verified.flags];
  const notes: string[] = [];
  let report: MachineCheckReport | undefined;
  let blocked: DeterministicAnalysis['blocked'];
  let claimComponents: ClaimComponentResult[] | undefined;

  // Dispositive short-circuits apply only to bilateral escrow cases. Every
  // other case shape goes straight to
  // the jury with the machine findings attached (see module doc).
  const space = caseObj.decisionSpace;
  const shortCircuitsEnabled = caseObj.caseType === 'bilateral' && space.kind === 'escrow_branches';
  const escrowPermitted: readonly EscrowRulingKind[] = space.kind === 'escrow_branches' ? space.permitted : [];

  const om = parseMandate(verified.plaintext[caseObj.orderMandateHash]);
  if (om === undefined) {
    notes.push('order mandate plaintext unavailable or not machine-readable JSON; no machine checks ran');
  } else if (caseObj.round !== undefined) {
    // Round 2's deadline is established by the signed redo verdict and the
    // rail state, not by mutating the original signed mandate bytes.
    om.deadlineUnixMs = caseObj.round.effectiveDeadlineUnixMs;
  }
  if (om !== undefined) {
    const customerRules = parseCustomerRules(caseObj, verified, om);
    if (customerRules !== undefined) om.customerRules = customerRules;
  }

  const wantShortCircuit = (
    rule: ShortCircuitRule,
    kind: 'requester_wins' | 'worker_wins',
    detail: string,
    scFlags: string[],
  ): DeterministicAnalysis | undefined => {
    flags.push(...scFlags);
    if (!shortCircuitsEnabled) {
      notes.push(
        `MACHINE FINDING (deterministic short-circuits apply only to bilateral escrow cases; this ${caseObj.caseType} case deciding a ${space.kind} space goes to the jury): rule ${rule} would have ruled ${kind} on a bilateral escrow case — ${detail}`,
      );
      return undefined;
    }
    if (escrowPermitted.includes(kind)) {
      return finish({ ruling: { kind }, rule, detail, flags: scFlags });
    }
    blocked = { rule, wantedKind: kind, detail };
    notes.push(
      `DISPOSITIVE FINDING BLOCKED: rule ${rule} would rule ${kind} (${detail}) but ${kind} is not a permitted ruling for this case; the jury must select among the pre-committed branches with this finding in mind.`,
    );
    return undefined;
  };

  const finish = (shortCircuit?: DeterministicShortCircuit): DeterministicAnalysis => {
    const out: DeterministicAnalysis = { flags: [] };
    if (report !== undefined) out.report = report;
    if (om !== undefined) out.parsedMandate = om;
    if (shortCircuit !== undefined) out.shortCircuit = shortCircuit;
    if (blocked !== undefined) out.blocked = blocked;
    if (claimComponents !== undefined) out.claimComponents = claimComponents;
    const section = renderFindingsSection(report, notes);
    if (section !== undefined) {
      // Party-controlled strings (manifest nonces, claimed hashes, receipt
      // fields) are interpolated into the findings text — screen the whole
      // section so smuggled instruction patterns are neutralized and flagged
      // before it reaches the jury frame.
      const screened = screenText(section, 'deterministic_findings');
      out.findingsSection = screened.sanitized;
      flags.push(...screened.flags);
    }
    out.flags = dedup(flags);
    return out;
  };

  // --- rule (b), forged committed manifest (integrity-layer hash mismatch) ---
  if (verified.mismatchedKinds.has('delivery_manifest')) {
    const r = wantShortCircuit(
      'forged_delivery_manifest',
      'requester_wins',
      'committed delivery-manifest plaintext does not hash to its evidence commitment (forged or substituted manifest)',
      ['deterministic:forged_delivery_manifest'],
    );
    if (r !== undefined) return r;
  }

  // --- rule (a), clean non-delivery -----------------------------------------
  const hasManifestCommitment =
    caseObj.deliveryManifestHash !== undefined || caseObj.evidence.some((e) => e.kind === 'delivery_manifest');
  if (!hasManifestCommitment && om?.deadlineUnixMs !== undefined && caseObj.openedAtUnixMs > om.deadlineUnixMs) {
    const r = wantShortCircuit(
      'non_delivery_after_deadline',
      'requester_wins',
      `no delivery manifest committed and the case opened at ${caseObj.openedAtUnixMs}, after the mandate deadline ${om.deadlineUnixMs} — deterministic non-delivery`,
      ['deterministic:non_delivery_after_deadline'],
    );
    if (r !== undefined) return r;
  }

  // --- rule (f), claim-component quantum (claim + bounded_scalar only) --------
  if (caseObj.caseType === 'claim' && space.kind === 'bounded_scalar' && om !== undefined && om.criteria.length > 0) {
    const criteria = normalizeCriteria(om.criteria);
    const anyPayable = criteria.some((c) => c.machineCheck?.params?.payableUsd !== undefined);
    if (anyPayable) {
      const components = evaluateClaimComponents(criteria, caseObj);
      claimComponents = components;
      const passing = components.filter((c) => c.status === 'pass');
      const undecidable = components.filter((c) => c.status === 'undecidable');
      const sum = passing.reduce((s, c) => s + (c.payableUsd ?? 0), 0);
      const quantum = clamp(sum, space.min, space.max);
      const componentLines = components.map(
        (c) => `claim component [${c.criterionId}] → ${c.status.toUpperCase()} — ${c.detail}`,
      );
      const clampNote = quantum !== sum ? ` (raw sum ${sum} clamped to [${space.min}, ${space.max}])` : '';
      if (undecidable.length === 0) {
        // Every criterion is machine-decided: deterministic scalar verdict.
        // Still subject to the shared escalation/finality gate in ../index.ts.
        return finish({
          ruling: { kind: 'scalar', value: quantum },
          rule: 'deterministic_claim_quantum',
          detail:
            `every acceptance criterion is machine-decided under the claim-component convention; ` +
            `quantum = ${quantum} ${space.unit}${clampNote} from ${passing.length} payable / ` +
            `${components.length} components — ${components
              .map((c) => `${c.criterionId}=${c.status}${c.payableUsd !== undefined ? `:${c.payableUsd}` : ''}`)
              .join(', ')}`,
          flags: ['deterministic:claim_quantum'],
        });
      }
      // Partial: attach the decided component sums as findings; jury decides.
      flags.push('deterministic:claim_partial_quantum');
      notes.push(...componentLines);
      notes.push(
        `CLAIM COMPONENTS (partial): ${passing.length} payable component(s) machine-verified for ` +
          `${quantum} ${space.unit}${clampNote}; ${undecidable.length} component(s) ` +
          `(${undecidable.map((c) => c.criterionId).join(', ')}) are not machine-decidable — ` +
          'the jury must resolve those and may only add to the machine-verified partial quantum where the committed terms support it.',
      );
    }
  }

  // --- parse + bind the manifest, run machine checks --------------------------
  const manifestText =
    caseObj.deliveryManifestHash !== undefined ? verified.plaintext[caseObj.deliveryManifestHash] : undefined;
  const pm = parseManifest(caseObj, om, manifestText);
  if (hasManifestCommitment && manifestText === undefined && !verified.mismatchedKinds.has('delivery_manifest')) {
    notes.push('delivery manifest committed but sealed (plaintext not provided); machine checks did not run');
  } else if (manifestText !== undefined && pm === undefined) {
    notes.push('delivery manifest plaintext is not machine-readable JSON; machine checks did not run');
  }

  if (pm !== undefined) {
    // rule (b), binding contradiction.
    if (pm.binding === 'contradiction') {
      const r = wantShortCircuit(
        'forged_delivery_manifest',
        'requester_wins',
        `delivery manifest does not bind to this order mandate: ${pm.bindingDetail}`,
        ['deterministic:manifest_binding_mismatch'],
      );
      if (r !== undefined) return r;
    }

    if (om !== undefined && om.criteria.length > 0) {
      const criteria = normalizeCriteria(om.criteria);
      const omForChecks = { ...om.raw, acceptanceCriteria: criteria } as unknown as OrderMandate;
      let results: MachineCheckResult[];
      try {
        results = runMachineChecks(omForChecks, pm.manifest).results;
      } catch {
        results = [];
        notes.push('machine-check execution failed on this mandate/manifest pair; falling through to the jury');
      }
      // Burden-default / target-evidence overrides.
      let hasNonManifestTargets = false;
      results = results.map((res) => {
        const criterion = criteria.find((c) => c.id === res.criterionId);
        if (criterion !== undefined && targetsNonManifestEvidence(criterion)) {
          hasNonManifestTargets = true;
          return { ...res, ...evaluateEvidenceContains(criterion, caseObj, verified) };
        }
        if (res.kind === 'deadline_before' && om.deadlineUnixMs === undefined &&
            criterion?.machineCheck?.params?.deadlineUnixMs === undefined) {
          return { ...res, status: 'skipped' as const, detail: 'mandate carries no machine-readable deadline; arbiter evaluates' };
        }
        return res;
      });
      const passed = results.filter((r) => r.status === 'pass').length;
      const failed = results.filter((r) => r.status === 'fail').length;
      const skipped = results.filter((r) => r.status === 'skipped').length;
      const mandateBound = pm.binding === 'bound';
      report = { mandateBound, results, passed, failed, skipped, allDeterministicPassed: mandateBound && failed === 0 };
      notes.unshift(
        pm.binding === 'bound'
          ? `Mandate binding: manifest is bound to this order mandate (${pm.bindingDetail}).`
          : `Mandate binding: ${pm.bindingDetail}.`,
      );

      // rule (b), affirmative false hash claim: the manifest LISTS the mandated
      // artifact under a different checksum.
      const falseClaims: string[] = [];
      for (const c of criteria) {
        if (c.machineCheck?.kind !== 'hash_equals') continue;
        const path = typeof c.machineCheck.params?.path === 'string' ? c.machineCheck.params.path : undefined;
        const shaRaw = typeof c.machineCheck.params?.sha256 === 'string' ? c.machineCheck.params.sha256 : undefined;
        const expected = shaRaw !== undefined ? normalizeSha256(shaRaw) : null;
        if (path === undefined || expected === null) continue;
        const entry = pm.manifest.artifactHashes.find((a) => a.path === path);
        if (entry !== undefined && normalizeSha256(entry.sha256) !== expected) {
          falseClaims.push(c.id);
        }
      }
      if (falseClaims.length > 0) {
        const r = wantShortCircuit(
          'forged_delivery_manifest',
          'requester_wins',
          `delivery manifest claims artifact hash(es) contradicting the mandated checksum(s) for ${falseClaims.join(', ')} — affirmative false conformance claim`,
          falseClaims.map((id) => `deterministic:manifest_artifact_hash_mismatch:${id}`),
        );
        if (r !== undefined) return r;
      }

      // rule (c), payment-receipt equality checks.
      let unresolvedReceipt = false;
      for (const commitment of caseObj.evidence) {
        if (commitment.kind !== 'payment_receipt') continue;
        const receipt = parseJson(verified.plaintext[commitment.sha256]);
        const short = commitment.sha256.slice(0, 8);
        if (receipt === undefined) {
          unresolvedReceipt = true;
          notes.push(`payment receipt ${short}… sealed or not machine-readable; the jury must weigh it`);
          continue;
        }
        const rNonce = typeof receipt.jobNonce === 'string' ? receipt.jobNonce : typeof receipt.nonce === 'string' ? receipt.nonce : undefined;
        const rOmhRaw = typeof receipt.orderMandateHash === 'string' ? receipt.orderMandateHash : undefined;
        const rOmh = rOmhRaw !== undefined ? normalizeSha256(rOmhRaw) : null;
        const nonceCheckable = rNonce !== undefined && om.nonce !== undefined;
        const omhCheckable = rOmh !== null;
        if (!nonceCheckable && !omhCheckable) {
          unresolvedReceipt = true;
          notes.push(`payment receipt ${short}… carries no checkable mandate binding; the jury must weigh it`);
          continue;
        }
        const nonceMismatch = nonceCheckable && rNonce !== om.nonce;
        const omhMismatch =
          omhCheckable && rOmh !== caseObj.orderMandateHash && (om.canonicalHash === undefined || rOmh !== om.canonicalHash);
        if (nonceMismatch || omhMismatch) {
          flags.push('deterministic:payment_receipt_binding_mismatch');
          notes.push(
            nonceMismatch
              ? `payment receipt ${short}… does NOT bind to this mandate (receipt jobNonce ${fmt(rNonce)} ≠ mandate nonce ${fmt(om.nonce)}) — it evidences a different engagement and is disregarded as settlement of this one`
              : `payment receipt ${short}… does NOT bind to this mandate (orderMandateHash mismatch) — it evidences a different engagement and is disregarded as settlement of this one`,
          );
        } else {
          unresolvedReceipt = true;
          notes.push(`payment receipt ${short}… binds to this mandate; the settlement question goes to the jury`);
        }
      }

      // rule (d), full deterministic conformance. Checks over adversarial
      // (non-manifest) evidence never enable (d): planted strings must not
      // hand the worker a dispositive win.
      const everyCriterionChecked = criteria.every((c) => c.machineCheck !== undefined);
      if (report.allDeterministicPassed && everyCriterionChecked && skipped === 0 && passed === criteria.length &&
          !unresolvedReceipt && !hasNonManifestTargets) {
        const r = wantShortCircuit(
          'deterministic_conformance',
          'worker_wins',
          `manifest bound to the mandate and all ${passed} acceptance criteria pass their machine checks — fully deterministic conformance`,
          ['deterministic:all_machine_checks_passed'],
        );
        if (r !== undefined) return r;
      }
    }
  }

  return finish();
}

// ---------------------------------------------------------------------------
// Frame section rendering (rule (e))
// ---------------------------------------------------------------------------

function renderFindingsSection(report: MachineCheckReport | undefined, notes: string[]): string | undefined {
  if (report === undefined && notes.length === 0) return undefined;
  const L: string[] = [];
  L.push('=== DETERMINISTIC FINDINGS (machine-verified by the tribunal — trusted, NOT party-supplied) ===');
  if (report !== undefined) {
    for (const r of report.results) {
      L.push(`- [${r.criterionId}] ${r.kind} → ${r.status.toUpperCase()} — ${r.detail}`);
    }
    L.push(
      `Summary: ${report.passed} PASS, ${report.failed} FAIL, ${report.skipped} SKIPPED; mandate binding ${report.mandateBound ? 'ESTABLISHED' : 'NOT ESTABLISHED'}.`,
    );
  }
  for (const n of notes) L.push(`- ${n}`);
  L.push(
    'These findings were computed deterministically from the committed evidence. They are not party assertions; weigh FAIL/PASS results accordingly and resolve only what the machine checks could not.',
  );
  return L.join('\n');
}

function dedup(xs: string[]): string[] {
  return [...new Set(xs)].sort();
}
