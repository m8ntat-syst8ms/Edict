/**
 * Precedent-side tool implementations: `edict_query_precedent`,
 * `edict_case_status`, `edict_explain_ruling`.
 *
 * Backed by the shadow-docket corpus (committed cases + groundtruth, plus
 * generated verdicts/reports when a docket run exists locally) and by the
 * sandbox cases adjudicated during this server session. All readers degrade
 * gracefully when generated reports are absent.
 */

import { ToolInputError } from './errors.js';
import { compactReasoning, tribunalInstructionsFor } from './explain.js';
import type { DocketStore } from './docket.js';
import type { SessionStore } from './session.js';

function requireCaseId(args: Record<string, unknown>): string {
  const v = args['caseId'];
  if (typeof v !== 'string' || v.trim().length === 0) {
    throw new ToolInputError(['caseId: must be a non-empty string (CaseObject.caseId uuid or a docket case slug)']);
  }
  return v.trim();
}

const REPORTS_HINT =
  'shadow-docket reports are not generated locally — run `npm run docket -w @edict/shadow-docket` to produce verdicts/reports';

function unknownCaseError(docket: DocketStore, caseId: string): ToolInputError {
  const known = docket
    .loadCases()
    .slice(0, 5)
    .map((c) => `${c.slug} (${c.caseObj.caseId})`);
  return new ToolInputError([
    `caseId "${caseId}" matches no shadow-docket case and no sandbox case from this session`,
    ...(known.length > 0 ? [`known docket cases include: ${known.join('; ')}${docket.loadCases().length > 5 ? '; …' : ''}`] : []),
  ]);
}

// ---------------------------------------------------------------------------
// edict_query_precedent
// ---------------------------------------------------------------------------

export function queryPrecedent(args: Record<string, unknown>, docket: DocketStore): Record<string, unknown> {
  const query = args['query'];
  if (typeof query !== 'string' || query.trim().length === 0) {
    throw new ToolInputError(['query: must be a non-empty string']);
  }
  let tags: string[] | undefined;
  if (args['tags'] !== undefined) {
    if (!Array.isArray(args['tags']) || args['tags'].some((t) => typeof t !== 'string')) {
      throw new ToolInputError(['tags: must be an array of strings']);
    }
    tags = args['tags'] as string[];
  }
  const results = docket.queryPrecedent(query, tags);
  return {
    query,
    ...(tags !== undefined ? { tags } : {}),
    corpus: {
      docketRoot: docket.root,
      totalCases: docket.loadCases().length,
      reportsAvailable: docket.hasReports(),
      ...(docket.hasReports() ? {} : { note: REPORTS_HINT }),
    },
    results,
  };
}

// ---------------------------------------------------------------------------
// edict_case_status
// ---------------------------------------------------------------------------

export function caseStatus(
  args: Record<string, unknown>,
  docket: DocketStore,
  session: SessionStore,
): Record<string, unknown> {
  const caseId = requireCaseId(args);

  const s = session.get(caseId);
  if (s !== undefined) {
    return {
      caseId: s.caseId,
      source: 'sandbox_session',
      status: s.settlement !== null ? 'settled' : s.verdict.final ? 'decided_final_unsettled' : 'escalated_advisory',
      mandateHash: s.mandateHash,
      ruling: s.verdict.ruling,
      final: s.verdict.final,
      quality: s.verdict.quality,
      ...(s.settlement !== null ? { settlement: s.settlement } : {}),
    };
  }

  const c = docket.findCase(caseId);
  if (c === undefined) throw unknownCaseError(docket, caseId);

  const verdict = docket.verdict(c.caseObj.caseId);
  const report = docket.reportResult(c.caseObj.caseId);
  const status =
    verdict === undefined
      ? 'no_local_verdict'
      : verdict.quality.escalated || !verdict.final
        ? 'escalated_advisory'
        : 'decided_final';

  return {
    caseId: c.caseObj.caseId,
    ref: c.slug,
    source: 'shadow_docket',
    status,
    title: c.groundtruth.title ?? c.slug,
    caseType: c.caseObj.caseType,
    publicity: c.caseObj.publicity,
    valueUsd: c.caseObj.valueUsd,
    tier: c.caseObj.tier,
    decisionSpace: c.caseObj.decisionSpace,
    legalProfile: c.caseObj.legalProfile,
    ...(verdict !== undefined
      ? {
          verdict: {
            ruling: verdict.ruling,
            final: verdict.final,
            quality: verdict.quality,
            issuedAtUnixMs: verdict.issuedAtUnixMs,
          },
        }
      : { note: REPORTS_HINT }),
    groundtruth: {
      expected: c.groundtruth.expected,
      ...(c.groundtruth.difficulty !== undefined ? { difficulty: c.groundtruth.difficulty } : {}),
      ...(c.groundtruth.tags !== undefined ? { tags: c.groundtruth.tags } : {}),
    },
    ...(report !== undefined
      ? {
          reportResult: {
            agreedWithGroundtruth: report.agreed,
            majority: report.majority,
            swapFlipRate: report.swapFlipRate,
            escalated: report.escalated,
          },
        }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// edict_explain_ruling
// ---------------------------------------------------------------------------

export function explainRuling(
  args: Record<string, unknown>,
  docket: DocketStore,
  session: SessionStore,
): Record<string, unknown> {
  const caseId = requireCaseId(args);

  const s = session.get(caseId);
  if (s !== undefined) {
    return {
      caseId: s.caseId,
      source: 'sandbox_session',
      ruling: s.verdict.ruling,
      final: s.verdict.final,
      quality: s.verdict.quality,
      reasoningSha256: s.verdict.reasoningSha256,
      ...(s.reasoning !== undefined ? { reasoning: s.reasoning } : {}),
      tribunalInstructions: s.tribunalInstructions,
      ...(s.settlement !== null ? { settlement: s.settlement } : {}),
    };
  }

  const c = docket.findCase(caseId);
  if (c === undefined) throw unknownCaseError(docket, caseId);

  const verdict = docket.verdict(c.caseObj.caseId);
  const reasoning = docket.reasoning(c.caseObj.caseId);
  const notes: string[] = [];
  if (verdict === undefined) notes.push(`no local verdict for this case; ${REPORTS_HINT}`);
  if (reasoning === undefined && verdict !== undefined) {
    notes.push('no archived reasoning document found for this case (reports/archive absent or pruned)');
  }

  // Which tribunal-instruction blocks applied — recomputed deterministically
  // from the committed case + VERIFIED evidence via the @edict/arbiter layer.
  // Files whose bytes no longer hash to their commitments are excluded and
  // surfaced below with an explicit 'integrity_failed' marker.
  const evidence = docket.loadEvidence(c);
  const tribunalInstructions = tribunalInstructionsFor(c.caseObj, evidence.plaintext);
  if (tribunalInstructions.note !== undefined) notes.push(tribunalInstructions.note);
  if (evidence.integrityFailed.length > 0) {
    notes.push(
      `${evidence.integrityFailed.length} evidence file(s) failed sha256 verification against their commitments and were excluded (integrity_failed): ${evidence.integrityFailed.map((f) => f.uri).join(', ')}`,
    );
  }

  return {
    caseId: c.caseObj.caseId,
    ref: c.slug,
    source: 'shadow_docket',
    title: c.groundtruth.title ?? c.slug,
    ...(verdict !== undefined
      ? {
          ruling: verdict.ruling,
          final: verdict.final,
          quality: verdict.quality,
          reasoningSha256: verdict.reasoningSha256,
        }
      : { expected: c.groundtruth.expected, rulingSource: 'groundtruth_expected' }),
    ...(reasoning !== undefined ? { reasoning: compactReasoning(reasoning) } : {}),
    tribunalInstructions,
    ...(evidence.integrityFailed.length > 0 ? { evidenceIntegrityFailures: evidence.integrityFailed } : {}),
    groundtruth: {
      expected: c.groundtruth.expected,
      ...(c.groundtruth.rationale !== undefined ? { rationale: c.groundtruth.rationale } : {}),
    },
    ...(notes.length > 0 ? { notes } : {}),
  };
}
