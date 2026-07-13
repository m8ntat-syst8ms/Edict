/**
 * Case + jury validation (operator-diversity rules).
 *
 * Enforced BEFORE any inference runs:
 * - FULL structural schema validation via @edict/core's validateCaseObject
 *   (closed enums, format checks, tier/value consistency, decisionSpace
 *   structural checks, caseType/publicity enums, conditional KYB,
 *   third_party submitter placement, unknown-key rejection, evidence
 *   cross-references) — runs FIRST. Core `warn:`-prefixed entries are
 *   SHOULD-level advisories (e.g. public_resolution SHOULD be public) and do
 *   NOT fail validation here.
 * - Outcome-in-space checking is NOT done here (no outcome exists yet): the
 *   jury parser enforces it per-pass via @edict/core's validateOutcome.
 * - orderMandateHash must match an order_mandate evidence commitment (and
 *   deliveryManifestHash a delivery_manifest commitment, when present).
 * - Jury placement (per-tier operator-diversity rules): tiers A/B require >= 2 DISTINCT
 *   providerIds across the seats (a provider majority is permitted); tier C
 *   requires >= 3 distinct providerIds AND no providerId majority. Model
 *   families are disjoint across seats at ALL tiers.
 */
import type { CaseObject, InferenceProvider, JurySeatSpec } from '@edict/core';
import { validateCaseObject } from '@edict/core';

export class CaseValidationError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`case validation failed:\n- ${problems.join('\n- ')}`);
    this.name = 'CaseValidationError';
    this.problems = problems;
  }
}

export function validateCase(
  caseObj: CaseObject,
  seats: JurySeatSpec[],
  providers: Map<string, InferenceProvider>,
): void {
  const problems: string[] = [];

  // --- canonical structural schema (core validator runs FIRST) ---------------
  // `warn:`-prefixed entries are SHOULD-level advisories in the core result
  // (they never flip ok there either) — advisory, not grounds to refuse the
  // case. Everything else is a hard problem. decisionSpace structure is
  // covered by validateCaseObject (validateDecisionSpace).
  const structural = validateCaseObject(caseObj);
  problems.push(...structural.errors.filter((e) => !e.startsWith('warn:')));

  // --- evidence hash presence ------------------------------------------------
  const hasMandate = caseObj.evidence.some(
    (c) => c.kind === 'order_mandate' && c.sha256 === caseObj.orderMandateHash,
  );
  if (!hasMandate) {
    problems.push(
      `orderMandateHash ${caseObj.orderMandateHash} has no matching order_mandate evidence commitment`,
    );
  }
  if (caseObj.deliveryManifestHash !== undefined) {
    const hasManifest = caseObj.evidence.some(
      (c) => c.kind === 'delivery_manifest' && c.sha256 === caseObj.deliveryManifestHash,
    );
    if (!hasManifest) {
      problems.push(
        `deliveryManifestHash ${caseObj.deliveryManifestHash} has no matching delivery_manifest evidence commitment`,
      );
    }
  }

  // --- jury placement rules ----------------------------------------------------
  if (seats.length === 0) {
    problems.push('jury has no seats');
  }
  const perProvider = new Map<string, number>();
  for (const seat of seats) {
    perProvider.set(seat.providerId, (perProvider.get(seat.providerId) ?? 0) + 1);
    const provider = providers.get(seat.providerId);
    if (provider === undefined) {
      problems.push(`seat ${seat.seatId}: providerId "${seat.providerId}" is not registered in config.providers`);
    } else if (provider.id !== seat.providerId) {
      problems.push(
        `seat ${seat.seatId}: registered provider id "${provider.id}" does not match seat providerId "${seat.providerId}"`,
      );
    }
  }
  // Per-tier operator spread : tiers A/B need >= 2 distinct
  // providers (majority permitted); tier C needs >= 3 distinct providers AND
  // no provider majority.
  if (seats.length > 0) {
    if (caseObj.tier === 'C') {
      if (perProvider.size < 3) {
        problems.push(`tier C requires >= 3 distinct providers across the jury (got ${perProvider.size})`);
      }
      for (const [providerId, count] of perProvider) {
        if (count * 2 > seats.length) {
          problems.push(
            `tier C jury placement violated: provider "${providerId}" holds ${count} of ${seats.length} seats — no provider may hold a jury majority at tier C`,
          );
        }
      }
    } else if (perProvider.size < 2) {
      problems.push(
        `tier ${caseObj.tier} requires >= 2 distinct providers across the jury (got ${perProvider.size})`,
      );
    }
  }
  const families = new Map<string, string>(); // family -> first seatId
  for (const seat of seats) {
    const prior = families.get(seat.modelFamily);
    if (prior !== undefined) {
      problems.push(
        `duplicate modelFamily "${seat.modelFamily}" across seats ${prior} and ${seat.seatId} — families must be disjoint`,
      );
    } else {
      families.set(seat.modelFamily, seat.seatId);
    }
  }

  if (problems.length > 0) throw new CaseValidationError(problems);
}
