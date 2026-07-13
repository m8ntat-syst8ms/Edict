import type { DeliveryManifest } from '@edict/evidence';
import type { OrderMandate } from '@edict/core';

export interface ObjectiveFailure {
  criterionId: string;
  reason: string;
}

function stringParam(params: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = params[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

/**
 * Fail-closed deterministic checks the runtime can prove from a signed
 * delivery manifest alone. Unsupported checks remain for the arbiter; they
 * never become automatic failures merely because the runtime cannot run them.
 */
export function evaluateObjectiveFailures(
  mandate: OrderMandate,
  manifest: DeliveryManifest,
): ObjectiveFailure[] {
  const failures: ObjectiveFailure[] = [];
  for (const criterion of mandate.acceptanceCriteria) {
    const check = criterion.machineCheck;
    if (check === undefined) continue;
    if (check.kind === 'deadline_before') {
      const configured = check.params['unixMs'];
      const deadline = typeof configured === 'number' && Number.isSafeInteger(configured)
        ? configured
        : mandate.deadlineUnixMs;
      if (manifest.deliveredAtUnixMs > deadline) {
        failures.push({ criterionId: criterion.id, reason: `delivery timestamp ${manifest.deliveredAtUnixMs} is after ${deadline}` });
      }
      continue;
    }
    if (check.kind === 'hash_equals') {
      const expected = stringParam(check.params, 'sha256', 'expectedSha256')?.toLowerCase().replace(/^0x/, '');
      const path = stringParam(check.params, 'path', 'artifact');
      if (expected === undefined || !/^[0-9a-f]{64}$/.test(expected)) continue;
      const candidates = path === undefined
        ? manifest.artifactHashes
        : manifest.artifactHashes.filter((artifact) => artifact.path === path);
      if (!candidates.some((artifact) => artifact.sha256.toLowerCase().replace(/^0x/, '') === expected)) {
        failures.push({
          criterionId: criterion.id,
          reason: path === undefined
            ? `no delivered artifact matches required hash ${expected}`
            : `artifact ${path} does not match required hash ${expected}`,
        });
      }
    }
  }
  return failures;
}
