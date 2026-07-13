/**
 * Deterministic machine checks — the pre-arbiter layer (spec C5).
 *
 * `runMachineChecks` evaluates every `AcceptanceCriterion.machineCheck` in an
 * order mandate against a delivery manifest (and, optionally, the actual
 * artifact bytes). It never calls a model and never guesses:
 *
 * - `pass`    — the check deterministically holds.
 * - `fail`    — the check deterministically does not hold.
 * - `skipped` — the check could not be evaluated deterministically
 *               (no machineCheck, `custom` kind, malformed params, or
 *               missing artifact bytes). Skipped criteria go to the arbiter.
 *
 * Burden default (evidence policy — ambiguity against drafter): a criterion the
 * requester drafted so poorly it cannot be evaluated is `skipped`, never
 * silently `fail`ed against the worker. Only genuine mismatches fail.
 */

import type { AcceptanceCriterion, OrderMandate } from '@edict/core';
import { normalizeSha256, sha256Hex } from './hash.js';
import { canonicalOrderMandateHash } from './orderMandate.js';
import type { DeliveryManifest } from './deliveryManifest.js';

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

export type MachineCheckStatus = 'pass' | 'fail' | 'skipped';

export interface MachineCheckResult {
  criterionId: string;
  statement: string;
  /** machineCheck.kind, or 'none' when the criterion has no machine check. */
  kind: 'hash_equals' | 'schema_valid' | 'deadline_before' | 'contains' | 'custom' | 'none';
  status: MachineCheckStatus;
  /** Human-readable, deterministic explanation (safe to hash / log). */
  detail: string;
}

export interface MachineCheckReport {
  /** manifest.orderMandateHash === canonicalOrderMandateHash(om). */
  mandateBound: boolean;
  results: MachineCheckResult[];
  passed: number;
  failed: number;
  skipped: number;
  /** True iff the manifest binds to the mandate AND no check failed (skipped checks are left to the arbiter). */
  allDeterministicPassed: boolean;
}

// ---------------------------------------------------------------------------
// Param helpers
// ---------------------------------------------------------------------------

function asString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

// ---------------------------------------------------------------------------
// Minimal structural schema validation (deliberately tiny — not JSON Schema)
// ---------------------------------------------------------------------------

/**
 * Supported schema keywords: `type` (string or string[]; one of object,
 * array, string, number, integer, boolean, null), `required` (string[]),
 * `properties` (recursive), `items` (recursive), `enum`, `const`.
 * Unknown keywords are ignored. Returns a list of error strings ([] = valid).
 */
export function validateStructuralSchema(value: unknown, schema: unknown, path = '$'): string[] {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    return [`${path}: schema must be an object`];
  }
  const s = schema as Record<string, unknown>;
  const errors: string[] = [];

  if (s.type !== undefined) {
    const allowed = Array.isArray(s.type) ? s.type : [s.type];
    const actual = jsonTypeOf(value);
    const matches = allowed.some((t) => t === actual || (t === 'number' && actual === 'integer'));
    if (!matches) errors.push(`${path}: expected type ${allowed.join('|')}, got ${actual}`);
  }

  if (Array.isArray(s.required) && value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of s.required) {
      if (typeof key === 'string' && !(key in (value as Record<string, unknown>))) {
        errors.push(`${path}: missing required property "${key}"`);
      }
    }
  }

  if (s.properties !== null && typeof s.properties === 'object' && !Array.isArray(s.properties)) {
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const props = s.properties as Record<string, unknown>;
      for (const [key, subSchema] of Object.entries(props)) {
        const record = value as Record<string, unknown>;
        if (key in record) {
          errors.push(...validateStructuralSchema(record[key], subSchema, `${path}.${key}`));
        }
      }
    }
  }

  if (s.items !== undefined && Array.isArray(value)) {
    value.forEach((el, i) => {
      errors.push(...validateStructuralSchema(el, s.items, `${path}[${i}]`));
    });
  }

  if (Array.isArray(s.enum)) {
    const match = s.enum.some((candidate) => deepEqualJson(candidate, value));
    if (!match) errors.push(`${path}: value not in enum`);
  }

  if ('const' in s) {
    if (!deepEqualJson(s.const, value)) errors.push(`${path}: value !== const`);
  }

  return errors;
}

function jsonTypeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  switch (typeof value) {
    case 'number':
      return Number.isInteger(value) ? 'integer' : 'number';
    case 'string':
    case 'boolean':
    case 'object':
      return typeof value;
    default:
      return typeof value;
  }
}

function deepEqualJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((el, i) => deepEqualJson(el, b[i]));
  }
  const ka = Object.keys(a as object).sort();
  const kb = Object.keys(b as object).sort();
  if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false;
  return ka.every((k) => deepEqualJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

// ---------------------------------------------------------------------------
// Individual check kinds
// ---------------------------------------------------------------------------

type CheckOutcome = { status: MachineCheckStatus; detail: string };

/**
 * hash_equals params: { path: string, sha256: string }
 * Pass iff the manifest lists `path` with the expected sha256 AND, when
 * artifact bytes are supplied, the recomputed hash matches too.
 */
function checkHashEquals(
  params: Record<string, unknown>,
  manifest: DeliveryManifest,
  artifacts?: Map<string, Uint8Array>,
): CheckOutcome {
  const path = asString(params.path);
  const rawExpected = asString(params.sha256);
  const expected = rawExpected === null ? null : normalizeSha256(rawExpected);
  if (path === null || expected === null) {
    return { status: 'skipped', detail: 'malformed params: need { path: string, sha256: 64-hex }' };
  }
  const entry = manifest.artifactHashes.find((a) => a.path === path);
  if (entry === undefined) {
    return { status: 'fail', detail: `artifact "${path}" not listed in delivery manifest` };
  }
  const claimed = normalizeSha256(entry.sha256);
  if (claimed !== expected) {
    return { status: 'fail', detail: `manifest hash for "${path}" is ${entry.sha256}, expected ${expected}` };
  }
  const bytes = artifacts?.get(path);
  if (bytes !== undefined) {
    const actual = sha256Hex(bytes);
    if (actual !== expected) {
      return { status: 'fail', detail: `artifact bytes for "${path}" hash to ${actual}, expected ${expected}` };
    }
    return { status: 'pass', detail: `manifest hash and artifact bytes both match ${expected}` };
  }
  return { status: 'pass', detail: `manifest hash matches ${expected} (artifact bytes not supplied, not recomputed)` };
}

/**
 * schema_valid params: { path: string, schema: object }
 * Requires artifact bytes; parses them as JSON and validates against the
 * minimal structural schema (see validateStructuralSchema).
 */
function checkSchemaValid(
  params: Record<string, unknown>,
  artifacts?: Map<string, Uint8Array>,
): CheckOutcome {
  const path = asString(params.path);
  const schema = params.schema;
  if (path === null || schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    return { status: 'skipped', detail: 'malformed params: need { path: string, schema: object }' };
  }
  const bytes = artifacts?.get(path);
  if (bytes === undefined) {
    return { status: 'skipped', detail: `artifact bytes for "${path}" not supplied; cannot validate schema` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeUtf8(bytes));
  } catch (err) {
    return { status: 'fail', detail: `artifact "${path}" is not valid JSON: ${(err as Error).message}` };
  }
  const errors = validateStructuralSchema(parsed, schema);
  if (errors.length > 0) {
    return { status: 'fail', detail: `schema violations: ${errors.join('; ')}` };
  }
  return { status: 'pass', detail: `artifact "${path}" conforms to the structural schema` };
}

/**
 * deadline_before params: { deadlineUnixMs?: number } — defaults to the
 * mandate's own deadline. Pass iff deliveredAtUnixMs <= deadline.
 */
function checkDeadlineBefore(
  params: Record<string, unknown>,
  om: OrderMandate,
  manifest: DeliveryManifest,
): CheckOutcome {
  let deadline = om.deadlineUnixMs;
  if (params.deadlineUnixMs !== undefined) {
    if (typeof params.deadlineUnixMs !== 'number' || !Number.isSafeInteger(params.deadlineUnixMs)) {
      return { status: 'skipped', detail: 'malformed params: deadlineUnixMs must be an integer when present' };
    }
    deadline = params.deadlineUnixMs;
  }
  if (!Number.isSafeInteger(manifest.deliveredAtUnixMs)) {
    return { status: 'skipped', detail: 'manifest.deliveredAtUnixMs is not an integer' };
  }
  if (manifest.deliveredAtUnixMs <= deadline) {
    return { status: 'pass', detail: `delivered at ${manifest.deliveredAtUnixMs} <= deadline ${deadline}` };
  }
  return {
    status: 'fail',
    detail: `delivered at ${manifest.deliveredAtUnixMs}, ${manifest.deliveredAtUnixMs - deadline}ms after deadline ${deadline}`,
  };
}

/**
 * contains params: { needle: string, path?: string }
 * With `path`: artifact bytes (required, else skipped) decoded as UTF-8 must
 * contain `needle`. Without `path`: some manifest formatClaim must contain it.
 */
function checkContains(
  params: Record<string, unknown>,
  manifest: DeliveryManifest,
  artifacts?: Map<string, Uint8Array>,
): CheckOutcome {
  const needle = asString(params.needle);
  if (needle === null) {
    return { status: 'skipped', detail: 'malformed params: need { needle: string, path?: string }' };
  }
  if (params.path !== undefined) {
    const path = asString(params.path);
    if (path === null) {
      return { status: 'skipped', detail: 'malformed params: path must be a non-empty string when present' };
    }
    const bytes = artifacts?.get(path);
    if (bytes === undefined) {
      return { status: 'skipped', detail: `artifact bytes for "${path}" not supplied; cannot search` };
    }
    if (decodeUtf8(bytes).includes(needle)) {
      return { status: 'pass', detail: `artifact "${path}" contains ${JSON.stringify(needle)}` };
    }
    return { status: 'fail', detail: `artifact "${path}" does not contain ${JSON.stringify(needle)}` };
  }
  if (manifest.formatClaims.some((claim) => claim.includes(needle))) {
    return { status: 'pass', detail: `a manifest formatClaim contains ${JSON.stringify(needle)}` };
  }
  return { status: 'fail', detail: `no manifest formatClaim contains ${JSON.stringify(needle)}` };
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

function runOne(
  criterion: AcceptanceCriterion,
  om: OrderMandate,
  manifest: DeliveryManifest,
  artifacts?: Map<string, Uint8Array>,
): MachineCheckResult {
  const base = { criterionId: criterion.id, statement: criterion.statement };
  const check = criterion.machineCheck;
  if (check === undefined) {
    return { ...base, kind: 'none', status: 'skipped', detail: 'no machine check defined; arbiter evaluates' };
  }
  const params = check.params ?? {};
  let outcome: CheckOutcome;
  switch (check.kind) {
    case 'hash_equals':
      outcome = checkHashEquals(params, manifest, artifacts);
      break;
    case 'schema_valid':
      outcome = checkSchemaValid(params, artifacts);
      break;
    case 'deadline_before':
      outcome = checkDeadlineBefore(params, om, manifest);
      break;
    case 'contains':
      outcome = checkContains(params, manifest, artifacts);
      break;
    case 'custom':
      outcome = { status: 'skipped', detail: 'custom checks are not deterministic here; arbiter evaluates' };
      break;
    default:
      outcome = { status: 'skipped', detail: `unknown machine check kind "${(check as { kind: string }).kind}"` };
      break;
  }
  return { ...base, kind: check.kind, ...outcome };
}

/**
 * Execute every deterministic machine check in the mandate against the
 * delivery manifest (and optional artifact bytes keyed by manifest path).
 * Pure and deterministic: same inputs → same report.
 */
export function runMachineChecks(
  om: OrderMandate,
  manifest: DeliveryManifest,
  artifacts?: Map<string, Uint8Array>,
): MachineCheckReport {
  const mandateBound = normalizeSha256(manifest.orderMandateHash) === canonicalOrderMandateHash(om);
  const results = om.acceptanceCriteria.map((criterion) => runOne(criterion, om, manifest, artifacts));
  const passed = results.filter((r) => r.status === 'pass').length;
  const failed = results.filter((r) => r.status === 'fail').length;
  const skipped = results.filter((r) => r.status === 'skipped').length;
  return {
    mandateBound,
    results,
    passed,
    failed,
    skipped,
    allDeterministicPassed: mandateBound && failed === 0,
  };
}
