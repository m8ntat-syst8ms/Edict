import {
  assertExecutableVerdict,
  validateCaseObject,
} from '@edict/core';
import {
  buildCustomerSettlementExecutionDigest,
  canonicalRuling,
} from '@edict/arbiter';
import { canonicalize, sha256Hex } from '@edict/evidence';
import type {
  ExecutionSignatureCollector,
  ExecutionSignatureRequest,
  RuntimeVerifierPolicy,
  VerdictSignature,
} from './types.js';
import {
  runtimeVerifierPolicySha256,
  validateRuntimeVerifierPolicy,
} from './verifierPolicy.js';

const SHA256 = /^[0-9a-f]{64}$/;
const REQUEST_KEYS = [
  'protectionId', 'caseObject', 'verdict', 'verdictSha256Hex', 'executionDigestHex',
  'nonceHex', 'policy', 'executionContext',
] as const;
const CONTEXT_KEYS = [
  'settlementAccountId', 'orderMandateSha256Hex', 'caseIdSha256Hex', 'round',
  'rulingCanonical', 'issuedAtUnixMs', 'verifierPolicySha256Hex',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function unknownFields(value: Record<string, unknown>, allowed: readonly string[], path: string): string[] {
  return Object.keys(value)
    .filter((key) => !allowed.includes(key))
    .map((key) => `${path}.${key} is not supported`);
}

/** Total validation of the outer request and every settlement-sensitive binding. */
export function validateExecutionSignatureRequest(request: unknown): string[] {
  if (!isRecord(request)) return ['execution request must be an object'];
  const problems = unknownFields(request, REQUEST_KEYS, 'execution request');
  const caseObject = request['caseObject'];
  const verdict = request['verdict'];
  const policy = request['policy'];
  const executionContext = request['executionContext'];

  const caseProblems = validateCaseObject(caseObject).errors.filter((problem) => !problem.startsWith('warn:'));
  problems.push(...caseProblems);
  if (!isRecord(verdict)) problems.push('execution request verdict must be an object');
  if (!isRecord(executionContext)) {
    problems.push('execution request executionContext must be an object');
  } else {
    problems.push(...unknownFields(executionContext, CONTEXT_KEYS, 'execution request executionContext'));
    if (typeof executionContext['settlementAccountId'] !== 'string'
        || executionContext['settlementAccountId'].length === 0) {
      problems.push('execution request settlement account is invalid');
    }
    for (const field of ['orderMandateSha256Hex', 'caseIdSha256Hex', 'verifierPolicySha256Hex'] as const) {
      if (typeof executionContext[field] !== 'string' || !SHA256.test(executionContext[field])) {
        problems.push(`execution request executionContext.${field} must be lowercase sha256 hex`);
      }
    }
    if (executionContext['round'] !== 1 && executionContext['round'] !== 2) {
      problems.push('execution request round must be 1 or 2');
    }
    if (typeof executionContext['rulingCanonical'] !== 'string'
        || executionContext['rulingCanonical'].length === 0) {
      problems.push('execution request canonical ruling is invalid');
    }
    if (!Number.isSafeInteger(executionContext['issuedAtUnixMs'])
        || (executionContext['issuedAtUnixMs'] as number) <= 0) {
      problems.push('execution request issued time is invalid');
    }
  }
  for (const field of ['protectionId', 'verdictSha256Hex', 'executionDigestHex', 'nonceHex'] as const) {
    if (typeof request[field] !== 'string' || !SHA256.test(request[field])) {
      problems.push(`execution request ${field} must be lowercase sha256 hex`);
    }
  }
  const policyProblems = validateRuntimeVerifierPolicy(policy, 'execution request policy');
  problems.push(...policyProblems);

  if (caseProblems.length > 0 || !isRecord(caseObject) || !isRecord(verdict) || !isRecord(executionContext)) {
    return problems;
  }
  const typedCase = caseObject as unknown as ExecutionSignatureRequest['caseObject'];
  const typedVerdict = verdict as unknown as ExecutionSignatureRequest['verdict'];
  try {
    assertExecutableVerdict(typedVerdict, typedCase.decisionSpace);
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  if (request['protectionId'] !== typedCase.orderMandateHash
      || executionContext['orderMandateSha256Hex'] !== request['protectionId']) {
    problems.push('execution request protection id does not match the case and digest context');
  }
  if (typedVerdict.caseId !== typedCase.caseId) {
    problems.push('execution request verdict case id does not match the case object');
  }
  if (executionContext['caseIdSha256Hex'] !== sha256Hex(typedCase.caseId)) {
    problems.push('execution request case id hash does not match the case object');
  }
  let verdictSha256Hex: string | undefined;
  try {
    verdictSha256Hex = sha256Hex(canonicalize(typedVerdict));
    if (request['verdictSha256Hex'] !== verdictSha256Hex) {
      problems.push('execution request verdict hash does not match the verdict bytes');
    }
  } catch (error) {
    problems.push(`execution request verdict is not canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  let rulingCanonical: string | undefined;
  try {
    rulingCanonical = canonicalRuling(typedVerdict.ruling as Parameters<typeof canonicalRuling>[0]);
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  if (rulingCanonical !== undefined && executionContext['rulingCanonical'] !== rulingCanonical) {
    problems.push('execution request ruling does not match the verdict');
  }
  if (executionContext['issuedAtUnixMs'] !== typedVerdict.issuedAtUnixMs) {
    problems.push('execution request issued time does not match the verdict');
  }
  if (executionContext['round'] !== (typedCase.round?.number ?? 1)) {
    problems.push('execution request round does not match the case object');
  }
  if (policyProblems.length === 0
      && runtimeVerifierPolicySha256(policy as RuntimeVerifierPolicy) !== executionContext['verifierPolicySha256Hex']) {
    problems.push('execution request verifier policy hash does not match its Borsh bytes');
  }
  if (SHA256.test(String(request['nonceHex'])) && rulingCanonical !== undefined && verdictSha256Hex !== undefined) {
    try {
      const digest = buildCustomerSettlementExecutionDigest({
        settlementAccountId: String(executionContext['settlementAccountId']),
        orderMandateSha256Hex: String(executionContext['orderMandateSha256Hex']),
        caseIdSha256Hex: String(executionContext['caseIdSha256Hex']),
        round: executionContext['round'] as 1 | 2,
        issuedAtUnixMs: executionContext['issuedAtUnixMs'] as number,
        verifierPolicySha256Hex: String(executionContext['verifierPolicySha256Hex']),
        rulingCanonical,
        verdictSha256Hex,
        nonce: Buffer.from(String(request['nonceHex']), 'hex'),
      });
      if (digest !== request['executionDigestHex']) {
        problems.push('execution request digest does not match the supplied case, verdict and policy context');
      }
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
  }
  return problems;
}

export function assertValidExecutionSignatureRequest(
  request: unknown,
): asserts request is ExecutionSignatureRequest {
  const problems = validateExecutionSignatureRequest(request);
  if (problems.length > 0) throw new TypeError(problems.join('; '));
}

export interface ExecutionSignerEndpoint {
  id: string;
  url: string;
  bearerToken?: string;
}

export interface HttpExecutionSignatureCollectorOptions {
  endpoints: ExecutionSignerEndpoint[];
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Collects contract-bound signatures from separately operated signer nodes.
 * Signers receive commitments-only case metadata plus the exact verdict and
 * policy so they can independently reconstruct every hash and digest. Keys
 * remain inside the node/TEE and the runtime re-verifies every response.
 */
export class HttpExecutionSignatureCollector implements ExecutionSignatureCollector {
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(readonly options: HttpExecutionSignatureCollectorOptions) {
    if (!Array.isArray(options.endpoints) || options.endpoints.length < 2) {
      throw new TypeError('execution signature collector requires at least two independent endpoints');
    }
    const ids = new Set<string>();
    for (const endpoint of options.endpoints) {
      if (ids.has(endpoint.id)) throw new TypeError(`duplicate execution signer endpoint ${endpoint.id}`);
      ids.add(endpoint.id);
      const url = new URL(endpoint.url);
      const loopbackHttp = url.protocol === 'http:' && url.hostname === '127.0.0.1';
      if (url.protocol !== 'https:' && !loopbackHttp) {
        throw new TypeError(`execution signer ${endpoint.id} must use HTTPS (or loopback for development)`);
      }
      if (url.username !== '' || url.password !== '') {
        throw new TypeError(`execution signer ${endpoint.id} URL must not contain credentials`);
      }
    }
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 8_000;
  }

  async collect(request: ExecutionSignatureRequest): Promise<VerdictSignature[]> {
    assertValidExecutionSignatureRequest(request);
    const responses = await Promise.allSettled(this.options.endpoints.map((endpoint) => this.request(endpoint, request)));
    const signatures: VerdictSignature[] = [];
    for (const response of responses) {
      if (response.status === 'fulfilled') signatures.push(response.value);
    }
    if (signatures.length < request.policy.quorum) {
      const failures = responses.filter((response) => response.status === 'rejected').length;
      throw new Error(`execution signature quorum unavailable: ${signatures.length}/${request.policy.quorum} signatures (${failures} endpoint failures)`);
    }
    return signatures;
  }

  private async request(
    endpoint: ExecutionSignerEndpoint,
    request: ExecutionSignatureRequest,
  ): Promise<VerdictSignature> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(endpoint.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(endpoint.bearerToken !== undefined ? { authorization: `Bearer ${endpoint.bearerToken}` } : {}),
        },
        body: JSON.stringify({
          version: 'edict-execution-sign-request-1',
          protectionId: request.protectionId,
          caseId: request.caseObject.caseId,
          caseObject: request.caseObject,
          verdict: request.verdict,
          verdictSha256Hex: request.verdictSha256Hex,
          executionDigestHex: request.executionDigestHex,
          nonceHex: request.nonceHex,
          executionContext: request.executionContext,
          policy: request.policy,
        }),
        signal: controller.signal,
      });
      const body = await response.json() as Record<string, unknown>;
      if (!response.ok) throw new Error(`${endpoint.id} returned HTTP ${response.status}`);
      const signingAddress = body['signing_address'] ?? body['signingAddress'];
      if (typeof signingAddress !== 'string' || typeof body['signature'] !== 'string') {
        throw new Error(`${endpoint.id} returned a malformed signature`);
      }
      return { signing_address: signingAddress.toLowerCase(), signature: body['signature'] };
    } finally {
      clearTimeout(timeout);
    }
  }
}
