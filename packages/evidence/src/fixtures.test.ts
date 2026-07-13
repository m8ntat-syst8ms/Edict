/**
 * Shared test fixtures. The .test.ts suffix keeps this out of the published
 * type surface conceptually; it exports helpers and contains no test cases
 * itself (node --test tolerates test files with zero tests).
 */

import type { OrderMandate } from '@edict/core';
import { sha256Hex } from './hash.js';
import type { DeliveryManifest } from './deliveryManifest.js';
import { canonicalOrderMandateHash } from './orderMandate.js';

export const ARTIFACT_BYTES = new TextEncoder().encode('{"title":"Q3 report","pages":12}');
export const ARTIFACT_SHA256 = sha256Hex(ARTIFACT_BYTES);

export function makeOrderMandate(overrides: Partial<OrderMandate> = {}): OrderMandate {
  return {
    version: 'edict-om-1',
    requester: { agentId: 'near:req.alice.near', principalKybRef: 'kyb:alice-llc' },
    worker: { agentId: 'near:wrk.bob.near', principalKybRef: 'kyb:bob-ltd' },
    description: 'Produce the Q3 market report as JSON',
    acceptanceCriteria: [
      {
        id: 'AC-1',
        statement: 'Delivered report.json bytes match the agreed hash',
        machineCheck: { kind: 'hash_equals', params: { path: 'report.json', sha256: ARTIFACT_SHA256 } },
      },
      {
        id: 'AC-2',
        statement: 'Delivered before the mandate deadline',
        machineCheck: { kind: 'deadline_before', params: {} },
      },
      {
        id: 'AC-3',
        statement: 'Report mentions Q3',
        machineCheck: { kind: 'contains', params: { path: 'report.json', needle: 'Q3' } },
      },
      {
        id: 'AC-4',
        statement: 'Report JSON has title and pages',
        machineCheck: {
          kind: 'schema_valid',
          params: {
            path: 'report.json',
            schema: {
              type: 'object',
              required: ['title', 'pages'],
              properties: { title: { type: 'string' }, pages: { type: 'integer' } },
            },
          },
        },
      },
      {
        id: 'AC-5',
        statement: 'Tone must be professional',
        machineCheck: { kind: 'custom', params: { rubric: 'tone' } },
      },
      { id: 'AC-6', statement: 'Requester is satisfied overall' },
    ],
    priceUsd: 125.5,
    currency: { asset: 'usdc', rail: 'near-agent-market' },
    deadlineUnixMs: 1_760_000_000_000,
    acceptanceWindowMs: 86_400_000,
    legalProfile: {
      governingLaw: 'england_wales',
      seat: 'london',
      rules: 'edict-drr-v0.1',
      enforcementTier: 'E1',
    },
    decisionSpace: { kind: 'escrow_branches', permitted: ['requester_wins', 'worker_wins', 'split'] },
    maeEvents: ['upstream_api_shutdown'],
    nonce: 'nonce-0001',
    ...overrides,
  };
}

export function makeManifest(om: OrderMandate, overrides: Partial<DeliveryManifest> = {}): DeliveryManifest {
  return {
    artifactHashes: [{ path: 'report.json', sha256: ARTIFACT_SHA256, mediaType: 'application/json' }],
    formatClaims: ['application/json', 'utf-8'],
    workerAgentId: om.worker.agentId,
    orderMandateHash: canonicalOrderMandateHash(om),
    deliveredAtUnixMs: om.deadlineUnixMs - 3_600_000,
    ...overrides,
  };
}

export function artifacts(): Map<string, Uint8Array> {
  return new Map([['report.json', ARTIFACT_BYTES]]);
}
