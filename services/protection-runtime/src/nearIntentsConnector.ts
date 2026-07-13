import { canonicalize, sha256Hex } from '@edict/evidence';
import type {
  ConnectorProtectionContext,
  ProtectionEventDraft,
} from './types.js';
import { runtimeSettlementBinding, type RuntimeSettlementBinding } from './binding.js';

const SHA256 = /^[0-9a-f]{64}$/;

export interface NearViewClient {
  callFunction<T>(accountId: string, methodName: string, args: Record<string, unknown>): Promise<T>;
}

interface NearRpcError {
  message?: string;
  data?: unknown;
}

interface NearRpcResponse {
  result?: { result?: number[] };
  error?: NearRpcError;
}

/** Minimal finality-only NEAR view client; it owns no account or signing key. */
export class NearJsonRpcViewClient implements NearViewClient {
  constructor(
    readonly rpcUrl = 'https://free.rpc.fastnear.com',
    readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async callFunction<T>(accountId: string, methodName: string, args: Record<string, unknown>): Promise<T> {
    const argsBase64 = Buffer.from(JSON.stringify(args), 'utf8').toString('base64');
    const response = await this.fetchImpl(this.rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: `edict-${methodName}-${Date.now()}`,
        method: 'query',
        params: {
          request_type: 'call_function',
          finality: 'final',
          account_id: accountId,
          method_name: methodName,
          args_base64: argsBase64,
        },
      }),
    });
    if (!response.ok) throw new Error(`NEAR RPC ${response.status} ${response.statusText}`);
    const envelope = await response.json() as NearRpcResponse;
    if (envelope.error !== undefined) {
      throw new Error(`NEAR RPC ${envelope.error.message ?? 'query failed'}: ${canonicalize(envelope.error.data)}`);
    }
    const bytes = envelope.result?.result;
    if (!Array.isArray(bytes)) throw new Error('NEAR RPC view response has no result bytes');
    return JSON.parse(Buffer.from(bytes).toString('utf8')) as T;
  }
}

interface IntentsDeliveryView {
  manifest_sha256: number[] | string;
  delivered_at_ms: number;
}

interface IntentsDisputeView {
  disputant: string;
  bond: string;
  opened_at_ms: number;
  case_id_sha256: number[] | string;
}

interface IntentsResolutionView {
  ruling: Record<string, unknown> | string;
  source: Record<string, unknown> | string;
  resolved_at_ms: number;
}

export interface IntentsOrderView {
  order_mandate_sha256: number[] | string;
  settlement_binding_sha256: number[] | string;
  requester: string;
  worker: string;
  principal: string;
  state: 'funded' | 'delivered' | 'disputed' | 'settled' | 'Funded' | 'Delivered' | 'Disputed' | 'Settled';
  deadline_ms: number;
  acceptance_window_ms: number;
  challenge_window_ms: number;
  resolution_timeout_ms: number;
  verifier_policy_sha256: number[] | string;
  delivery?: IntentsDeliveryView | null;
  dispute?: IntentsDisputeView | null;
  redo_count: number;
  last_resolution?: IntentsResolutionView | null;
}

export interface IntentsRoundView {
  number: number;
  case_id_sha256: number[] | string;
  resolution?: IntentsResolutionView | null;
  bond_held_after: string;
}

function hex32(value: number[] | string, label: string): string {
  if (typeof value === 'string') {
    const normalized = value.toLowerCase().replace(/^0x/, '');
    if (SHA256.test(normalized)) return normalized;
  } else if (value.length === 32 && value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    return Buffer.from(value).toString('hex');
  }
  throw new TypeError(`${label} must be a 32-byte value`);
}

function bytes32(hex: string): number[] {
  if (!SHA256.test(hex)) throw new TypeError('bytes32 input must be lowercase sha256 hex');
  return [...Buffer.from(hex, 'hex')];
}

function atomic(value: unknown, label: string): string {
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) return value;
  if (typeof value === 'object' && value !== null && '0' in value) {
    return atomic((value as Record<string, unknown>)['0'], label);
  }
  throw new TypeError(`${label} must be an atomic-unit integer string`);
}

function rulingCanonical(ruling: Record<string, unknown> | string | undefined): string {
  if (typeof ruling === 'string') return ruling;
  const kind = ruling?.['kind'];
  if (kind === 'requester_wins' || kind === 'worker_wins') return kind;
  if (kind === 'split') return `split:${String(ruling?.['requester_bps'] ?? ruling?.['requesterBps'])}`;
  if (kind === 'redo') return `redo:${String(ruling?.['new_deadline_unix_ms'] ?? ruling?.['newDeadlineUnixMs'])}`;
  return 'unknown';
}

function state(value: IntentsOrderView['state']): 'funded' | 'delivered' | 'disputed' | 'settled' {
  const normalized = value.toLowerCase();
  if (normalized === 'funded' || normalized === 'delivered' || normalized === 'disputed' || normalized === 'settled') {
    return normalized;
  }
  throw new TypeError(`unsupported Intents order state ${String(value)}`);
}

function connectorAuthentication(contractId: string) {
  return { kind: 'connector_receipt' as const, contractId, finality: 'final' as const };
}

class NearTransportError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'NearTransportError';
  }
}

/**
 * State-polling NEAR Intents connector. It observes only final view state and
 * emits deterministic upstream ids, so repeated polls and process restarts are
 * harmless. Receipt/indexer ingestion can be added without changing events.
 */
export class NearIntentsConnector {
  constructor(
    readonly id: string,
    readonly client: NearViewClient = new NearJsonRpcViewClient(),
    readonly now: () => number = Date.now,
    readonly railKind: 'near_intents' | 'near_native' = 'near_intents',
  ) {
    if (id.trim().length === 0) throw new TypeError('connector id must be non-empty');
  }

  async poll(contexts: ConnectorProtectionContext[]): Promise<ProtectionEventDraft[]> {
    const observations: ProtectionEventDraft[] = [];
    for (const context of contexts) {
      let binding: RuntimeSettlementBinding;
      try {
        binding = runtimeSettlementBinding(context.registration);
      } catch {
        continue;
      }
      if (binding.kind !== this.railKind || binding.connectorId !== this.id) continue;
      try {
        observations.push(...await this.pollProtection(context, binding));
        const latestHealth = [...context.events].reverse().find((event) =>
          (event.type === 'connector_warning' || event.type === 'connector_recovered')
          && event.source.kind === this.railKind
          && event.source.id === this.id);
        if (latestHealth?.type === 'connector_warning') {
          const now = this.now();
          observations.push({
            protectionId: context.registration.mandateHash,
            type: 'connector_recovered',
            source: {
              kind: this.railKind,
              id: this.id,
              externalId: `recovered:${latestHealth.eventId}`,
            },
            effectiveAtUnixMs: now,
            observedAtUnixMs: now,
            payload: {
              warningEventId: latestHealth.eventId,
              codes: [latestHealth.payload.code],
              message: 'Final-state settlement observation recovered.',
            },
            authentication: { kind: 'runtime', reason: 'successful final-state integrity validation' },
          });
        }
      } catch (error) {
        const now = this.now();
        const warningWindow = Math.floor(now / 60_000) * 60_000;
        const availabilityFailure = error instanceof NearTransportError;
        const prefix = this.railKind === 'near_intents' ? 'near_intents' : 'near_native';
        const code = availabilityFailure
          ? `${prefix}_poll_failed`
          : `${prefix}_state_mismatch`;
        const recoveryCount = context.events.filter((event) =>
          event.type === 'connector_recovered'
          && event.source.kind === this.railKind
          && event.source.id === this.id).length;
        observations.push({
          protectionId: context.registration.mandateHash,
          type: 'connector_warning',
          source: {
            kind: this.railKind,
            id: this.id,
            externalId: `${code}:${warningWindow}:${recoveryCount}`,
          },
          effectiveAtUnixMs: warningWindow,
          observedAtUnixMs: now,
          payload: {
            code,
            message: error instanceof Error ? error.message : String(error),
          },
          authentication: {
            kind: 'runtime',
            reason: availabilityFailure
              ? 'connector transport error'
              : 'final-state integrity validation failed',
          },
        });
      }
    }
    return observations;
  }

  private async pollProtection(
    context: ConnectorProtectionContext,
    binding: RuntimeSettlementBinding,
  ): Promise<ProtectionEventDraft[]> {
    const registration = context.registration;
    const protectionId = registration.mandateHash;
    const contractId = binding.settlementAccount;
    const args = { order_mandate_sha256: bytes32(protectionId) };
    const order = await this.callView<IntentsOrderView | null>(contractId, 'get_order', args);
    if (order === null) return [];
    const now = this.now();
    const source = (externalId: string) => ({ kind: this.railKind, id: this.id, externalId });
    const auth = connectorAuthentication(contractId);
    const out: ProtectionEventDraft[] = [];
    const orderId = hex32(order.order_mandate_sha256, 'order.order_mandate_sha256');
    if (orderId !== protectionId) throw new Error('NEAR settlement view returned a different order id');
    const expectedSettlementHash = sha256Hex(canonicalize(registration.mandate.settlement));
    if (hex32(order.settlement_binding_sha256, 'order.settlement_binding_sha256') !== expectedSettlementHash) {
      throw new Error('on-chain settlement binding hash does not match the signed mandate');
    }
    if (order.requester !== binding.requesterAccount || order.worker !== binding.workerAccount) {
      throw new Error('on-chain parties do not match the registered settlement identities');
    }
    if (atomic(order.principal, 'order.principal') !== binding.principalAtomic) {
      throw new Error('on-chain principal does not match the registered protection');
    }
    if (order.deadline_ms !== registration.mandate.deadlineUnixMs
        || order.acceptance_window_ms !== registration.mandate.acceptanceWindowMs
        || order.challenge_window_ms !== binding.challengeWindowMs
        || order.resolution_timeout_ms !== binding.resolutionTimeoutMs) {
      throw new Error('on-chain protection windows do not match the signed mandate and Legal Policy');
    }
    if (hex32(order.verifier_policy_sha256, 'order.verifier_policy_sha256')
        !== binding.verifierPolicySha256Hex) {
      throw new Error('on-chain verifier policy hash does not match runtime registration');
    }

    out.push({
      protectionId,
      type: 'funding_confirmed',
      source: source(`${contractId}:${protectionId}:funded`),
      effectiveAtUnixMs: context.events.find((event) => event.type === 'funding_confirmed')?.effectiveAtUnixMs ?? now,
      observedAtUnixMs: now,
      payload: {
        requester: order.requester,
        worker: order.worker,
        tokenId: binding.settlementAsset,
        principalAtomic: atomic(order.principal, 'order.principal'),
      },
      authentication: auth,
    });

    if (order.delivery !== undefined && order.delivery !== null) {
      const manifestSha256 = hex32(order.delivery.manifest_sha256, 'delivery.manifest_sha256');
      out.push({
        protectionId,
        type: 'delivery_submitted',
        source: source(`${contractId}:${protectionId}:delivery:${manifestSha256}`),
        effectiveAtUnixMs: order.delivery.delivered_at_ms,
        observedAtUnixMs: now,
        payload: {
          manifestSha256,
          deliveredAtUnixMs: order.delivery.delivered_at_ms,
          worker: order.worker,
        },
        authentication: auth,
      });
    }

    if (order.dispute !== undefined && order.dispute !== null) {
      const caseIdSha256 = hex32(order.dispute.case_id_sha256, 'dispute.case_id_sha256');
      const requested = context.events.find((event) =>
        event.type === 'challenge_requested' && event.payload.caseIdSha256 === caseIdSha256);
      const by = order.dispute.disputant === order.requester ? 'requester' : 'worker';
      out.push({
        protectionId,
        type: 'challenge_opened',
        source: source(`${contractId}:${protectionId}:challenge:${caseIdSha256}`),
        effectiveAtUnixMs: order.dispute.opened_at_ms,
        observedAtUnixMs: now,
        payload: {
          ...(requested?.type === 'challenge_requested' ? { caseId: requested.payload.caseId } : {}),
          caseIdSha256,
          by,
          openedAtUnixMs: order.dispute.opened_at_ms,
          bondAtomic: atomic(order.dispute.bond, 'dispute.bond'),
          round: order.redo_count === 0 ? 1 : 2,
        },
        authentication: auth,
      });
    }

    const rounds = order.redo_count === 1
      ? await this.callView<IntentsRoundView[]>(contractId, 'get_rounds', args)
      : [];
    const firstRound = rounds.find((round) => round.number === 1);
    if (order.redo_count === 1 && state(order.state) !== 'settled' && firstRound?.resolution !== undefined && firstRound.resolution !== null) {
      const canonical = rulingCanonical(firstRound.resolution.ruling);
      if (canonical.startsWith('redo:')) {
        const newDeadlineUnixMs = Number(canonical.slice('redo:'.length));
        out.push({
          protectionId,
          type: 'redo_ordered',
          source: source(`${contractId}:${protectionId}:${canonical}`),
          effectiveAtUnixMs: firstRound.resolution.resolved_at_ms,
          observedAtUnixMs: now,
          payload: {
            newDeadlineUnixMs,
            bondHeldAtomic: atomic(firstRound.bond_held_after, 'round.bond_held_after'),
            round: 1,
          },
          authentication: auth,
        });
      }
    }

    if (state(order.state) === 'settled' && order.last_resolution !== undefined && order.last_resolution !== null) {
      const ruling = rulingCanonical(order.last_resolution.ruling);
      const priorSettlements = context.events.filter((event) => event.type === 'settlement_finalized');
      const submittedPlanIds = new Set(context.events.flatMap((event) =>
        event.type === 'relay_submitted' ? [event.payload.planId] : []));
      const unresolvedWithdrawal = context.events.some((event) =>
        event.type === 'relay_ready'
        && !submittedPlanIds.has(event.payload.plan.planId)
        && event.payload.plan.kind === 'near_function_call'
        && event.payload.plan.methodName === 'withdraw_claim');
      if (priorSettlements.length > 0 && !unresolvedWithdrawal) return out;
      const requesterClaim = atomic(
        await this.callView<string>(contractId, 'claim_of', { account_id: order.requester }),
        'requester claim',
      );
      const workerClaim = atomic(
        await this.callView<string>(contractId, 'claim_of', { account_id: order.worker }),
        'worker claim',
      );
      const latestSettlement = priorSettlements.at(-1);
      if (latestSettlement?.type === 'settlement_finalized'
          && latestSettlement.payload.requesterClaimAtomic === requesterClaim
          && latestSettlement.payload.workerClaimAtomic === workerClaim) return out;
      const claimSnapshot = sha256Hex(canonicalize({ requesterClaim, workerClaim }));
      out.push({
        protectionId,
        type: 'settlement_finalized',
        source: source(
          `${contractId}:${protectionId}:settled:${sha256Hex(canonicalize(order.last_resolution))}:claims:${claimSnapshot}`,
        ),
        effectiveAtUnixMs: priorSettlements.length === 0 ? order.last_resolution.resolved_at_ms : now,
        observedAtUnixMs: now,
        payload: {
          ruling,
          requesterClaimAtomic: requesterClaim,
          workerClaimAtomic: workerClaim,
          settledAtUnixMs: order.last_resolution.resolved_at_ms,
        },
        authentication: auth,
      });
    }
    return out;
  }

  private async callView<T>(
    contractId: string,
    methodName: string,
    args: Record<string, unknown>,
  ): Promise<T> {
    try {
      return await this.client.callFunction<T>(contractId, methodName, args);
    } catch (error) {
      const label = this.railKind === 'near_intents' ? 'NEAR Intents' : 'native NEAR';
      throw new NearTransportError(
        `${label} ${methodName} observation failed: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error },
      );
    }
  }
}

/** Final-state observer for the keyless native-NEAR M2 staging and release track. */
export class NearNativeConnector extends NearIntentsConnector {
  constructor(
    id: string,
    client: NearViewClient = new NearJsonRpcViewClient('https://test.rpc.fastnear.com'),
    now: () => number = Date.now,
  ) {
    super(id, client, now, 'near_native');
  }
}
