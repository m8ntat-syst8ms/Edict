import { sha256Hex } from '@edict/evidence';
import type {
  AnyProtectionEvent,
  ProtectionAttention,
  ProtectionProjection,
  RelayPlan,
} from './types.js';

function attention(
  protectionId: string,
  kind: ProtectionAttention['kind'],
  title: string,
  detail: string,
  createdAtUnixMs: number,
): ProtectionAttention {
  return {
    id: sha256Hex(`${protectionId}:${kind}:${title}:${createdAtUnixMs}`),
    protectionId,
    kind,
    title,
    detail,
    createdAtUnixMs,
  };
}

export function projectProtection(events: AnyProtectionEvent[], nowUnixMs = Date.now()): ProtectionProjection {
  if (events.length === 0) throw new TypeError('cannot project an empty protection stream');
  const ordered = [...events].sort((a, b) =>
    a.effectiveAtUnixMs - b.effectiveAtUnixMs || a.observedAtUnixMs - b.observedAtUnixMs || a.eventId.localeCompare(b.eventId));
  const registrationEvent = ordered.find((event) => event.type === 'protection_registered');
  if (registrationEvent === undefined) throw new TypeError('protection stream has no registration event');
  const registration = registrationEvent.payload.registration;
  const mandate = registration.mandate;
  let state: ProtectionProjection['state'] = 'awaiting_funding';
  let requesterApproved = false;
  let workerApproved = false;
  let deliveryAt: number | undefined;
  let latestVerdict: ProtectionProjection['latestVerdict'];
  let latestOutcome: ProtectionProjection['latestOutcome'];
  let executionAuthorized = false;
  let integrityBlocked = false;
  let challengeOpened = false;
  let settlementFinalized = false;
  let requesterClaimAtomic: string | undefined;
  let workerClaimAtomic: string | undefined;
  const attentions: ProtectionAttention[] = [];
  const relayPlans: RelayPlan[] = [];
  const submitted = new Set<string>();

  const replaceAttention = (item: ProtectionAttention): void => {
    const existing = attentions.findIndex((candidate) =>
      candidate.kind === item.kind && candidate.title === item.title);
    if (existing >= 0) attentions.splice(existing, 1);
    attentions.push(item);
  };

  const removeAttention = (kind: ProtectionAttention['kind'], title: string): void => {
    const existing = attentions.findIndex((candidate) => candidate.kind === kind && candidate.title === title);
    if (existing >= 0) attentions.splice(existing, 1);
  };

  for (const event of ordered) {
    switch (event.type) {
      case 'protection_accepted':
        if (event.payload.party === 'requester') requesterApproved = true;
        else workerApproved = true;
        break;
      case 'funding_confirmed':
        requesterApproved = true;
        state = 'protected';
        break;
      case 'delivery_submitted':
        workerApproved = true;
        deliveryAt = event.payload.deliveredAtUnixMs;
        state = 'delivered';
        break;
      case 'acceptance_signed':
        requesterApproved = true;
        break;
      case 'challenge_opened':
        challengeOpened = true;
        state = 'challenged';
        removeAttention('party_signature', 'Approve the dispute Bond');
        if (event.payload.caseId === undefined) {
          attentions.push(attention(
            registration.mandateHash,
            'evidence_required',
            'Challenge context required',
            'A dispute was observed on-chain without the signed off-chain case identifier. Supply the original challenge request before adjudication.',
            event.observedAtUnixMs,
          ));
        }
        break;
      case 'objective_failure_detected':
        if (event.payload.requiresPartySignature) {
          attentions.push(attention(
            registration.mandateHash,
            'party_signature',
            'Approve the dispute Bond',
            event.payload.reason,
            event.effectiveAtUnixMs,
          ));
        }
        break;
      case 'verdict_issued':
        latestVerdict = event.payload.verdict;
        latestOutcome = event.payload.verdict.ruling;
        executionAuthorized = event.payload.execution !== undefined;
        state = event.payload.disposition.route === 'human_review' ? 'review_required' : 'challenged';
        break;
      case 'webhook_delivery_recorded': {
        const title = `Decision webhook · ${event.payload.targetId}`;
        if (event.payload.delivered) {
          removeAttention('webhook_delivery', title);
        } else {
          replaceAttention(attention(
            registration.mandateHash,
            'webhook_delivery',
            title,
            event.payload.error ?? 'The configured decision webhook did not accept delivery.',
            event.payload.attemptedAtUnixMs,
          ));
        }
        break;
      }
      case 'execution_authorized':
        executionAuthorized = true;
        break;
      case 'review_required':
        state = 'review_required';
        attentions.push(attention(
          registration.mandateHash,
          'human_review',
          'Human review required',
          event.payload.trigger,
          event.effectiveAtUnixMs,
        ));
        break;
      case 'redo_ordered':
        state = 'protected';
        deliveryAt = undefined;
        break;
      case 'relay_ready':
        relayPlans.push(event.payload.plan);
        if (event.payload.plan.kind === 'near_function_call'
            && event.payload.plan.methodName === 'submit_ruling') state = 'settlement_ready';
        break;
      case 'relay_submitted':
        submitted.add(event.payload.planId);
        break;
      case 'settlement_finalized':
        settlementFinalized = true;
        requesterClaimAtomic = event.payload.requesterClaimAtomic;
        workerClaimAtomic = event.payload.workerClaimAtomic;
        state = 'settled';
        latestOutcome = latestVerdict?.ruling;
        break;
      case 'connector_warning':
        if (event.payload.code === 'near_intents_state_mismatch'
            || event.payload.code === 'near_native_state_mismatch') {
          integrityBlocked = true;
          replaceAttention(attention(
            registration.mandateHash,
            'connector_integrity',
            'Protection state mismatch',
            event.payload.message,
            event.effectiveAtUnixMs,
          ));
        } else {
          replaceAttention(attention(
            registration.mandateHash,
            'connector_availability',
            'Observation temporarily delayed',
            event.payload.message,
            event.effectiveAtUnixMs,
          ));
        }
        break;
      case 'connector_recovered':
        integrityBlocked = false;
        removeAttention('connector_integrity', 'Protection state mismatch');
        removeAttention('connector_availability', 'Observation temporarily delayed');
        break;
      default:
        break;
    }
  }

  if (!workerApproved && state !== 'settled') {
    attentions.push(attention(
      registration.mandateHash,
      'counterparty_approval',
      'Counterparty approval pending',
      'Protection becomes bilateral when the worker signs acceptance or submits the authenticated delivery.',
      registrationEvent.effectiveAtUnixMs,
    ));
    if (state === 'awaiting_funding') state = 'setup_required';
  }

  if (latestVerdict?.final === true && state !== 'review_required' && state !== 'settled' && !executionAuthorized) {
    attentions.push(attention(
      registration.mandateHash,
      'execution_signatures',
      'Settlement signatures pending',
      'The decision is final, but the independent execution quorum has not yet signed the contract-bound digest.',
      ordered.at(-1)!.effectiveAtUnixMs,
    ));
  }

  if (integrityBlocked && state !== 'settled') state = 'blocked';
  if (settlementFinalized) state = 'settled';

  const requesterSettlementAccount = registration.intents?.requesterIntentsAccount
    ?? registration.nativeNear?.requesterAccount;
  const workerSettlementAccount = registration.intents?.workerIntentsAccount
    ?? registration.nativeNear?.workerAccount;
  const pendingRelayPlans = relayPlans.filter((plan) => {
    if (submitted.has(plan.planId)) return false;
    if (challengeOpened && plan.kind === 'near_signed_intent') return false;
    if (plan.kind !== 'near_function_call') return true;
    if (settlementFinalized && ['claim_timeout', 'submit_ruling', 'execute_liveness_fallback'].includes(plan.methodName)) {
      return false;
    }
    if (plan.methodName !== 'withdraw_claim') return true;
    const accountId = plan.args['account_id'];
    if (accountId === requesterSettlementAccount && requesterClaimAtomic === '0') return false;
    if (accountId === workerSettlementAccount && workerClaimAtomic === '0') return false;
    return true;
  });

  let nextDeadlineUnixMs: number | undefined;
  if (state === 'protected') nextDeadlineUnixMs = mandate.deadlineUnixMs;
  else if (state === 'delivered' && deliveryAt !== undefined) nextDeadlineUnixMs = deliveryAt + mandate.acceptanceWindowMs;
  if (nextDeadlineUnixMs !== undefined && nextDeadlineUnixMs <= nowUnixMs && state !== 'settled') {
    // The scheduler will add the permissionless relay. Projection remains
    // factual and does not invent a state transition before that event exists.
  }

  return {
    protectionId: registration.mandateHash,
    state,
    title: mandate.description,
    counterparty: mandate.worker.agentId,
    amountUsd: mandate.priceUsd,
    asset: mandate.currency.asset,
    createdAtUnixMs: registrationEvent.effectiveAtUnixMs,
    updatedAtUnixMs: ordered.at(-1)!.effectiveAtUnixMs,
    deliveryDeadlineUnixMs: mandate.deadlineUnixMs,
    ...(nextDeadlineUnixMs !== undefined ? { nextDeadlineUnixMs } : {}),
    requesterApproved,
    workerApproved,
    events: structuredClone(ordered),
    attention: attentions,
    relayPlans: pendingRelayPlans,
    ...(latestVerdict !== undefined ? { latestVerdict } : {}),
    ...(latestOutcome !== undefined ? { latestOutcome } : {}),
  };
}

export function projectAll(events: AnyProtectionEvent[], nowUnixMs = Date.now()): ProtectionProjection[] {
  const streams = new Map<string, AnyProtectionEvent[]>();
  for (const event of events) {
    const stream = streams.get(event.protectionId) ?? [];
    stream.push(event);
    streams.set(event.protectionId, stream);
  }
  return [...streams.values()]
    .map((stream) => projectProtection(stream, nowUnixMs))
    .sort((a, b) => b.updatedAtUnixMs - a.updatedAtUnixMs || a.protectionId.localeCompare(b.protectionId));
}
