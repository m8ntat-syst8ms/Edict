import { canonicalize, sha256Hex } from '@edict/evidence';
import {
  PROTECTION_EVENT_VERSION,
  type AnyProtectionEvent,
  type ProtectionEvent,
  type ProtectionEventDraft,
  type ProtectionEventType,
} from './types.js';

const SHA256 = /^[0-9a-f]{64}$/;

function positiveUnixMs(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive unix-ms integer`);
  }
}

export function eventPayloadSha256(payload: unknown): string {
  return sha256Hex(canonicalize(payload));
}

export function protectionEventId(draft: ProtectionEventDraft): string {
  return sha256Hex(canonicalize({
    version: PROTECTION_EVENT_VERSION,
    protectionId: draft.protectionId,
    type: draft.type,
    source: draft.source,
    effectiveAtUnixMs: draft.effectiveAtUnixMs,
    payloadSha256: eventPayloadSha256(draft.payload),
  }));
}

export function createProtectionEvent<T extends ProtectionEventType>(
  draft: ProtectionEventDraft<T>,
): ProtectionEvent<T> {
  if (!SHA256.test(draft.protectionId)) {
    throw new TypeError('protectionId must be lowercase sha256 hex');
  }
  if (draft.source.id.trim().length === 0 || draft.source.externalId.trim().length === 0) {
    throw new TypeError('event source id and externalId must be non-empty');
  }
  positiveUnixMs(draft.effectiveAtUnixMs, 'effectiveAtUnixMs');
  const observedAtUnixMs = draft.observedAtUnixMs ?? Date.now();
  positiveUnixMs(observedAtUnixMs, 'observedAtUnixMs');
  const payloadSha256 = eventPayloadSha256(draft.payload);
  return {
    version: PROTECTION_EVENT_VERSION,
    eventId: protectionEventId(draft),
    protectionId: draft.protectionId,
    type: draft.type,
    source: structuredClone(draft.source),
    effectiveAtUnixMs: draft.effectiveAtUnixMs,
    observedAtUnixMs,
    payloadSha256,
    payload: structuredClone(draft.payload),
    authentication: structuredClone(draft.authentication),
  };
}

export function validateProtectionEvent(value: unknown): asserts value is AnyProtectionEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('event must be an object');
  }
  const event = value as AnyProtectionEvent;
  if (event.version !== PROTECTION_EVENT_VERSION) throw new TypeError('unsupported protection event version');
  if (!SHA256.test(event.eventId) || !SHA256.test(event.protectionId)) {
    throw new TypeError('eventId and protectionId must be lowercase sha256 hex');
  }
  positiveUnixMs(event.effectiveAtUnixMs, 'event.effectiveAtUnixMs');
  positiveUnixMs(event.observedAtUnixMs, 'event.observedAtUnixMs');
  if (eventPayloadSha256(event.payload) !== event.payloadSha256) {
    throw new TypeError(`event ${event.eventId} payload hash mismatch`);
  }
  const reconstructed = protectionEventId(event);
  if (reconstructed !== event.eventId) {
    throw new TypeError(`event ${event.eventId} identity hash mismatch`);
  }
}
