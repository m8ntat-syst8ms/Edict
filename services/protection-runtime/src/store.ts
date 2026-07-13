import { mkdir, open, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { canonicalize } from '@edict/evidence';
import { validateProtectionEvent } from './events.js';
import type { AnyProtectionEvent } from './types.js';

function semanticBytes(event: AnyProtectionEvent): string {
  const { observedAtUnixMs: _observedAtUnixMs, ...semantic } = event;
  return canonicalize(semantic);
}

export type AppendEventResult = 'appended' | 'duplicate';

export interface ProtectionEventStore {
  initialize(): Promise<void>;
  list(): Promise<AnyProtectionEvent[]>;
  append(event: AnyProtectionEvent): Promise<AppendEventResult>;
}

export class MemoryProtectionEventStore implements ProtectionEventStore {
  private readonly events: AnyProtectionEvent[] = [];
  private readonly byId = new Map<string, string>();

  async initialize(): Promise<void> {}

  async list(): Promise<AnyProtectionEvent[]> {
    return structuredClone(this.events);
  }

  async append(event: AnyProtectionEvent): Promise<AppendEventResult> {
    validateProtectionEvent(event);
    const bytes = semanticBytes(event);
    const existing = this.byId.get(event.eventId);
    if (existing !== undefined) {
      if (existing !== bytes) throw new Error(`conflicting event bytes for ${event.eventId}`);
      return 'duplicate';
    }
    this.byId.set(event.eventId, bytes);
    this.events.push(structuredClone(event));
    return 'appended';
  }
}

/** Durable append-only JSONL store with fsync before an append is acknowledged. */
export class JsonlProtectionEventStore implements ProtectionEventStore {
  private readonly events: AnyProtectionEvent[] = [];
  private readonly byId = new Map<string, string>();
  private initialized = false;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(readonly path: string) {}

  async initialize(): Promise<void> {
    if (this.initialized) return;
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    let raw = '';
    try {
      raw = await readFile(this.path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const lines = raw.split('\n');
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index]!.trim();
      if (line.length === 0) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        throw new Error(`invalid JSON in event store ${this.path}:${index + 1}`);
      }
      validateProtectionEvent(parsed);
      const bytes = semanticBytes(parsed);
      const existing = this.byId.get(parsed.eventId);
      if (existing !== undefined && existing !== bytes) {
        throw new Error(`conflicting persisted event ${parsed.eventId}`);
      }
      if (existing === undefined) {
        this.byId.set(parsed.eventId, bytes);
        this.events.push(parsed);
      }
    }
    this.initialized = true;
  }

  async list(): Promise<AnyProtectionEvent[]> {
    await this.initialize();
    return structuredClone(this.events);
  }

  async append(event: AnyProtectionEvent): Promise<AppendEventResult> {
    await this.initialize();
    validateProtectionEvent(event);
    const canonical = canonicalize(event);
    const semantic = semanticBytes(event);
    const existing = this.byId.get(event.eventId);
    if (existing !== undefined) {
      if (existing !== semantic) throw new Error(`conflicting event bytes for ${event.eventId}`);
      return 'duplicate';
    }

    let appendResult: AppendEventResult = 'appended';
    this.writeQueue = this.writeQueue.then(async () => {
      const queuedExisting = this.byId.get(event.eventId);
      if (queuedExisting !== undefined) {
        if (queuedExisting !== semantic) throw new Error(`conflicting event bytes for ${event.eventId}`);
        appendResult = 'duplicate';
        return;
      }
      const handle = await open(this.path, 'a', 0o600);
      try {
        await handle.write(`${canonical}\n`, undefined, 'utf8');
        await handle.sync();
      } finally {
        await handle.close();
      }
      this.byId.set(event.eventId, semantic);
      this.events.push(structuredClone(event));
    });
    await this.writeQueue;
    return appendResult;
  }
}
