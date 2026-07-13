/**
 * Edict SDK quickstart — the whole integration in seven lines of code:
 * create a client, protect an order, take delivery, dispute it, settle the
 * verdict. Fully offline: the sandbox runs the @edict/arbiter pipeline
 * over three disjoint-family deterministic mock jury seats.
 *
 * In your own app, import from '@edict/sdk' instead of '../src/index.js'.
 */
import { createEdict, isFinalVerdict } from '../src/index.js';
const edict = createEdict({ mode: 'sandbox' });
edict.escrow.deposit('agent:alice', 1_000);
const order = await edict.protectPayment({ requester: 'agent:alice', worker: 'agent:bob', promise: 'Produce guide.de.md.', amountUsd: 500, deadlineUnixMs: Date.now() + 86_400_000, acceptanceCriteria: [{ id: 'AC-1', statement: 'guide.de.md matches the pinned checksum.', machineCheck: { kind: 'hash_equals', params: { path: 'guide.de.md', sha256: 'a'.repeat(64) } } }] });
await edict.deliver(order, { artifactHashes: [{ path: 'draft.de.md', sha256: 'b'.repeat(64), mediaType: 'text/markdown' }] });
const verdict = await edict.dispute(order, { submissions: { requester: 'guide.de.md is missing.' } });
if (isFinalVerdict(verdict)) console.log(verdict.ruling, edict.settle(verdict).settlement);
