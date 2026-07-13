/**
 * Edict Protect customer workspace and explicit SDK sandbox.
 *
 * Same architecture as the developer console (apps/console): ONE node:http
 * server (zero third-party runtime dependencies) serving ONE static
 * index.html (vanilla JS/CSS, no framework, no build step) plus a JSON API.
 * Binds 127.0.0.1. It can present either the local SDK sandbox or the
 * production, non-custodial @edict/protection-runtime through a same-origin
 * read proxy; customer API credentials never enter browser JavaScript.
 *
 *   GET  /                          the app (Transactions · Disputes · Settings · Integrations · Audit)
 *   GET  /healthz                   liveness
 *   GET  /api/summary               dashboard cards
 *   GET  /api/transactions          the main table
 *   POST /api/transactions          create test transaction (guided: preset/policy + terms + amount)
 *   GET  /api/transactions/:id      transaction detail (terms/delivery/protection/timeline)
 *   POST /api/transactions/:id/deliver  simulate the worker's delivery ({quality:'as_agreed'|'incomplete'})
 *   POST /api/transactions/:id/accept   accept delivery (releases payment)
 *   POST /api/transactions/:id/dispute  raise a dispute (runs the real pipeline)
 *   POST /api/transactions/:id/settle   settle a final decision
 *   POST /api/transactions/:id/appeal   file an appeal (optional-appeal policies)
 *   GET  /api/disputes              disputes list
 *   GET  /api/disputes/:id          the claim tracker
 *   POST /api/disputes/:id/resolve-review  human reviewer resolves (SDK resolveHumanReview)
 *   GET  /api/presets               the three step-1 presets (copy + hashes)
 *   GET  /api/policies              saved policies
 *   POST /api/policies              save a hash-committed policy (immutable versions)
 *   GET  /api/integrations          keys (stubs), quickstart, webhooks, mode banner
 *   GET  /api/audit/:id             the audit drawer payload (protocol vocabulary lives HERE only)
 *   GET  /api/audit/:id/bundle      Download audit bundle (single-JSON attachment)
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { mkdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { OrderMandate } from '@edict/core';
import type { ProtectionProfile } from '@edict/sdk';
import { presetCards, TransactionStore } from './store.js';

export interface StartProtectAppOptions {
  /** TCP port. Default 4880; pass 0 for an ephemeral port (tests). */
  port?: number;
  /** Where sandbox archives live. Default `~/.edict-protect`. */
  dataDir?: string;
  /** Where the developer console lives (Integrations → Developer setup link). */
  devConsoleUrl?: string;
  /** Edict Protect runtime base URL. When set, the app becomes the read-only connected-runtime UX. */
  runtimeBaseUrl?: string;
  /** Server-side runtime bearer token; never sent to the browser. */
  runtimeApiToken?: string;
  /** Visible environment label, for example "NEAR testnet". */
  environmentLabel?: string;
}

const DEFAULT_PORT = 4880;
const MAX_BODY_BYTES = 1024 * 1024;

const STATIC_HTML = fileURLToPath(new URL('../static/index.html', import.meta.url));

const CSP =
  "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    ...headers,
  });
  res.end(payload);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new RangeError(`request body exceeds ${MAX_BODY_BYTES} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJsonBody(req: IncomingMessage): Promise<{ value?: Record<string, unknown>; error?: string }> {
  let raw: string;
  try {
    raw = await readBody(req);
  } catch (e) {
    return { error: (e as Error).message };
  }
  if (raw.trim().length === 0) return { value: {} };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { error: 'request body must be a JSON object' };
    }
    return { value: parsed as Record<string, unknown> };
  } catch {
    return { error: 'request body is not valid JSON' };
  }
}

/** Map a store outcome onto HTTP. */
function send(res: ServerResponse, outcome: import('./store.js').StoreOutcome): void {
  switch (outcome.kind) {
    case 'ok':
      sendJson(res, 200, outcome.body);
      return;
    case 'blocked':
      sendJson(res, 422, outcome.body);
      return;
    case 'not_found':
      sendJson(res, 404, { error: 'not_found', message: outcome.message });
      return;
    case 'bad_request':
      sendJson(res, 400, {
        error: 'bad_request',
        message: outcome.message,
        ...(outcome.problems !== undefined ? { problems: outcome.problems } : {}),
      });
      return;
  }
}

const QUICKSTART_SNIPPET = `import { createEdict, isFinalVerdict } from '@edict/sdk';
const edict = createEdict({ mode: 'sandbox' });
edict.escrow.deposit('wallet:buyer', 1_000);
const payment = await edict.protectPayment({ requester: 'wallet:buyer', worker: 'wallet:seller', promise: 'Deliver dataset.bin matching the agreed checksum.', amountUsd: 500, deadlineUnixMs: Date.now() + 86_400_000 });
await edict.deliver(payment, { artifactHashes: [] });
const decision = await edict.dispute(payment, { submissions: { requester: 'The promised file is missing.' } });
if (isFinalVerdict(decision)) edict.settle(decision);
`;

type RuntimeProjection = {
  protectionId: string;
  state: string;
  title: string;
  counterparty: string;
  amountUsd: number;
  asset: string;
  createdAtUnixMs: number;
  updatedAtUnixMs: number;
  deliveryDeadlineUnixMs: number;
  nextDeadlineUnixMs?: number;
  attention?: Array<{ kind: string; title: string; detail: string; createdAtUnixMs: number }>;
  events?: Array<{
    type: string;
    effectiveAtUnixMs: number;
    observedAtUnixMs?: number;
    payload?: Record<string, unknown>;
  }>;
  relayPlans?: Array<{ kind: string; methodName?: string; eligibleAtUnixMs: number }>;
  latestVerdict?: { ruling?: Record<string, unknown>; final?: boolean; quality?: { escalated?: boolean } };
};

type RuntimeRegistrationSnapshot = {
  mandate?: OrderMandate;
  profile?: ProtectionProfile;
};

type RuntimeSetup = {
  runtime?: 'ready' | 'configuration_required';
  capabilities?: {
    observation?: { ready?: boolean; connectorCount?: number };
    adjudication?: { ready?: boolean; providerCount?: number };
    executionSignatures?: { ready?: boolean };
    relaying?: { automatic?: boolean; permissionlessPlans?: boolean };
    webhooks?: { configured?: boolean; targetCount?: number };
    missingRequired?: string[];
  };
  custody?: {
    customerFundsHeld?: boolean;
    customerKeysHeld?: boolean;
    settlementAuthority?: string;
    relays?: string;
  };
};

const RUNTIME_QUICKSTART = `import { createEdict } from '@edict/sdk';
import { ProtectionRuntimeHttpClient } from '@edict/protection-runtime';

const edict = createEdict({ mode: 'live', settlement });
const protect = new ProtectionRuntimeHttpClient({ baseUrl, apiToken });
const payment = await edict.protectPayment(input);
await protect.protect(payment, { profile: edict.profile, intents });`;

const RUNTIME_STATE: Record<string, { label: string; color: string }> = {
  setup_required: { label: 'Setup required', color: '#b45309' },
  awaiting_funding: { label: 'Awaiting funding', color: '#64748b' },
  protected: { label: 'Protected', color: '#2563eb' },
  delivered: { label: 'Delivered', color: '#0f766e' },
  challenged: { label: 'Disputed', color: '#c2410c' },
  review_required: { label: 'Under Review', color: '#a21caf' },
  settlement_ready: { label: 'Decided', color: '#0f766e' },
  settled: { label: 'Settled', color: '#15803d' },
  blocked: { label: 'Escalated', color: '#b91c1c' },
};

function runtimeState(value: string): { label: string; color: string } {
  return RUNTIME_STATE[value] ?? { label: 'Monitoring', color: '#64748b' };
}

function runtimeNeedsAttention(projection: RuntimeProjection): boolean {
  return (projection.attention?.length ?? 0) > 0
    || ['challenged', 'review_required', 'settlement_ready', 'blocked'].includes(projection.state);
}

function runtimeSettlementDeadline(projection: RuntimeProjection): number | undefined {
  return projection.relayPlans?.find((plan) =>
    plan.kind === 'near_function_call' && plan.methodName === 'submit_ruling')?.eligibleAtUnixMs;
}

function runtimeRegistration(projection: RuntimeProjection): RuntimeRegistrationSnapshot {
  const event = projection.events?.find((candidate) => candidate.type === 'protection_registered');
  return (event?.payload?.['registration'] ?? {}) as RuntimeRegistrationSnapshot;
}

function runtimeRow(projection: RuntimeProjection): Record<string, unknown> {
  const state = runtimeState(projection.state);
  const settlementDeadline = runtimeSettlementDeadline(projection);
  return {
    id: projection.protectionId,
    title: projection.title,
    counterparty: projection.counterparty,
    amountUsd: projection.amountUsd,
    protection: 'Edict Protect',
    state: state.label,
    stateColor: state.color,
    createdAtUnixMs: projection.createdAtUnixMs,
    deadline: settlementDeadline !== undefined
      ? { label: 'Challenge window ends', atUnixMs: settlementDeadline }
      : projection.nextDeadlineUnixMs === undefined
      ? null
      : { label: projection.state === 'delivered' ? 'Review closes' : 'Delivery due', atUnixMs: projection.nextDeadlineUnixMs },
    needsAttention: runtimeNeedsAttention(projection),
    attentionCount: projection.attention?.length ?? 0,
    actions: ['view'],
  };
}

function outcomeLabel(ruling: Record<string, unknown> | undefined): string | undefined {
  const kind = ruling?.['kind'];
  if (kind === 'requester_wins') return 'Payment returned to buyer';
  if (kind === 'worker_wins') return 'Payment released to worker';
  if (kind === 'split') return `Payment split ${String(ruling?.['requesterBps'] ?? '')} bps to buyer`;
  if (kind === 'redo') return 'Worker asked to deliver again';
  return undefined;
}

function relayLabel(method: string | undefined, submitted: boolean): string {
  const phase = submitted ? 'submitted' : 'ready';
  if (method === 'submit_ruling') return `Settlement proof ${phase}`;
  if (method === 'withdraw_claim') return `Claim withdrawal ${phase}`;
  if (method === 'claim_timeout') return `Timeout claim ${phase}`;
  if (method === 'execute_liveness_fallback') return `Fallback settlement ${phase}`;
  if (method === 'near_signed_intent') return `Signed dispute ${phase}`;
  return `Settlement relay ${phase}`;
}

function runtimeTimeline(projection: RuntimeProjection): Array<Record<string, unknown>> {
  const labels: Record<string, string> = {
    protection_registered: 'Protection registered',
    protection_accepted: 'Counterparty approved protection',
    funding_confirmed: 'Funding confirmed',
    delivery_submitted: 'Delivery recorded',
    challenge_requested: 'Dispute signature prepared',
    challenge_opened: 'Dispute opened',
    verdict_issued: 'Decision issued',
    webhook_delivery_recorded: 'Decision webhook delivery checked',
    review_required: 'Human review requested',
    settlement_finalized: 'Settlement finalized',
    deadline_elapsed: 'Protection deadline reached',
    connector_warning: 'Connection check needs attention',
    connector_recovered: 'Connection restored',
  };
  const relayMethods = new Map<string, string>();
  for (const event of projection.events ?? []) {
    if (event.type !== 'relay_ready') continue;
    const plan = event.payload?.['plan'];
    if (typeof plan !== 'object' || plan === null || Array.isArray(plan)) continue;
    const planId = (plan as Record<string, unknown>)['planId'];
    const methodName = (plan as Record<string, unknown>)['methodName'];
    const kind = (plan as Record<string, unknown>)['kind'];
    if (typeof planId === 'string') {
      relayMethods.set(planId, typeof methodName === 'string' ? methodName : String(kind ?? ''));
    }
  }
  return (projection.events ?? []).map((event) => {
    let label = labels[event.type] ?? event.type.replaceAll('_', ' ');
    if (event.type === 'relay_ready') {
      const plan = event.payload?.['plan'];
      const method = typeof plan === 'object' && plan !== null && !Array.isArray(plan)
        ? ((plan as Record<string, unknown>)['methodName'] ?? (plan as Record<string, unknown>)['kind'])
        : undefined;
      label = relayLabel(typeof method === 'string' ? method : undefined, false);
    } else if (event.type === 'relay_submitted') {
      const planId = event.payload?.['planId'];
      label = relayLabel(typeof planId === 'string' ? relayMethods.get(planId) : undefined, true);
    }
    return {
      atUnixMs: event.observedAtUnixMs ?? event.effectiveAtUnixMs,
      label,
      stateColor: runtimeState(projection.state).color,
      relayPhaseOrder: event.type === 'relay_ready' ? 0 : event.type === 'relay_submitted' ? 1 : 0,
    };
  }).sort((a, b) => a.atUnixMs - b.atUnixMs || a.relayPhaseOrder - b.relayPhaseOrder)
    .map(({ relayPhaseOrder: _relayPhaseOrder, ...entry }) => entry);
}

function runtimeDetail(projection: RuntimeProjection): Record<string, unknown> {
  const state = runtimeState(projection.state);
  const delivery = [...(projection.events ?? [])].reverse().find((event) => event.type === 'delivery_submitted');
  const deliveredAt = delivery?.payload?.['deliveredAtUnixMs'];
  const manifest = delivery?.payload?.['manifestSha256'];
  const registration = runtimeRegistration(projection);
  const mandate = registration.mandate;
  const profile = registration.profile;
  const settlementDeadline = runtimeSettlementDeadline(projection);
  const possibleOutcomes = mandate?.decisionSpace.kind === 'escrow_branches'
    ? mandate.decisionSpace.permitted.map((outcome) => ({
        requester_wins: 'Return payment',
        worker_wins: 'Release payment',
        split: 'Split payment',
        redo: 'Redo delivery',
      })[outcome])
    : ['Committed decision space'];
  const humanMode = profile?.humanEscalation?.mode ?? profile?.legalPolicy.humanEscalation.mode;
  return {
    header: {
      title: projection.title,
      state: state.label,
      stateColor: state.color,
      amountProtectedUsd: projection.amountUsd,
      deadlineUnixMs: settlementDeadline ?? projection.deliveryDeadlineUnixMs,
      deadlineLabel: settlementDeadline === undefined ? 'delivery due' : 'challenge window ends',
      protectionLevel: 'Edict Protect',
    },
    actions: ['view'],
    terms: {
      description: projection.title,
      acceptanceCriteria: mandate?.acceptanceCriteria.map((criterion) => ({
        statement: criterion.statement,
        automated: criterion.machineCheck !== undefined,
      })) ?? [{ statement: 'The signed payment promise and committed acceptance criteria', automated: true }],
      deadlineUnixMs: projection.deliveryDeadlineUnixMs,
      possibleOutcomes,
    },
    ...(typeof deliveredAt === 'number' ? {
      delivery: {
        deliveredAtUnixMs: deliveredAt,
        files: [{ name: typeof manifest === 'string' ? `Committed delivery ${manifest.slice(0, 12)}…` : 'Committed delivery' }],
        notes: ['Content remains sealed; integrity is checked against its signed hash.'],
      },
    } : {}),
    protection: {
      custody: 'Funds remain in the customer-owned, keyless settlement contract',
      identity: 'Wallet and payment-rail signatures',
      reviewType: 'Objective checks, then independent AI judges when needed',
      humanReview: projection.state === 'review_required'
        ? 'Required for this case'
        : humanMode === 'off' ? 'Off for this protection' : 'Available under the selected policy',
      autoAcceptWindowMs: mandate?.acceptanceWindowMs ?? 0,
      policy: profile?.name ?? 'Edict Protect',
      policyVersion: profile?.version ?? '1',
    },
    timeline: runtimeTimeline(projection),
  };
}

function runtimeDispute(projection: RuntimeProjection): Record<string, unknown> {
  const state = runtimeState(projection.state);
  const firstAttention = projection.attention?.[0];
  const evidence = (projection.events ?? [])
    .filter((event) => event.type === 'evidence_attached')
    .map((event) => ({
      item: String(event.payload?.['kind'] ?? 'Evidence'),
      submittedBy: String(event.payload?.['submitter'] ?? 'party'),
      verified: event.payload?.['authenticated'] === true,
    }));
  const checks = (projection.events ?? [])
    .filter((event) => event.type === 'objective_failure_detected')
    .map((event) => ({ name: String(event.payload?.['criterionId'] ?? 'Acceptance check'), result: 'failed', detail: String(event.payload?.['reason'] ?? '') }));
  const decision = outcomeLabel(projection.latestVerdict?.ruling);
  const settlementDeadline = runtimeSettlementDeadline(projection);
  return {
    id: projection.protectionId,
    title: projection.title,
    amountUsd: projection.amountUsd,
    state: state.label,
    stateColor: state.color,
    reason: firstAttention?.title ?? (decision ?? 'Protection review'),
    needsReview: projection.state === 'review_required',
    header: {
      reason: firstAttention?.title ?? 'Protection review',
      reviewType: 'Edict Protect autonomous resolution',
      expectedTime: settlementDeadline !== undefined
        ? `Challenge window ends ${new Date(settlementDeadline).toISOString()}`
        : projection.nextDeadlineUnixMs === undefined ? 'Monitoring' : `By ${new Date(projection.nextDeadlineUnixMs).toISOString()}`,
    },
    sides: { buyer: 'Signed evidence is sealed in the protection record.', worker: 'Signed evidence is sealed in the protection record.' },
    evidence,
    automatedChecks: checks,
    ...(decision !== undefined ? {
      decision: { decision, confidence: projection.latestVerdict?.quality?.escalated ? 'Held for review' : 'Verified', status: state.label },
    } : {}),
    ...(firstAttention !== undefined ? {
      escalation: { title: firstAttention.title, reason: firstAttention.detail, nextStep: 'Complete the requested action in the connected wallet or review queue.' },
    } : {}),
    review: { available: false },
  };
}

export async function startProtectApp(opts: StartProtectAppOptions = {}): Promise<Server> {
  const port = opts.port ?? DEFAULT_PORT;
  const dataDir = opts.dataDir ?? join(homedir(), '.edict-protect');
  const devConsoleUrl = opts.devConsoleUrl ?? 'http://127.0.0.1:4870/';
  let runtimeBaseUrl: string | undefined;
  if (opts.runtimeBaseUrl !== undefined) {
    const parsed = new URL(opts.runtimeBaseUrl);
    const localHttp = parsed.protocol === 'http:' && parsed.hostname === '127.0.0.1';
    if (parsed.protocol !== 'https:' && !localHttp) {
      throw new TypeError('runtime URL must use HTTPS (or loopback HTTP for development)');
    }
    if (parsed.username.length > 0 || parsed.password.length > 0) {
      throw new TypeError('runtime URL cannot contain credentials');
    }
    if (parsed.search.length > 0 || parsed.hash.length > 0) {
      throw new TypeError('runtime URL cannot contain a query or fragment');
    }
    runtimeBaseUrl = parsed.toString().replace(/\/+$/, '');
  }
  const appMode = runtimeBaseUrl === undefined ? 'sandbox' : 'runtime';
  const archiveRoot = join(dataDir, 'archive');
  await mkdir(archiveRoot, { recursive: true });
  const store = new TransactionStore(archiveRoot);

  async function runtimeApi<T>(path: string): Promise<T> {
    if (runtimeBaseUrl === undefined) throw new Error('production runtime is not configured');
    const response = await fetch(`${runtimeBaseUrl}${path}`, {
      headers: opts.runtimeApiToken === undefined ? {} : { authorization: `Bearer ${opts.runtimeApiToken}` },
    });
    const body = await response.json() as T & { message?: string };
    if (!response.ok) throw new Error(body.message ?? `protection runtime returned HTTP ${response.status}`);
    return body;
  }

  async function runtimeProtections(): Promise<RuntimeProjection[]> {
    const body = await runtimeApi<{ activity: RuntimeProjection[] }>('/v1/activity');
    return body.activity;
  }

  const server = createServer((req, res) => {
    void route(req, res).catch((e: unknown) => {
      if (!res.headersSent) sendJson(res, 500, { error: 'internal', message: (e as Error).message });
      else res.end();
    });
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://protect.local');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // --- UI + liveness ---------------------------------------------------------
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      const html = await readFile(STATIC_HTML);
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'content-length': html.length,
        'content-security-policy': CSP,
      });
      res.end(html);
      return;
    }
    if (method === 'GET' && path === '/healthz') {
      sendJson(res, 200, { ok: true, name: '@edict/protect-app', mode: appMode, dataDir, runtimeBaseUrl });
      return;
    }
    if (method === 'GET' && path === '/api/config') {
      sendJson(res, 200, {
        mode: appMode,
        product: 'Edict Protect',
        ...(opts.environmentLabel !== undefined ? { environmentLabel: opts.environmentLabel } : {}),
        primaryNavigation: ['Activity', 'Needs attention'],
        transactionCreation: appMode === 'sandbox',
      });
      return;
    }

    // --- production runtime read model ------------------------------------------
    if (appMode === 'runtime') {
      if (path === '/api/summary' && method === 'GET') {
        const [protections, setup] = await Promise.all([
          runtimeProtections(),
          runtimeApi<RuntimeSetup>('/v1/setup'),
        ]);
        sendJson(res, 200, {
          transactionCount: protections.length,
          attentionCount: protections.filter(runtimeNeedsAttention).length,
          attentionItemCount: protections.reduce((total, protection) => total + (protection.attention?.length ?? 0), 0),
          runtimeReady: setup.runtime === 'ready',
          setupAttention: setup.capabilities?.missingRequired ?? [],
        });
        return;
      }
      if (path === '/api/transactions') {
        if (method !== 'GET') {
          sendJson(res, 405, { error: 'method_not_allowed', message: 'Production payments are created by the connected rail, not this dashboard.' });
          return;
        }
        sendJson(res, 200, { transactions: (await runtimeProtections()).map(runtimeRow) });
        return;
      }
      const runtimeTx = /^\/api\/transactions\/([0-9a-f]{64})$/.exec(path);
      if (runtimeTx !== null) {
        if (method !== 'GET') {
          sendJson(res, 405, { error: 'method_not_allowed' });
          return;
        }
        const body = await runtimeApi<{ protection: RuntimeProjection }>(`/v1/protections/${runtimeTx[1]}`);
        sendJson(res, 200, runtimeDetail(body.protection));
        return;
      }
      if (path === '/api/disputes' && method === 'GET') {
        const protections = await runtimeProtections();
        sendJson(res, 200, {
          disputes: protections
            .filter(runtimeNeedsAttention)
            .map((projection) => {
              const detail = runtimeDispute(projection);
              return {
                id: projection.protectionId,
                title: projection.title,
                amountUsd: projection.amountUsd,
                state: runtimeState(projection.state).label,
                stateColor: runtimeState(projection.state).color,
                reason: detail['reason'],
                needsReview: projection.state === 'review_required',
                decision: outcomeLabel(projection.latestVerdict?.ruling),
              };
            }),
        });
        return;
      }
      const runtimeDisputeMatch = /^\/api\/disputes\/([0-9a-f]{64})$/.exec(path);
      if (runtimeDisputeMatch !== null && method === 'GET') {
        const body = await runtimeApi<{ protection: RuntimeProjection }>(`/v1/protections/${runtimeDisputeMatch[1]}`);
        sendJson(res, 200, runtimeDispute(body.protection));
        return;
      }
      if (path === '/api/integrations' && method === 'GET') {
        const setup = await runtimeApi<RuntimeSetup>('/v1/setup');
        const capabilities = setup.capabilities ?? {};
        const runtimeReady = setup.runtime === 'ready';
        sendJson(res, 200, {
          mode: 'runtime',
          banner: runtimeReady
            ? 'Protection is connected. Edict observes and resolves exceptions without holding customer funds or keys.'
            : 'Finish the runtime connections below before protecting production payments.',
          settlementSetup: {
            title: 'Protection runtime',
            status: runtimeReady ? 'Ready' : 'Finish setup',
            statusColor: runtimeReady ? '#15803d' : '#b45309',
            summary: 'Connect once at the rail. Every protected payment then appears here automatically; settlement remains in the customer-owned contract.',
            checks: [
              {
                label: 'Observe payments',
                ready: capabilities.observation?.ready === true,
                detail: capabilities.observation?.ready === true
                  ? `${capabilities.observation.connectorCount ?? 0} final-state connector configured`
                  : 'Add the payment-event connector',
              },
              {
                label: 'Resolve disputes',
                ready: capabilities.adjudication?.ready === true,
                detail: capabilities.adjudication?.ready === true
                  ? `${capabilities.adjudication.providerCount ?? 0} arbiter providers configured`
                  : 'Add the selected independent model providers',
              },
              {
                label: 'Authorize settlement',
                ready: capabilities.executionSignatures?.ready === true,
                detail: capabilities.executionSignatures?.ready === true
                  ? 'Independent signer collection configured'
                  : 'Add the independent execution signer endpoints',
              },
            ],
            guarantees: ['No customer key in Edict', 'No arbitrary payout destination', 'Customer-owned immutable settlement contract'],
            sdk: RUNTIME_QUICKSTART,
          },
          confidentialSettlement: {
            title: 'Confidential Intents',
            status: 'Capability-gated',
            statusColor: '#64748b',
            summary: 'Private settlement activates only for independently audited provider capabilities; public fallback remains fail-closed.',
            safeguards: ['Selective disclosure', 'Commitments-only public record', 'No silent privacy downgrade'],
          },
          webhooks: {
            configured: capabilities.webhooks?.configured === true,
            targetCount: capabilities.webhooks?.targetCount ?? 0,
            automaticRelay: capabilities.relaying?.automatic === true,
            doc: 'Final decisions are delivered as HMAC-signed canonical events. Permissionless relay plans remain available even when automatic gas relay is off.',
            events: ['verdict_issued'],
          },
        });
        return;
      }
      if (path.startsWith('/api/policies') || path.startsWith('/api/presets') || path.startsWith('/api/audit/')) {
        sendJson(res, 404, { error: 'not_found', message: 'Advanced policy and audit tools are outside the core connected-runtime workspace.' });
        return;
      }
    }

    // --- dashboard + transactions ------------------------------------------------
    if (path === '/api/summary' && method === 'GET') {
      sendJson(res, 200, store.summary());
      return;
    }
    if (path === '/api/transactions') {
      if (method === 'GET') {
        sendJson(res, 200, { transactions: store.listRows() });
        return;
      }
      if (method === 'POST') {
        const body = await readJsonBody(req);
        if (body.error !== undefined) {
          sendJson(res, 400, { error: 'bad_request', message: body.error });
          return;
        }
        send(res, await store.create(body.value ?? {}));
        return;
      }
      sendJson(res, 405, { error: 'method_not_allowed' });
      return;
    }
    const txAction = /^\/api\/transactions\/([0-9a-f]{64})(?:\/(deliver|accept|dispute|settle|appeal))?$/.exec(path);
    if (txAction !== null) {
      const id = txAction[1]!;
      const action = txAction[2];
      if (action === undefined) {
        if (method !== 'GET') {
          sendJson(res, 405, { error: 'method_not_allowed' });
          return;
        }
        send(res, store.detail(id));
        return;
      }
      if (method !== 'POST') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const body = await readJsonBody(req);
      if (body.error !== undefined) {
        sendJson(res, 400, { error: 'bad_request', message: body.error });
        return;
      }
      const args = body.value ?? {};
      switch (action) {
        case 'deliver':
          send(res, await store.deliver(id, args.quality));
          return;
        case 'accept':
          send(res, await store.accept(id));
          return;
        case 'dispute':
          send(res, await store.dispute(id, args));
          return;
        case 'settle':
          send(res, store.settle(id));
          return;
        case 'appeal':
          send(res, await store.appeal(id, args.by));
          return;
      }
    }

    // --- disputes ------------------------------------------------------------------
    if (path === '/api/disputes' && method === 'GET') {
      sendJson(res, 200, { disputes: await store.listDisputes() });
      return;
    }
    const disputeMatch = /^\/api\/disputes\/([0-9a-f]{64})(?:\/(resolve-review))?$/.exec(path);
    if (disputeMatch !== null) {
      const id = disputeMatch[1]!;
      if (!store.has(id)) {
        sendJson(res, 404, { error: 'not_found', message: `No dispute ${id}.` });
        return;
      }
      if (disputeMatch[2] === 'resolve-review') {
        if (method !== 'POST') {
          sendJson(res, 405, { error: 'method_not_allowed' });
          return;
        }
        const body = await readJsonBody(req);
        if (body.error !== undefined) {
          sendJson(res, 400, { error: 'bad_request', message: body.error });
          return;
        }
        send(res, store.resolveReview(id, body.value ?? {}));
        return;
      }
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      sendJson(res, 200, await store.disputeDetail(id));
      return;
    }

    // --- policies -------------------------------------------------------------------
    if (path === '/api/presets' && method === 'GET') {
      sendJson(res, 200, { presets: presetCards() });
      return;
    }
    if (path === '/api/policies') {
      if (method === 'GET') {
        sendJson(res, 200, {
          policies: store.policies.list().map((p) => ({
            name: p.name,
            version: p.version,
            profileHash: p.profileHash,
            savedAtUnixMs: p.savedAtUnixMs,
            basePreset: p.basePreset ?? null,
            ref: `${p.name}@${p.version}`,
          })),
        });
        return;
      }
      if (method === 'POST') {
        const body = await readJsonBody(req);
        if (body.error !== undefined) {
          sendJson(res, 400, { error: 'bad_request', message: body.error });
          return;
        }
        const args = body.value ?? {};
        const saved = store.policies.save(
          args.profile,
          typeof args.basePreset === 'string' ? args.basePreset : undefined,
        );
        switch (saved.status) {
          case 'invalid':
            sendJson(res, 400, { error: 'invalid_policy', problems: saved.problems });
            return;
          case 'conflict':
            sendJson(res, 409, {
              error: 'immutable_version',
              message: `Policy ${saved.name}@${saved.version} already exists with different content — bump the version.`,
              existingHash: saved.existingHash,
              incomingHash: saved.incomingHash,
            });
            return;
          case 'unchanged':
            sendJson(res, 200, { status: 'unchanged', ...publicPolicy(saved.stored) });
            return;
          case 'created':
            sendJson(res, 201, { status: 'created', ...publicPolicy(saved.stored) });
            return;
        }
      }
      sendJson(res, 405, { error: 'method_not_allowed' });
      return;
    }

    // --- integrations ------------------------------------------------------------------
    if (path === '/api/integrations' && method === 'GET') {
      sendJson(res, 200, {
        mode: 'sandbox',
        banner:
          'Sandbox mode: test transactions and a simulated customer ledger. In production your wallet, rail or ' +
          'customer-approved keyless settlement instance holds the funds and applies only pre-committed outcomes.',
        settlementSetup: {
          title: 'Customer-owned settlement',
          status: 'External audit pending',
          statusColor: '#9a6700',
          summary:
            'NEAR Intents is the preferred cross-chain route. Exact-output 1Click funding, signed quote checks and ' +
            'beneficiary-controlled payout plans, keyless settlement contract/factory and exact-Verifier sandbox are ' +
            'implemented; independent audit, mainnet deployment and canary are still pending. Native-NEAR v1 remains a separate tested fallback ' +
            'artifact. Customers will approve one factory call and run no settlement node. Edict may sponsor gas, ' +
            'relay and monitor, but cannot move or freeze funds or sign withdrawals.',
          steps: [
            'Review the Intents adapter audit, exact hashes and pinned Verifier assumptions',
            'Choose the settlement asset and removal identity, then approve one factory call',
            'Verify the keyless manifest, save the adapter reference and preflight Intents before funding',
          ],
          guarantees: [
            'Customer approves deployment; no contract admin key exists',
            'Edict is not a required settlement signer',
            'No customer-operated node is needed on-chain',
            'Funding refunds and payout destinations remain party controlled',
          ],
          sdk:
            'const settlement = nearIntentsSettlementFromManifest(deploymentManifest);\n' +
            'await verifyIntentsRuntime({ manifest: deploymentManifest });\n' +
            'const route = nearIntentsRoute(customerSettlementConfig);\n' +
            "const edict = createEdict({ mode: 'live', settlement });\n" +
            'const quote = buildProtectionFundingQuote({ ...payment, settlementAsset: route.settlementAsset });',
        },
        confidentialSettlement: {
          title: 'Confidential settlement',
          status: 'Partner interface required',
          statusColor: '#6e7781',
          availability: 'gated',
          summary:
            'The target profile runs the customer-approved keyless Edict settlement state machine on the ' +
            'Confidential Intents private shard, with a commitments-only public record. The signed capability, ' +
            'selective-disclosure and fail-closed policy are implemented, but this mode is not active until a ' +
            'stable provider interface, independent audit and private-shard canary are verified.',
          safeguards: [
            'Private settlement, not transport-only privacy',
            'No silent downgrade to a public route',
            'Capability and disclosure policy signed per order',
            'No Edict settlement or withdrawal key',
          ],
        },
        apiKeys: [
          { label: 'Sandbox key', key: 'edict_sk_sandbox_************************', status: 'active' },
          { label: 'Live key', key: 'edict_sk_live_—', status: 'Available after developer setup' },
        ],
        quickstart: QUICKSTART_SNIPPET,
        webhooks: {
          doc:
            'Subscribe to decision webhooks: every decision is delivered as canonical JSON, HMAC-signed with your ' +
            'webhook secret (verify with verifyVerdictWebhook from @edict/sdk). Events: decision issued, ' +
            'human review started, human review decided. Your rail, sidecar or customer-approved keyless contract ' +
            'verifies and applies the result; Edict receives no custody credentials.',
          events: ['decision.issued', 'review.started', 'review.decided'],
        },
        devConsoleUrl,
        devConsoleLabel: 'Developer setup — open the Edict developer console',
      });
      return;
    }

    // --- audit drawer ---------------------------------------------------------------------
    const auditMatch = /^\/api\/audit\/([0-9a-f]{64})(?:\/(bundle))?$/.exec(path);
    if (auditMatch !== null) {
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const outcome = await store.auditBundle(auditMatch[1]!);
      if (outcome.kind === 'ok' && auditMatch[2] === 'bundle') {
        sendJson(res, 200, outcome.body, {
          'content-disposition': `attachment; filename="edict-audit-${auditMatch[1]!.slice(0, 12)}.json"`,
        });
        return;
      }
      send(res, outcome);
      return;
    }

    sendJson(res, 404, { error: 'not_found', message: `no route ${method} ${path}` });
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  return server;
}

function publicPolicy(p: import('./store.js').StoredPolicy): Record<string, unknown> {
  return {
    name: p.name,
    version: p.version,
    profileHash: p.profileHash,
    savedAtUnixMs: p.savedAtUnixMs,
    basePreset: p.basePreset ?? null,
    ref: `${p.name}@${p.version}`,
  };
}
