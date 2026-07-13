import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ProtectionRuntime } from './runtime.js';
import type { ProtectionRegistration, SignedActionEnvelope } from './types.js';

const MAX_BODY_BYTES = 2 * 1024 * 1024;

export interface ProtectionRuntimeServerOptions {
  host?: string;
  port?: number;
  /** SHA-256 digests or plaintext tokens; plaintext is hashed at startup. */
  apiTokens?: string[];
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_BODY_BYTES) throw new RangeError(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    chunks.push(bytes);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (raw.trim().length === 0) return {};
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new TypeError('request body must be a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function digestToken(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

export async function startProtectionRuntimeServer(
  runtime: ProtectionRuntime,
  options: ProtectionRuntimeServerOptions = {},
): Promise<Server> {
  await runtime.initialize();
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 4890;
  const configuredTokens = options.apiTokens ?? [];
  if (configuredTokens.some((token) => token.length === 0)) {
    throw new TypeError('runtime API tokens must not be empty');
  }
  const loopbackOnly = host === '127.0.0.1' || host === '::1' || host === 'localhost';
  if (!loopbackOnly && configuredTokens.length === 0) {
    throw new TypeError('a runtime API token is required when listening outside loopback');
  }
  const acceptedTokens = configuredTokens.flatMap((token) => {
    const plaintextDigest = digestToken(token);
    return /^[0-9a-f]{64}$/.test(token)
      ? [Buffer.from(token, 'hex'), plaintextDigest]
      : [plaintextDigest];
  });

  function authorized(req: IncomingMessage): boolean {
    if (acceptedTokens.length === 0) return true;
    const header = req.headers.authorization;
    if (header === undefined || !header.startsWith('Bearer ')) return false;
    const received = digestToken(header.slice('Bearer '.length));
    return acceptedTokens.some((candidate) => candidate.length === received.length && timingSafeEqual(candidate, received));
  }

  const server = createServer((req, res) => {
    void route(req, res).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      const status = error instanceof SyntaxError || error instanceof TypeError || error instanceof RangeError ? 400 : 422;
      if (!res.headersSent) sendJson(res, status, { error: status === 400 ? 'bad_request' : 'operation_rejected', message });
      else res.end();
    });
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method ?? 'GET';
    const url = new URL(req.url ?? '/', 'http://runtime.local');
    const path = url.pathname;
    if (method === 'GET' && path === '/healthz') {
      sendJson(res, 200, {
        ok: true,
        name: '@edict/protection-runtime',
        product: 'Edict Protect',
        custody: 'none',
      });
      return;
    }
    if (!authorized(req)) {
      res.setHeader('www-authenticate', 'Bearer');
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }
    if (method === 'GET' && path === '/v1/setup') {
      const observationReady = (runtime.options.connectors?.length ?? 0) > 0;
      const providers = runtime.options.adjudicator?.providers ?? new Map();
      const providerCount = providers.size;
      const registrationEvents = (await runtime.listEvents()).filter(
        (event) => event.type === 'protection_registered',
      );
      const requiredProviderIds = new Set(registrationEvents.flatMap(
        (event) => event.payload.registration.profile.juryPolicy.seats?.map((seat) => seat.providerId) ?? [],
      ));
      const missingProviderIds = [...requiredProviderIds].filter((providerId) => !providers.has(providerId)).sort();
      const mismatchedProviderIds = [...providers.entries()]
        .filter(([providerId, provider]) => provider.id !== providerId)
        .map(([providerId]) => providerId)
        .sort();
      const adjudicationReady = providerCount >= 2
        && missingProviderIds.length === 0
        && mismatchedProviderIds.length === 0;
      const executionReady = runtime.options.executionSignatures !== undefined;
      const automaticRelayReady = runtime.options.relayer !== undefined && runtime.options.autoRelay === true;
      const webhookCount = runtime.options.verdictWebhooks?.length ?? 0;
      const missingRequired = [
        ...(!observationReady ? ['payment observation connector'] : []),
        ...(!adjudicationReady ? ['live arbiter providers'] : []),
        ...(!executionReady ? ['independent execution signers'] : []),
      ];
      sendJson(res, 200, {
        product: 'Edict Protect',
        runtime: missingRequired.length === 0 ? 'ready' : 'configuration_required',
        capabilities: {
          observation: { ready: observationReady, connectorCount: runtime.options.connectors?.length ?? 0 },
          adjudication: {
            ready: adjudicationReady,
            providerCount,
            minimumProviderCount: 2,
            registeredProfileCount: registrationEvents.length,
            missingProviderIds,
            mismatchedProviderIds,
          },
          executionSignatures: { ready: executionReady },
          relaying: { automatic: automaticRelayReady, permissionlessPlans: true },
          webhooks: { configured: webhookCount > 0, targetCount: webhookCount },
          missingRequired,
        },
        custody: {
          customerFundsHeld: false,
          customerKeysHeld: false,
          settlementAuthority: 'customer-owned immutable contract',
          relays: 'contract-revalidated and permissionless',
        },
      });
      return;
    }
    if (path === '/v1/protections' && method === 'POST') {
      const body = await readJson(req);
      const projection = await runtime.register((body.registration ?? body) as ProtectionRegistration);
      sendJson(res, 201, { protection: projection });
      return;
    }
    if (path === '/v1/protections' && method === 'GET') {
      sendJson(res, 200, { protections: await runtime.listProtections() });
      return;
    }
    if (path === '/v1/activity' && method === 'GET') {
      sendJson(res, 200, { activity: await runtime.listProtections() });
      return;
    }
    if (path === '/v1/attention' && method === 'GET') {
      const protections = await runtime.listProtections();
      sendJson(res, 200, { attention: protections.flatMap((protection) => protection.attention) });
      return;
    }
    if (path === '/v1/relay-plans' && method === 'GET') {
      const protections = await runtime.listProtections();
      sendJson(res, 200, { relayPlans: protections.flatMap((protection) => protection.relayPlans) });
      return;
    }
    const match = /^\/v1\/protections\/([0-9a-f]{64})(?:\/(events|actions))?$/.exec(path);
    if (match !== null) {
      const protectionId = match[1]!;
      const child = match[2];
      if (child === undefined && method === 'GET') {
        sendJson(res, 200, { protection: await runtime.getProtection(protectionId) });
        return;
      }
      if (child === 'events' && method === 'GET') {
        sendJson(res, 200, { events: await runtime.listEvents(protectionId) });
        return;
      }
      if (child === 'actions' && method === 'POST') {
        const envelope = await readJson(req) as unknown as SignedActionEnvelope;
        if (envelope.protectionId !== protectionId) throw new TypeError('URL protection id does not match signed envelope');
        sendJson(res, 200, await runtime.handleSignedAction(envelope));
        return;
      }
    }
    if (path === '/v1/connectors/poll' && method === 'POST') {
      sendJson(res, 200, await runtime.pollConnectors());
      return;
    }
    if (path === '/v1/tick' && method === 'POST') {
      sendJson(res, 200, await runtime.tick());
      return;
    }
    sendJson(res, 404, { error: 'not_found' });
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}

export function protectionRuntimeServerUrl(server: Server): string {
  const address = server.address() as AddressInfo | null;
  if (address === null) throw new Error('runtime server is not listening');
  const host = address.address === '::' ? '127.0.0.1' : address.address;
  return `http://${host}:${address.port}`;
}
