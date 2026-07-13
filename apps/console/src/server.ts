/**
 * Local policy, case inspection, and sandbox dispute console.
 *
 * A LOCAL, single-user tool: one node:http server (zero third-party runtime
 * dependencies) serving ONE static index.html (vanilla JS/CSS, no framework,
 * no frontend build step) plus a JSON API:
 *
 *   GET  /                     the console UI
 *   GET  /healthz              liveness
 *   GET  /api/profiles         list saved ProtectionProfile versions + hashes
 *   POST /api/profiles         save a profile version (immutable: content-conflict → 409)
 *   GET  /api/profiles/:n/:v   one stored version
 *   POST /api/lint             { mandateDraft } → completed mandate + full LintReport
 *   GET  /api/cases            shadow-docket listing (resilient to absent reports)
 *   GET  /api/cases/:id        case detail: verdict, reasoning, instruction blocks
 *   POST /api/sandbox/run      drive the @edict/sdk sandbox end-to-end
 *   GET  /api/sandbox/reviews  sandbox cases held for human review (review policy)
 *   POST /api/sandbox/review   resolve a held case (ruling within the decision
 *                              space + reviewerRef) → human-reviewed verdict + settlement
 *
 * Binds 127.0.0.1 — this is not hosted SaaS.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { mkdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getCase, listCases } from './docket.js';
import { lintDraft } from './lintDraft.js';
import { ProfileStore } from './profiles.js';
import { resolveSandboxReview, ReviewQueueStore, runSandbox } from './sandboxRun.js';

export interface StartConsoleOptions {
  /** TCP port. Default 4870; pass 0 for an ephemeral port (tests). */
  port?: number;
  /** Where profiles + sandbox archives persist. Default `~/.edict-console`. */
  dataDir?: string;
  /** Shadow-docket root (contains cases/ and reports/). Default: the sibling apps/shadow-docket. */
  docketDir?: string;
}

const DEFAULT_PORT = 4870;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** apps/console/static/index.html, resolved relative to the compiled module. */
const STATIC_HTML = fileURLToPath(new URL('../static/index.html', import.meta.url));
/** apps/shadow-docket, resolved relative to the compiled module. */
const DEFAULT_DOCKET_DIR = fileURLToPath(new URL('../../shadow-docket', import.meta.url));

const CSP =
  "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'";

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
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

async function readJsonBody(req: IncomingMessage): Promise<{ value?: unknown; error?: string }> {
  let raw: string;
  try {
    raw = await readBody(req);
  } catch (e) {
    return { error: (e as Error).message };
  }
  if (raw.trim().length === 0) return { error: 'empty request body — send JSON' };
  try {
    return { value: JSON.parse(raw) as unknown };
  } catch {
    return { error: 'request body is not valid JSON' };
  }
}

/**
 * Start the policy console. Resolves with the listening node:http server
 * (read the bound port off `server.address()`).
 */
export async function startConsole(opts: StartConsoleOptions = {}): Promise<Server> {
  const port = opts.port ?? DEFAULT_PORT;
  const dataDir = opts.dataDir ?? join(homedir(), '.edict-console');
  const docketDir = opts.docketDir ?? DEFAULT_DOCKET_DIR;
  const archiveRoot = join(dataDir, 'archive');
  await mkdir(join(dataDir, 'profiles'), { recursive: true });
  await mkdir(archiveRoot, { recursive: true });
  const profiles = new ProfileStore(join(dataDir, 'profiles'));
  // Sandbox cases held for human review (review policy) — in-memory, per server.
  const reviews = new ReviewQueueStore();

  const server = createServer((req, res) => {
    void route(req, res).catch((e: unknown) => {
      // Last-resort guard: never leave a request hanging.
      if (!res.headersSent) sendJson(res, 500, { error: 'internal', message: (e as Error).message });
      else res.end();
    });
  });

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://console.local');
    const path = url.pathname;
    const method = req.method ?? 'GET';

    // --- UI + liveness ----------------------------------------------------------
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
      sendJson(res, 200, { ok: true, name: '@edict/console', dataDir, docketDir });
      return;
    }

    // --- profiles -----------------------------------------------------------------
    if (path === '/api/profiles') {
      if (method === 'GET') {
        sendJson(res, 200, { profiles: await profiles.list() });
        return;
      }
      if (method === 'POST') {
        const body = await readJsonBody(req);
        if (body.error !== undefined) {
          sendJson(res, 400, { error: 'bad_request', message: body.error });
          return;
        }
        const saved = await profiles.save(body.value);
        switch (saved.status) {
          case 'invalid':
            sendJson(res, 400, { error: 'invalid_profile', problems: saved.problems });
            return;
          case 'conflict':
            sendJson(res, 409, {
              error: 'immutable_version',
              message: `profile ${saved.name}@${saved.version} already exists with different content — bump the version`,
              existingHash: saved.existingHash,
              incomingHash: saved.incomingHash,
            });
            return;
          case 'unchanged':
            sendJson(res, 200, { status: 'unchanged', ...saved.stored });
            return;
          case 'created':
            sendJson(res, 201, { status: 'created', ...saved.stored });
            return;
        }
      }
      sendJson(res, 405, { error: 'method_not_allowed' });
      return;
    }
    const profileMatch = /^\/api\/profiles\/([^/]+)\/([^/]+)$/.exec(path);
    if (profileMatch !== null) {
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const stored = await profiles.get(decodeURIComponent(profileMatch[1]!), decodeURIComponent(profileMatch[2]!));
      if (stored === undefined) sendJson(res, 404, { error: 'not_found' });
      else sendJson(res, 200, stored);
      return;
    }

    // --- lint -----------------------------------------------------------------------
    if (path === '/api/lint') {
      if (method !== 'POST') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const body = await readJsonBody(req);
      if (body.error !== undefined) {
        sendJson(res, 400, { error: 'bad_request', message: body.error });
        return;
      }
      const v = body.value;
      if (typeof v !== 'object' || v === null || Array.isArray(v) || !('mandateDraft' in v)) {
        sendJson(res, 400, { error: 'bad_request', message: 'body must be { mandateDraft: {...} }' });
        return;
      }
      const draft = (v as { mandateDraft: unknown }).mandateDraft;
      if (typeof draft !== 'object' || draft === null || Array.isArray(draft)) {
        sendJson(res, 400, { error: 'bad_request', message: 'mandateDraft must be an object' });
        return;
      }
      sendJson(res, 200, lintDraft(draft));
      return;
    }

    // --- cases ------------------------------------------------------------------------
    if (path === '/api/cases') {
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      sendJson(res, 200, await listCases(docketDir));
      return;
    }
    const caseMatch = /^\/api\/cases\/([^/]+)$/.exec(path);
    if (caseMatch !== null) {
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const detail = await getCase(docketDir, decodeURIComponent(caseMatch[1]!));
      if (detail === undefined) sendJson(res, 404, { error: 'not_found' });
      else sendJson(res, 200, detail);
      return;
    }

    // --- sandbox -----------------------------------------------------------------------
    if (path === '/api/sandbox/run') {
      if (method !== 'POST') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const body = await readJsonBody(req);
      if (body.error !== undefined) {
        sendJson(res, 400, { error: 'bad_request', message: body.error });
        return;
      }
      if (typeof body.value !== 'object' || body.value === null || Array.isArray(body.value)) {
        sendJson(res, 400, { error: 'bad_request', message: 'body must be a JSON object' });
        return;
      }
      const outcome = await runSandbox(body.value as import('./sandboxRun.js').SandboxRunRequest, {
        profiles,
        docketDir,
        archiveRoot,
        reviews,
      });
      switch (outcome.kind) {
        case 'ok':
          sendJson(res, 200, outcome.body);
          return;
        case 'lint_blocked':
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

    // --- human review queue (review policy) ------------------------------------------
    if (path === '/api/sandbox/reviews') {
      if (method !== 'GET') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      sendJson(res, 200, { reviews: reviews.list() });
      return;
    }
    if (path === '/api/sandbox/review') {
      if (method !== 'POST') {
        sendJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      const body = await readJsonBody(req);
      if (body.error !== undefined) {
        sendJson(res, 400, { error: 'bad_request', message: body.error });
        return;
      }
      if (typeof body.value !== 'object' || body.value === null || Array.isArray(body.value)) {
        sendJson(res, 400, { error: 'bad_request', message: 'body must be a JSON object' });
        return;
      }
      const outcome = resolveSandboxReview(body.value as import('./sandboxRun.js').ReviewResolveRequest, reviews);
      switch (outcome.kind) {
        case 'ok':
          sendJson(res, 200, outcome.body);
          return;
        case 'not_found':
          sendJson(res, 404, { error: 'not_found', message: outcome.message });
          return;
        default:
          sendJson(res, 400, {
            error: 'bad_request',
            message: outcome.kind === 'bad_request' ? outcome.message : 'bad request',
            ...(outcome.kind === 'bad_request' && outcome.problems !== undefined ? { problems: outcome.problems } : {}),
          });
          return;
      }
    }

    sendJson(res, 404, { error: 'not_found', message: `no route ${method} ${path}` });
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  return server;
}
