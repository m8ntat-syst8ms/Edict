/**
 * edict-node HTTP service — Edict's OPERATOR #3 attested inference node
 * An OpenAI-compatible signing proxy in front of a local model
 * server (llama.cpp `llama-server` / ollama — anything serving `/v1`).
 *
 * Endpoints (deliberately mirroring the NEAR AI Cloud / dstack
 * private-ai-gateway surface the arbiter already speaks):
 *
 *   POST /v1/chat/completions   proxy; captures byte-exact request/response,
 *                               signs `${model_id}:${sha256(req)}:${sha256(resp)}`
 *                               and persists the signature BEFORE responding
 *   GET  /v1/signature/{chat_id}  persistent signature doc — NO cache expiry
 *   GET  /v1/attestation/report[?nonce=hex]  real TDX quote via the dstack
 *                               guest agent (dstack mode) binding the signing
 *                               key; clearly-labeled `{dev_mode:true}` mock in
 *                               dev mode (no fabricated quote fields, ever)
 *   GET  /v1/models             pass-through to the local model server
 *   GET  /healthz               liveness + mode + signer address
 *
 * Byte-exactness invariant: the response bytes the CLIENT receives are the
 * bytes that were hashed into `response_sha256` and signed. When the
 * upstream response already carries a string `id`, the upstream bytes pass
 * through UNTOUCHED; when it does not (some local servers), an id is
 * injected by re-serialization and the REWRITTEN bytes are both signed and
 * returned. The request hash covers the exact bytes received from the
 * client, which are forwarded to the model server unmodified.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { NodeConfig, NodeMode } from './config.js';
import type { DstackClient } from './dstack.js';
import type { SigningIdentity } from './identity.js';
import {
  SIGNING_ENVELOPE_FORMAT,
  SIGNING_SCHEME,
  ethPersonalMessageDigest,
  proofEnvelope,
  recoverEthAddress,
  signEnvelopeEth,
} from './signer.js';
import { SignatureConflictError, SignatureStore, type SignatureDoc } from './store.js';
import { sha256Hex } from './util.js';

export const API_VERSION = 'edict-node/1' as const;
/** Domain-separation context for the quote's report_data (see attestation handler). */
export const REPORT_DATA_CONTEXT = 'edict-node-signing-key-v1';

export interface NodeDeps {
  mode: NodeMode;
  identity: SigningIdentity;
  store: SignatureStore;
  /** OpenAI-compatible base URL (…/v1) of the local model server. */
  localModelUrl: string;
  modelIdPin?: string | undefined;
  apiKey?: string | undefined;
  /** Required in dstack mode; absent in dev mode. */
  dstack?: DstackClient | undefined;
  maxBodyBytes?: number;
  upstreamTimeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export function depsFromConfig(
  config: NodeConfig,
  identity: SigningIdentity,
  dstack?: DstackClient,
): NodeDeps {
  return {
    mode: config.mode,
    identity,
    store: new SignatureStore(`${config.dataDir}/signatures`),
    localModelUrl: config.localModelUrl,
    modelIdPin: config.modelIdPin,
    apiKey: config.apiKey,
    dstack,
    maxBodyBytes: config.maxBodyBytes,
    upstreamTimeoutMs: config.upstreamTimeoutMs,
  };
}

export function createNodeServer(deps: NodeDeps): Server {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const maxBody = deps.maxBodyBytes ?? 10 * 1024 * 1024;
  const upstreamTimeoutMs = deps.upstreamTimeoutMs ?? 180_000;

  return createServer((req, res) => {
    handle(req, res).catch((err) => {
      // Last-resort handler — never leak stack traces to clients.
      if (!res.headersSent) {
        sendJson(res, 500, { error: `internal error: ${(err as Error).message}` });
      } else {
        res.destroy();
      }
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://edict-node');
    const path = url.pathname;

    if (path === '/healthz' && req.method === 'GET') {
      return healthz(res);
    }
    if (path.startsWith('/v1/') && !authorized(req)) {
      sendJson(res, 401, { error: 'missing or invalid bearer token' });
      return;
    }
    if (path === '/v1/chat/completions' && req.method === 'POST') {
      return chatCompletions(req, res);
    }
    if (path.startsWith('/v1/signature/') && req.method === 'GET') {
      let chatId: string;
      try {
        chatId = decodeURIComponent(path.slice('/v1/signature/'.length));
      } catch {
        sendJson(res, 400, { error: 'chat id is not valid URL encoding' });
        return;
      }
      return signature(chatId, res);
    }
    if (path === '/v1/attestation/report' && req.method === 'GET') {
      return attestationReport(url, res);
    }
    if (path === '/v1/models' && req.method === 'GET') {
      return models(res);
    }
    sendJson(res, 404, { error: `no route: ${req.method} ${path}` });
  }

  function authorized(req: IncomingMessage): boolean {
    if (deps.apiKey === undefined) return true;
    const header = req.headers.authorization;
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
    const presented = Buffer.from(header.slice('Bearer '.length));
    const expected = Buffer.from(deps.apiKey);
    return presented.length === expected.length && timingSafeEqual(presented, expected);
  }

  // -- POST /v1/chat/completions --------------------------------------------

  async function chatCompletions(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let requestBytes: Buffer;
    try {
      requestBytes = await readBody(req, maxBody);
    } catch (err) {
      sendJson(res, err instanceof BodyTooLarge ? 413 : 400, { error: (err as Error).message });
      return;
    }

    let parsedReq: unknown;
    try {
      parsedReq = JSON.parse(requestBytes.toString('utf8'));
    } catch {
      sendJson(res, 400, { error: 'request body is not valid JSON' });
      return;
    }
    if (parsedReq === null || typeof parsedReq !== 'object' || Array.isArray(parsedReq)) {
      sendJson(res, 400, { error: 'request body must be a JSON object' });
      return;
    }
    const body = parsedReq as Record<string, unknown>;
    if (body.stream === true) {
      sendJson(res, 400, {
        error: 'stream:true is not supported — per-inference proofs require whole-body hashing',
      });
      return;
    }
    const modelId = body.model;
    if (typeof modelId !== 'string' || modelId.length === 0) {
      sendJson(res, 400, { error: 'request body must carry a string "model"' });
      return;
    }
    if (deps.modelIdPin !== undefined && modelId !== deps.modelIdPin) {
      sendJson(res, 400, {
        error: `this node serves model "${deps.modelIdPin}" only (got "${modelId}") — the signed envelope must never mislabel the model`,
      });
      return;
    }

    // Hash the EXACT bytes received; forward them unmodified.
    const requestSha256 = sha256Hex(requestBytes);

    let upstream: Response;
    try {
      upstream = await fetchImpl(`${deps.localModelUrl}/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        // Fresh Uint8Array copy: byte-identical to what was hashed, and
        // satisfies the fetch BodyInit type (Buffer does not).
        body: new Uint8Array(requestBytes),
        signal: AbortSignal.timeout(upstreamTimeoutMs),
      });
    } catch (err) {
      sendJson(res, 502, { error: `local model server unreachable: ${(err as Error).message}` });
      return;
    }
    const upstreamBytes = Buffer.from(await upstream.arrayBuffer());

    if (!upstream.ok) {
      // Error responses are passed through UNSIGNED — there is no completion to prove.
      res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') ?? 'application/json' });
      res.end(upstreamBytes);
      return;
    }

    let parsedResp: unknown;
    try {
      parsedResp = JSON.parse(upstreamBytes.toString('utf8'));
    } catch {
      sendJson(res, 502, { error: 'local model server returned non-JSON completion body; cannot sign' });
      return;
    }
    if (parsedResp === null || typeof parsedResp !== 'object' || Array.isArray(parsedResp)) {
      sendJson(res, 502, { error: 'local model server returned a non-object completion body; cannot sign' });
      return;
    }

    // chat id: pass upstream bytes through untouched when an id exists;
    // otherwise inject one (the rewritten bytes become the signed bytes).
    const upstreamId = (parsedResp as { id?: unknown }).id;
    let chatId: string;
    let responseBytes: Buffer;
    if (typeof upstreamId === 'string' && upstreamId.length > 0) {
      chatId = upstreamId;
      responseBytes = upstreamBytes;
    } else {
      chatId = `edictcmpl-${randomBytes(12).toString('hex')}`;
      responseBytes = Buffer.from(JSON.stringify({ ...(parsedResp as object), id: chatId }), 'utf8');
    }

    const sign = (id: string, bytes: Buffer): SignatureDoc => {
      const responseSha256 = sha256Hex(bytes);
      const envelope = proofEnvelope(modelId, requestSha256, responseSha256);
      const signatureHex = signEnvelopeEth(deps.identity.privateKey, envelope);
      const recovered = recoverEthAddress(signatureHex, ethPersonalMessageDigest(envelope));
      if (recovered === null || recovered.toLowerCase() !== deps.identity.address.toLowerCase()) {
        throw new Error('signature self-check failed; refusing to serve unprovable completion');
      }
      return {
        api_version: API_VERSION,
        chat_id: id,
        model_id: modelId,
        request_sha256: requestSha256,
        response_sha256: responseSha256,
        text: envelope,
        signature: signatureHex,
        signing_address: deps.identity.address,
        signing_algo: 'ecdsa',
        signature_scheme: SIGNING_SCHEME,
        created_at_unix_ms: Date.now(),
      };
    };

    let doc: SignatureDoc;
    try {
      doc = sign(chatId, responseBytes);
    } catch (err) {
      sendJson(res, 500, { error: (err as Error).message });
      return;
    }
    // Persist BEFORE responding — if the write fails the completion is not
    // served, so a served completion always has a fetchable proof.
    try {
      await deps.store.put(doc);
    } catch (err) {
      if (!(err instanceof SignatureConflictError)) {
        sendJson(res, 500, { error: `signature store write failed: ${(err as Error).message}` });
        return;
      }
      // Some deterministic local servers reuse an id for identical requests.
      // Never overwrite the first proof: issue a node-local id, rewrite the
      // response, and sign the exact rewritten bytes instead.
      chatId = `edictcmpl-${randomBytes(12).toString('hex')}`;
      responseBytes = Buffer.from(JSON.stringify({ ...(parsedResp as object), id: chatId }), 'utf8');
      try {
        doc = sign(chatId, responseBytes);
        await deps.store.put(doc);
      } catch (retryErr) {
        sendJson(res, 500, { error: `signature store write failed: ${(retryErr as Error).message}` });
        return;
      }
    }

    res.writeHead(200, {
      'content-type': 'application/json',
      'content-length': responseBytes.length,
      'x-edict-node-mode': deps.mode,
      'x-edict-chat-id': chatId,
    });
    res.end(responseBytes);
  }

  // -- GET /v1/signature/{chat_id} -------------------------------------------

  async function signature(chatId: string, res: ServerResponse): Promise<void> {
    if (chatId.length === 0) {
      sendJson(res, 400, { error: 'missing chat id' });
      return;
    }
    const doc = await deps.store.get(chatId);
    if (doc === undefined) {
      sendJson(res, 404, { error: `no signature stored for chat id "${chatId}"` });
      return;
    }
    sendJson(res, 200, doc);
  }

  // -- GET /v1/attestation/report --------------------------------------------

  async function attestationReport(url: URL, res: ServerResponse): Promise<void> {
    const nonce = url.searchParams.get('nonce') ?? undefined;
    if (nonce !== undefined && !/^[0-9a-fA-F]{1,128}$/.test(nonce)) {
      sendJson(res, 400, { error: 'nonce must be 1..128 hex characters' });
      return;
    }

    const common = {
      provider: 'edict-node',
      api_version: API_VERSION,
      signing_address: deps.identity.address,
      signing_scheme: SIGNING_SCHEME,
      signing_envelope: SIGNING_ENVELOPE_FORMAT,
    };

    if (deps.mode === 'dev') {
      // MOCK — clearly labeled, and deliberately carries NO quote/event_log/
      // report_data fields: a dev node must be impossible to mistake for an
      // attested one, and we never fabricate quote material.
      sendJson(res, 200, {
        ...common,
        dev_mode: true,
        warning:
          'DEV MODE — this node is NOT running in a TEE. This document is a mock attestation ' +
          'for local development only and MUST NOT be trusted or allowlisted for real cases.',
        generated_at_unix_ms: Date.now(),
      });
      return;
    }

    if (deps.dstack === undefined) {
      sendJson(res, 500, { error: 'dstack mode without a guest agent client (misconfiguration)' });
      return;
    }

    // Bind the quote to THIS signing key (and the caller's nonce):
    //   report_data = sha256("edict-node-signing-key-v1:" + signing_address [+ ":" + nonce])
    // Verifiers recompute this and require it to equal the quote's report_data
    // (zero-padded to 64 bytes by the guest agent).
    const preimage = `${REPORT_DATA_CONTEXT}:${deps.identity.address}${nonce !== undefined ? `:${nonce.toLowerCase()}` : ''}`;
    const reportData = sha256Hex(preimage);

    let quote;
    let info: Record<string, unknown> = {};
    try {
      quote = await deps.dstack.getQuote(reportData);
      info = await deps.dstack.info();
    } catch (err) {
      sendJson(res, 502, { error: (err as Error).message });
      return;
    }

    sendJson(res, 200, {
      ...common,
      dev_mode: false,
      report_data: reportData,
      report_data_scheme: `sha256("${REPORT_DATA_CONTEXT}:" + signing_address${nonce !== undefined ? ' + ":" + nonce' : ''})`,
      ...(nonce !== undefined ? { nonce: nonce.toLowerCase() } : {}),
      quote: quote.quote,
      event_log: quote.event_log,
      ...(quote.vm_config !== undefined ? { vm_config: quote.vm_config } : {}),
      key_derivation: deps.identity.keyDerivation ?? null,
      instance: info,
      generated_at_unix_ms: Date.now(),
    });
  }

  // -- GET /v1/models + /healthz ----------------------------------------------

  async function models(res: ServerResponse): Promise<void> {
    try {
      const upstream = await fetchImpl(`${deps.localModelUrl}/models`, {
        signal: AbortSignal.timeout(5000),
      });
      const bytes = Buffer.from(await upstream.arrayBuffer());
      res.writeHead(upstream.status, {
        'content-type': upstream.headers.get('content-type') ?? 'application/json',
      });
      res.end(bytes);
    } catch (err) {
      sendJson(res, 502, { error: `local model server unreachable: ${(err as Error).message}` });
    }
  }

  async function healthz(res: ServerResponse): Promise<void> {
    let upstreamOk = false;
    try {
      const r = await fetchImpl(`${deps.localModelUrl}/models`, { signal: AbortSignal.timeout(1500) });
      upstreamOk = r.ok;
    } catch {
      upstreamOk = false;
    }
    sendJson(res, 200, {
      ok: true,
      api_version: API_VERSION,
      mode: deps.mode,
      dev_mode: deps.mode === 'dev',
      signing_address: deps.identity.address,
      model_upstream: { url: deps.localModelUrl, ok: upstreamOk },
    });
  }
}

// ---------------------------------------------------------------------------

class BodyTooLarge extends Error {}

function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        reject(new BodyTooLarge(`request body exceeds ${limit} bytes`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(`${JSON.stringify(body, null, 2)}\n`, 'utf8');
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': bytes.length });
  res.end(bytes);
}
