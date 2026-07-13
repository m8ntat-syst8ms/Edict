/**
 * Tiny deterministic OpenAI-compatible "LLM" stub — a node:http echo server
 * for dev-mode verification and tests. NO model download required.
 *
 * POST /v1/chat/completions → a chat.completion object whose content echoes
 * the last user message and whose id is derived from the request hash
 * (deterministic). `omitId: true` exercises the node's id-injection path.
 */
import { createServer, type Server } from 'node:http';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';

export interface StubLlmOptions {
  port?: number;
  host?: string;
  /** Omit the `id` field from completions (tests the proxy's id injection). */
  omitId?: boolean;
  modelId?: string;
}

export interface StubLlm {
  server: Server;
  port: number;
  url: string; // base .../v1
  close(): Promise<void>;
}

export async function startStubLlm(opts: StubLlmOptions = {}): Promise<StubLlm> {
  const modelId = opts.modelId ?? 'stub-model';
  const server = createServer((req, res) => {
    const send = (status: number, body: unknown): void => {
      const bytes = Buffer.from(JSON.stringify(body), 'utf8');
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': bytes.length });
      res.end(bytes);
    };

    if (req.method === 'GET' && req.url === '/v1/models') {
      send(200, { object: 'list', data: [{ id: modelId, object: 'model' }] });
      return;
    }
    if (req.method === 'POST' && req.url === '/v1/chat/completions') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const raw = Buffer.concat(chunks);
        let parsed: Record<string, unknown> = {};
        try {
          parsed = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
        } catch {
          send(400, { error: { message: 'invalid json' } });
          return;
        }
        const messages = Array.isArray(parsed.messages) ? (parsed.messages as Array<Record<string, unknown>>) : [];
        const lastUser = [...messages].reverse().find((m) => m.role === 'user');
        const echo = typeof lastUser?.content === 'string' ? lastUser.content : '';
        const completion: Record<string, unknown> = {
          ...(opts.omitId === true
            ? {}
            : { id: `stubcmpl-${createHash('sha256').update(raw).digest('hex').slice(0, 24)}` }),
          object: 'chat.completion',
          created: 1_700_000_000,
          model: typeof parsed.model === 'string' ? parsed.model : modelId,
          choices: [
            {
              index: 0,
              message: { role: 'assistant', content: `STUB ECHO: ${echo.slice(0, 400)}` },
              finish_reason: 'stop',
            },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
        };
        send(200, completion);
      });
      return;
    }
    send(404, { error: { message: `no route: ${req.method} ${req.url}` } });
  });

  await new Promise<void>((resolve) => server.listen(opts.port ?? 0, opts.host ?? '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    port,
    url: `http://127.0.0.1:${port}/v1`,
    close: () => new Promise((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}
