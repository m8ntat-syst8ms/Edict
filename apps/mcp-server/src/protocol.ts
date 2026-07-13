/**
 * Minimal hand-rolled MCP stdio server — JSON-RPC 2.0 over stdin/stdout with
 * MCP stdio framing (one JSON message per line, newline-delimited).
 *
 * Protocol version targeted: MCP `2025-06-18` (the server echoes whatever
 * version string the client requests at `initialize`, per the minimal
 * handshake this repo needs; `2025-06-18` is what the tool surface was built
 * and tested against). Deliberately NO dependency on
 * `@modelcontextprotocol/sdk` (zero new runtime deps — node builtins only);
 * swapping this module for the official SDK transport is the known upgrade
 * path if client framing/handshake expectations drift.
 *
 * Handled methods:
 * - `initialize`                → protocolVersion echo + serverInfo + { tools: {} }
 * - `notifications/initialized` → ignored (notification)
 * - `tools/list`                → the registered tool definitions
 * - `tools/call`                → dispatch to a registered tool handler
 * - `ping`                      → `{}`
 * - anything else with an id    → JSON-RPC -32601 method-not-found
 * - malformed lines             → logged to stderr; the server keeps serving
 */

import type { Readable, Writable } from 'node:stream';

export const MCP_PROTOCOL_VERSION = '2025-06-18';
export const SERVER_NAME = 'edict';
/** Keep in sync with package.json (hardcoded so the server never reads its own manifest at runtime). */
export const SERVER_VERSION = '0.0.1';

// ---------------------------------------------------------------------------
// JSON-RPC shapes
// ---------------------------------------------------------------------------

export type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: JsonRpcId;
  method?: unknown;
  params?: unknown;
}

/** JSON-RPC 2.0 error codes used by this server. */
export const JSONRPC_METHOD_NOT_FOUND = -32601;
export const JSONRPC_INVALID_PARAMS = -32602;
export const JSONRPC_INVALID_REQUEST = -32600;
export const JSONRPC_INTERNAL_ERROR = -32603;

// ---------------------------------------------------------------------------
// Tool plumbing contracts (implemented in tools.ts)
// ---------------------------------------------------------------------------

/** MCP tool definition as served by `tools/list`. */
export interface ToolDefinition {
  name: string;
  description: string;
  /** JSON Schema (draft-07 subset) for the tool's arguments object. */
  inputSchema: Record<string, unknown>;
}

/** MCP `tools/call` result: content blocks (+ isError for tool-level failures). */
export interface ToolCallResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface ToolRegistry {
  list(): ToolDefinition[];
  /** Returns undefined for unknown tool names (mapped to -32602 by the server). */
  call(name: string, args: Record<string, unknown>): Promise<ToolCallResult> | undefined;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export interface McpStdioServerOptions {
  input: Readable;
  output: Writable;
  tools: ToolRegistry;
  /** Where malformed-line / internal diagnostics go. Default: process.stderr writes. */
  logError?: (message: string) => void;
  /** Invoked once stdin has ended AND every in-flight request has settled. */
  onClose?: () => void;
}

export class McpStdioServer {
  private readonly input: Readable;
  private readonly output: Writable;
  private readonly tools: ToolRegistry;
  private readonly logError: (message: string) => void;
  private readonly onClose: (() => void) | undefined;

  private buffer = '';
  /** Serialises message handling so responses come out in request order. */
  private queue: Promise<void> = Promise.resolve();

  constructor(opts: McpStdioServerOptions) {
    this.input = opts.input;
    this.output = opts.output;
    this.tools = opts.tools;
    this.logError = opts.logError ?? ((m) => process.stderr.write(`${m}\n`));
    this.onClose = opts.onClose;
  }

  /** Attach the stdin listeners and start serving. */
  start(): void {
    this.input.setEncoding('utf8');
    this.input.on('data', (chunk: string) => this.onData(chunk));
    this.input.on('end', () => {
      if (this.buffer.trim().length > 0) this.enqueueLine(this.buffer);
      this.buffer = '';
      // Drain in-flight work, then let the host shut down cleanly.
      void this.queue.then(() => this.onClose?.());
    });
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, nl);
      this.buffer = this.buffer.slice(nl + 1);
      if (line.trim().length > 0) this.enqueueLine(line);
    }
  }

  private enqueueLine(line: string): void {
    this.queue = this.queue
      .then(() => this.handleLine(line))
      .catch((err) => this.logError(`edict-mcp: internal error handling a message: ${String(err)}`));
  }

  private async handleLine(line: string): Promise<void> {
    let msg: JsonRpcMessage;
    try {
      const parsed: unknown = JSON.parse(line);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        this.logError(`edict-mcp: ignoring non-object JSON-RPC message: ${line.slice(0, 120)}`);
        return;
      }
      msg = parsed as JsonRpcMessage;
    } catch {
      // Malformed line: log to stderr, keep serving (never crash the transport).
      this.logError(`edict-mcp: ignoring malformed JSON line: ${line.slice(0, 120)}`);
      return;
    }

    const method = typeof msg.method === 'string' ? msg.method : undefined;
    const hasId = 'id' in msg && msg.id !== undefined;

    if (method === undefined) {
      if (hasId) this.sendError(msg.id ?? null, JSONRPC_INVALID_REQUEST, 'missing method');
      else this.logError('edict-mcp: ignoring message without a method');
      return;
    }

    // Notifications (no id) never receive a response.
    if (!hasId) {
      // notifications/initialized (and any other notification) is deliberately ignored.
      return;
    }
    const id = msg.id ?? null;
    const params =
      typeof msg.params === 'object' && msg.params !== null && !Array.isArray(msg.params)
        ? (msg.params as Record<string, unknown>)
        : {};

    switch (method) {
      case 'initialize': {
        const requested = params['protocolVersion'];
        this.sendResult(id, {
          protocolVersion: typeof requested === 'string' && requested.length > 0 ? requested : MCP_PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        });
        return;
      }
      case 'ping': {
        this.sendResult(id, {});
        return;
      }
      case 'tools/list': {
        this.sendResult(id, { tools: this.tools.list() });
        return;
      }
      case 'tools/call': {
        const name = params['name'];
        if (typeof name !== 'string' || name.length === 0) {
          this.sendError(id, JSONRPC_INVALID_PARAMS, 'tools/call requires params.name (string)');
          return;
        }
        const rawArgs = params['arguments'];
        const args =
          typeof rawArgs === 'object' && rawArgs !== null && !Array.isArray(rawArgs)
            ? (rawArgs as Record<string, unknown>)
            : {};
        const pending = this.tools.call(name, args);
        if (pending === undefined) {
          this.sendError(id, JSONRPC_INVALID_PARAMS, `unknown tool: ${name}`);
          return;
        }
        try {
          this.sendResult(id, await pending);
        } catch (err) {
          // Defensive: the registry already converts handler failures into
          // isError results; anything reaching here is a server bug.
          this.sendError(id, JSONRPC_INTERNAL_ERROR, `tool ${name} crashed: ${String(err)}`);
        }
        return;
      }
      default:
        this.sendError(id, JSONRPC_METHOD_NOT_FOUND, `method not found: ${method}`);
    }
  }

  private sendResult(id: JsonRpcId, result: unknown): void {
    this.send({ jsonrpc: '2.0', id, result });
  }

  private sendError(id: JsonRpcId, code: number, message: string): void {
    this.send({ jsonrpc: '2.0', id, error: { code, message } });
  }

  private send(obj: unknown): void {
    this.output.write(`${JSON.stringify(obj)}\n`);
  }
}
