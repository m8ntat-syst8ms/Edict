#!/usr/bin/env node
/**
 * `edict-mcp` - Edict tools over MCP stdio.
 *
 * Newline-delimited JSON-RPC 2.0 over stdin/stdout; diagnostics on stderr
 * only (stdout is reserved for the protocol). Exits 0 when the client closes
 * stdin.
 */

import { McpStdioServer } from './protocol.js';
import { createEdictTools } from './tools.js';

const server = new McpStdioServer({
  input: process.stdin,
  output: process.stdout,
  tools: createEdictTools(),
  onClose: () => process.exit(0),
});
server.start();
