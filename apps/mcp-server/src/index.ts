/**
 * MCP tools for Edict mandates, sandbox disputes, and case inspection.
 *
 * A minimal hand-rolled MCP stdio server (JSON-RPC 2.0, newline-delimited;
 * targets MCP protocol version 2025-06-18; zero runtime deps beyond the
 * Edict workspaces + node builtins) exposing six tools:
 * draft/lint mandates, sandbox disputes through the real arbiter, and
 * precedent/status/explanation over the shadow docket.
 */

export {
  McpStdioServer,
  MCP_PROTOCOL_VERSION,
  SERVER_NAME,
  SERVER_VERSION,
  type JsonRpcId,
  type JsonRpcMessage,
  type McpStdioServerOptions,
  type ToolCallResult,
  type ToolDefinition,
  type ToolRegistry,
} from './protocol.js';

export { TOOL_DEFINITIONS, createEdictTools, type EdictToolsOptions } from './tools.js';

export {
  DocketStore,
  resolveDocketRoot,
  tokenize,
  type DocketCase,
  type Groundtruth,
  type PrecedentHit,
  type ReportResult,
} from './docket.js';

export { tribunalInstructionsFor, compactReasoning, type TribunalInstructions } from './explain.js';
export { draftMandate, lintMandateTool, sandboxDispute, normalizeCriteria, type DraftMandateResult, type SandboxDisputeResult } from './mandateTools.js';
export { caseStatus, explainRuling, queryPrecedent } from './docketTools.js';
export { ToolInputError } from './errors.js';
export type { SessionCase, SessionStore } from './session.js';
