# @edict/mcp-server

Model Context Protocol tools for Edict mandate preparation, linting, sandbox
resolution, and case inspection.

The server uses stdio JSON-RPC and runs locally. It does not connect to a
payment rail or move real assets.

## Tools

| Tool | Purpose |
|---|---|
| `edict_draft_mandate` | Build and hash a complete mandate, then return its lint report |
| `edict_lint_mandate` | Analyze an existing mandate |
| `edict_sandbox_dispute` | Run a dispute through the SDK and arbiter sandbox |
| `edict_resolve_review` | Resolve a sandbox case held for human review |
| `edict_query_precedent` | Search the illustrative local docket |
| `edict_case_status` | Read local docket or session case status |
| `edict_explain_ruling` | Return archived reasoning and instruction frames |

## Run

```sh
npm ci
npm run build
node apps/mcp-server/dist/cli.js
```

Example MCP configuration:

```json
{
  "mcpServers": {
    "edict": {
      "command": "node",
      "args": ["/absolute/path/to/edict/apps/mcp-server/dist/cli.js"],
      "env": {
        "EDICT_DOCKET_DIR": "/absolute/path/to/edict/apps/shadow-docket"
      }
    }
  }
}
```

`EDICT_DOCKET_DIR` is optional when the server runs from this monorepo.

## Protocol

- Transport: newline-delimited MCP JSON-RPC 2.0 over stdio.
- Target protocol version: `2025-06-18`.
- Advertised capability: tools.
- Supported methods: `initialize`, `notifications/initialized`, `tools/list`,
  `tools/call`, and `ping`.
- Diagnostics are written to stderr; malformed input does not terminate the
  server.

## Sandbox Boundary

Sandbox disputes use deterministic mock model seats, placeholder parties, and
an in-memory ledger seeded with test balances. Mandate hashing, linting,
machine checks, verdict aggregation, review routing, settlement directives,
and payout arithmetic use the same library code as the rest of the
repository.

## Development

```sh
npm test -w @edict/mcp-server
```
