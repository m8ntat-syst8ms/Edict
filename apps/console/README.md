# @edict/console

Local development console for Edict protection policies and sandbox disputes.

The console provides:

- immutable, hash-addressed `ProtectionProfile` storage;
- live `OrderMandate` linting;
- illustrative public-case and local verdict inspection;
- end-to-end SDK sandbox disputes; and
- a human-review queue for profiles that elect escalation.

It is a local developer tool, not the customer-facing Edict Protect
workspace. It serves one same-origin HTML application through `node:http` and
uses no third-party frontend runtime.

## Run

```sh
npm run build -w @edict/console
node apps/console/dist/cli.js --port 4870
```

Options:

- `--port` / `-p`: loopback port, default `4870`;
- `--data-dir`: profile and sandbox archive directory, default
  `~/.edict-console`; and
- `--docket-dir`: shadow-docket root, default `apps/shadow-docket`.

## Views

### Policies

Create and version Protection Profiles, configure Decision Spaces and review
policy, and lint a representative mandate before saving. A saved
`name@version` is immutable; changed content requires a new version.

### Cases

Browse the committed illustrative examples and locally generated verdicts.
The bundled examples are not production qualification evidence.
Reasoning and instruction frames appear when a docket report has been
generated.

### Sandbox

Run a docket case or mandate draft through the real SDK and arbiter pipeline
with deterministic mock providers and simulated balances. No real asset or
external model call is used.

## HTTP API

| Route | Purpose |
|---|---|
| `GET /healthz` | Liveness and configured paths |
| `GET /api/profiles` | List saved profile versions |
| `POST /api/profiles` | Validate and save an immutable profile version |
| `GET /api/profiles/:name/:version` | Read one profile version |
| `POST /api/lint` | Complete and lint a mandate draft |
| `GET /api/cases` | List docket cases and available reports |
| `GET /api/cases/:id` | Read case, verdict, reasoning, and instructions |
| `POST /api/sandbox/run` | Run a sandbox dispute |
| `GET /api/sandbox/reviews` | List cases held for human review |
| `POST /api/sandbox/review` | Resolve a held sandbox case |

## Development

```sh
npm test -w @edict/console
```

The test suite runs the server on ephemeral ports and covers profile
immutability, linting, docket containment, sandbox settlement, review routing,
and same-origin static assets.
