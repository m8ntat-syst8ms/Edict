# @edict/sdk

Customer integration SDK for Edict Protect.

The default profile is wallet-native E0: no Edict account, KYB workflow, or
enterprise legal setup is required. The SDK builds and verifies signed
protection data; it does not receive payment credentials or move real funds.

## Quick Start

[`examples/quickstart.ts`](examples/quickstart.ts) is executable and limited by
test to seven non-comment lines:

```ts
import { createEdict, isFinalVerdict } from '@edict/sdk';
const edict = createEdict({ mode: 'sandbox' });
edict.escrow.deposit('agent:alice', 1_000);
const order = await edict.protectPayment({ requester: 'agent:alice', worker: 'agent:bob', promise: 'Produce guide.de.md.', amountUsd: 500, deadlineUnixMs: Date.now() + 86_400_000, acceptanceCriteria: [{ id: 'AC-1', statement: 'guide.de.md matches the pinned checksum.', machineCheck: { kind: 'hash_equals', params: { path: 'guide.de.md', sha256: 'a'.repeat(64) } } }] });
await edict.deliver(order, { artifactHashes: [{ path: 'draft.de.md', sha256: 'b'.repeat(64), mediaType: 'text/markdown' }] });
const verdict = await edict.dispute(order, { submissions: { requester: 'guide.de.md is missing.' } });
if (isFinalVerdict(verdict)) console.log(verdict.ruling, edict.settle(verdict).settlement);
```

The quick start is an in-memory simulation. It uses the real mandate,
evidence, linter, arbiter, review, directive, and settlement-economics code,
but no real asset or external model.

## Core API

| API | Purpose |
|---|---|
| `createEdict(options)` | Create a sandbox or live-mode client with one committed profile and settlement binding |
| `protectPayment(input)` | Build, lint, hash, and register the signed payment mandate |
| `protect(input)` | Advanced mandate builder with explicit criteria and policy overrides |
| `deliver(ref, delivery)` | Build and commit a canonical delivery manifest |
| `accept(ref)` | Accept a delivery; applies simulated settlement only in sandbox mode |
| `dispute(ref, input)` | Assemble and adjudicate a sandbox case |
| `prepareSettlement(verdict)` | Revalidate a final verdict and return a pure `SettlementDirective` |
| `verifySettlementDirective(...)` | Rebuild and verify a directive inside the customer trust boundary |
| `appeal(ref, by)` | Invoke a profile-elected sandbox appeal path |
| `resolveHumanReview(ref, result)` | Create a new final verdict for a held sandbox case |
| `onVerdict(handler)` | Subscribe to in-process sandbox verdict events |
| `onEscalation(handler)` | Subscribe to in-process sandbox review events |

`settle()` is intentionally sandbox-only. Live settlement belongs to the
customer-controlled rail or contract after local directive verification.

## Protection Profiles

A `ProtectionProfile` commits:

- Decision Space and acceptance defaults;
- wallet-native, rail-verified, or enterprise assurance mode;
- lint score and error gates;
- model seats, operator diversity, proof requirements, and signer allowlists;
- human-review and appeal policy; and
- optional customer policy terms.

The canonical profile hash is attached to every case. Changing any policy
field creates a different profile identity.

Three presets are included:

| Preset | Intended use | Human review |
|---|---|---|
| Basic | Small, objective tasks | Off |
| Standard | Typical agent payments | Off; uncertain results remain unexecuted |
| High Assurance | Higher-value or sensitive work | Optional appeal, quality-gate routing, and mandatory review above the configured threshold |

The explicit `enterpriseLegalProfile()` requires principal and delegated
authority evidence. It is experimental and must not be used externally
without customer-specific legal review.

## Human Review Invariant

An escalated or uncertain verdict is never executable. Review policy decides
where the case goes next; it cannot convert the held AI output into a payable
ruling.

A human reviewer must create a new verdict whose ruling remains inside the
original Decision Space. The original model votes, proof flags, and review
basis stay in the audit record.

## Settlement Boundary

Every v2 mandate signs that Edict:

- cannot transfer or freeze the protected amount;
- is not a required settlement signer; and
- cannot change the beneficiary or expand the Decision Space.

`prepareSettlement()` rechecks finality, review holds, the recorded case and
verdict, custody mode, rail identity, payout arithmetic, and replay fields
before returning data to the customer executor.

Supported production-conforming bindings are:

- `M2_external_escrow`: a customer or rail-approved settlement contract; and
- `M4_no_custody`: decision data used by an external customer process.

## NEAR and NEAR Intents

The SDK exposes helpers for:

- customer-approved native-NEAR contract bindings;
- release-manifest verification;
- exact-output NEAR Intents funding quotes;
- signed quote and terminal-status verification;
- authenticated principal, Bond, delivery, and acceptance actions;
- fixed-beneficiary claim withdrawal quotes; and
- fail-closed Confidential Intents capability bindings.

The native NEAR path is deployed on NEAR Testnet. The Intents contracts pass a
local real-Wasm sandbox against the pinned mainnet Verifier but are not
deployed. Both remain blocked from production value pending independent audit
and mainnet canaries.

## Sandbox Economics

- The default opening Bond is 5% of principal.
- Split outcomes allocate principal and Bond pro rata.
- The forfeited Bond remainder is divided between the counterparty and the
  configured removal destination.
- `redo` holds principal and the original Bond through one second round.
- Acceptance, timeout, or the second-round ruling allocates the held value.
- Every round remains in the append-only lifecycle record.

The Rust contracts and TypeScript SDK share fixed cross-language economics
vectors.

## Development

```sh
npm run build -w @edict/sdk
npm test -w @edict/sdk
```

See the [Protection Runtime](../../services/protection-runtime/README.md) for
the live coordination path and the
[self-custody architecture](../../docs/self-custody-architecture.md) for the
settlement boundary.
