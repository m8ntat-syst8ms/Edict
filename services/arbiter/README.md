# @edict/arbiter

Deterministic and multi-provider adjudication for Edict cases.

```text
CaseObject + committed evidence
  -> schema and evidence-integrity validation
  -> prompt-injection screening
  -> deterministic machine checks
  -> dual-orientation model jury when judgment is required
  -> proof, operator-diversity, consistency, and confidence gates
  -> final or safely held VerdictObject
```

The arbiter can return only an outcome inside the case's pre-committed
Decision Space:

- `escrow_branches`: requester, worker, split, or redo branches;
- `categorical`: one label from a closed outcome set; and
- `bounded_scalar`: a value inside a committed numeric range.

An uncertain or invalid result is never made executable. It is returned with
`final: false`, `quality.escalated: true`, and a recorded reason for the hold.

## API

```ts
import { adjudicate, type ArbiterConfig } from '@edict/arbiter';

const verdict = await adjudicate(caseObject, evidencePlaintext, {
  seats,
  providers,
  archiveDir: './arbiter-archive',
  requireProofs: true,
  proofPolicy,
} satisfies ArbiterConfig);
```

`evidencePlaintext` maps each evidence SHA-256 commitment to the corresponding
plaintext. Missing entries remain sealed in the normalized evidence frame.

## Deterministic Layer

Machine-checkable non-delivery, manifest integrity, deadline, schema, content,
and exact-hash conditions run before model inference. A substituted order
mandate is fatal and produces no verdict. A mismatched delivery manifest is
recorded as evidence of a forged delivery claim.

For bounded-scalar claims, criteria may commit `payableUsd` components. A
component with an authenticated exact-hash proof can be included
deterministically; unresolved components remain for the jury.

## Jury Rules

Every seat evaluates both party orientations. The second pass reverses party
position while preserving facts and instructions. Aggregation checks:

- outcome parsing and Decision Space membership;
- model-family disjointness;
- at least two infrastructure providers for Tiers A and B;
- at least three providers with no provider majority for Tier C;
- proof validity and configured signer allowlists;
- majority or scalar spread;
- swap consistency; and
- confidence thresholds.

Hosted providers are pinned by exact model identifier and called with
deterministic settings where supported. Serving-stack nondeterminism is
measured through replay and dual-orientation results rather than assumed away.

## Proof Verification

When `requireProofs` is enabled, a proof must bind the exact model, request
hash, response hash, signer, attestation reference, and freshness window.
Supported signature schemes are:

| Scheme | Verification |
|---|---|
| `ecdsa_secp256k1_eth` | Recover signer from an Ethereum personal-message signature over `modelId:requestSha256:responseSha256` |
| `ecdsa_secp256k1_eth_bodyhashes` | Recover signer over `requestSha256:responseSha256` when the model is bound in the request bytes |
| `ed25519` | Verify the raw UTF-8 envelope with the supplied public key |
| `ecdsa_p256` | Verify the raw UTF-8 envelope with the supplied P-256 key |
| `none_mock` | Accepted only when proof enforcement is disabled |

Recovered signers must match the configured provider allowlist. A failed proof
excludes the seat; loss of quorum safely holds the case.

## Providers

The repository includes adapters for:

- NEAR AI Cloud;
- Phala/RedPill confidential inference;
- self-hosted Edict dstack nodes;
- generic OpenAI-compatible endpoints;
- Anthropic for non-executable benchmark runs; and
- deterministic offline mock providers.

Provider credentials and signer allowlists are configured through
[`services/arbiter/.env.example`](.env.example). Never treat a recovered
signature as trusted without a reviewed signer allowlist and attestation
policy.

## Offline Run

```sh
npm run build -w @edict/arbiter
npm test -w @edict/arbiter

node services/arbiter/dist/cli.js adjudicate \
  --case services/arbiter/examples/case.json \
  --evidence services/arbiter/examples/evidence \
  --seats services/arbiter/seats.example.json \
  --out verdict.json \
  --archive ./arbiter-archive
```

Without provider credentials, the CLI substitutes deterministic mock
providers so the full pipeline remains reproducible offline.

## Archive

Each run records byte-exact provider requests and responses, provider proofs,
per-orientation seat output, normalized reasoning, and the final verdict under
the configured archive directory. The reasoning document is content-hashed
into `verdict.reasoningSha256`.

Archives may contain sensitive evidence or provider material. Production
deployments must encrypt them, enforce tenant isolation, and apply an explicit
retention policy.
