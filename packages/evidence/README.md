# @edict/evidence

Canonical hashing, hash-chains, wallet-signable
order-mandate payloads (EIP-712 / NEP-413), delivery manifests, evidence commitments,
and the deterministic machine-check layer that runs *before* any model sees a case.

This package never signs anything and never calls a model. Wallets sign; the arbiter
adjudicates. Everything here is pure, deterministic, and dependency-free
(`node:crypto` only). Types come from `@edict/core` — nothing is redefined.

## Canonical hashing

All object hashes are sha256 (lowercase hex) over **canonical JSON**: keys sorted
lexicographically at every depth, `undefined` properties omitted, no whitespace,
non-finite numbers / non-plain objects rejected. Two semantically identical objects
always hash identically regardless of construction order — a prerequisite for
"same case → same verdict".

```ts
import { canonicalize, sha256Canonical, HashChain, GENESIS_HEAD } from '@edict/evidence';

sha256Canonical({ b: 1, a: 2 }) === sha256Canonical({ a: 2, b: 1 }); // true

// Interaction logs: append-only hash chain; anchor head() on-chain.
const chain = new HashChain();
chain.append(sha256Canonical({ msg: 'hello', at: 1 }));
chain.append(sha256Canonical({ msg: 'result', at: 2 }));
chain.head();                    // the interaction_log_head evidence value
chain.verify(entryHashes);       // replay-verify a disclosed log against the head
```

Chain rule: `newHead = sha256(prevHeadHex + entryHex)` over the UTF-8 bytes of the
two concatenated lowercase hex strings, starting from `GENESIS_HEAD` (64 zeros).

## What exactly is signed (order mandates)

Wallets do **not** sign the raw `OrderMandate` object. They sign a documented
**flattened mapping** (`flattenOrderMandate`), identical on both rails:

| field | EIP-712 type | source |
|---|---|---|
| `version` | `string` | `om.version` |
| `requesterAgentId` | `string` | `om.requester.agentId` |
| `workerAgentId` | `string` | `om.worker.agentId` |
| `description` | `string` | `om.description` |
| `acceptanceCriteriaSha256` | `bytes32` | `0x` + sha256 of canonical JSON of `om.acceptanceCriteria` |
| `priceUsdE6` | `uint256` | `round(om.priceUsd * 1e6)` as a decimal string |
| `currencyAsset` / `currencyRail` | `string` | `om.currency.*` |
| `deadlineUnixMs` / `acceptanceWindowMs` | `uint256` | decimal strings |
| `governingLaw` / `seat` / `rules` / `enforcementTier` | `string` | `om.legalProfile.*` |
| `decisionSpaceSha256` | `bytes32` | `0x` + sha256 of canonical JSON of `om.decisionSpace` |
| `maeEvents` | `string[]` | order preserved |
| `nonce` | `string` | `om.nonce` |

`decisionSpaceSha256` binds `OrderMandate.decisionSpace`, a
`DecisionSpace` from `@edict/core` — `escrow_branches` (the former permitted
rulings), `categorical` (closed label set, e.g. YES/NO/INVALID) or
`bounded_scalar` (numeric quantum in `[min, max]`). The space is flattened to
the sha256 of its **canonical JSON**, so the signature binds every branch,
label and bound byte-for-byte while the signed envelope stays flat: presenting
a different decision space later cannot reproduce the digest.

Deliberately **not** signed: the parties' `principalKybRef` / `erc8004Ref`
(directory metadata that may rotate — the rail-scoped `agentId` is the signing
identity), the acceptance-criteria *text* (bound byte-for-byte via its hash;
a substituted criteria set cannot reproduce `acceptanceCriteriaSha256`), and
the decision-space *object* (bound the same way via `decisionSpaceSha256`).

- **EIP-712** — `buildEip712TypedData(om, chainId?)` returns
  `{ domain: { name: 'EdictOrderMandate', version: '1', chainId? }, types, primaryType: 'OrderMandate', message }`.
  `types` omits `EIP712Domain` (ethers v6 compatibility; viem rebuilds it from `domain`).
- **NEP-413** — `buildNep413Payload(om, recipient, nonce32, callbackUrl?)` returns
  `{ message, recipient, nonce }` where `message` is the **canonical JSON of the same
  flattened mapping** and `nonce` is exactly 32 caller-supplied bytes. The wallet
  performs the NEP-413 tagged-borsh hashing and ed25519 signature.

Separately from signing, `canonicalOrderMandateHash(om)` hashes the **full** mandate
object — that is the value `CaseObject.orderMandateHash` and evidence commitments
reference; check it with `verifyOrderMandateHash(om, expected)`.

```ts
import { buildEip712TypedData, buildNep413Payload, canonicalOrderMandateHash } from '@edict/evidence';

const typed = buildEip712TypedData(om, 8453);        // -> wallet.signTypedData(...)
const nep = buildNep413Payload(om, 'court.edict.near', crypto.getRandomValues(new Uint8Array(32)));
const omHash = canonicalOrderMandateHash(om);        // goes into the CaseObject
```

## Delivery manifests & evidence commitments

`DeliveryManifest` is **local to this package** (core only ever sees its hash):
`{ artifactHashes: {path, sha256, mediaType}[], formatClaims, workerAgentId, orderMandateHash, deliveredAtUnixMs }`.

```ts
import { canonicalDeliveryManifestHash, buildEvidenceCommitment } from '@edict/evidence';

const dmHash = canonicalDeliveryManifestHash(manifest);      // -> CaseObject.deliveryManifestHash
const commitment = buildEvidenceCommitment('delivery_manifest', manifest, 'worker', 'vault://case-42/dm');
// Uint8Array input -> hash of raw bytes; anything else -> hash of canonical JSON.
// commitment.authenticated is ALWAYS false here: a commitment pins content; it
// becomes authenticated only after signature/zkTLS/attestation verification upstream.
```

## Machine Checks

`runMachineChecks(om, manifest, artifacts?)` evaluates every
`AcceptanceCriterion.machineCheck` with three possible statuses:
**pass** / **fail** (deterministically decided) or **skipped** (cannot be decided
here: no machineCheck, `custom` kind, malformed params, or missing artifact bytes —
skipped criteria go to the jury).

| kind | params | behaviour |
|---|---|---|
| `hash_equals` | `{ path, sha256 }` | manifest must list `path` with that hash; if bytes are supplied they are re-hashed too |
| `schema_valid` | `{ path, schema }` | parse artifact bytes as JSON; minimal structural schema (`type`, `required`, `properties`, `items`, `enum`, `const`) |
| `deadline_before` | `{ deadlineUnixMs? }` | `deliveredAtUnixMs <= deadline` (defaults to the mandate deadline) |
| `contains` | `{ needle, path? }` | needle in UTF-8 artifact bytes; without `path`, in some `formatClaims` entry |
| `custom` | anything | always skipped — arbiter territory |

The report also carries `mandateBound`
(`manifest.orderMandateHash === canonicalOrderMandateHash(om)`) and
`allDeterministicPassed` (bound **and** zero failures; skips don't count as passes).

```ts
const report = runMachineChecks(om, manifest, new Map([['report.json', bytes]]));
if (!report.mandateBound) /* manifest answers a different mandate */;
report.results; // [{ criterionId, kind, status, detail }, ...]
```

## Burden defaults — why they are what they are

- **Receipt ≠ acceptance.** A `delivery_receipt` proves the requester *received*
  bytes, nothing more; a `delivery_manifest` is the worker's *claim* of what was
  delivered. Neither alone establishes conformance — that's what acceptance
  criteria, machine checks, and (failing those) the jury are for. This is why the
  manifest hash and receipt are separate evidence kinds in core, and why
  `buildEvidenceCommitment` never marks anything `authenticated`.
- **Ambiguity against the drafter (contra proferentem).** The requester drafts the
  acceptance criteria. A criterion so malformed it cannot be evaluated
  deterministically is `skipped` — surfaced to the jury with the ambiguity noted —
  never silently `fail`ed against the worker. Only genuine, byte-provable
  mismatches produce `fail`. Conversely `allDeterministicPassed` never treats a
  skip as a pass, so the worker can't launder unverifiable claims either.
- **Missing evidence is neutral here.** If artifact bytes aren't supplied, checks
  that need them are `skipped`, not failed: whether non-production of evidence
  should draw an adverse inference is a tier- and rules-dependent question for the
  arbiter (edict-drr), not for a hashing library.

## Build & test

```sh
npm run build -w @edict/evidence
npm run test -w @edict/evidence   # node --test "dist/**/*.test.js"
```
