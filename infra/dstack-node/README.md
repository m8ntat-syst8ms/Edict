# Edict Attested Inference Node

Self-hosted OpenAI-compatible inference proxy packaged for a dstack Intel TDX
confidential VM.

The node captures exact request and response bytes, signs their hashes with a
TEE-derived key, persists the proof before returning the completion, and
exposes a nonce-bound attestation report. It provides an independently
operated seat for the Edict arbiter.

```text
arbiter
  -> edict-node signing proxy
       -> local OpenAI-compatible model server
       -> dstack guest agent (GetKey, GetQuote, Info)
       -> persistent signature store
```

## Endpoints

| Endpoint | Behavior |
|---|---|
| `POST /v1/chat/completions` | Proxy a non-streaming completion, capture exact bytes, sign `modelId:requestSha256:responseSha256`, and persist the proof |
| `GET /v1/signature/:chatId` | Return the immutable signature document for a completion |
| `GET /v1/attestation/report?nonce=...` | Return a TDX quote binding the signing address and optional nonce |
| `GET /v1/models` | Proxy the local model catalog |
| `GET /healthz` | Report mode, signer address, and upstream reachability |

Streaming is rejected because the proof commits to one complete response
body. If the upstream omits a completion identifier, the proxy inserts one
before hashing and returns exactly the rewritten bytes it signed.

## Modes

`EDICT_NODE_MODE` is mandatory:

- `dstack`: derive the signing key through the dstack guest agent and return a
  real TDX quote;
- `dev`: use a local persisted key and return an explicit mock-attestation
  object with `dev_mode: true`.

The arbiter rejects dev attestations when proof enforcement is enabled.

Production `dstack` mode also requires:

- a pinned `EDICT_NODE_MODEL_ID`;
- an `EDICT_NODE_API_KEY` of at least 32 characters;
- a persistent data volume; and
- a reviewed image digest and compose measurement.

## Local Verification

The verification script starts a stub model server and a development-mode
node, then verifies positive, tampered-hash, and signer-allowlist cases through
the arbiter's real proof verifier.

```sh
npm ci
npm run build -w @edict/arbiter -w @edict/dstack-node
npm test -w @edict/dstack-node
node infra/dstack-node/scripts/dev-verify.mjs
```

Run the node against a local OpenAI-compatible model server:

```sh
cd infra/dstack-node/app
npm run build

EDICT_NODE_MODE=dev \
LOCAL_MODEL_URL=http://127.0.0.1:8000/v1 \
EDICT_NODE_DATA_DIR=./data \
node dist/main.js
```

## Arbiter Configuration

```sh
export EDICT_NODE_BASE_URL=https://node.example/v1
export EDICT_NODE_API_KEY='<bearer token>'
export EDICT_SIGNER_ALLOWLIST_EDICT_NODE='0x<approved signing address>'
```

The provider verifies the signature document, byte hashes, signer allowlist,
and nonce-bound report-data relationship. Production admission must also
verify the TDX quote, dstack signature chain, app identity, compose hash, image
digests, and security policy.

## dstack Deployment

[`docker-compose.yml`](docker-compose.yml) defines the measured application:
a private llama.cpp model service and the Edict signing proxy. Before
deployment:

1. build and test the node image;
2. pin both container images by immutable digest;
3. review the model license and artifact hash;
4. inject `EDICT_NODE_API_KEY` through the platform's encrypted secret
   channel;
5. keep the raw model port private;
6. mount the dstack guest-agent socket and persistent signature volume;
7. record the expected compose hash and signing address; and
8. verify a fresh nonce-bound quote from outside the VM.

Do not approve the signer in an arbiter roster until these checks pass.

## Operations

- Back up the append-only signature store and test restoration.
- Monitor upstream reachability, proof persistence, disk use, and quote
  verification.
- Rotate API credentials without changing the TEE-derived signing identity.
- Treat a model, image, compose, key-path, or key-purpose change as a new
  measured deployment requiring re-approval.
- Never expose the unsigned model endpoint to clients.

This package provides proof-generation infrastructure. It does not by itself
establish operator independence, model quality, or production security.
