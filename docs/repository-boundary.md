# Public Repository Boundary

This repository contains the code and public artifacts needed to inspect,
integrate, reproduce, and verify Edict's testnet architecture. Public source
does not include the material used to qualify a production adjudication or
signing deployment.

## Public

- contracts, deployment tooling, SDKs, connector interfaces, and schemas;
- deterministic checks, proof verification, and verdict aggregation;
- legal rules and customer policy-pack formats;
- testnet manifests and reproducible test infrastructure; and
- a small synthetic docket for documentation and harness regression.

The committed docket is illustrative. Its expected outcomes are public and
must not be used as evidence that a model, provider, or operator is qualified
for production.

## Private

- unreleased holdout cases and expected outcomes;
- detailed adversarial and anti-manipulation corpora;
- model and provider qualification results;
- production jury rosters and arbiter configuration;
- customer-specific policy and connector configuration; and
- operational signer thresholds, key policy, and incident procedures.

Credentials and private keys do not belong in either repository. Production
secret material must remain in the approved secret manager or TEE key path.

## Enforcement

`npm run check:public-boundary` compares the committed public fixtures with
`apps/shadow-docket/PUBLIC_FIXTURES.json` and rejects tracked private paths,
credentials, production rosters, signing policies, or adversarial fixtures.
CI runs this check on every pull request.

Any fixture disclosed publicly is permanently retired from holdout use. A
fresh, independently reviewed private case must replace it before the next
production qualification run.
