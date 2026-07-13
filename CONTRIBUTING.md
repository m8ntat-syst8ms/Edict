# Contributing

Edict is currently a testnet engineering release. Contributions should be
small, reviewable, and accompanied by tests appropriate to their risk.

## Pull Requests

1. Create a focused branch and open a pull request against `main`.
2. Explain the behavior changed and any security or settlement implications.
3. Run `npm ci`, `npm run check`, and the relevant sandbox tests.
4. Wait for CI and one approving review before merge.

Do not commit credentials, private keys, customer data, production rosters,
operational signer policies, unreleased holdouts, provider qualification
results, or detailed adversarial corpora. Run `npm run check:public-boundary`
before pushing.

Public fixture changes require an update to
`apps/shadow-docket/PUBLIC_FIXTURES.json`. Once a fixture is published, it is
permanently ineligible for private qualification.

Report suspected vulnerabilities through the process in `SECURITY.md`, not a
public issue.
