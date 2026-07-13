# Security Policy

## Supported Release

| Release | Security status |
|---|---|
| `v0.1.0-testnet` | Testnet evaluation only; unaudited |

No contract in this repository should be used with production value until the
exact release artifacts have completed the gates in
[`docs/production-readiness.md`](docs/production-readiness.md).

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability. Submit a private
[GitHub security advisory](https://github.com/m8ntat-syst8ms/Edict/security/advisories/new)
and include:

- the affected commit, package, contract, or deployment hash;
- the impact and assumptions required to reproduce it;
- minimal reproduction steps or a proof of concept; and
- whether customer keys, funds, evidence, or signer integrity may be affected.

Please allow the maintainers a reasonable opportunity to investigate and
remediate the issue before public disclosure.

## Priority Areas

High-priority reports include:

- unauthorized settlement or custody capability;
- signature, nonce, or proof replay;
- verifier-policy or decision-space bypass;
- evidence disclosure or cross-protection data access;
- hidden owner, upgrade, freeze, or administrative authority;
- settlement to a beneficiary other than the fixed signed party; and
- divergence between signed terms, observed state, and executed settlement.

Testnet accounts and test-only credentials are not production systems, but a
vulnerability that can propagate into a release artifact remains in scope.
