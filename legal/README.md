# Testnet Rules

This directory contains the rules document referenced by the Edict testnet
profiles:

- [`edict-dispute-resolution-rules-v0.1.md`](edict-dispute-resolution-rules-v0.1.md)

The rules are an evaluation artifact for the wallet-native E0 testnet flow.
They have not been independently reviewed, do not create production legal
assurance, and are not legal advice.

Enterprise E1, E2, and E3 schema support is experimental. It must not be
enabled for an external deployment without customer-specific terms, verified
authority, and advice covering the selected entities, jurisdictions,
regulatory perimeter, tax treatment, and data processing.

## Integrity

The canonical SHA-256 hash of the rules file in this release is:

```text
17701fa24d618290fb28da1315fdaa4480e7634aeccba074f3fbd393e2f848c5
```

The SDK binds this value in each `LegalPolicy`. Changing the rules requires a
new identifier, version, hash, and release.
