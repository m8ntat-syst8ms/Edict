# EDICT_SETTLEMENT_V1 execution digest

The production customer contract signs a domain-separated digest over:

```text
utf8("EDICT_SETTLEMENT_V1")
|| utf8(settlement_account) || 0x00
|| order_mandate_sha256
|| case_id_sha256
|| u32_le(round)
|| utf8(ruling_canonical) || 0x00
|| verdict_sha256
|| u64_le(issued_at_ms)
|| verifier_policy_sha256
|| nonce
```

Signers sign the 32-byte SHA-256 result through the Ethereum personal-message
envelope. The contract performs low-s ECDSA recovery and matches the recovered
address to the immutable operator policy.

Frozen vector:

| Field | Value |
|---|---|
| settlement account | `locked.customer-settlement.near` |
| order mandate | byte `01` repeated 32 |
| case id | byte `02` repeated 32 |
| round | `1` |
| ruling | `split:2500` |
| verdict | byte `03` repeated 32 |
| issued at | `1800000000000` |
| verifier policy | byte `04` repeated 32 |
| nonce | byte `05` repeated 32 |
| SHA-256 digest | `16964bc5fb584f55c88cc6535482b781abb996d032bbf4511b124143febe2ea7` |

The vector is asserted independently in Rust and TypeScript. Changing this
layout requires a new contract/domain version, not an in-place edit.
