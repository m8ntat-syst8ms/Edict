//! Shared production settlement wire types.
//!
//! This crate deliberately contains no contract state or administrative API.
//! The customer settlement contract and deployment factory both consume these
//! exact types so configuration cannot change shape between deployment and
//! initialization.

use near_sdk::{borsh, env, near, AccountId};
use std::collections::BTreeSet;

pub const CONTRACT_VERSION: &str = "edict-customer-settlement-v1";
pub const SIGNATURE_SCHEME: &str = "ecdsa_secp256k1_eth";
pub const MIN_SIGNERS: usize = 2;
pub const MAX_SIGNERS: usize = 16;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierSigner {
    /// Lowercase Ethereum address: `0x` followed by 40 hex characters.
    pub signing_address: String,
    /// Independent infrastructure/provider identity. Quorum counts operators.
    pub operator_id: String,
    /// True only when Edict controls this signer or its operating environment.
    pub edict_controlled: bool,
    /// Hash of the retained signer-attestation bundle.
    pub attestation_sha256: [u8; 32],
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierPolicy {
    pub scheme: String,
    pub quorum: u16,
    /// Strictly sorted by `operator_id` for one canonical policy hash.
    pub signers: Vec<VerifierSigner>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomerSettlementConfig {
    /// Customer multisig, DAO or rail account. It has no generic fund power.
    pub customer_governance: AccountId,
    /// Pre-disclosed irreversible sink or customer/independent protection pool.
    pub removal_account: AccountId,
    /// Immutable for the lifetime of this versioned settlement instance.
    pub verifier_policy: VerifierPolicy,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LivenessFallback {
    RefundRequester,
    ReleaseWorker,
    #[serde(rename = "split_50_50")]
    Split5050,
    ControllerResolution,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RulingKind {
    RequesterWins,
    WorkerWins,
    Split,
    Redo,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ruling {
    RequesterWins,
    WorkerWins,
    Split {
        #[serde(rename = "requesterBps")]
        requester_bps: u16,
    },
    Redo {
        #[serde(rename = "newDeadlineUnixMs")]
        new_deadline_unix_ms: u64,
    },
}

impl Ruling {
    pub fn kind(&self) -> RulingKind {
        match self {
            Self::RequesterWins => RulingKind::RequesterWins,
            Self::WorkerWins => RulingKind::WorkerWins,
            Self::Split { .. } => RulingKind::Split,
            Self::Redo { .. } => RulingKind::Redo,
        }
    }

    pub fn canonical(&self) -> String {
        match self {
            Self::RequesterWins => "requester_wins".to_string(),
            Self::WorkerWins => "worker_wins".to_string(),
            Self::Split { requester_bps } => format!("split:{requester_bps}"),
            Self::Redo {
                new_deadline_unix_ms,
            } => format!("redo:{new_deadline_unix_ms}"),
        }
    }

    pub fn terminal_requester_share_bps(&self) -> Option<u16> {
        match self {
            Self::RequesterWins => Some(10_000),
            Self::WorkerWins => Some(0),
            Self::Split { requester_bps } => Some(*requester_bps),
            Self::Redo { .. } => None,
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictSignature {
    pub signing_address: String,
    /// Recoverable 65-byte `r || s || v`, with or without a `0x` prefix.
    pub signature: String,
}

pub fn normalize_eth_address(value: &str) -> Option<String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", value.to_ascii_lowercase()))
}

fn valid_operator_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
}

pub fn validate_config(config: &CustomerSettlementConfig) -> Result<(), String> {
    let policy = &config.verifier_policy;
    if policy.scheme != SIGNATURE_SCHEME {
        return Err(format!("verifier policy scheme must be {SIGNATURE_SCHEME}"));
    }
    if !(MIN_SIGNERS..=MAX_SIGNERS).contains(&policy.signers.len()) {
        return Err(format!(
            "verifier policy must contain {MIN_SIGNERS}..={MAX_SIGNERS} signers"
        ));
    }
    let quorum = usize::from(policy.quorum);
    if quorum < 2 || quorum > policy.signers.len() {
        return Err("verifier quorum must be at least 2 and no greater than signer count".into());
    }

    let mut addresses = BTreeSet::new();
    let mut operators = BTreeSet::new();
    let mut previous_operator: Option<&str> = None;
    let mut edict_controlled = 0usize;
    for signer in &policy.signers {
        let normalized = normalize_eth_address(&signer.signing_address)
            .ok_or_else(|| "signing_address must be 0x plus 40 hex characters".to_string())?;
        if normalized != signer.signing_address {
            return Err("signing_address must be normalized lowercase with a 0x prefix".into());
        }
        if !addresses.insert(normalized) {
            return Err("verifier signing addresses must be unique".into());
        }
        if !valid_operator_id(&signer.operator_id) {
            return Err("operator_id contains unsupported characters or length".into());
        }
        if !operators.insert(signer.operator_id.clone()) {
            return Err("verifier operator_id values must be unique".into());
        }
        if let Some(previous) = previous_operator {
            if previous >= signer.operator_id.as_str() {
                return Err("verifier signers must be strictly sorted by operator_id".into());
            }
        }
        previous_operator = Some(&signer.operator_id);
        if signer.attestation_sha256 == [0u8; 32] {
            return Err("attestation_sha256 must not be all zeroes".into());
        }
        if signer.edict_controlled {
            edict_controlled += 1;
        }
    }

    let independent = policy.signers.len() - edict_controlled;
    if independent < quorum {
        return Err("quorum must remain satisfiable without every Edict-controlled signer".into());
    }
    if edict_controlled >= quorum {
        return Err("Edict-controlled signers must not be able to satisfy quorum alone".into());
    }
    Ok(())
}

pub fn verifier_policy_sha256(policy: &VerifierPolicy) -> [u8; 32] {
    let bytes = borsh::to_vec(policy).expect("verifier policy serialization cannot fail");
    env::sha256_array(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn signer(operator: &str, suffix: u8, edict_controlled: bool) -> VerifierSigner {
        VerifierSigner {
            signing_address: format!("0x{:040x}", suffix),
            operator_id: operator.into(),
            edict_controlled,
            attestation_sha256: [suffix; 32],
        }
    }

    fn config() -> CustomerSettlementConfig {
        CustomerSettlementConfig {
            customer_governance: account("customer.near"),
            removal_account: account("pool.near"),
            verifier_policy: VerifierPolicy {
                scheme: SIGNATURE_SCHEME.into(),
                quorum: 2,
                signers: vec![
                    signer("edict", 1, true),
                    signer("independent-a", 2, false),
                    signer("independent-b", 3, false),
                ],
            },
        }
    }

    #[test]
    fn valid_policy_is_canonical_and_independent() {
        testing_env!(VMContextBuilder::new().build());
        let cfg = config();
        assert_eq!(validate_config(&cfg), Ok(()));
        assert_eq!(
            verifier_policy_sha256(&cfg.verifier_policy),
            [
                0x43, 0xaf, 0x56, 0xe8, 0x07, 0xdf, 0x1d, 0x13, 0x40, 0x86, 0x9d, 0x46, 0xec, 0x64,
                0x59, 0x0e, 0x6d, 0x2f, 0xf5, 0x66, 0x0d, 0x98, 0xba, 0x8a, 0x1a, 0xa3, 0xc8, 0x2c,
                0xd7, 0x03, 0x03, 0x8d,
            ],
        );
    }

    #[test]
    fn edict_can_neither_supply_nor_be_required_for_quorum() {
        let mut only_edict = config();
        only_edict.verifier_policy.signers[1].edict_controlled = true;
        assert!(validate_config(&only_edict)
            .unwrap_err()
            .contains("without every Edict-controlled signer"));

        let mut edict_alone = config();
        edict_alone
            .verifier_policy
            .signers
            .push(signer("independent-c", 4, false));
        edict_alone.verifier_policy.signers[1].edict_controlled = true;
        edict_alone.verifier_policy.quorum = 2;
        assert!(validate_config(&edict_alone)
            .unwrap_err()
            .contains("Edict-controlled signers"));
    }

    #[test]
    fn rejects_noncanonical_and_duplicate_signers() {
        let mut unsorted = config();
        unsorted.verifier_policy.signers.swap(1, 2);
        assert!(validate_config(&unsorted).unwrap_err().contains("sorted"));

        let mut duplicate = config();
        duplicate.verifier_policy.signers[2].signing_address =
            duplicate.verifier_policy.signers[1].signing_address.clone();
        assert!(validate_config(&duplicate).unwrap_err().contains("unique"));
    }
}
