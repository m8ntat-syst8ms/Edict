//! Shared wire configuration for the cross-chain NEAR Intents settlement line.

use edict_settlement_common::{validate_config, CustomerSettlementConfig};
use near_sdk::{near, AccountId};

pub const INTENTS_SETTLEMENT_VERSION: &str = "edict-customer-settlement-intents-v1";
pub const INTENTS_FACTORY_VERSION: &str = "edict-intents-deployment-factory-v1";
pub const MIN_MAX_ORDERS: u32 = 1;
pub const MAX_MAX_ORDERS: u32 = 100_000;
pub const ORDER_STORAGE_RESERVE_BYTES: u128 = 8_192;
pub const MIN_OPERATIONAL_RESERVE_YOCTO: u128 = 50_000_000_000_000_000_000_000;

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentsSettlementConfig {
    pub customer: CustomerSettlementConfig,
    /// The sole accepted predecessor for `mt_on_transfer` and `on_auth`.
    pub intents_contract: AccountId,
    /// One immutable Verifier balance id, e.g. `nep141:usdc.omft.near`.
    pub settlement_token_id: String,
    /// Lifetime order limit backed by the instance's prefunded NEAR storage.
    pub max_orders: u32,
}

pub fn settlement_token_contract(token_id: &str) -> Option<AccountId> {
    token_id.strip_prefix("nep141:")?.parse().ok()
}

pub fn validate_intents_config(config: &IntentsSettlementConfig) -> Result<(), String> {
    validate_config(&config.customer)?;
    if config.customer.customer_governance == config.customer.removal_account {
        return Err("customer governance and removal account must differ".into());
    }
    if config.intents_contract == config.customer.customer_governance
        || config.intents_contract == config.customer.removal_account
    {
        return Err("intents contract cannot be a customer beneficiary".into());
    }
    if config.settlement_token_id.len() > 256
        || settlement_token_contract(&config.settlement_token_id).is_none()
    {
        return Err("settlement_token_id must be nep141:<valid NEAR account id>".into());
    }
    if !(MIN_MAX_ORDERS..=MAX_MAX_ORDERS).contains(&config.max_orders) {
        return Err(format!(
            "max_orders must be between {MIN_MAX_ORDERS} and {MAX_MAX_ORDERS}"
        ));
    }
    Ok(())
}

pub fn required_instance_balance(
    config: &IntentsSettlementConfig,
    storage_byte_cost_yocto: u128,
) -> Option<u128> {
    storage_byte_cost_yocto
        .checked_mul(ORDER_STORAGE_RESERVE_BYTES)?
        .checked_mul(u128::from(config.max_orders))?
        .checked_add(MIN_OPERATIONAL_RESERVE_YOCTO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edict_settlement_common::{VerifierPolicy, VerifierSigner, SIGNATURE_SCHEME};

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn config() -> IntentsSettlementConfig {
        IntentsSettlementConfig {
            customer: CustomerSettlementConfig {
                customer_governance: account("customer.near"),
                removal_account: account("pool.near"),
                verifier_policy: VerifierPolicy {
                    scheme: SIGNATURE_SCHEME.into(),
                    quorum: 2,
                    signers: vec![
                        VerifierSigner {
                            signing_address: format!("0x{:040x}", 1),
                            operator_id: "independent-a".into(),
                            edict_controlled: false,
                            attestation_sha256: [1; 32],
                        },
                        VerifierSigner {
                            signing_address: format!("0x{:040x}", 2),
                            operator_id: "independent-b".into(),
                            edict_controlled: false,
                            attestation_sha256: [2; 32],
                        },
                    ],
                },
            },
            intents_contract: account("intents.near"),
            settlement_token_id: "nep141:usdc.omft.near".into(),
            max_orders: 1_000,
        }
    }

    #[test]
    fn validates_one_nep141_asset_and_capacity() {
        assert_eq!(validate_intents_config(&config()), Ok(()));
        let mut invalid = config();
        invalid.settlement_token_id = "native:near".into();
        assert!(validate_intents_config(&invalid).is_err());
        invalid = config();
        invalid.max_orders = 0;
        assert!(validate_intents_config(&invalid).is_err());
    }
}
