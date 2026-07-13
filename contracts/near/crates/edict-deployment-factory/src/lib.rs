//! # Edict keyless deployment factory
//!
//! The factory creates customer-bound settlement instances from one immutable
//! NEAR global-contract hash. It has no owner, code-hash update, fee withdrawal,
//! child upgrade, key-management, or generic promise method.
//!
//! `create_instance` batches account creation, initial balance, immutable code
//! selection, and initialization. It intentionally adds no access key. NEAR
//! executes the child actions atomically, so a failed initializer cannot leave
//! an uninitialized account behind. The caller must be the customer governance
//! account embedded in the immutable child configuration.

use edict_settlement_common::{validate_config, CustomerSettlementConfig, CONTRACT_VERSION};
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{borsh, env, near, require, AccountId, Gas, NearToken, PanicOnDefault};

pub const FACTORY_VERSION: &str = "edict-deployment-factory-v1";
pub const DEPLOYMENT_RECORD_STORAGE_BYTES: u128 = 2_048;
pub const MIN_INSTANCE_BALANCE_FLOOR_YOCTO: u128 = 100_000_000_000_000_000_000_000;

const CHILD_INIT_GAS: Gas = Gas::from_tgas(80);
const DEPLOY_CALLBACK_GAS: Gas = Gas::from_tgas(15);

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Deploying,
    Active,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub instance_account: AccountId,
    pub customer_governance: AccountId,
    pub config_sha256: [u8; 32],
    pub global_code_sha256: [u8; 32],
    pub created_at_ms: u64,
    pub instance_balance: NearToken,
    pub status: DeploymentStatus,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct FactoryConfigView {
    pub factory_version: String,
    pub settlement_contract_version: String,
    pub global_code_sha256: [u8; 32],
    pub minimum_instance_balance: U128,
    pub deployment_record_storage_deposit: U128,
    pub adminless: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct DeploymentFactory {
    global_code_sha256: [u8; 32],
    minimum_instance_balance: NearToken,
    deployments: LookupMap<AccountId, DeploymentRecord>,
}

#[near]
impl DeploymentFactory {
    #[init]
    pub fn new(global_code_sha256: [u8; 32], minimum_instance_balance: U128) -> Self {
        require!(
            global_code_sha256 != [0u8; 32],
            "global contract hash is zero"
        );
        require!(
            minimum_instance_balance.0 >= MIN_INSTANCE_BALANCE_FLOOR_YOCTO,
            "minimum instance balance is below the production floor"
        );
        Self {
            global_code_sha256,
            minimum_instance_balance: NearToken::from_yoctonear(minimum_instance_balance.0),
            deployments: LookupMap::new(b"d"),
        }
    }

    pub fn get_config(&self) -> FactoryConfigView {
        FactoryConfigView {
            factory_version: FACTORY_VERSION.to_string(),
            settlement_contract_version: CONTRACT_VERSION.to_string(),
            global_code_sha256: self.global_code_sha256,
            minimum_instance_balance: U128(self.minimum_instance_balance.as_yoctonear()),
            deployment_record_storage_deposit: U128(self.record_storage_deposit().as_yoctonear()),
            adminless: true,
        }
    }

    pub fn deployment_account(&self, slug: String) -> AccountId {
        instance_account(&slug, &env::current_account_id())
    }

    pub fn get_deployment(&self, instance_account: AccountId) -> Option<DeploymentRecord> {
        self.deployments.get(&instance_account).cloned()
    }

    pub fn required_deployment_deposit(&self) -> U128 {
        U128(
            self.minimum_instance_balance
                .as_yoctonear()
                .checked_add(self.record_storage_deposit().as_yoctonear())
                .expect("deployment deposit overflow"),
        )
    }

    /// One customer approval creates and initializes a keyless instance.
    #[payable]
    pub fn create_instance(&mut self, slug: String, config: CustomerSettlementConfig) {
        if let Err(problem) = validate_config(&config) {
            env::panic_str(&problem);
        }
        let customer = env::predecessor_account_id();
        require!(
            customer == config.customer_governance,
            "caller must be the configured customer governance account"
        );
        let instance = instance_account(&slug, &env::current_account_id());
        require!(
            self.deployments.get(&instance).is_none(),
            "instance slug is already reserved"
        );
        let required = self.required_deployment_deposit().0;
        require!(
            env::attached_deposit().as_yoctonear() == required,
            "attach exactly required_deployment_deposit()"
        );

        let config_bytes = borsh::to_vec(&config).expect("config serialization cannot fail");
        let config_sha256 = env::sha256_array(&config_bytes);
        let before = env::storage_usage();
        self.deployments.insert(
            instance.clone(),
            DeploymentRecord {
                instance_account: instance.clone(),
                customer_governance: customer.clone(),
                config_sha256,
                global_code_sha256: self.global_code_sha256,
                created_at_ms: env::block_timestamp_ms(),
                instance_balance: self.minimum_instance_balance,
                status: DeploymentStatus::Deploying,
            },
        );
        let stored_bytes = u128::from(env::storage_usage().saturating_sub(before));
        require!(
            stored_bytes <= DEPLOYMENT_RECORD_STORAGE_BYTES,
            "deployment record exceeds its storage reserve"
        );

        let init_args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
            "config": config,
        }))
        .expect("init JSON serialization cannot fail");
        let attached = env::attached_deposit();
        let deployment = env::promise_batch_create(&instance);
        env::promise_batch_action_create_account(deployment);
        env::promise_batch_action_transfer(deployment, self.minimum_instance_balance);
        env::promise_batch_action_use_global_contract(deployment, &self.global_code_sha256);
        env::promise_batch_action_function_call(
            deployment,
            "new",
            &init_args,
            NearToken::from_yoctonear(0),
            CHILD_INIT_GAS,
        );
        let callback = env::promise_batch_then(deployment, &env::current_account_id());
        let callback_args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
            "instance_account": instance,
            "customer_governance": customer,
            "attached_deposit": U128(attached.as_yoctonear()),
        }))
        .expect("deployment callback JSON cannot fail");
        env::promise_batch_action_function_call(
            callback,
            "on_instance_deployed",
            &callback_args,
            NearToken::from_yoctonear(0),
            DEPLOY_CALLBACK_GAS,
        );
        env::promise_return(callback);
    }

    #[private]
    pub fn on_instance_deployed(
        &mut self,
        instance_account: AccountId,
        customer_governance: AccountId,
        attached_deposit: U128,
    ) -> bool {
        if env::promise_result_checked(0, 0).is_ok() {
            let record = self
                .deployments
                .get_mut(&instance_account)
                .expect("missing deployment callback record");
            require!(
                record.customer_governance == customer_governance,
                "deployment callback customer mismatch"
            );
            record.status = DeploymentStatus::Active;
            true
        } else {
            let record = self
                .deployments
                .remove(&instance_account)
                .expect("missing failed deployment record");
            require!(
                record.customer_governance == customer_governance,
                "deployment callback customer mismatch"
            );
            let refund = env::promise_batch_create(&customer_governance);
            env::promise_batch_action_transfer(
                refund,
                NearToken::from_yoctonear(attached_deposit.0),
            );
            false
        }
    }
}

impl DeploymentFactory {
    fn record_storage_deposit(&self) -> NearToken {
        NearToken::from_yoctonear(
            env::storage_byte_cost()
                .as_yoctonear()
                .checked_mul(DEPLOYMENT_RECORD_STORAGE_BYTES)
                .expect("factory storage deposit overflow"),
        )
    }
}

fn instance_account(slug: &str, factory: &AccountId) -> AccountId {
    require!(
        (2..=32).contains(&slug.len()),
        "instance slug must contain 2..=32 characters"
    );
    require!(
        slug.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "instance slug permits lowercase letters, digits and hyphens only"
    );
    require!(
        slug.as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && slug
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "instance slug must start and end with a letter or digit"
    );
    format!("{slug}.{factory}")
        .parse()
        .unwrap_or_else(|_| env::panic_str("derived instance account is invalid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use edict_settlement_common::{VerifierPolicy, VerifierSigner, SIGNATURE_SCHEME};
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    const NOW_MS: u64 = 1_800_000_000_000;
    const MIN_BALANCE: u128 = 500_000_000_000_000_000_000_000;

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn factory_account() -> AccountId {
        account("factory.edict.near")
    }

    fn customer() -> AccountId {
        account("customer.near")
    }

    fn signer(operator: &str, suffix: u8, edict_controlled: bool) -> VerifierSigner {
        VerifierSigner {
            signing_address: format!("0x{:040x}", suffix),
            operator_id: operator.into(),
            edict_controlled,
            attestation_sha256: [suffix; 32],
        }
    }

    fn customer_config() -> CustomerSettlementConfig {
        CustomerSettlementConfig {
            customer_governance: customer(),
            removal_account: account("pool.customer.near"),
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

    fn set_context(predecessor: AccountId, deposit: u128) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(factory_account())
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .account_balance(NearToken::from_near(100))
            .block_timestamp(NOW_MS * 1_000_000);
        testing_env!(builder.build());
    }

    fn factory() -> DeploymentFactory {
        set_context(account("deployer.near"), 0);
        DeploymentFactory::new([0xAB; 32], U128(MIN_BALANCE))
    }

    fn callback_context(result: PromiseResult) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(factory_account())
            .signer_account_id(factory_account())
            .predecessor_account_id(factory_account())
            .account_balance(NearToken::from_near(100))
            .block_timestamp((NOW_MS + 1_000) * 1_000_000);
        testing_env!(
            builder.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            std::collections::HashMap::default(),
            vec![result],
        );
    }

    #[test]
    fn factory_configuration_is_immutable_and_adminless() {
        let factory = factory();
        let view = factory.get_config();
        assert_eq!(view.factory_version, FACTORY_VERSION);
        assert_eq!(view.settlement_contract_version, CONTRACT_VERSION);
        assert_eq!(view.global_code_sha256, [0xAB; 32]);
        assert_eq!(view.minimum_instance_balance.0, MIN_BALANCE);
        assert!(view.deployment_record_storage_deposit.0 > 0);
        assert!(view.adminless);
    }

    #[test]
    fn one_call_creates_keyless_global_contract_instance_and_initializer() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(customer(), required);
        factory.create_instance("payments".into(), customer_config());

        let instance = account("payments.factory.edict.near");
        let record = factory.get_deployment(instance.clone()).unwrap();
        assert_eq!(record.status, DeploymentStatus::Deploying);
        assert_eq!(record.customer_governance, customer());
        assert_eq!(record.global_code_sha256, [0xAB; 32]);

        let receipts = get_created_receipts();
        let child = receipts
            .iter()
            .find(|receipt| receipt.receiver_id == instance)
            .expect("child receipt");
        assert!(child
            .actions
            .iter()
            .any(|action| matches!(action, MockAction::CreateAccount { .. })));
        assert!(child.actions.iter().any(|action| matches!(
            action,
            MockAction::Transfer { deposit, .. } if deposit.as_yoctonear() == MIN_BALANCE
        )));
        assert!(child
            .actions
            .iter()
            .any(|action| matches!(action, MockAction::UseGlobalContract { .. })));
        assert!(child.actions.iter().any(|action| matches!(
            action,
            MockAction::FunctionCallWeight { method_name, attached_deposit, .. }
                if method_name == b"new" && attached_deposit.is_zero()
        )));
        assert!(!child.actions.iter().any(|action| matches!(
            action,
            MockAction::AddKeyWithFullAccess { .. }
                | MockAction::AddKeyWithFunctionCall { .. }
                | MockAction::AddGasKeyWithFullAccess { .. }
                | MockAction::AddGasKeyWithFunctionCall { .. }
        )));
    }

    #[test]
    fn successful_callback_activates_the_customer_instance() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(customer(), required);
        factory.create_instance("payments".into(), customer_config());
        let instance = account("payments.factory.edict.near");
        callback_context(PromiseResult::Successful(vec![]));
        assert!(factory.on_instance_deployed(instance.clone(), customer(), U128(required)));
        assert_eq!(
            factory.get_deployment(instance).unwrap().status,
            DeploymentStatus::Active
        );
    }

    #[test]
    fn failed_atomic_deployment_releases_slug_and_refunds_customer() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(customer(), required);
        factory.create_instance("payments".into(), customer_config());
        let instance = account("payments.factory.edict.near");
        callback_context(PromiseResult::Failed);
        assert!(!factory.on_instance_deployed(instance.clone(), customer(), U128(required)));
        assert!(factory.get_deployment(instance).is_none());
        assert!(get_created_receipts().iter().any(|receipt| {
            receipt.receiver_id == customer()
                && receipt.actions.iter().any(|action| {
                    matches!(
                        action,
                        MockAction::Transfer { deposit, .. }
                            if deposit.as_yoctonear() == required
                    )
                })
        }));
    }

    #[test]
    #[should_panic(expected = "instance slug is already reserved")]
    fn concurrent_or_duplicate_slug_cannot_overwrite_a_deployment_record() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(customer(), required);
        factory.create_instance("payments".into(), customer_config());
        set_context(customer(), required);
        factory.create_instance("payments".into(), customer_config());
    }

    #[test]
    #[should_panic(expected = "caller must be the configured customer governance")]
    fn factory_cannot_install_an_edict_governance_substitute() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(account("edict.near"), required);
        factory.create_instance("payments".into(), customer_config());
    }

    #[test]
    #[should_panic(expected = "attach exactly required_deployment_deposit")]
    fn deployment_has_no_hidden_or_variable_factory_fee() {
        let mut factory = factory();
        set_context(customer(), MIN_BALANCE);
        factory.create_instance("payments".into(), customer_config());
    }

    #[test]
    #[should_panic(expected = "slug permits lowercase")]
    fn rejects_noncanonical_instance_names() {
        let mut factory = factory();
        let required = factory.required_deployment_deposit().0;
        set_context(customer(), required);
        factory.create_instance("Customer_Admin".into(), customer_config());
    }
}
