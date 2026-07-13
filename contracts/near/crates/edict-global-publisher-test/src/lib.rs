//! Test-only helper for exercising NEAR global contracts in local sandbox.

use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, near, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GlobalPublisher;

#[near]
impl GlobalPublisher {
    #[init]
    pub fn new() -> Self {
        Self
    }

    pub fn publish_by_hash(&self, code: Base64VecU8) {
        let publish = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_global_contract(publish, &code.0);
        env::promise_return(publish);
    }
}
