//! # Edict customer settlement v1
//!
//! An immutable, customer-bound NEAR settlement instance. The account is
//! expected to use an immutable global contract by hash and contain no access
//! keys. The code has no owner, upgrade, pause, freeze, generic transfer,
//! signer-admission, or administrative withdrawal method.
//!
//! Edict supplies verdict data and a proof package. Any account may relay that
//! package. The contract recomputes the execution digest, verifies an immutable
//! independent-operator quorum, enforces challenge and liveness clocks, and
//! allocates only pre-committed branches. Payouts become account-specific
//! claims; anyone may trigger a claim withdrawal, but nobody can redirect it.
//!
//! V1 settles native NEAR. Fungible-token rails require a separately audited
//! NEP-141 adapter and are intentionally outside this contract's authority.

use edict_settlement_common::{
    normalize_eth_address, validate_config, verifier_policy_sha256, CustomerSettlementConfig,
    LivenessFallback, Ruling, RulingKind, VerdictSignature, CONTRACT_VERSION,
};
use near_sdk::json_types::U128;
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault};
use std::collections::HashSet;

pub const BPS_DENOM: u128 = 10_000;
pub const EXECUTION_DOMAIN: &[u8] = b"EDICT_SETTLEMENT_V1";
pub const ORDER_STORAGE_RESERVE_BYTES: u128 = 8_192;
pub const MAX_ORDER_HORIZON_MS: u64 = 365 * 24 * 60 * 60 * 1_000;
pub const MAX_POLICY_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_REDO_EXTENSION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MIN_CHALLENGE_WINDOW_MS: u64 = 2 * 60 * 60 * 1_000;
pub const MAX_CHALLENGE_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MIN_DISPUTE_BOND_BPS: u16 = 500;
pub const MAX_DISPUTE_BOND_BPS: u16 = 1_000;

const WITHDRAW_CALLBACK_GAS: Gas = Gas::from_tgas(10);

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderState {
    Funded,
    Delivered,
    Disputed,
    Settled,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub manifest_sha256: [u8; 32],
    pub delivered_at_ms: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeRecord {
    /// The original Bond poster remains the Bond owner through a redo.
    pub disputant: AccountId,
    pub bond: NearToken,
    pub opened_at_ms: u64,
    pub case_id_sha256: [u8; 32],
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolutionSource {
    Acceptance,
    NonDeliveryTimeout,
    AcceptanceTimeout,
    LivenessFallback,
    VerifiedProof {
        verdict_sha256: [u8; 32],
        execution_digest: [u8; 32],
        issued_at_ms: u64,
        nonce: [u8; 32],
    },
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionRecord {
    pub ruling: Ruling,
    pub source: ResolutionSource,
    pub resolved_at_ms: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeRound {
    pub number: u8,
    pub case_id_sha256: [u8; 32],
    pub manifest_sha256: Option<[u8; 32]>,
    pub opened_at_ms: u64,
    pub resolution: Option<ResolutionRecord>,
    pub bond_held_after: NearToken,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The canonical order-mandate hash is also the immutable order id.
    pub order_mandate_sha256: [u8; 32],
    pub settlement_binding_sha256: [u8; 32],
    pub requester: AccountId,
    pub worker: AccountId,
    pub principal: NearToken,
    pub storage_deposit: NearToken,
    pub deadline_ms: u64,
    pub acceptance_window_ms: u64,
    pub challenge_window_ms: u64,
    pub resolution_timeout_ms: u64,
    pub liveness_fallback: LivenessFallback,
    pub permitted_rulings: Vec<RulingKind>,
    pub dispute_bond_bps: u16,
    pub verifier_policy_sha256: [u8; 32],
    pub state: OrderState,
    pub delivery: Option<DeliveryRecord>,
    pub dispute: Option<DisputeRecord>,
    pub redo_count: u8,
    pub last_resolution: Option<ResolutionRecord>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct FundOrderArgs {
    pub order_mandate_sha256: [u8; 32],
    pub settlement_binding_sha256: [u8; 32],
    pub worker: AccountId,
    pub principal: U128,
    pub deadline_ms: u64,
    pub acceptance_window_ms: u64,
    pub challenge_window_ms: u64,
    pub resolution_timeout_ms: u64,
    pub liveness_fallback: LivenessFallback,
    pub permitted_rulings: Vec<RulingKind>,
    pub dispute_bond_bps: u16,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ConfigView {
    pub contract_version: String,
    pub customer_governance: AccountId,
    pub removal_account: AccountId,
    pub verifier_policy: edict_settlement_common::VerifierPolicy,
    pub verifier_policy_sha256: [u8; 32],
    pub native_near_only: bool,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AccountingView {
    pub locked_principal: U128,
    pub locked_bonds: U128,
    pub payable_claims: U128,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct CustomerSettlement {
    config: CustomerSettlementConfig,
    verifier_policy_sha256: [u8; 32],
    orders: LookupMap<[u8; 32], Order>,
    rounds: LookupMap<[u8; 32], Vec<DisputeRound>>,
    used_nonces: LookupSet<Vec<u8>>,
    claims: LookupMap<AccountId, NearToken>,
    locked_principal_yocto: u128,
    locked_bonds_yocto: u128,
    payable_claims_yocto: u128,
}

#[near]
impl CustomerSettlement {
    #[init]
    pub fn new(config: CustomerSettlementConfig) -> Self {
        if let Err(problem) = validate_config(&config) {
            env::panic_str(&problem);
        }
        require!(
            config.customer_governance != env::current_account_id(),
            "customer governance must be external to the locked settlement account"
        );
        require!(
            config.removal_account != env::current_account_id(),
            "removal account must be external to the locked settlement account"
        );
        let policy_hash = verifier_policy_sha256(&config.verifier_policy);
        Self {
            config,
            verifier_policy_sha256: policy_hash,
            orders: LookupMap::new(b"o"),
            rounds: LookupMap::new(b"r"),
            used_nonces: LookupSet::new(b"n"),
            claims: LookupMap::new(b"c"),
            locked_principal_yocto: 0,
            locked_bonds_yocto: 0,
            payable_claims_yocto: 0,
        }
    }

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            contract_version: CONTRACT_VERSION.to_string(),
            customer_governance: self.config.customer_governance.clone(),
            removal_account: self.config.removal_account.clone(),
            verifier_policy: self.config.verifier_policy.clone(),
            verifier_policy_sha256: self.verifier_policy_sha256,
            native_near_only: true,
        }
    }

    pub fn get_order(&self, order_mandate_sha256: [u8; 32]) -> Option<Order> {
        self.orders.get(&order_mandate_sha256).cloned()
    }

    pub fn get_rounds(&self, order_mandate_sha256: [u8; 32]) -> Vec<DisputeRound> {
        self.rounds
            .get(&order_mandate_sha256)
            .cloned()
            .unwrap_or_default()
    }

    pub fn claim_of(&self, account_id: AccountId) -> U128 {
        U128(
            self.claims
                .get(&account_id)
                .map(NearToken::as_yoctonear)
                .unwrap_or(0),
        )
    }

    pub fn accounting(&self) -> AccountingView {
        AccountingView {
            locked_principal: U128(self.locked_principal_yocto),
            locked_bonds: U128(self.locked_bonds_yocto),
            payable_claims: U128(self.payable_claims_yocto),
        }
    }

    pub fn is_nonce_used(&self, order_mandate_sha256: [u8; 32], nonce: [u8; 32]) -> bool {
        self.used_nonces
            .contains(&nonce_key(&order_mandate_sha256, &nonce))
    }

    pub fn order_storage_deposit(&self) -> U128 {
        U128(
            env::storage_byte_cost()
                .as_yoctonear()
                .checked_mul(ORDER_STORAGE_RESERVE_BYTES)
                .expect("storage deposit overflow"),
        )
    }

    pub fn required_funding_deposit(&self, principal: U128) -> U128 {
        U128(
            principal
                .0
                .checked_add(self.order_storage_deposit().0)
                .expect("funding deposit overflow"),
        )
    }

    #[payable]
    pub fn fund(&mut self, args: FundOrderArgs) -> [u8; 32] {
        let now = env::block_timestamp_ms();
        require!(
            args.order_mandate_sha256 != [0u8; 32],
            "order mandate hash is zero"
        );
        require!(
            args.settlement_binding_sha256 != [0u8; 32],
            "settlement binding hash is zero"
        );
        require!(
            self.orders.get(&args.order_mandate_sha256).is_none(),
            "order mandate is already funded"
        );
        require!(args.principal.0 > 0, "principal must be positive");
        require!(
            env::predecessor_account_id() != args.worker,
            "requester and worker must differ"
        );
        require!(
            env::predecessor_account_id() != self.config.removal_account
                && args.worker != self.config.removal_account,
            "removal account cannot be an order party"
        );
        require!(args.deadline_ms > now, "deadline must be in the future");
        require!(
            args.deadline_ms <= now.saturating_add(MAX_ORDER_HORIZON_MS),
            "deadline exceeds the maximum order horizon"
        );
        require!(
            args.acceptance_window_ms > 0 && args.acceptance_window_ms <= MAX_POLICY_WINDOW_MS,
            "acceptance window is outside the supported range"
        );
        require!(
            (MIN_CHALLENGE_WINDOW_MS..=MAX_CHALLENGE_WINDOW_MS).contains(&args.challenge_window_ms),
            "challenge window must be between 2 and 24 hours"
        );
        require!(
            args.resolution_timeout_ms > args.challenge_window_ms
                && args.resolution_timeout_ms <= MAX_POLICY_WINDOW_MS,
            "resolution timeout must exceed the challenge window and be at most 30 days"
        );
        require!(
            (MIN_DISPUTE_BOND_BPS..=MAX_DISPUTE_BOND_BPS).contains(&args.dispute_bond_bps),
            "dispute Bond must be between 500 and 1000 bps"
        );
        require!(
            mul_bps(args.principal.0, args.dispute_bond_bps) > 0,
            "principal is too small for a positive atomic Bond"
        );
        validate_permitted_and_fallback(&args.permitted_rulings, args.liveness_fallback);

        let storage_deposit = NearToken::from_yoctonear(self.order_storage_deposit().0);
        let required = args
            .principal
            .0
            .checked_add(storage_deposit.as_yoctonear())
            .expect("funding amount overflow");
        require!(
            env::attached_deposit().as_yoctonear() == required,
            "attach exactly principal plus order_storage_deposit()"
        );

        let requester = env::predecessor_account_id();
        let principal = NearToken::from_yoctonear(args.principal.0);
        let before = env::storage_usage();
        self.orders.insert(
            args.order_mandate_sha256,
            Order {
                order_mandate_sha256: args.order_mandate_sha256,
                settlement_binding_sha256: args.settlement_binding_sha256,
                requester: requester.clone(),
                worker: args.worker.clone(),
                principal,
                storage_deposit,
                deadline_ms: args.deadline_ms,
                acceptance_window_ms: args.acceptance_window_ms,
                challenge_window_ms: args.challenge_window_ms,
                resolution_timeout_ms: args.resolution_timeout_ms,
                liveness_fallback: args.liveness_fallback,
                permitted_rulings: args.permitted_rulings,
                dispute_bond_bps: args.dispute_bond_bps,
                verifier_policy_sha256: self.verifier_policy_sha256,
                state: OrderState::Funded,
                delivery: None,
                dispute: None,
                redo_count: 0,
                last_resolution: None,
            },
        );
        let initial_bytes = u128::from(env::storage_usage().saturating_sub(before));
        require!(
            initial_bytes <= ORDER_STORAGE_RESERVE_BYTES,
            "order representation exceeds its storage reserve"
        );
        self.locked_principal_yocto = self
            .locked_principal_yocto
            .checked_add(principal.as_yoctonear())
            .expect("locked principal overflow");
        emit(
            "order_funded",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&args.order_mandate_sha256),
                "requester": requester,
                "worker": args.worker,
                "principal_yocto": args.principal.0.to_string(),
            }),
        );
        args.order_mandate_sha256
    }

    pub fn deliver(&mut self, order_mandate_sha256: [u8; 32], manifest_sha256: [u8; 32]) {
        require!(
            manifest_sha256 != [0u8; 32],
            "delivery manifest hash is zero"
        );
        let now = env::block_timestamp_ms();
        let order = self
            .orders
            .get_mut(&order_mandate_sha256)
            .expect("no such order");
        require!(env::predecessor_account_id() == order.worker, "worker only");
        require!(
            order.state == OrderState::Funded,
            "delivery requires funded state"
        );
        require!(now <= order.deadline_ms, "past the delivery deadline");
        order.state = OrderState::Delivered;
        order.delivery = Some(DeliveryRecord {
            manifest_sha256,
            delivered_at_ms: now,
        });
        emit(
            "delivery_committed",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_mandate_sha256),
                "manifest_sha256": hex32(&manifest_sha256),
            }),
        );
    }

    pub fn accept(&mut self, order_mandate_sha256: [u8; 32]) {
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(
            env::predecessor_account_id() == order.requester,
            "requester only"
        );
        require!(
            order.state == OrderState::Delivered,
            "acceptance requires delivered state"
        );
        self.ensure_automatic_round(&order_mandate_sha256, &order);
        self.apply_resolution(
            order_mandate_sha256,
            &mut order,
            Ruling::WorkerWins,
            ResolutionSource::Acceptance,
        );
    }

    #[payable]
    pub fn open_dispute(&mut self, order_mandate_sha256: [u8; 32], case_id_sha256: [u8; 32]) {
        require!(case_id_sha256 != [0u8; 32], "case id hash is zero");
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        let actor = env::predecessor_account_id();
        require!(
            actor == order.requester || actor == order.worker,
            "only an order party may dispute"
        );
        require!(
            order.state == OrderState::Delivered,
            "dispute requires delivered state"
        );
        let delivered = order.delivery.as_ref().expect("delivered state invariant");
        require!(
            now <= delivered
                .delivered_at_ms
                .saturating_add(order.acceptance_window_ms),
            "acceptance window has closed"
        );

        let held = order.dispute.clone();
        let required_bond = if let Some(existing) = held.as_ref() {
            require!(order.redo_count == 1, "held Bond is valid only after redo");
            require!(
                actor == existing.disputant,
                "original bonded disputant only"
            );
            NearToken::from_yoctonear(0)
        } else {
            NearToken::from_yoctonear(mul_bps(
                order.principal.as_yoctonear(),
                order.dispute_bond_bps,
            ))
        };
        require!(
            env::attached_deposit() == required_bond,
            "attach exactly the required dispute Bond"
        );
        if held.is_none() {
            self.locked_bonds_yocto = self
                .locked_bonds_yocto
                .checked_add(required_bond.as_yoctonear())
                .expect("locked Bond overflow");
        }
        order.state = OrderState::Disputed;
        order.dispute = Some(match held {
            Some(mut existing) => {
                existing.opened_at_ms = now;
                existing.case_id_sha256 = case_id_sha256;
                existing
            }
            None => DisputeRecord {
                disputant: actor.clone(),
                bond: required_bond,
                opened_at_ms: now,
                case_id_sha256,
            },
        });
        self.open_round(&order_mandate_sha256, &order);
        self.orders.insert(order_mandate_sha256, order);
        emit(
            "dispute_opened",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_mandate_sha256),
                "case_id_sha256": hex32(&case_id_sha256),
                "disputant": actor,
                "bond_yocto": required_bond.as_yoctonear().to_string(),
            }),
        );
    }

    /// Permissionless clean-path timeout: non-delivery refunds the requester;
    /// an unchallenged delivery releases to the worker.
    pub fn claim_timeout(&mut self, order_mandate_sha256: [u8; 32]) {
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        match order.state {
            OrderState::Funded => {
                require!(now > order.deadline_ms, "delivery deadline is still open");
                self.ensure_automatic_round(&order_mandate_sha256, &order);
                self.apply_resolution(
                    order_mandate_sha256,
                    &mut order,
                    Ruling::RequesterWins,
                    ResolutionSource::NonDeliveryTimeout,
                );
            }
            OrderState::Delivered => {
                let delivered = order.delivery.as_ref().expect("delivered state invariant");
                require!(
                    now > delivered
                        .delivered_at_ms
                        .saturating_add(order.acceptance_window_ms),
                    "acceptance window is still open"
                );
                self.ensure_automatic_round(&order_mandate_sha256, &order);
                self.apply_resolution(
                    order_mandate_sha256,
                    &mut order,
                    Ruling::WorkerWins,
                    ResolutionSource::AcceptanceTimeout,
                );
            }
            _ => env::panic_str("no clean-path timeout is available in this state"),
        }
    }

    /// Permissionless proof relay. Signatures authorize data, not the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_ruling(
        &mut self,
        order_mandate_sha256: [u8; 32],
        ruling: Ruling,
        verdict_sha256: [u8; 32],
        issued_at_ms: u64,
        nonce: [u8; 32],
        signatures: Vec<VerdictSignature>,
    ) -> [u8; 32] {
        require!(verdict_sha256 != [0u8; 32], "verdict hash is zero");
        require!(nonce != [0u8; 32], "execution nonce is zero");
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(
            order.state == OrderState::Disputed,
            "ruling requires disputed state"
        );
        let dispute = order.dispute.as_ref().expect("disputed state invariant");
        require!(
            issued_at_ms >= dispute.opened_at_ms,
            "verdict predates this dispute round"
        );
        require!(issued_at_ms <= now, "verdict issued_at is in the future");
        require!(
            now >= issued_at_ms.saturating_add(order.challenge_window_ms),
            "signed challenge window has not elapsed"
        );
        require!(
            now <= dispute
                .opened_at_ms
                .saturating_add(order.resolution_timeout_ms),
            "resolution timeout elapsed; execute the signed liveness fallback"
        );
        validate_ruling(&order, &ruling, now);

        let digest = compute_execution_digest(
            &env::current_account_id(),
            &order_mandate_sha256,
            &dispute.case_id_sha256,
            u32::from(order.redo_count) + 1,
            &ruling.canonical(),
            &verdict_sha256,
            issued_at_ms,
            &order.verifier_policy_sha256,
            &nonce,
        );
        self.verify_signatures(&digest, &signatures);
        require!(
            self.used_nonces
                .insert(nonce_key(&order_mandate_sha256, &nonce)),
            "execution nonce already used for this order"
        );
        self.apply_resolution(
            order_mandate_sha256,
            &mut order,
            ruling,
            ResolutionSource::VerifiedProof {
                verdict_sha256,
                execution_digest: digest,
                issued_at_ms,
                nonce,
            },
        );
        digest
    }

    /// Execute the order's signed outage/deadlock route after its objective
    /// resolution timeout. Fixed fallbacks are permissionless. Only the
    /// customer governance account can supply a controller-resolution branch.
    pub fn execute_liveness_fallback(
        &mut self,
        order_mandate_sha256: [u8; 32],
        controller_ruling: Option<Ruling>,
    ) {
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(
            order.state == OrderState::Disputed,
            "fallback requires disputed state"
        );
        let dispute = order.dispute.as_ref().expect("disputed state invariant");
        require!(
            now > dispute
                .opened_at_ms
                .saturating_add(order.resolution_timeout_ms),
            "resolution timeout has not elapsed"
        );
        let ruling = match order.liveness_fallback {
            LivenessFallback::RefundRequester => {
                require!(
                    controller_ruling.is_none(),
                    "fixed fallback takes no ruling"
                );
                Ruling::RequesterWins
            }
            LivenessFallback::ReleaseWorker => {
                require!(
                    controller_ruling.is_none(),
                    "fixed fallback takes no ruling"
                );
                Ruling::WorkerWins
            }
            LivenessFallback::Split5050 => {
                require!(
                    controller_ruling.is_none(),
                    "fixed fallback takes no ruling"
                );
                Ruling::Split {
                    requester_bps: 5_000,
                }
            }
            LivenessFallback::ControllerResolution => {
                require!(
                    env::predecessor_account_id() == self.config.customer_governance,
                    "customer governance only"
                );
                controller_ruling.expect("controller_resolution requires a ruling")
            }
        };
        require!(
            ruling.terminal_requester_share_bps().is_some(),
            "liveness fallback must be terminal"
        );
        validate_ruling(&order, &ruling, now);
        self.apply_resolution(
            order_mandate_sha256,
            &mut order,
            ruling,
            ResolutionSource::LivenessFallback,
        );
    }

    /// Permissionless withdrawal to the claim owner. The destination is not an
    /// argument and can never be redirected by the relayer.
    pub fn withdraw_claim(&mut self, account_id: AccountId) {
        let amount = self
            .claims
            .remove(&account_id)
            .expect("account has no claim");
        require!(!amount.is_zero(), "account has no claim");
        self.payable_claims_yocto = self
            .payable_claims_yocto
            .checked_sub(amount.as_yoctonear())
            .expect("claim accounting underflow");
        let transfer = env::promise_batch_create(&account_id);
        env::promise_batch_action_transfer(transfer, amount);
        let callback = env::promise_batch_then(transfer, &env::current_account_id());
        let callback_args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
            "account_id": account_id,
            "amount": U128(amount.as_yoctonear()),
        }))
        .expect("withdraw callback JSON cannot fail");
        env::promise_batch_action_function_call(
            callback,
            "on_withdraw_claim",
            &callback_args,
            NearToken::from_yoctonear(0),
            WITHDRAW_CALLBACK_GAS,
        );
        env::promise_return(callback);
    }

    #[private]
    pub fn on_withdraw_claim(&mut self, account_id: AccountId, amount: U128) -> bool {
        if env::promise_result_checked(0, 0).is_ok() {
            true
        } else {
            self.credit(&account_id, NearToken::from_yoctonear(amount.0));
            false
        }
    }
}

impl CustomerSettlement {
    fn order_or_panic(&self, id: &[u8; 32]) -> Order {
        self.orders.get(id).expect("no such order").clone()
    }

    fn verify_signatures(&self, digest: &[u8; 32], signatures: &[VerdictSignature]) {
        let policy = &self.config.verifier_policy;
        require!(
            signatures.len() >= usize::from(policy.quorum)
                && signatures.len() <= policy.signers.len(),
            "signature count cannot satisfy the immutable verifier policy"
        );
        let message = eth_personal_digest(digest);
        let mut seen_addresses = HashSet::new();
        let mut operators = HashSet::new();
        for entry in signatures {
            let address = normalize_eth_address(&entry.signing_address)
                .unwrap_or_else(|| env::panic_str("malformed signing address"));
            require!(
                seen_addresses.insert(address.clone()),
                "duplicate signing address"
            );
            let signer = policy
                .signers
                .iter()
                .find(|candidate| candidate.signing_address == address)
                .unwrap_or_else(|| {
                    env::panic_str("signer is not in the immutable verifier policy")
                });
            let recovered = recover_eth_address(&message, &entry.signature)
                .unwrap_or_else(|| env::panic_str("malformed or unrecoverable signature"));
            require!(
                recovered == address,
                "signature does not bind this execution digest"
            );
            operators.insert(signer.operator_id.clone());
        }
        require!(
            operators.len() >= usize::from(policy.quorum),
            "distinct-operator execution quorum not met"
        );
    }

    fn apply_resolution(
        &mut self,
        order_id: [u8; 32],
        order: &mut Order,
        ruling: Ruling,
        source: ResolutionSource,
    ) {
        let now = env::block_timestamp_ms();
        let record = ResolutionRecord {
            ruling: ruling.clone(),
            source: source.clone(),
            resolved_at_ms: now,
        };
        if let Ruling::Redo {
            new_deadline_unix_ms,
        } = ruling
        {
            require!(order.redo_count == 0, "only one redo is permitted");
            require!(
                new_deadline_unix_ms > order.deadline_ms && new_deadline_unix_ms > now,
                "redo deadline must extend the current deadline"
            );
            require!(
                new_deadline_unix_ms <= now.saturating_add(MAX_REDO_EXTENSION_MS),
                "redo deadline exceeds the maximum extension"
            );
            order.redo_count = 1;
            order.deadline_ms = new_deadline_unix_ms;
            order.state = OrderState::Funded;
            order.delivery = None;
            order.last_resolution = Some(record.clone());
            let bond = order.dispute.as_ref().expect("redo requires dispute").bond;
            self.resolve_latest_round(&order_id, record, bond);
            self.orders.insert(order_id, order.clone());
            emit(
                "redo_ordered",
                near_sdk::serde_json::json!({
                    "order_mandate_sha256": hex32(&order_id),
                    "new_deadline_ms": new_deadline_unix_ms,
                    "bond_held_yocto": bond.as_yoctonear().to_string(),
                }),
            );
            return;
        }

        let requester_share_bps = ruling
            .terminal_requester_share_bps()
            .expect("terminal ruling invariant");
        let requester_cut =
            NearToken::from_yoctonear(mul_bps(order.principal.as_yoctonear(), requester_share_bps));
        let worker_cut = order.principal.saturating_sub(requester_cut);
        self.locked_principal_yocto = self
            .locked_principal_yocto
            .checked_sub(order.principal.as_yoctonear())
            .expect("locked principal underflow");
        self.credit(&order.requester, requester_cut);
        self.credit(&order.worker, worker_cut);
        if let Some(dispute) = order.dispute.clone() {
            self.distribute_bond(order, &dispute, requester_share_bps);
        }
        order.state = OrderState::Settled;
        order.dispute = None;
        order.last_resolution = Some(record.clone());
        if self
            .rounds
            .get(&order_id)
            .map(|rounds| !rounds.is_empty())
            .unwrap_or(false)
        {
            self.resolve_latest_round(&order_id, record, NearToken::from_yoctonear(0));
        }
        self.orders.insert(order_id, order.clone());
        emit(
            "order_settled",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_id),
                "ruling": ruling.canonical(),
                "requester_claim_yocto": requester_cut.as_yoctonear().to_string(),
                "worker_claim_yocto": worker_cut.as_yoctonear().to_string(),
            }),
        );
    }

    fn distribute_bond(
        &mut self,
        order: &Order,
        dispute: &DisputeRecord,
        requester_share_bps: u16,
    ) {
        if dispute.bond.is_zero() {
            return;
        }
        self.locked_bonds_yocto = self
            .locked_bonds_yocto
            .checked_sub(dispute.bond.as_yoctonear())
            .expect("locked Bond underflow");
        let disputant_is_requester = dispute.disputant == order.requester;
        let (refund_yocto, counterparty_yocto, removal_yocto) = bond_allocation(
            dispute.bond.as_yoctonear(),
            disputant_is_requester,
            requester_share_bps,
        );
        let refund = NearToken::from_yoctonear(refund_yocto);
        let counterparty_cut = NearToken::from_yoctonear(counterparty_yocto);
        let removal_cut = NearToken::from_yoctonear(removal_yocto);
        let counterparty = if disputant_is_requester {
            order.worker.clone()
        } else {
            order.requester.clone()
        };
        self.credit(&dispute.disputant, refund);
        self.credit(&counterparty, counterparty_cut);
        let removal = self.config.removal_account.clone();
        self.credit(&removal, removal_cut);
    }

    fn credit(&mut self, account_id: &AccountId, amount: NearToken) {
        if amount.is_zero() {
            return;
        }
        let current = self
            .claims
            .get(account_id)
            .copied()
            .unwrap_or_else(|| NearToken::from_yoctonear(0));
        let next = current
            .as_yoctonear()
            .checked_add(amount.as_yoctonear())
            .expect("claim overflow");
        self.claims
            .insert(account_id.clone(), NearToken::from_yoctonear(next));
        self.payable_claims_yocto = self
            .payable_claims_yocto
            .checked_add(amount.as_yoctonear())
            .expect("claim accounting overflow");
    }

    fn open_round(&mut self, order_id: &[u8; 32], order: &Order) {
        let dispute = order.dispute.as_ref().expect("open round requires dispute");
        let mut rounds = self.rounds.get(order_id).cloned().unwrap_or_default();
        require!(rounds.len() < 2, "at most two dispute rounds are permitted");
        require!(
            rounds
                .last()
                .map(|round| round.resolution.is_some())
                .unwrap_or(true),
            "current dispute round is already open"
        );
        rounds.push(DisputeRound {
            number: (rounds.len() + 1) as u8,
            case_id_sha256: dispute.case_id_sha256,
            manifest_sha256: order
                .delivery
                .as_ref()
                .map(|delivery| delivery.manifest_sha256),
            opened_at_ms: dispute.opened_at_ms,
            resolution: None,
            bond_held_after: dispute.bond,
        });
        self.rounds.insert(*order_id, rounds);
    }

    fn ensure_automatic_round(&mut self, order_id: &[u8; 32], order: &Order) {
        if order.dispute.is_none() {
            return;
        }
        let has_open = self
            .rounds
            .get(order_id)
            .and_then(|rounds| rounds.last())
            .map(|round| round.resolution.is_none())
            .unwrap_or(false);
        if !has_open {
            self.open_round(order_id, order);
        }
    }

    fn resolve_latest_round(
        &mut self,
        order_id: &[u8; 32],
        resolution: ResolutionRecord,
        bond_held_after: NearToken,
    ) {
        let mut rounds = self
            .rounds
            .get(order_id)
            .cloned()
            .expect("missing dispute rounds");
        let round = rounds.last_mut().expect("missing current dispute round");
        require!(
            round.resolution.is_none(),
            "dispute round is already resolved"
        );
        round.resolution = Some(resolution);
        round.bond_held_after = bond_held_after;
        self.rounds.insert(*order_id, rounds);
    }
}

fn mul_bps(value: u128, basis_points: u16) -> u128 {
    let basis_points = u128::from(basis_points);
    assert!(basis_points <= BPS_DENOM, "basis points exceed 10000");
    let whole = (value / BPS_DENOM)
        .checked_mul(basis_points)
        .expect("basis-point whole-part overflow");
    let remainder = (value % BPS_DENOM)
        .checked_mul(basis_points)
        .expect("basis-point remainder overflow")
        / BPS_DENOM;
    whole
        .checked_add(remainder)
        .expect("basis-point allocation overflow")
}

fn bond_allocation(
    bond_atomic: u128,
    disputant_is_requester: bool,
    requester_share_bps: u16,
) -> (u128, u128, u128) {
    assert!(
        u128::from(requester_share_bps) <= BPS_DENOM,
        "requester share exceeds 10000 basis points"
    );
    let disputant_share_bps = if disputant_is_requester {
        requester_share_bps
    } else {
        10_000u16 - requester_share_bps
    };
    let refund = mul_bps(bond_atomic, disputant_share_bps);
    let forfeited = bond_atomic
        .checked_sub(refund)
        .expect("Bond forfeiture underflow");
    let counterparty = forfeited / 2;
    let removal = forfeited
        .checked_sub(counterparty)
        .expect("Bond removal allocation underflow");
    (refund, counterparty, removal)
}

fn validate_permitted_and_fallback(permitted: &[RulingKind], fallback: LivenessFallback) {
    require!(
        !permitted.is_empty(),
        "at least one permitted ruling is required"
    );
    require!(permitted.len() <= 4, "too many permitted rulings");
    let unique: std::collections::BTreeSet<_> = permitted.iter().copied().collect();
    require!(
        unique.len() == permitted.len(),
        "permitted rulings contain duplicates"
    );
    require!(
        permitted.iter().any(|kind| *kind != RulingKind::Redo),
        "decision space must include a terminal ruling"
    );
    match fallback {
        LivenessFallback::RefundRequester => require!(
            permitted.contains(&RulingKind::RequesterWins),
            "refund fallback must be pre-committed"
        ),
        LivenessFallback::ReleaseWorker => require!(
            permitted.contains(&RulingKind::WorkerWins),
            "release fallback must be pre-committed"
        ),
        LivenessFallback::Split5050 => require!(
            permitted.contains(&RulingKind::Split),
            "split fallback must be pre-committed"
        ),
        LivenessFallback::ControllerResolution => {}
    }
}

fn validate_ruling(order: &Order, ruling: &Ruling, now: u64) {
    require!(
        order.permitted_rulings.contains(&ruling.kind()),
        "ruling is outside the pre-committed decision space"
    );
    match ruling {
        Ruling::Split { requester_bps } => {
            require!(
                u128::from(*requester_bps) <= BPS_DENOM,
                "split bps must be <= 10000"
            )
        }
        Ruling::Redo {
            new_deadline_unix_ms,
        } => {
            require!(order.redo_count == 0, "only one redo is permitted");
            require!(
                *new_deadline_unix_ms > order.deadline_ms && *new_deadline_unix_ms > now,
                "redo deadline must extend the current deadline"
            );
            require!(
                *new_deadline_unix_ms <= now.saturating_add(MAX_REDO_EXTENSION_MS),
                "redo deadline exceeds the maximum extension"
            );
        }
        _ => {}
    }
}

/// Production execution digest. Every verdict-affecting field is fixed-width
/// or NUL-delimited so TypeScript and Rust produce identical bytes.
#[allow(clippy::too_many_arguments)]
pub fn compute_execution_digest(
    settlement_account_id: &AccountId,
    order_mandate_sha256: &[u8; 32],
    case_id_sha256: &[u8; 32],
    round: u32,
    ruling_canonical: &str,
    verdict_sha256: &[u8; 32],
    issued_at_ms: u64,
    verifier_policy_sha256: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(
        EXECUTION_DOMAIN.len()
            + settlement_account_id.as_bytes().len()
            + 1
            + 32
            + 32
            + 4
            + ruling_canonical.len()
            + 1
            + 32
            + 8
            + 32
            + 32,
    );
    preimage.extend_from_slice(EXECUTION_DOMAIN);
    preimage.extend_from_slice(settlement_account_id.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(order_mandate_sha256);
    preimage.extend_from_slice(case_id_sha256);
    preimage.extend_from_slice(&round.to_le_bytes());
    preimage.extend_from_slice(ruling_canonical.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(verdict_sha256);
    preimage.extend_from_slice(&issued_at_ms.to_le_bytes());
    preimage.extend_from_slice(verifier_policy_sha256);
    preimage.extend_from_slice(nonce);
    env::sha256_array(&preimage)
}

pub fn eth_personal_digest(digest: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(28 + 32);
    bytes.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    bytes.extend_from_slice(digest);
    env::keccak256_array(&bytes)
}

fn nonce_key(order_id: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(order_id);
    key.extend_from_slice(nonce);
    key
}

fn recover_eth_address(digest: &[u8; 32], signature_hex: &str) -> Option<String> {
    let bytes = decode_hex(signature_hex)?;
    if bytes.len() != 65 {
        return None;
    }
    let recovery_id = match bytes[64] {
        value @ (0 | 1) => value,
        value @ (27 | 28) => value - 27,
        _ => return None,
    };
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[..64]);
    let public_key = env::ecrecover(digest, &signature, recovery_id, true)?;
    let hash = env::keccak256_array(public_key);
    Some(format!("0x{}", encode_hex(&hash[12..])))
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(value.get(index..index + 2)?, 16).ok())
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        },
    )
}

fn hex32(value: &[u8; 32]) -> String {
    encode_hex(value)
}

fn emit(event: &str, data: near_sdk::serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        near_sdk::serde_json::json!({
            "standard": "edict",
            "version": "1.0.0",
            "event": event,
            "data": data,
        })
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use edict_settlement_common::{VerifierPolicy, VerifierSigner, SIGNATURE_SCHEME};
    use k256::ecdsa::{RecoveryId, SigningKey};
    use near_sdk::serde::Deserialize;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, PromiseResult};

    const START_MS: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 86_400_000;
    const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
    const BOND: u128 = ONE_NEAR / 20;

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn settlement_account() -> AccountId {
        account("locked.customer-settlement.near")
    }

    fn requester() -> AccountId {
        account("requester.near")
    }

    fn worker() -> AccountId {
        account("worker.near")
    }

    fn removal() -> AccountId {
        account("protection-pool.near")
    }

    fn governance() -> AccountId {
        account("customer-dao.near")
    }

    fn set_context(predecessor: AccountId, deposit: u128, now_ms: u64) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(settlement_account())
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .account_balance(NearToken::from_near(100))
            .block_timestamp(now_ms.saturating_mul(1_000_000));
        testing_env!(builder.build());
    }

    struct Juror {
        signing_key: SigningKey,
        address: String,
    }

    fn juror(seed: u8) -> Juror {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let signing_key = SigningKey::from_bytes(&bytes.into()).expect("valid signing key");
        let public_key = signing_key.verifying_key().to_sec1_point(false);
        let hash = env::keccak256_array(&public_key.as_bytes()[1..]);
        Juror {
            signing_key,
            address: format!("0x{}", encode_hex(&hash[12..])),
        }
    }

    fn signer(juror: &Juror, operator_id: &str, edict_controlled: bool) -> VerifierSigner {
        VerifierSigner {
            signing_address: juror.address.clone(),
            operator_id: operator_id.into(),
            edict_controlled,
            attestation_sha256: env::sha256_array(operator_id.as_bytes()),
        }
    }

    fn config(jurors: &[Juror; 3]) -> CustomerSettlementConfig {
        CustomerSettlementConfig {
            customer_governance: governance(),
            removal_account: removal(),
            verifier_policy: VerifierPolicy {
                scheme: SIGNATURE_SCHEME.into(),
                quorum: 2,
                signers: vec![
                    signer(&jurors[0], "edict", true),
                    signer(&jurors[1], "independent-a", false),
                    signer(&jurors[2], "independent-b", false),
                ],
            },
        }
    }

    fn contract() -> (CustomerSettlement, [Juror; 3]) {
        set_context(account("factory.near"), 0, START_MS);
        let jurors = [juror(1), juror(2), juror(3)];
        let contract = CustomerSettlement::new(config(&jurors));
        (contract, jurors)
    }

    fn order_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fund_args(seed: u8, fallback: LivenessFallback) -> FundOrderArgs {
        FundOrderArgs {
            order_mandate_sha256: order_id(seed),
            settlement_binding_sha256: [seed.wrapping_add(50); 32],
            worker: worker(),
            principal: U128(ONE_NEAR),
            deadline_ms: START_MS + DAY_MS,
            acceptance_window_ms: DAY_MS,
            challenge_window_ms: DAY_MS,
            resolution_timeout_ms: 3 * DAY_MS,
            liveness_fallback: fallback,
            permitted_rulings: vec![
                RulingKind::RequesterWins,
                RulingKind::WorkerWins,
                RulingKind::Split,
                RulingKind::Redo,
            ],
            dispute_bond_bps: 500,
        }
    }

    fn fund(contract: &mut CustomerSettlement, seed: u8, fallback: LivenessFallback) -> [u8; 32] {
        let args = fund_args(seed, fallback);
        let required = contract.required_funding_deposit(args.principal).0;
        set_context(requester(), required, START_MS);
        contract.fund(args)
    }

    fn deliver(contract: &mut CustomerSettlement, id: [u8; 32], now: u64) {
        set_context(worker(), 0, now);
        contract.deliver(id, [0xDD; 32]);
    }

    fn dispute(contract: &mut CustomerSettlement, id: [u8; 32], now: u64, case: u8) {
        let order = contract.get_order(id).unwrap();
        let bond = if order.dispute.is_some() { 0 } else { BOND };
        set_context(requester(), bond, now);
        contract.open_dispute(id, [case; 32]);
    }

    fn sign(juror: &Juror, message: &[u8; 32]) -> VerdictSignature {
        let (signature, recovery_id) = juror.signing_key.sign_prehash_recoverable(message);
        let normalized = signature.normalize_s();
        let recovery_id = if normalized != signature {
            RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced())
        } else {
            recovery_id
        };
        let signature = normalized;
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte());
        VerdictSignature {
            signing_address: juror.address.clone(),
            signature: format!("0x{}", encode_hex(&bytes)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proof(
        contract: &CustomerSettlement,
        jurors: &[Juror; 3],
        id: [u8; 32],
        ruling: &Ruling,
        verdict: [u8; 32],
        issued_at: u64,
        nonce: [u8; 32],
    ) -> Vec<VerdictSignature> {
        let order = contract.get_order(id).unwrap();
        let dispute = order.dispute.unwrap();
        let digest = compute_execution_digest(
            &settlement_account(),
            &id,
            &dispute.case_id_sha256,
            u32::from(order.redo_count) + 1,
            &ruling.canonical(),
            &verdict,
            issued_at,
            &order.verifier_policy_sha256,
            &nonce,
        );
        let message = eth_personal_digest(&digest);
        vec![sign(&jurors[1], &message), sign(&jurors[2], &message)]
    }

    fn submit(
        contract: &mut CustomerSettlement,
        jurors: &[Juror; 3],
        id: [u8; 32],
        ruling: Ruling,
        issued_at: u64,
        nonce: [u8; 32],
    ) -> [u8; 32] {
        let verdict = [0xA5; 32];
        let signatures = proof(contract, jurors, id, &ruling, verdict, issued_at, nonce);
        set_context(
            account("permissionless-relayer.near"),
            0,
            issued_at + DAY_MS,
        );
        contract.submit_ruling(id, ruling, verdict, issued_at, nonce, signatures)
    }

    fn setup_dispute(
        fallback: LivenessFallback,
    ) -> (CustomerSettlement, [Juror; 3], [u8; 32], u64) {
        let (mut contract, jurors) = contract();
        let id = fund(&mut contract, 1, fallback);
        deliver(&mut contract, id, START_MS + 1_000);
        let opened = START_MS + 2_000;
        dispute(&mut contract, id, opened, 7);
        (contract, jurors, id, opened)
    }

    #[test]
    fn immutable_config_and_storage_quote_are_exposed() {
        let (contract, _) = contract();
        let view = contract.get_config();
        assert_eq!(view.contract_version, CONTRACT_VERSION);
        assert_eq!(view.customer_governance, governance());
        assert_eq!(view.removal_account, removal());
        assert!(view.native_near_only);
        assert_ne!(view.verifier_policy_sha256, [0u8; 32]);
        assert!(contract.order_storage_deposit().0 > 0);
    }

    #[test]
    fn basis_point_math_handles_full_u128_values_without_overflow() {
        assert_eq!(mul_bps(u128::MAX, 10_000), u128::MAX);
        assert_eq!(mul_bps(u128::MAX, 5_000), u128::MAX / 2);
        let (refund, counterparty, removal) = bond_allocation(u128::MAX, true, 5_000);
        assert_eq!(
            refund
                .checked_add(counterparty)
                .and_then(|value| value.checked_add(removal)),
            Some(u128::MAX),
        );
    }

    #[test]
    fn fund_deliver_accept_moves_liability_to_worker_claim() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        assert_eq!(contract.accounting().locked_principal.0, ONE_NEAR);
        deliver(&mut contract, id, START_MS + 1_000);
        set_context(requester(), 0, START_MS + 2_000);
        contract.accept(id);
        assert_eq!(contract.get_order(id).unwrap().state, OrderState::Settled);
        assert_eq!(contract.claim_of(worker()).0, ONE_NEAR);
        assert_eq!(contract.accounting().locked_principal.0, 0);
        assert_eq!(contract.accounting().payable_claims.0, ONE_NEAR);
    }

    #[test]
    #[should_panic(expected = "attach exactly principal plus order_storage_deposit")]
    fn funding_requires_exact_separate_storage_collateral() {
        let (mut contract, _) = contract();
        let args = fund_args(1, LivenessFallback::RefundRequester);
        set_context(requester(), ONE_NEAR, START_MS);
        contract.fund(args);
    }

    #[test]
    #[should_panic(expected = "challenge window must be between 2 and 24 hours")]
    fn funding_rejects_a_sub_rules_challenge_window() {
        let (mut contract, _) = contract();
        let mut args = fund_args(1, LivenessFallback::RefundRequester);
        args.challenge_window_ms = MIN_CHALLENGE_WINDOW_MS - 1;
        let required = contract.required_funding_deposit(args.principal).0;
        set_context(requester(), required, START_MS);
        contract.fund(args);
    }

    #[test]
    #[should_panic(expected = "dispute Bond must be between 500 and 1000 bps")]
    fn funding_rejects_a_bond_outside_the_rules_range() {
        let (mut contract, _) = contract();
        let mut args = fund_args(1, LivenessFallback::RefundRequester);
        args.dispute_bond_bps = MIN_DISPUTE_BOND_BPS - 1;
        let required = contract.required_funding_deposit(args.principal).0;
        set_context(requester(), required, START_MS);
        contract.fund(args);
    }

    #[test]
    #[should_panic(expected = "principal is too small for a positive atomic Bond")]
    fn funding_rejects_a_principal_that_rounds_the_bond_to_zero() {
        let (mut contract, _) = contract();
        let mut args = fund_args(1, LivenessFallback::RefundRequester);
        args.principal = U128(1);
        let required = contract.required_funding_deposit(args.principal).0;
        set_context(requester(), required, START_MS);
        contract.fund(args);
    }

    #[test]
    fn clean_path_timeouts_refund_or_release() {
        let (mut no_delivery, _) = contract();
        let id = fund(&mut no_delivery, 1, LivenessFallback::RefundRequester);
        set_context(account("anyone.near"), 0, START_MS + DAY_MS + 1);
        no_delivery.claim_timeout(id);
        assert_eq!(no_delivery.claim_of(requester()).0, ONE_NEAR);

        let (mut delivered, _) = contract();
        let id = fund(&mut delivered, 2, LivenessFallback::RefundRequester);
        deliver(&mut delivered, id, START_MS + 1_000);
        set_context(account("anyone.near"), 0, START_MS + DAY_MS + 1_001);
        delivered.claim_timeout(id);
        assert_eq!(delivered.claim_of(worker()).0, ONE_NEAR);
    }

    #[test]
    fn independent_quorum_executes_requester_win_and_returns_bond() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let nonce = [0x11; 32];
        let digest = submit(
            &mut contract,
            &jurors,
            id,
            Ruling::RequesterWins,
            opened,
            nonce,
        );
        assert_ne!(digest, [0u8; 32]);
        assert!(contract.is_nonce_used(id, nonce));
        assert_eq!(contract.claim_of(requester()).0, ONE_NEAR + BOND);
        assert_eq!(contract.claim_of(worker()).0, 0);
        assert_eq!(contract.accounting().locked_bonds.0, 0);
    }

    #[test]
    fn losing_bond_is_split_between_counterparty_and_removal_account() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::WorkerWins,
            opened,
            [0x12; 32],
        );
        assert_eq!(contract.claim_of(requester()).0, 0);
        assert_eq!(contract.claim_of(worker()).0, ONE_NEAR + BOND / 2);
        assert_eq!(contract.claim_of(removal()).0, BOND - BOND / 2);
    }

    #[test]
    fn split_ruling_allocates_principal_and_bond_pro_rata() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Split {
                requester_bps: 7_500,
            },
            opened,
            [0x13; 32],
        );
        let refund = BOND * 7_500 / 10_000;
        let forfeited = BOND - refund;
        assert_eq!(contract.claim_of(requester()).0, ONE_NEAR * 3 / 4 + refund);
        assert_eq!(contract.claim_of(worker()).0, ONE_NEAR / 4 + forfeited / 2);
        assert_eq!(contract.claim_of(removal()).0, forfeited - forfeited / 2);
    }

    #[test]
    fn redo_holds_principal_and_original_bond_through_round_two() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: opened + 5 * DAY_MS,
            },
            opened,
            [0x14; 32],
        );
        let after_redo = contract.get_order(id).unwrap();
        assert_eq!(after_redo.state, OrderState::Funded);
        assert_eq!(after_redo.redo_count, 1);
        assert_eq!(contract.accounting().locked_principal.0, ONE_NEAR);
        assert_eq!(contract.accounting().locked_bonds.0, BOND);
        assert_eq!(
            contract.get_rounds(id)[0].bond_held_after.as_yoctonear(),
            BOND
        );

        let second_delivery = opened + DAY_MS + 10;
        deliver(&mut contract, id, second_delivery);
        dispute(&mut contract, id, second_delivery + 10, 8);
        let second_opened = second_delivery + 10;
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::WorkerWins,
            second_opened,
            [0x15; 32],
        );
        assert_eq!(contract.get_rounds(id).len(), 2);
        assert_eq!(contract.get_order(id).unwrap().state, OrderState::Settled);
        assert_eq!(contract.accounting().locked_bonds.0, 0);
    }

    #[test]
    fn redo_non_delivery_timeout_resolves_round_two_and_original_bond() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let redo_deadline = opened + 4 * DAY_MS;
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: redo_deadline,
            },
            opened,
            [0x16; 32],
        );
        set_context(account("anyone.near"), 0, redo_deadline + 1);
        contract.claim_timeout(id);
        let rounds = contract.get_rounds(id);
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[1].manifest_sha256, None);
        assert_eq!(contract.claim_of(requester()).0, ONE_NEAR + BOND);
    }

    #[test]
    #[should_panic(expected = "signed challenge window has not elapsed")]
    fn proof_cannot_execute_during_challenge_window() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let ruling = Ruling::RequesterWins;
        let verdict = [0xA5; 32];
        let nonce = [0x17; 32];
        let signatures = proof(&contract, &jurors, id, &ruling, verdict, opened, nonce);
        set_context(account("relayer.near"), 0, opened + DAY_MS - 1);
        contract.submit_ruling(id, ruling, verdict, opened, nonce, signatures);
    }

    #[test]
    #[should_panic(expected = "signature does not bind this execution digest")]
    fn changed_ruling_invalidates_every_signature() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let signed = Ruling::RequesterWins;
        let verdict = [0xA5; 32];
        let nonce = [0x18; 32];
        let signatures = proof(&contract, &jurors, id, &signed, verdict, opened, nonce);
        set_context(account("relayer.near"), 0, opened + DAY_MS);
        contract.submit_ruling(id, Ruling::WorkerWins, verdict, opened, nonce, signatures);
    }

    #[test]
    #[should_panic(expected = "signature does not bind this execution digest")]
    fn changed_verdict_hash_invalidates_every_signature() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let ruling = Ruling::RequesterWins;
        let nonce = [0x21; 32];
        let signatures = proof(&contract, &jurors, id, &ruling, [0xA5; 32], opened, nonce);
        set_context(account("relayer.near"), 0, opened + DAY_MS);
        contract.submit_ruling(id, ruling, [0xB6; 32], opened, nonce, signatures);
    }

    #[test]
    #[should_panic(expected = "duplicate signing address")]
    fn duplicate_signature_does_not_inflate_quorum() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let ruling = Ruling::RequesterWins;
        let verdict = [0xA5; 32];
        let nonce = [0x19; 32];
        let mut signatures = proof(&contract, &jurors, id, &ruling, verdict, opened, nonce);
        signatures[1] = signatures[0].clone();
        set_context(account("relayer.near"), 0, opened + DAY_MS);
        contract.submit_ruling(id, ruling, verdict, opened, nonce, signatures);
    }

    #[test]
    #[should_panic(expected = "signature count cannot satisfy")]
    fn edict_signer_is_neither_sufficient_nor_required() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let ruling = Ruling::RequesterWins;
        let verdict = [0xA5; 32];
        let nonce = [0x22; 32];
        let order = contract.get_order(id).unwrap();
        let dispute = order.dispute.unwrap();
        let digest = compute_execution_digest(
            &settlement_account(),
            &id,
            &dispute.case_id_sha256,
            1,
            &ruling.canonical(),
            &verdict,
            opened,
            &order.verifier_policy_sha256,
            &nonce,
        );
        let only_edict = vec![sign(&jurors[0], &eth_personal_digest(&digest))];
        set_context(account("relayer.near"), 0, opened + DAY_MS);
        contract.submit_ruling(id, ruling, verdict, opened, nonce, only_edict);
    }

    #[test]
    #[should_panic(expected = "execution nonce already used")]
    fn nonce_cannot_be_replayed_across_redo_rounds() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let nonce = [0x23; 32];
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: opened + 5 * DAY_MS,
            },
            opened,
            nonce,
        );
        let delivered_at = opened + DAY_MS + 10;
        deliver(&mut contract, id, delivered_at);
        let second_opened = delivered_at + 10;
        dispute(&mut contract, id, second_opened, 9);
        let ruling = Ruling::WorkerWins;
        let verdict = [0xA5; 32];
        let signatures = proof(
            &contract,
            &jurors,
            id,
            &ruling,
            verdict,
            second_opened,
            nonce,
        );
        set_context(account("relayer.near"), 0, second_opened + DAY_MS);
        contract.submit_ruling(id, ruling, verdict, second_opened, nonce, signatures);
    }

    #[test]
    #[should_panic(expected = "only one redo is permitted")]
    fn a_second_redo_is_rejected_even_with_a_valid_quorum() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: opened + 5 * DAY_MS,
            },
            opened,
            [0x24; 32],
        );
        let delivered_at = opened + DAY_MS + 10;
        deliver(&mut contract, id, delivered_at);
        let second_opened = delivered_at + 10;
        dispute(&mut contract, id, second_opened, 10);
        let _ = submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: opened + 6 * DAY_MS,
            },
            second_opened,
            [0x25; 32],
        );
    }

    #[test]
    fn fixed_liveness_fallback_is_permissionless_and_terminal() {
        let (mut contract, _, id, opened) = setup_dispute(LivenessFallback::Split5050);
        set_context(
            account("independent-relayer.near"),
            0,
            opened + 3 * DAY_MS + 1,
        );
        contract.execute_liveness_fallback(id, None);
        assert_eq!(contract.claim_of(requester()).0, ONE_NEAR / 2 + BOND / 2);
        let forfeited = BOND / 2;
        assert_eq!(contract.claim_of(worker()).0, ONE_NEAR / 2 + forfeited / 2);
        assert_eq!(contract.claim_of(removal()).0, forfeited - forfeited / 2);
    }

    #[test]
    #[should_panic(expected = "customer governance only")]
    fn controller_fallback_cannot_be_exercised_by_edict_or_a_relayer() {
        let (mut contract, _, id, opened) = setup_dispute(LivenessFallback::ControllerResolution);
        set_context(account("edict-relayer.near"), 0, opened + 3 * DAY_MS + 1);
        contract.execute_liveness_fallback(id, Some(Ruling::RequesterWins));
    }

    #[test]
    fn customer_controller_fallback_stays_inside_permitted_branches() {
        let (mut contract, _, id, opened) = setup_dispute(LivenessFallback::ControllerResolution);
        set_context(governance(), 0, opened + 3 * DAY_MS + 1);
        contract.execute_liveness_fallback(
            id,
            Some(Ruling::Split {
                requester_bps: 6_000,
            }),
        );
        assert_eq!(contract.get_order(id).unwrap().state, OrderState::Settled);
    }

    #[test]
    #[should_panic(expected = "outside the pre-committed decision space")]
    fn customer_controller_cannot_invent_an_uncommitted_branch() {
        let (mut contract, _) = contract();
        let mut args = fund_args(3, LivenessFallback::ControllerResolution);
        args.permitted_rulings = vec![RulingKind::RequesterWins];
        let required = contract.required_funding_deposit(args.principal).0;
        set_context(requester(), required, START_MS);
        let id = contract.fund(args);
        deliver(&mut contract, id, START_MS + 1_000);
        dispute(&mut contract, id, START_MS + 2_000, 11);
        set_context(governance(), 0, START_MS + 2_000 + 3 * DAY_MS + 1);
        contract.execute_liveness_fallback(id, Some(Ruling::WorkerWins));
    }

    #[test]
    #[should_panic(expected = "resolution timeout elapsed")]
    fn proof_cannot_race_the_fallback_after_resolution_timeout() {
        let (mut contract, jurors, id, opened) = setup_dispute(LivenessFallback::RefundRequester);
        let ruling = Ruling::RequesterWins;
        let verdict = [0xA5; 32];
        let nonce = [0x20; 32];
        let signatures = proof(&contract, &jurors, id, &ruling, verdict, opened, nonce);
        set_context(account("relayer.near"), 0, opened + 3 * DAY_MS + 1);
        contract.submit_ruling(id, ruling, verdict, opened, nonce, signatures);
    }

    #[test]
    fn failed_claim_transfer_restores_exact_owner_claim() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        deliver(&mut contract, id, START_MS + 1_000);
        set_context(requester(), 0, START_MS + 2_000);
        contract.accept(id);
        set_context(account("relayer.near"), 0, START_MS + 3_000);
        contract.withdraw_claim(worker());
        assert_eq!(contract.claim_of(worker()).0, 0);

        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(settlement_account())
            .signer_account_id(settlement_account())
            .predecessor_account_id(settlement_account())
            .account_balance(NearToken::from_near(100))
            .block_timestamp((START_MS + 4_000) * 1_000_000);
        testing_env!(
            builder.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            std::collections::HashMap::default(),
            vec![PromiseResult::Failed],
        );
        assert!(!contract.on_withdraw_claim(worker(), U128(ONE_NEAR)));
        assert_eq!(contract.claim_of(worker()).0, ONE_NEAR);
        assert_eq!(contract.accounting().payable_claims.0, ONE_NEAR);
    }

    #[test]
    fn digest_binds_account_order_case_round_policy_time_and_nonce() {
        set_context(account("anyone.near"), 0, START_MS);
        let base = compute_execution_digest(
            &settlement_account(),
            &[1; 32],
            &[2; 32],
            1,
            "split:2500",
            &[3; 32],
            START_MS,
            &[4; 32],
            &[5; 32],
        );
        let changed = compute_execution_digest(
            &settlement_account(),
            &[1; 32],
            &[2; 32],
            2,
            "split:2500",
            &[3; 32],
            START_MS,
            &[4; 32],
            &[5; 32],
        );
        assert_ne!(base, changed);
        assert_eq!(
            encode_hex(&base),
            "16964bc5fb584f55c88cc6535482b781abb996d032bbf4511b124143febe2ea7"
        );
        assert_eq!(
            base,
            compute_execution_digest(
                &settlement_account(),
                &[1; 32],
                &[2; 32],
                1,
                "split:2500",
                &[3; 32],
                START_MS,
                &[4; 32],
                &[5; 32],
            )
        );
    }

    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
    struct EconomicsVectors {
        principal_atomic: String,
        bond_atomic: String,
        vectors: Vec<EconomicsVector>,
    }

    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
    struct EconomicsVector {
        requester_bps: u16,
        disputant: String,
        requester_principal_atomic: String,
        worker_principal_atomic: String,
        bond_refund_atomic: String,
        bond_to_counterparty_atomic: String,
        bond_to_removal_atomic: String,
    }

    #[test]
    fn economics_match_the_shared_cross_language_vectors() {
        let fixture: EconomicsVectors = near_sdk::serde_json::from_str(include_str!(
            "../../../SETTLEMENT_ECONOMICS_VECTORS.json"
        ))
        .unwrap();
        let principal = fixture.principal_atomic.parse::<u128>().unwrap();
        let bond = fixture.bond_atomic.parse::<u128>().unwrap();
        for vector in fixture.vectors {
            let requester = mul_bps(principal, vector.requester_bps);
            let worker = principal - requester;
            let (refund, counterparty, removal) =
                bond_allocation(bond, vector.disputant == "requester", vector.requester_bps);
            assert_eq!(
                requester,
                vector.requester_principal_atomic.parse().unwrap()
            );
            assert_eq!(worker, vector.worker_principal_atomic.parse().unwrap());
            assert_eq!(refund, vector.bond_refund_atomic.parse().unwrap());
            assert_eq!(
                counterparty,
                vector.bond_to_counterparty_atomic.parse().unwrap()
            );
            assert_eq!(removal, vector.bond_to_removal_atomic.parse().unwrap());
            assert_eq!(refund + counterparty + removal, bond);
        }
    }
}
