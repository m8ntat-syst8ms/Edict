//! # Edict customer settlement over NEAR Intents
//!
//! A keyless, immutable settlement state machine whose monetary liabilities
//! live in one account inside the configured NEAR Intents Verifier. Principal
//! and first-round Bonds can enter only through Verifier `mt_on_transfer`;
//! role-authenticated non-monetary actions enter through Verifier `on_auth`.
//! Claims can leave only through `mt_transfer` to their fixed Intents owner.
//!
//! The contract has no owner, upgrade, pause, freeze, signer-admission,
//! arbitrary destination or generic cross-contract-call method. Edict may
//! relay proofs and claim transfers through permissionless methods, but owns no
//! credential needed for correctness or liveness.

use edict_intents_settlement_common::{
    required_instance_balance, validate_intents_config, IntentsSettlementConfig,
    INTENTS_SETTLEMENT_VERSION, ORDER_STORAGE_RESERVE_BYTES,
};
use edict_settlement_common::{
    normalize_eth_address, verifier_policy_sha256, LivenessFallback, Ruling, RulingKind,
    VerdictSignature,
};
use near_sdk::json_types::U128;
use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault};
use std::collections::HashSet;

pub const BPS_DENOM: u128 = 10_000;
pub const EXECUTION_DOMAIN: &[u8] = b"EDICT_SETTLEMENT_V1";
pub const MAX_ORDER_HORIZON_MS: u64 = 365 * 24 * 60 * 60 * 1_000;
pub const MAX_POLICY_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_REDO_EXTENSION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const MIN_CHALLENGE_WINDOW_MS: u64 = 2 * 60 * 60 * 1_000;
pub const MAX_CHALLENGE_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MIN_DISPUTE_BOND_BPS: u16 = 500;
pub const MAX_DISPUTE_BOND_BPS: u16 = 1_000;
pub const FUNDING_MESSAGE_VERSION: &str = "edict-intents-funding-1";
pub const MAX_ACTION_MESSAGE_BYTES: usize = 16_384;

const INTENTS_TRANSFER_GAS: Gas = Gas::from_tgas(35);
const CLAIM_CALLBACK_GAS: Gas = Gas::from_tgas(10);

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
    pub disputant: AccountId,
    pub bond: U128,
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
    pub bond_held_after: U128,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub order_mandate_sha256: [u8; 32],
    pub settlement_binding_sha256: [u8; 32],
    pub requester: AccountId,
    pub worker: AccountId,
    pub principal: U128,
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

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde", tag = "action", rename_all = "snake_case")]
enum TransferAction {
    Fund {
        args: FundOrderArgs,
    },
    OpenDispute {
        order_mandate_sha256: [u8; 32],
        case_id_sha256: [u8; 32],
    },
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct TransferEnvelope {
    version: String,
    #[serde(flatten)]
    action: TransferAction,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde", tag = "action", rename_all = "snake_case")]
enum AuthAction {
    Deliver {
        order_mandate_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
    },
    Accept {
        order_mandate_sha256: [u8; 32],
    },
    OpenHeldDispute {
        order_mandate_sha256: [u8; 32],
        case_id_sha256: [u8; 32],
    },
    ControllerFallback {
        order_mandate_sha256: [u8; 32],
        ruling: Ruling,
    },
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct AuthEnvelope {
    version: String,
    #[serde(flatten)]
    action: AuthAction,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ConfigView {
    pub contract_version: String,
    pub customer_governance: AccountId,
    pub removal_account: AccountId,
    pub intents_contract: AccountId,
    pub settlement_token_id: String,
    pub max_orders: u32,
    pub order_count: u32,
    pub verifier_policy: edict_settlement_common::VerifierPolicy,
    pub verifier_policy_sha256: [u8; 32],
    pub native_near_only: bool,
    pub keyless_intents_account: bool,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AccountingView {
    pub locked_principal: U128,
    pub locked_bonds: U128,
    pub payable_claims: U128,
    pub total_liability: U128,
    pub remaining_order_capacity: u32,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct IntentsSettlement {
    config: IntentsSettlementConfig,
    verifier_policy_sha256: [u8; 32],
    orders: LookupMap<[u8; 32], Order>,
    rounds: LookupMap<[u8; 32], Vec<DisputeRound>>,
    used_nonces: LookupSet<Vec<u8>>,
    claims: LookupMap<AccountId, u128>,
    pending_claims: LookupMap<AccountId, u128>,
    locked_principal: u128,
    locked_bonds: u128,
    payable_claims: u128,
    order_count: u32,
}

#[near]
impl IntentsSettlement {
    #[init]
    pub fn new(config: IntentsSettlementConfig) -> Self {
        if let Err(problem) = validate_intents_config(&config) {
            env::panic_str(&problem);
        }
        require!(
            config.customer.customer_governance != env::current_account_id(),
            "customer governance must be external to the keyless settlement account"
        );
        require!(
            config.customer.removal_account != env::current_account_id(),
            "removal account must be external to the keyless settlement account"
        );
        require!(
            config.intents_contract != env::current_account_id(),
            "intents contract must be external to the settlement account"
        );
        let required_reserve = calculate_instance_reserve(&config);
        require!(
            env::account_balance().as_yoctonear() >= required_reserve,
            "instance balance is below its immutable order-capacity reserve"
        );
        let policy_hash = verifier_policy_sha256(&config.customer.verifier_policy);
        Self {
            config,
            verifier_policy_sha256: policy_hash,
            orders: LookupMap::new(b"o"),
            rounds: LookupMap::new(b"r"),
            used_nonces: LookupSet::new(b"n"),
            claims: LookupMap::new(b"c"),
            pending_claims: LookupMap::new(b"p"),
            locked_principal: 0,
            locked_bonds: 0,
            payable_claims: 0,
            order_count: 0,
        }
    }

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            contract_version: INTENTS_SETTLEMENT_VERSION.into(),
            customer_governance: self.config.customer.customer_governance.clone(),
            removal_account: self.config.customer.removal_account.clone(),
            intents_contract: self.config.intents_contract.clone(),
            settlement_token_id: self.config.settlement_token_id.clone(),
            max_orders: self.config.max_orders,
            order_count: self.order_count,
            verifier_policy: self.config.customer.verifier_policy.clone(),
            verifier_policy_sha256: self.verifier_policy_sha256,
            native_near_only: false,
            keyless_intents_account: true,
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
        U128(self.claims.get(&account_id).copied().unwrap_or(0))
    }

    pub fn pending_claim_of(&self, account_id: AccountId) -> U128 {
        U128(self.pending_claims.get(&account_id).copied().unwrap_or(0))
    }

    pub fn accounting(&self) -> AccountingView {
        let total = self
            .locked_principal
            .checked_add(self.locked_bonds)
            .and_then(|value| value.checked_add(self.payable_claims))
            .expect("liability accounting overflow");
        AccountingView {
            locked_principal: U128(self.locked_principal),
            locked_bonds: U128(self.locked_bonds),
            payable_claims: U128(self.payable_claims),
            total_liability: U128(total),
            remaining_order_capacity: self.config.max_orders - self.order_count,
        }
    }

    pub fn required_instance_reserve(&self) -> U128 {
        U128(calculate_instance_reserve(&self.config))
    }

    pub fn is_nonce_used(&self, order_mandate_sha256: [u8; 32], nonce: [u8; 32]) -> bool {
        self.used_nonces
            .contains(&nonce_key(&order_mandate_sha256, &nonce))
    }

    /// NEP-245 receiver invoked only by the immutable Intents Verifier.
    pub fn mt_on_transfer(
        &mut self,
        sender_id: AccountId,
        previous_owner_ids: Vec<AccountId>,
        token_ids: Vec<String>,
        amounts: Vec<U128>,
        msg: String,
    ) -> Vec<U128> {
        require!(
            env::predecessor_account_id() == self.config.intents_contract,
            "mt_on_transfer may only be called by the configured Intents contract"
        );
        require!(
            previous_owner_ids.len() == 1 && token_ids.len() == 1 && amounts.len() == 1,
            "exactly one token transfer is required"
        );
        require!(
            previous_owner_ids[0] == sender_id,
            "Intents sender and previous owner must match"
        );
        require!(
            token_ids[0] == self.config.settlement_token_id,
            "unexpected settlement token"
        );
        require!(amounts[0].0 > 0, "transfer amount must be positive");
        require!(
            msg.len() <= MAX_ACTION_MESSAGE_BYTES,
            "settlement transfer message is too large"
        );
        let envelope: TransferEnvelope =
            near_sdk::serde_json::from_str(&msg).expect("malformed settlement transfer message");
        require!(
            envelope.version == FUNDING_MESSAGE_VERSION,
            "unsupported settlement transfer message version"
        );
        match envelope.action {
            TransferAction::Fund { args } => {
                require!(
                    args.principal == amounts[0],
                    "principal does not match transfer"
                );
                self.internal_fund(sender_id, args);
            }
            TransferAction::OpenDispute {
                order_mandate_sha256,
                case_id_sha256,
            } => self.internal_open_first_dispute(
                sender_id,
                order_mandate_sha256,
                case_id_sha256,
                amounts[0],
            ),
        }
        vec![U128(0)]
    }

    /// Verifier-authenticated non-monetary party actions for any supported key standard.
    pub fn on_auth(&mut self, signer_id: AccountId, msg: String) -> bool {
        require!(
            env::predecessor_account_id() == self.config.intents_contract,
            "on_auth may only be called by the configured Intents contract"
        );
        require!(
            env::attached_deposit().is_zero(),
            "on_auth must not attach native NEAR"
        );
        require!(
            msg.len() <= MAX_ACTION_MESSAGE_BYTES,
            "settlement auth message is too large"
        );
        let envelope: AuthEnvelope =
            near_sdk::serde_json::from_str(&msg).expect("malformed settlement auth message");
        require!(
            envelope.version == FUNDING_MESSAGE_VERSION,
            "unsupported settlement auth message version"
        );
        match envelope.action {
            AuthAction::Deliver {
                order_mandate_sha256,
                manifest_sha256,
            } => self.internal_deliver(signer_id, order_mandate_sha256, manifest_sha256),
            AuthAction::Accept {
                order_mandate_sha256,
            } => self.internal_accept(signer_id, order_mandate_sha256),
            AuthAction::OpenHeldDispute {
                order_mandate_sha256,
                case_id_sha256,
            } => self.internal_open_held_dispute(signer_id, order_mandate_sha256, case_id_sha256),
            AuthAction::ControllerFallback {
                order_mandate_sha256,
                ruling,
            } => self.internal_execute_liveness_fallback(
                signer_id,
                order_mandate_sha256,
                Some(ruling),
            ),
        }
        true
    }

    pub fn deliver(&mut self, order_mandate_sha256: [u8; 32], manifest_sha256: [u8; 32]) {
        self.internal_deliver(
            env::predecessor_account_id(),
            order_mandate_sha256,
            manifest_sha256,
        );
    }

    pub fn accept(&mut self, order_mandate_sha256: [u8; 32]) {
        self.internal_accept(env::predecessor_account_id(), order_mandate_sha256);
    }

    pub fn open_held_dispute(&mut self, order_mandate_sha256: [u8; 32], case_id_sha256: [u8; 32]) {
        self.internal_open_held_dispute(
            env::predecessor_account_id(),
            order_mandate_sha256,
            case_id_sha256,
        );
    }

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

    /// Permissionless proof relay; signatures authorize the data, not the caller.
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

    pub fn execute_liveness_fallback(
        &mut self,
        order_mandate_sha256: [u8; 32],
        controller_ruling: Option<Ruling>,
    ) {
        self.internal_execute_liveness_fallback(
            env::predecessor_account_id(),
            order_mandate_sha256,
            controller_ruling,
        );
    }

    /// Anyone may trigger a claim, but the recipient is the fixed claim owner.
    pub fn withdraw_claim(&mut self, account_id: AccountId) {
        require!(
            self.pending_claims.get(&account_id).is_none(),
            "account already has a pending claim transfer"
        );
        let amount = self
            .claims
            .remove(&account_id)
            .expect("account has no claim");
        require!(amount > 0, "account has no claim");
        self.pending_claims.insert(account_id.clone(), amount);
        let transfer_args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
            "receiver_id": account_id,
            "token_id": self.config.settlement_token_id,
            "amount": U128(amount),
            "approval": null,
            "memo": "edict-settlement-claim",
        }))
        .expect("claim transfer JSON cannot fail");
        let transfer = env::promise_batch_create(&self.config.intents_contract);
        env::promise_batch_action_function_call(
            transfer,
            "mt_transfer",
            &transfer_args,
            NearToken::from_yoctonear(1),
            INTENTS_TRANSFER_GAS,
        );
        let callback = env::promise_batch_then(transfer, &env::current_account_id());
        let callback_args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({
            "account_id": account_id,
            "amount": U128(amount),
        }))
        .expect("claim callback JSON cannot fail");
        env::promise_batch_action_function_call(
            callback,
            "on_claim_transfer",
            &callback_args,
            NearToken::ZERO,
            CLAIM_CALLBACK_GAS,
        );
        env::promise_return(callback);
    }

    #[private]
    pub fn on_claim_transfer(&mut self, account_id: AccountId, amount: U128) -> bool {
        let pending = self
            .pending_claims
            .remove(&account_id)
            .expect("missing pending claim transfer");
        require!(
            pending == amount.0,
            "pending claim callback amount mismatch"
        );
        if env::promise_result_checked(0, 0).is_ok() {
            self.payable_claims = self
                .payable_claims
                .checked_sub(amount.0)
                .expect("claim accounting underflow");
            true
        } else {
            let current = self.claims.get(&account_id).copied().unwrap_or(0);
            self.claims.insert(
                account_id,
                current
                    .checked_add(amount.0)
                    .expect("claim restore overflow"),
            );
            false
        }
    }
}

fn calculate_instance_reserve(config: &IntentsSettlementConfig) -> u128 {
    required_instance_balance(config, env::storage_byte_cost().as_yoctonear())
        .expect("instance reserve overflow")
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

fn required_bond(principal: u128, dispute_bond_bps: u16) -> u128 {
    mul_bps(principal, dispute_bond_bps)
}

pub fn bond_allocation(
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
        Ruling::Split { requester_bps } => require!(
            u128::from(*requester_bps) <= BPS_DENOM,
            "split bps must be <= 10000"
        ),
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
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use edict_settlement_common::{
        CustomerSettlementConfig, VerifierPolicy, VerifierSigner, SIGNATURE_SCHEME,
    };
    use k256::ecdsa::{RecoveryId, SigningKey};
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    const START_MS: u64 = 1_800_000_000_000;
    const DAY_MS: u64 = 86_400_000;
    const PRINCIPAL: u128 = 10_000;
    const BOND: u128 = 500;
    const TOKEN: &str = "nep141:usdc.omft.near";

    fn account(value: &str) -> AccountId {
        value.parse().unwrap()
    }

    fn settlement_account() -> AccountId {
        account("locked.intents-settlement.near")
    }

    fn intents() -> AccountId {
        account("intents.near")
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

    fn set_context(predecessor: AccountId, now_ms: u64) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(settlement_account())
            .signer_account_id(predecessor.clone())
            .predecessor_account_id(predecessor)
            .account_balance(NearToken::from_near(100))
            .block_timestamp(now_ms.saturating_mul(1_000_000));
        testing_env!(builder.build());
    }

    fn set_claim_callback_context(result: PromiseResult, now_ms: u64) {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(settlement_account())
            .signer_account_id(settlement_account())
            .predecessor_account_id(settlement_account())
            .account_balance(NearToken::from_near(100))
            .block_timestamp(now_ms * 1_000_000);
        testing_env!(
            builder.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            std::collections::HashMap::default(),
            vec![result],
        );
    }

    struct Juror {
        signing_key: SigningKey,
        address: String,
    }

    fn juror(seed: u8) -> Juror {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let signing_key = SigningKey::from_bytes(&bytes.into()).expect("valid signing key");
        let public_key = signing_key.verifying_key().to_encoded_point(false);
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

    fn config(jurors: &[Juror; 3], max_orders: u32) -> IntentsSettlementConfig {
        IntentsSettlementConfig {
            customer: CustomerSettlementConfig {
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
            },
            intents_contract: intents(),
            settlement_token_id: TOKEN.into(),
            max_orders,
        }
    }

    fn contract_with_capacity(max_orders: u32) -> (IntentsSettlement, [Juror; 3]) {
        set_context(account("factory.near"), START_MS);
        let jurors = [juror(1), juror(2), juror(3)];
        let contract = IntentsSettlement::new(config(&jurors, max_orders));
        (contract, jurors)
    }

    fn contract() -> (IntentsSettlement, [Juror; 3]) {
        contract_with_capacity(100)
    }

    fn order_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fund_args(seed: u8, fallback: LivenessFallback) -> FundOrderArgs {
        FundOrderArgs {
            order_mandate_sha256: order_id(seed),
            settlement_binding_sha256: [seed.wrapping_add(50); 32],
            worker: worker(),
            principal: U128(PRINCIPAL),
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

    fn transfer(
        contract: &mut IntentsSettlement,
        sender: AccountId,
        amount: u128,
        msg: String,
        now: u64,
    ) {
        set_context(intents(), now);
        let result = contract.mt_on_transfer(
            sender.clone(),
            vec![sender],
            vec![TOKEN.into()],
            vec![U128(amount)],
            msg,
        );
        assert_eq!(result, vec![U128(0)]);
    }

    fn fund(contract: &mut IntentsSettlement, seed: u8, fallback: LivenessFallback) -> [u8; 32] {
        let args = fund_args(seed, fallback);
        let id = args.order_mandate_sha256;
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-1",
            "action": "fund",
            "args": args,
        })
        .to_string();
        transfer(contract, requester(), PRINCIPAL, msg, START_MS);
        id
    }

    fn deliver(contract: &mut IntentsSettlement, id: [u8; 32], now: u64) {
        set_context(intents(), now);
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-1",
            "action": "deliver",
            "order_mandate_sha256": id,
            "manifest_sha256": vec![0xDD; 32],
        })
        .to_string();
        assert!(contract.on_auth(worker(), msg));
    }

    fn dispute(contract: &mut IntentsSettlement, id: [u8; 32], now: u64, case: u8) {
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-1",
            "action": "open_dispute",
            "order_mandate_sha256": id,
            "case_id_sha256": vec![case; 32],
        })
        .to_string();
        transfer(contract, requester(), BOND, msg, now);
    }

    fn sign(juror: &Juror, message: &[u8; 32]) -> VerdictSignature {
        let (signature, recovery_id) = juror
            .signing_key
            .sign_prehash_recoverable(message)
            .expect("signing succeeds");
        let (signature, recovery_id) = match signature.normalize_s() {
            Some(normalized) => (
                normalized,
                RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced()),
            ),
            None => (signature, recovery_id),
        };
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte());
        VerdictSignature {
            signing_address: juror.address.clone(),
            signature: format!("0x{}", encode_hex(&bytes)),
        }
    }

    fn proof(
        contract: &IntentsSettlement,
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
        contract: &mut IntentsSettlement,
        jurors: &[Juror; 3],
        id: [u8; 32],
        ruling: Ruling,
        issued_at: u64,
        nonce: [u8; 32],
    ) {
        let verdict = [0xA5; 32];
        let signatures = proof(contract, jurors, id, &ruling, verdict, issued_at, nonce);
        set_context(account("permissionless-relayer.near"), issued_at + DAY_MS);
        contract.submit_ruling(id, ruling, verdict, issued_at, nonce, signatures);
    }

    fn setup_dispute() -> (IntentsSettlement, [Juror; 3], [u8; 32], u64) {
        let (mut contract, jurors) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        deliver(&mut contract, id, START_MS + 1_000);
        let opened = START_MS + 2_000;
        dispute(&mut contract, id, opened, 7);
        (contract, jurors, id, opened)
    }

    #[test]
    fn immutable_config_and_reserve_are_exposed() {
        let (contract, _) = contract();
        let view = contract.get_config();
        assert_eq!(view.contract_version, INTENTS_SETTLEMENT_VERSION);
        assert_eq!(view.intents_contract, intents());
        assert_eq!(view.settlement_token_id, TOKEN);
        assert!(!view.native_near_only);
        assert!(view.keyless_intents_account);
        assert!(
            contract.required_instance_reserve().0
                > edict_intents_settlement_common::MIN_OPERATIONAL_RESERVE_YOCTO
        );
    }

    #[test]
    fn maximum_u128_principal_can_reach_a_terminal_claim_without_overflow() {
        let (mut contract, _) = contract();
        let mut args = fund_args(17, LivenessFallback::RefundRequester);
        args.principal = U128(u128::MAX);
        let id = args.order_mandate_sha256;
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-1",
            "action": "fund",
            "args": args,
        })
        .to_string();
        transfer(&mut contract, requester(), u128::MAX, msg, START_MS);
        set_context(
            account("permissionless-timeout.near"),
            START_MS + DAY_MS + 1,
        );
        contract.claim_timeout(id);
        assert_eq!(contract.claim_of(requester()).0, u128::MAX);
        assert_eq!(contract.accounting().total_liability.0, u128::MAX);

        let (refund, counterparty, removal) = bond_allocation(u128::MAX, true, 5_000);
        assert_eq!(
            refund
                .checked_add(counterparty)
                .and_then(|value| value.checked_add(removal)),
            Some(u128::MAX),
        );
    }

    #[test]
    fn transfer_funding_and_authenticated_accept_create_fixed_worker_claim() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        assert_eq!(contract.accounting().locked_principal.0, PRINCIPAL);
        deliver(&mut contract, id, START_MS + 1_000);
        set_context(intents(), START_MS + 2_000);
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-1",
            "action": "accept",
            "order_mandate_sha256": id,
        })
        .to_string();
        contract.on_auth(requester(), msg);
        assert_eq!(contract.claim_of(worker()).0, PRINCIPAL);
        assert_eq!(contract.accounting().total_liability.0, PRINCIPAL);
    }

    #[test]
    #[should_panic(expected = "unexpected settlement token")]
    fn transfer_rejects_any_other_asset() {
        let (mut contract, _) = contract();
        let args = fund_args(1, LivenessFallback::RefundRequester);
        let msg = near_sdk::serde_json::json!({ "action": "fund", "args": args }).to_string();
        set_context(intents(), START_MS);
        let _ = contract.mt_on_transfer(
            requester(),
            vec![requester()],
            vec!["nep141:attacker.near".into()],
            vec![U128(PRINCIPAL)],
            msg,
        );
    }

    #[test]
    #[should_panic(expected = "may only be called by the configured Intents contract")]
    fn transfer_rejects_a_spoofed_intents_predecessor() {
        let (mut contract, _) = contract();
        let msg = near_sdk::serde_json::json!({
            "version": FUNDING_MESSAGE_VERSION,
            "action": "fund",
            "args": fund_args(1, LivenessFallback::RefundRequester),
        })
        .to_string();
        set_context(account("attacker.near"), START_MS);
        let _ = contract.mt_on_transfer(
            requester(),
            vec![requester()],
            vec![TOKEN.into()],
            vec![U128(PRINCIPAL)],
            msg,
        );
    }

    #[test]
    #[should_panic(expected = "unsupported settlement transfer message version")]
    fn transfer_rejects_an_unknown_wire_version() {
        let (mut contract, _) = contract();
        let msg = near_sdk::serde_json::json!({
            "version": "edict-intents-funding-2",
            "action": "fund",
            "args": fund_args(1, LivenessFallback::RefundRequester),
        })
        .to_string();
        transfer(&mut contract, requester(), PRINCIPAL, msg, START_MS);
    }

    #[test]
    #[should_panic(expected = "principal does not match transfer")]
    fn transfer_rejects_a_message_amount_mismatch() {
        let (mut contract, _) = contract();
        let msg = near_sdk::serde_json::json!({
            "version": FUNDING_MESSAGE_VERSION,
            "action": "fund",
            "args": fund_args(1, LivenessFallback::RefundRequester),
        })
        .to_string();
        transfer(&mut contract, requester(), PRINCIPAL + 1, msg, START_MS);
    }

    #[test]
    #[should_panic(expected = "on_auth may only be called by the configured Intents contract")]
    fn auth_call_rejects_a_spoofed_intents_predecessor() {
        let (mut contract, _) = contract();
        set_context(account("attacker.near"), START_MS);
        let _ = contract.on_auth(
            worker(),
            near_sdk::serde_json::json!({
                "version": FUNDING_MESSAGE_VERSION,
                "action": "deliver",
                "order_mandate_sha256": order_id(1),
                "manifest_sha256": vec![0xDD; 32],
            })
            .to_string(),
        );
    }

    #[test]
    fn signed_split_conserves_principal_and_pro_rata_bond() {
        let (mut contract, jurors, id, opened) = setup_dispute();
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Split {
                requester_bps: 2_500,
            },
            opened,
            [9; 32],
        );
        assert_eq!(contract.claim_of(requester()).0, 2_500 + 125);
        assert_eq!(contract.claim_of(worker()).0, 7_500 + 187);
        assert_eq!(contract.claim_of(removal()).0, 188);
        assert_eq!(contract.accounting().total_liability.0, PRINCIPAL + BOND);
    }

    #[test]
    fn redo_keeps_one_bond_and_round_two_reopens_without_transfer() {
        let (mut contract, jurors, id, opened) = setup_dispute();
        let new_deadline = opened + 2 * DAY_MS;
        submit(
            &mut contract,
            &jurors,
            id,
            Ruling::Redo {
                new_deadline_unix_ms: new_deadline,
            },
            opened,
            [10; 32],
        );
        assert_eq!(contract.accounting().locked_bonds.0, BOND);
        deliver(&mut contract, id, opened + DAY_MS);
        set_context(intents(), opened + DAY_MS + 1_000);
        let msg = near_sdk::serde_json::json!({
            "version": FUNDING_MESSAGE_VERSION,
            "action": "open_held_dispute",
            "order_mandate_sha256": id,
            "case_id_sha256": vec![8; 32],
        })
        .to_string();
        contract.on_auth(requester(), msg);
        assert_eq!(contract.get_rounds(id).len(), 2);
        assert_eq!(contract.accounting().locked_bonds.0, BOND);
    }

    #[test]
    fn failed_intents_claim_transfer_restores_exact_owner_claim() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        deliver(&mut contract, id, START_MS + 1_000);
        set_context(requester(), START_MS + 2_000);
        contract.accept(id);
        set_context(account("relayer.near"), START_MS + 3_000);
        contract.withdraw_claim(worker());
        assert_eq!(contract.claim_of(worker()).0, 0);
        assert_eq!(contract.pending_claim_of(worker()).0, PRINCIPAL);
        assert_eq!(contract.accounting().payable_claims.0, PRINCIPAL);
        let transfer = get_created_receipts()
            .into_iter()
            .find(|receipt| receipt.receiver_id == intents())
            .expect("Intents transfer receipt");
        let call = transfer.actions.iter().find_map(|action| match action {
            MockAction::FunctionCallWeight {
                method_name,
                args,
                attached_deposit,
                ..
            } if method_name == b"mt_transfer" => Some((args, attached_deposit)),
            _ => None,
        });
        let (args, attached_deposit) = call.expect("fixed mt_transfer call");
        assert_eq!(attached_deposit.as_yoctonear(), 1);
        let args: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
        assert_eq!(args["receiver_id"], worker().as_str());
        assert_eq!(args["token_id"], TOKEN);
        assert_eq!(args["amount"], PRINCIPAL.to_string());

        set_claim_callback_context(PromiseResult::Failed, START_MS + 4_000);
        assert!(!contract.on_claim_transfer(worker(), U128(PRINCIPAL)));
        assert_eq!(contract.claim_of(worker()).0, PRINCIPAL);
        assert_eq!(contract.pending_claim_of(worker()).0, 0);
        assert_eq!(contract.accounting().payable_claims.0, PRINCIPAL);
    }

    #[test]
    fn successful_intents_claim_transfer_clears_the_exact_liability() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::RefundRequester);
        deliver(&mut contract, id, START_MS + 1_000);
        set_context(requester(), START_MS + 2_000);
        contract.accept(id);
        set_context(account("relayer.near"), START_MS + 3_000);
        contract.withdraw_claim(worker());
        set_claim_callback_context(PromiseResult::Successful(Vec::new()), START_MS + 4_000);
        assert!(contract.on_claim_transfer(worker(), U128(PRINCIPAL)));
        assert_eq!(contract.claim_of(worker()).0, 0);
        assert_eq!(contract.pending_claim_of(worker()).0, 0);
        assert_eq!(contract.accounting().payable_claims.0, 0);
    }

    #[test]
    fn authenticated_customer_governance_can_execute_only_the_committed_controller_fallback() {
        let (mut contract, _) = contract();
        let id = fund(&mut contract, 1, LivenessFallback::ControllerResolution);
        deliver(&mut contract, id, START_MS + 1_000);
        let opened = START_MS + 2_000;
        dispute(&mut contract, id, opened, 7);
        set_context(intents(), opened + 3 * DAY_MS + 1);
        let msg = near_sdk::serde_json::json!({
            "version": FUNDING_MESSAGE_VERSION,
            "action": "controller_fallback",
            "order_mandate_sha256": id,
            "ruling": { "kind": "worker_wins" },
        })
        .to_string();
        assert!(contract.on_auth(governance(), msg));
        assert_eq!(contract.claim_of(worker()).0, PRINCIPAL + BOND / 2);
        assert_eq!(contract.claim_of(removal()).0, BOND / 2);
    }

    #[test]
    fn fixed_fallback_is_permissionless_after_timeout() {
        let (mut contract, _, id, opened) = setup_dispute();
        set_context(account("any-relayer.near"), opened + 3 * DAY_MS + 1);
        contract.execute_liveness_fallback(id, None);
        assert_eq!(contract.claim_of(requester()).0, PRINCIPAL + BOND);
    }

    #[test]
    #[should_panic(expected = "immutable order capacity is exhausted")]
    fn prefunded_storage_capacity_fails_closed() {
        let (mut contract, _) = contract_with_capacity(1);
        fund(&mut contract, 1, LivenessFallback::RefundRequester);
        fund(&mut contract, 2, LivenessFallback::RefundRequester);
    }
}

impl IntentsSettlement {
    fn internal_fund(&mut self, requester: AccountId, args: FundOrderArgs) {
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
        require!(
            self.order_count < self.config.max_orders,
            "immutable order capacity is exhausted"
        );
        require!(args.principal.0 > 0, "principal must be positive");
        require!(requester != args.worker, "requester and worker must differ");
        require!(
            requester != env::current_account_id() && args.worker != env::current_account_id(),
            "settlement account cannot be an order party"
        );
        require!(
            requester != self.config.intents_contract
                && args.worker != self.config.intents_contract,
            "Intents Verifier cannot be an order party"
        );
        require!(
            requester != self.config.customer.removal_account
                && args.worker != self.config.customer.removal_account,
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
            required_bond(args.principal.0, args.dispute_bond_bps) > 0,
            "principal is too small for a positive atomic Bond"
        );
        validate_permitted_and_fallback(&args.permitted_rulings, args.liveness_fallback);

        let before = env::storage_usage();
        self.orders.insert(
            args.order_mandate_sha256,
            Order {
                order_mandate_sha256: args.order_mandate_sha256,
                settlement_binding_sha256: args.settlement_binding_sha256,
                requester: requester.clone(),
                worker: args.worker.clone(),
                principal: args.principal,
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
        self.order_count = self
            .order_count
            .checked_add(1)
            .expect("order count overflow");
        self.locked_principal = self
            .locked_principal
            .checked_add(args.principal.0)
            .expect("locked principal overflow");
        emit(
            "intents_order_funded",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&args.order_mandate_sha256),
                "requester": requester,
                "worker": args.worker,
                "token_id": self.config.settlement_token_id,
                "principal_atomic": args.principal.0.to_string(),
            }),
        );
    }

    fn internal_deliver(
        &mut self,
        actor: AccountId,
        order_mandate_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
    ) {
        require!(
            manifest_sha256 != [0u8; 32],
            "delivery manifest hash is zero"
        );
        let now = env::block_timestamp_ms();
        let order = self
            .orders
            .get_mut(&order_mandate_sha256)
            .expect("no such order");
        require!(actor == order.worker, "worker only");
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
            "intents_delivery_committed",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_mandate_sha256),
                "manifest_sha256": hex32(&manifest_sha256),
            }),
        );
    }

    fn internal_accept(&mut self, actor: AccountId, order_mandate_sha256: [u8; 32]) {
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(actor == order.requester, "requester only");
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

    fn internal_open_first_dispute(
        &mut self,
        actor: AccountId,
        order_mandate_sha256: [u8; 32],
        case_id_sha256: [u8; 32],
        bond: U128,
    ) {
        require!(case_id_sha256 != [0u8; 32], "case id hash is zero");
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(
            actor == order.requester || actor == order.worker,
            "only an order party may dispute"
        );
        require!(
            order.state == OrderState::Delivered,
            "dispute requires delivered state"
        );
        require!(
            order.dispute.is_none(),
            "held Bond dispute must use on_auth"
        );
        let delivered = order.delivery.as_ref().expect("delivered state invariant");
        require!(
            now <= delivered
                .delivered_at_ms
                .saturating_add(order.acceptance_window_ms),
            "acceptance window has closed"
        );
        let expected = required_bond(order.principal.0, order.dispute_bond_bps);
        require!(
            bond.0 == expected,
            "transfer exactly the required dispute Bond"
        );
        self.locked_bonds = self
            .locked_bonds
            .checked_add(bond.0)
            .expect("locked Bond overflow");
        order.state = OrderState::Disputed;
        order.dispute = Some(DisputeRecord {
            disputant: actor.clone(),
            bond,
            opened_at_ms: now,
            case_id_sha256,
        });
        self.open_round(&order_mandate_sha256, &order);
        self.orders.insert(order_mandate_sha256, order);
        emit(
            "intents_dispute_opened",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_mandate_sha256),
                "case_id_sha256": hex32(&case_id_sha256),
                "disputant": actor,
                "bond_atomic": bond.0.to_string(),
            }),
        );
    }

    fn internal_open_held_dispute(
        &mut self,
        actor: AccountId,
        order_mandate_sha256: [u8; 32],
        case_id_sha256: [u8; 32],
    ) {
        require!(case_id_sha256 != [0u8; 32], "case id hash is zero");
        let now = env::block_timestamp_ms();
        let mut order = self.order_or_panic(&order_mandate_sha256);
        require!(order.redo_count == 1, "held Bond exists only after redo");
        require!(
            order.state == OrderState::Delivered,
            "held-Bond dispute requires delivered state"
        );
        let delivered = order.delivery.as_ref().expect("delivered state invariant");
        require!(
            now <= delivered
                .delivered_at_ms
                .saturating_add(order.acceptance_window_ms),
            "acceptance window has closed"
        );
        let mut dispute = order.dispute.clone().expect("redo must retain its Bond");
        require!(actor == dispute.disputant, "original bonded disputant only");
        dispute.opened_at_ms = now;
        dispute.case_id_sha256 = case_id_sha256;
        order.state = OrderState::Disputed;
        order.dispute = Some(dispute);
        self.open_round(&order_mandate_sha256, &order);
        self.orders.insert(order_mandate_sha256, order);
        emit(
            "intents_dispute_reopened",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_mandate_sha256),
                "case_id_sha256": hex32(&case_id_sha256),
                "disputant": actor,
            }),
        );
    }

    fn internal_execute_liveness_fallback(
        &mut self,
        actor: AccountId,
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
                    actor == self.config.customer.customer_governance,
                    "customer governance only"
                );
                controller_ruling.expect("controller_resolution requires an authenticated ruling")
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

    fn order_or_panic(&self, id: &[u8; 32]) -> Order {
        self.orders.get(id).expect("no such order").clone()
    }

    fn verify_signatures(&self, digest: &[u8; 32], signatures: &[VerdictSignature]) {
        let policy = &self.config.customer.verifier_policy;
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
            source,
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
                "intents_redo_ordered",
                near_sdk::serde_json::json!({
                    "order_mandate_sha256": hex32(&order_id),
                    "new_deadline_ms": new_deadline_unix_ms,
                    "bond_held_atomic": bond.0.to_string(),
                }),
            );
            return;
        }

        let requester_share_bps = ruling
            .terminal_requester_share_bps()
            .expect("terminal ruling invariant");
        let requester_cut = mul_bps(order.principal.0, requester_share_bps);
        let worker_cut = order
            .principal
            .0
            .checked_sub(requester_cut)
            .expect("principal allocation underflow");
        self.locked_principal = self
            .locked_principal
            .checked_sub(order.principal.0)
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
            self.resolve_latest_round(&order_id, record, U128(0));
        }
        self.orders.insert(order_id, order.clone());
        emit(
            "intents_order_settled",
            near_sdk::serde_json::json!({
                "order_mandate_sha256": hex32(&order_id),
                "ruling": ruling.canonical(),
                "requester_claim_atomic": requester_cut.to_string(),
                "worker_claim_atomic": worker_cut.to_string(),
            }),
        );
    }

    fn distribute_bond(
        &mut self,
        order: &Order,
        dispute: &DisputeRecord,
        requester_share_bps: u16,
    ) {
        if dispute.bond.0 == 0 {
            return;
        }
        self.locked_bonds = self
            .locked_bonds
            .checked_sub(dispute.bond.0)
            .expect("locked Bond underflow");
        let disputant_is_requester = dispute.disputant == order.requester;
        let (refund, counterparty_cut, removal_cut) =
            bond_allocation(dispute.bond.0, disputant_is_requester, requester_share_bps);
        let counterparty = if disputant_is_requester {
            order.worker.clone()
        } else {
            order.requester.clone()
        };
        self.credit(&dispute.disputant, refund);
        self.credit(&counterparty, counterparty_cut);
        let removal = self.config.customer.removal_account.clone();
        self.credit(&removal, removal_cut);
    }

    fn credit(&mut self, account_id: &AccountId, amount: u128) {
        if amount == 0 {
            return;
        }
        let current = self.claims.get(account_id).copied().unwrap_or(0);
        self.claims.insert(
            account_id.clone(),
            current.checked_add(amount).expect("claim overflow"),
        );
        self.payable_claims = self
            .payable_claims
            .checked_add(amount)
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
        bond_held_after: U128,
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
