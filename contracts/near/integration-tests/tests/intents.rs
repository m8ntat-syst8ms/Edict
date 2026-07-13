use anyhow::{Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use near_workspaces::network::Sandbox;
use near_workspaces::operations::Function;
use near_workspaces::types::{AccountId, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Worker};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PINNED_INTENTS_SHA256: &str =
    "f4b908b631562d62c133cc58b0a053dab41d6e243990c54694ac42264679f4ea";
const ONE_DAY_MS: u64 = 86_400_000;
const PRINCIPAL: u128 = 10_000;

fn read_artifact(path: impl AsRef<Path>, label: &str) -> Result<Vec<u8>> {
    fs::read(path.as_ref()).with_context(|| {
        format!(
            "missing {label} Wasm artifact at {}",
            path.as_ref().display()
        )
    })
}

fn settlement_artifact() -> Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/release/edict_customer_settlement_intents.wasm");
    read_artifact(path, "Edict Intents settlement")
}

fn local_release_artifact(name: &str, label: &str) -> Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/release")
        .join(name);
    read_artifact(path, label)
}

fn pinned_intents_artifact() -> Result<Vec<u8>> {
    let path = std::env::var("EDICT_INTENTS_VERIFIER_WASM")
        .context("EDICT_INTENTS_VERIFIER_WASM is required; run scripts/test-intents-sandbox.sh")?;
    let wasm = read_artifact(path, "pinned mainnet Intents Verifier")?;
    let digest = hex::encode(Sha256::digest(&wasm));
    anyhow::ensure!(
        digest == PINNED_INTENTS_SHA256,
        "Intents Verifier artifact hash mismatch: {digest}"
    );
    Ok(wasm)
}

async fn implicit_account(
    sandbox: &Worker<Sandbox>,
    root: &Account,
    seed: &str,
) -> Result<Account> {
    let secret_key = SecretKey::from_seed(KeyType::ED25519, seed);
    let crypto_key: near_crypto::SecretKey = secret_key.to_string().parse()?;
    let account_id: AccountId = hex::encode(crypto_key.public_key().key_data()).parse()?;
    root.transfer_near(&account_id, NearToken::from_near(2))
        .await?
        .into_result()?;
    Ok(Account::from_secret_key(account_id, secret_key, sandbox))
}

fn borsh_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_le_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn signed_nep413_intents(
    signer: &Account,
    intents_contract: &AccountId,
    intents: Vec<Value>,
    nonce_seed: u8,
) -> Result<Value> {
    let message = serde_json::to_string(&json!({
        "signer_id": signer.id(),
        "deadline": "2099-01-01T00:00:00Z",
        "intents": intents,
    }))?;
    let nonce = [nonce_seed; 32];
    let recipient = intents_contract.as_str();

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&((1u32 << 31) + 413).to_le_bytes());
    borsh_string(&mut preimage, &message);
    preimage.extend_from_slice(&nonce);
    borsh_string(&mut preimage, recipient);
    preimage.push(0); // callback_url: None
    let digest: [u8; 32] = Sha256::digest(preimage).into();

    let secret_key: near_crypto::SecretKey = signer.secret_key().to_string().parse()?;
    Ok(json!({
        "standard": "nep413",
        "payload": {
            "message": message,
            "nonce": BASE64_STANDARD.encode(nonce),
            "recipient": recipient,
        },
        "public_key": secret_key.public_key().to_string(),
        "signature": secret_key.sign(&digest).to_string(),
    }))
}

fn transfer_intent(
    receiver_id: &AccountId,
    token_id: &str,
    amount: u128,
    memo: &str,
    msg: String,
) -> Value {
    let mut tokens = Map::new();
    tokens.insert(token_id.to_owned(), json!(amount.to_string()));
    json!({
        "intent": "transfer",
        "receiver_id": receiver_id,
        "tokens": tokens,
        "memo": memo,
        "msg": msg,
        "min_gas": "30000000000000",
    })
}

fn auth_call_intent(contract_id: &AccountId, msg: String) -> Value {
    json!({
        "intent": "auth_call",
        "contract_id": contract_id,
        "msg": msg,
        "min_gas": "30000000000000",
    })
}

async fn execute_intents(
    relayer: &Account,
    intents_contract: &AccountId,
    signed: Value,
) -> Result<()> {
    relayer
        .call(intents_contract, "execute_intents")
        .args_json(json!({ "signed": [signed] }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

async fn intents_balance(
    sandbox: &Worker<Sandbox>,
    intents_contract: &AccountId,
    account_id: &AccountId,
    token_id: &str,
) -> Result<u128> {
    let value: String = sandbox
        .view(intents_contract, "mt_balance_of")
        .args_json(json!({ "account_id": account_id, "token_id": token_id }))
        .await?
        .json()?;
    Ok(value.parse()?)
}

fn bytes32(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

#[tokio::test]
#[ignore = "downloads a hash-pinned mainnet Verifier and starts a local NEAR sandbox"]
async fn pinned_mainnet_verifier_funds_authenticates_refunds_and_pays_keyless_settlement(
) -> Result<()> {
    let settlement_wasm = settlement_artifact()?;
    let factory_wasm = local_release_artifact(
        "edict_intents_deployment_factory.wasm",
        "Edict Intents deployment factory",
    )?;
    let publisher_wasm = local_release_artifact(
        "edict_global_publisher_test.wasm",
        "test-only global publisher",
    )?;
    let intents_wasm = pinned_intents_artifact()?;
    let sandbox = near_workspaces::sandbox().await?;
    let root = sandbox.root_account()?;
    let token = sandbox.dev_create_account().await?;
    let removal = sandbox.dev_create_account().await?;
    let requester = implicit_account(&sandbox, &root, "edict-intents-requester").await?;
    let worker = implicit_account(&sandbox, &root, "edict-intents-worker").await?;

    let intents_id: AccountId = format!("intents.{}", root.id()).parse()?;
    root.batch(&intents_id)
        .create_account()
        .transfer(NearToken::from_near(30))
        .deploy(&intents_wasm)
        .call(
            Function::new("new")
                .args_json(json!({
                    "config": {
                        "wnear_id": token.id(),
                        "fees": { "fee": 0, "fee_collector": root.id() },
                        "roles": {},
                    }
                }))
                .gas(Gas::from_tgas(100)),
        )
        .transact()
        .await?
        .into_result()?;

    let publisher = sandbox.dev_deploy(&publisher_wasm).await?;
    publisher.call("new").transact().await?.into_result()?;
    publisher
        .call("publish_by_hash")
        .args_json(json!({
            "code": BASE64_STANDARD.encode(&settlement_wasm),
        }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;

    let settlement_hash: [u8; 32] = Sha256::digest(&settlement_wasm).into();
    let factory_id: AccountId = format!("intents-factory.{}", root.id()).parse()?;
    root.batch(&factory_id)
        .create_account()
        .transfer(NearToken::from_near(10))
        .deploy(&factory_wasm)
        .call(
            Function::new("new")
                .args_json(json!({
                    "global_code_sha256": settlement_hash,
                    "minimum_instance_balance": NearToken::from_near(2).as_yoctonear().to_string(),
                }))
                .gas(Gas::from_tgas(100)),
        )
        .transact()
        .await?
        .into_result()?;
    assert!(sandbox.view_access_keys(&factory_id).await?.is_empty());

    let settlement_id: AccountId = format!("settlement.{factory_id}").parse()?;
    let verifier_policy = json!({
        "scheme": "ecdsa_secp256k1_eth",
        "quorum": 2,
        "signers": [
            {
                "signing_address": format!("0x{:040x}", 1),
                "operator_id": "edict",
                "edict_controlled": true,
                "attestation_sha256": bytes32(1),
            },
            {
                "signing_address": format!("0x{:040x}", 2),
                "operator_id": "independent-a",
                "edict_controlled": false,
                "attestation_sha256": bytes32(2),
            },
            {
                "signing_address": format!("0x{:040x}", 3),
                "operator_id": "independent-b",
                "edict_controlled": false,
                "attestation_sha256": bytes32(3),
            }
        ]
    });
    let token_id = format!("nep141:{}", token.id());
    let settlement_config = json!({
        "customer": {
            "customer_governance": root.id(),
            "removal_account": removal.id(),
            "verifier_policy": verifier_policy,
        },
        "intents_contract": intents_id,
        "settlement_token_id": token_id,
        "max_orders": 10,
    });
    let required_deposit: String = sandbox
        .view(&factory_id, "required_deployment_deposit")
        .await?
        .json()?;
    root.call(&factory_id, "create_instance")
        .args_json(json!({
            "slug": "settlement",
            "config": settlement_config,
        }))
        .deposit(NearToken::from_yoctonear(required_deposit.parse()?))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?
        .into_result()?;
    assert!(sandbox.view_access_keys(&settlement_id).await?.is_empty());

    token
        .call(&intents_id, "ft_on_transfer")
        .args_json(json!({
            "sender_id": requester.id(),
            "amount": PRINCIPAL.to_string(),
            "msg": "",
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        intents_balance(&sandbox, &intents_id, requester.id(), &token_id).await?,
        PRINCIPAL
    );

    let now_ms = sandbox.view_block().await?.timestamp() / 1_000_000;
    let order_id = bytes32(0x11);
    let funding_msg = json!({
        "version": "edict-intents-funding-1",
        "action": "fund",
        "args": {
            "order_mandate_sha256": order_id,
            "settlement_binding_sha256": bytes32(0x22),
            "worker": worker.id(),
            "principal": PRINCIPAL.to_string(),
            "deadline_ms": now_ms + ONE_DAY_MS,
            "acceptance_window_ms": ONE_DAY_MS,
            "challenge_window_ms": 2 * 60 * 60 * 1_000u64,
            "resolution_timeout_ms": ONE_DAY_MS,
            "liveness_fallback": "refund_requester",
            "permitted_rulings": ["requester_wins", "worker_wins", "split", "redo"],
            "dispute_bond_bps": 500,
        }
    })
    .to_string();
    let funding = signed_nep413_intents(
        &requester,
        &intents_id,
        vec![transfer_intent(
            &settlement_id,
            &token_id,
            PRINCIPAL,
            "edict-fund",
            funding_msg,
        )],
        1,
    )?;
    execute_intents(&root, &intents_id, funding).await?;
    let order: Value = sandbox
        .view(&settlement_id, "get_order")
        .args_json(json!({ "order_mandate_sha256": order_id }))
        .await?
        .json()?;
    assert_eq!(order["state"], "funded");
    assert_eq!(
        intents_balance(&sandbox, &intents_id, &settlement_id, &token_id).await?,
        PRINCIPAL
    );

    let delivery_msg = json!({
        "version": "edict-intents-funding-1",
        "action": "deliver",
        "order_mandate_sha256": bytes32(0x11),
        "manifest_sha256": bytes32(0x33),
    })
    .to_string();
    execute_intents(
        &root,
        &intents_id,
        signed_nep413_intents(
            &worker,
            &intents_id,
            vec![auth_call_intent(&settlement_id, delivery_msg)],
            2,
        )?,
    )
    .await?;
    let delivered: Value = sandbox
        .view(&settlement_id, "get_order")
        .args_json(json!({ "order_mandate_sha256": bytes32(0x11) }))
        .await?
        .json()?;
    assert_eq!(delivered["state"], "delivered");

    let accept_msg = json!({
        "version": "edict-intents-funding-1",
        "action": "accept",
        "order_mandate_sha256": bytes32(0x11),
    })
    .to_string();
    execute_intents(
        &root,
        &intents_id,
        signed_nep413_intents(
            &requester,
            &intents_id,
            vec![auth_call_intent(&settlement_id, accept_msg)],
            3,
        )?,
    )
    .await?;
    let worker_claim: String = sandbox
        .view(&settlement_id, "claim_of")
        .args_json(json!({ "account_id": worker.id() }))
        .await?
        .json()?;
    assert_eq!(worker_claim.parse::<u128>()?, PRINCIPAL);

    root.call(&settlement_id, "withdraw_claim")
        .args_json(json!({ "account_id": worker.id() }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        intents_balance(&sandbox, &intents_id, worker.id(), &token_id).await?,
        PRINCIPAL
    );
    let accounting: Value = sandbox.view(&settlement_id, "accounting").await?.json()?;
    assert_eq!(accounting["total_liability"], "0");

    let malformed_amount = PRINCIPAL + 1;
    token
        .call(&intents_id, "ft_on_transfer")
        .args_json(json!({
            "sender_id": requester.id(),
            "amount": malformed_amount.to_string(),
            "msg": "",
        }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    let mismatched_msg = json!({
        "version": "edict-intents-funding-1",
        "action": "fund",
        "args": {
            "order_mandate_sha256": bytes32(0x44),
            "settlement_binding_sha256": bytes32(0x55),
            "worker": worker.id(),
            "principal": PRINCIPAL.to_string(),
            "deadline_ms": now_ms + ONE_DAY_MS,
            "acceptance_window_ms": ONE_DAY_MS,
            "challenge_window_ms": 2 * 60 * 60 * 1_000u64,
            "resolution_timeout_ms": ONE_DAY_MS,
            "liveness_fallback": "refund_requester",
            "permitted_rulings": ["requester_wins", "worker_wins"],
            "dispute_bond_bps": 500,
        }
    })
    .to_string();
    let mismatched = signed_nep413_intents(
        &requester,
        &intents_id,
        vec![transfer_intent(
            &settlement_id,
            &token_id,
            malformed_amount,
            "edict-refund-check",
            mismatched_msg,
        )],
        4,
    )?;
    execute_intents(&root, &intents_id, mismatched).await?;
    assert_eq!(
        intents_balance(&sandbox, &intents_id, requester.id(), &token_id).await?,
        malformed_amount
    );
    let rejected: Option<Value> = sandbox
        .view(&settlement_id, "get_order")
        .args_json(json!({ "order_mandate_sha256": bytes32(0x44) }))
        .await?
        .json()?;
    assert!(rejected.is_none());

    Ok(())
}
