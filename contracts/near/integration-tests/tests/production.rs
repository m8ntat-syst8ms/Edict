use anyhow::{Context, Result};
use base64::prelude::{Engine, BASE64_STANDARD};
use k256::ecdsa::{RecoveryId, SigningKey};
use near_workspaces::operations::Function;
use near_workspaces::types::{Gas, NearToken};
use serde_json::{json, Value};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::fs;
use std::path::{Path, PathBuf};

const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const ONE_DAY_MS: u64 = 86_400_000;

struct Juror {
    signing_key: SigningKey,
    address: String,
}

fn juror(seed: u8) -> Juror {
    let mut bytes = [0u8; 32];
    bytes[31] = seed;
    let signing_key = SigningKey::from_bytes(&bytes.into()).expect("valid signing key");
    let public_key = signing_key.verifying_key().to_encoded_point(false);
    let address_hash = Keccak256::digest(&public_key.as_bytes()[1..]);
    Juror {
        signing_key,
        address: format!("0x{}", hex::encode(&address_hash[12..])),
    }
}

fn artifact(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/wasm32-unknown-unknown/release")
        .join(name)
}

fn read_artifact(name: &str) -> Result<Vec<u8>> {
    let path = artifact(name);
    fs::read(&path).with_context(|| {
        format!(
            "missing Wasm artifact {}; run scripts/test-production-sandbox.sh",
            path.display()
        )
    })
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[allow(clippy::too_many_arguments)]
fn execution_digest(
    settlement_account: &str,
    order_id: &[u8; 32],
    case_id: &[u8; 32],
    ruling: &str,
    verdict: &[u8; 32],
    issued_at_ms: u64,
    policy_hash: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"EDICT_SETTLEMENT_V1");
    preimage.extend_from_slice(settlement_account.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(order_id);
    preimage.extend_from_slice(case_id);
    preimage.extend_from_slice(&1u32.to_le_bytes());
    preimage.extend_from_slice(ruling.as_bytes());
    preimage.push(0);
    preimage.extend_from_slice(verdict);
    preimage.extend_from_slice(&issued_at_ms.to_le_bytes());
    preimage.extend_from_slice(policy_hash);
    preimage.extend_from_slice(nonce);
    sha256_array(&preimage)
}

fn verdict_signature(juror: &Juror, digest: &[u8; 32]) -> Value {
    let mut personal = Vec::with_capacity(60);
    personal.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    personal.extend_from_slice(digest);
    let message: [u8; 32] = Keccak256::digest(personal).into();
    let (signature, recovery_id) = juror
        .signing_key
        .sign_prehash_recoverable(&message)
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
    json!({
        "signing_address": juror.address,
        "signature": format!("0x{}", hex::encode(bytes)),
    })
}

fn bytes32(value: u8) -> Vec<u8> {
    vec![value; 32]
}

fn verifier_config(
    customer: &near_workspaces::Account,
    removal: &near_workspaces::Account,
) -> Value {
    let jurors = [juror(1), juror(2), juror(3)];
    json!({
        "customer_governance": customer.id(),
        "removal_account": removal.id(),
        "verifier_policy": {
            "scheme": "ecdsa_secp256k1_eth",
            "quorum": 2,
            "signers": [
                {
                    "signing_address": jurors[0].address,
                    "operator_id": "edict",
                    "edict_controlled": true,
                    "attestation_sha256": bytes32(1),
                },
                {
                    "signing_address": jurors[1].address,
                    "operator_id": "independent-a",
                    "edict_controlled": false,
                    "attestation_sha256": bytes32(2),
                },
                {
                    "signing_address": jurors[2].address,
                    "operator_id": "independent-b",
                    "edict_controlled": false,
                    "attestation_sha256": bytes32(3),
                }
            ]
        }
    })
}

#[tokio::test]
#[ignore = "starts a local NEAR sandbox; run contracts/near/scripts/test-production-sandbox.sh"]
async fn failed_child_initialization_rolls_back_the_batch_and_releases_the_slug() -> Result<()> {
    let factory_wasm = read_artifact("edict_deployment_factory.wasm")?;
    let publisher_wasm = read_artifact("edict_global_publisher_test.wasm")?;
    let wrong_child_hash = sha256_array(&factory_wasm);

    let sandbox = near_workspaces::sandbox().await?;
    let root = sandbox.root_account()?;
    let publisher = sandbox.dev_deploy(&publisher_wasm).await?;
    publisher.call("new").transact().await?.into_result()?;
    publisher
        .call("publish_by_hash")
        .args_json(json!({ "code": BASE64_STANDARD.encode(&factory_wasm) }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;

    let factory_id = format!("failure.{}", root.id()).parse()?;
    root.batch(&factory_id)
        .create_account()
        .transfer(NearToken::from_near(10))
        .deploy(&factory_wasm)
        .call(
            Function::new("new")
                .args_json(json!({
                    "global_code_sha256": wrong_child_hash,
                    "minimum_instance_balance": (ONE_NEAR / 2).to_string(),
                }))
                .gas(Gas::from_tgas(100)),
        )
        .transact()
        .await?
        .into_result()?;

    let customer = sandbox.dev_create_account().await?;
    let removal = sandbox.dev_create_account().await?;
    let required_deposit: String = sandbox
        .view(&factory_id, "required_deployment_deposit")
        .await?
        .json()?;
    customer
        .call(&factory_id, "create_instance")
        .args_json(json!({
            "slug": "rolled-back",
            "config": verifier_config(&customer, &removal),
        }))
        .deposit(NearToken::from_yoctonear(required_deposit.parse()?))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?
        .into_result()?;

    let child_id = format!("rolled-back.{factory_id}").parse()?;
    assert!(sandbox.view_account(&child_id).await.is_err());
    let record: Value = sandbox
        .view(&factory_id, "get_deployment")
        .args_json(json!({ "instance_account": child_id }))
        .await?
        .json()?;
    assert!(record.is_null(), "failed deployment must release its slug");
    Ok(())
}

#[tokio::test]
#[ignore = "starts a local NEAR sandbox; run contracts/near/scripts/test-production-sandbox.sh"]
async fn global_factory_creates_keyless_instance_and_executes_verified_ruling() -> Result<()> {
    let settlement_wasm = read_artifact("edict_customer_settlement.wasm")?;
    let factory_wasm = read_artifact("edict_deployment_factory.wasm")?;
    let publisher_wasm = read_artifact("edict_global_publisher_test.wasm")?;
    let settlement_hash = sha256_array(&settlement_wasm);

    let sandbox = near_workspaces::sandbox().await?;
    let root = sandbox.root_account()?;
    let publisher = sandbox.dev_deploy(&publisher_wasm).await?;
    publisher.call("new").transact().await?.into_result()?;
    publisher
        .call("publish_by_hash")
        .args_json(json!({ "code": BASE64_STANDARD.encode(&settlement_wasm) }))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?
        .into_result()?;

    let factory_id = format!("v1.{}", root.id()).parse()?;
    root.batch(&factory_id)
        .create_account()
        .transfer(NearToken::from_near(10))
        .deploy(&factory_wasm)
        .call(
            Function::new("new")
                .args_json(json!({
                    "global_code_sha256": settlement_hash,
                    "minimum_instance_balance": (ONE_NEAR / 2).to_string(),
                }))
                .gas(Gas::from_tgas(100)),
        )
        .transact()
        .await?
        .into_result()?;
    assert!(sandbox.view_access_keys(&factory_id).await?.is_empty());

    let customer = sandbox.dev_create_account().await?;
    let worker = sandbox.dev_create_account().await?;
    let removal = sandbox.dev_create_account().await?;
    let relayer = sandbox.dev_create_account().await?;
    let jurors = [juror(1), juror(2), juror(3)];
    let config = json!({
        "customer_governance": customer.id(),
        "removal_account": removal.id(),
        "verifier_policy": {
            "scheme": "ecdsa_secp256k1_eth",
            "quorum": 2,
            "signers": [
                {
                    "signing_address": jurors[0].address,
                    "operator_id": "edict",
                    "edict_controlled": true,
                    "attestation_sha256": bytes32(1),
                },
                {
                    "signing_address": jurors[1].address,
                    "operator_id": "independent-a",
                    "edict_controlled": false,
                    "attestation_sha256": bytes32(2),
                },
                {
                    "signing_address": jurors[2].address,
                    "operator_id": "independent-b",
                    "edict_controlled": false,
                    "attestation_sha256": bytes32(3),
                }
            ]
        }
    });
    let required_deposit: String = sandbox
        .view(&factory_id, "required_deployment_deposit")
        .await?
        .json()?;
    customer
        .call(&factory_id, "create_instance")
        .args_json(json!({ "slug": "acme", "config": config }))
        .deposit(NearToken::from_yoctonear(required_deposit.parse()?))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?
        .into_result()?;

    let settlement_id = format!("acme.{factory_id}").parse()?;
    assert!(sandbox.view_access_keys(&settlement_id).await?.is_empty());
    let deployed_code = sandbox.view_code(&settlement_id).await?;
    assert_eq!(sha256_array(&deployed_code), settlement_hash);
    let deployment: Value = sandbox
        .view(&factory_id, "get_deployment")
        .args_json(json!({ "instance_account": settlement_id }))
        .await?
        .json()?;
    assert_eq!(deployment["status"], "active");

    let now_ms = sandbox.view_block().await?.timestamp() / 1_000_000;
    let order_id = [0x11; 32];
    let case_id = [0x44; 32];
    let principal = ONE_NEAR;
    let storage_deposit: String = sandbox
        .view(&settlement_id, "order_storage_deposit")
        .await?
        .json()?;
    customer
        .call(&settlement_id, "fund")
        .args_json(json!({
            "args": {
                "order_mandate_sha256": order_id,
                "settlement_binding_sha256": bytes32(0x22),
                "worker": worker.id(),
                "principal": principal.to_string(),
                "deadline_ms": now_ms + ONE_DAY_MS,
                "acceptance_window_ms": ONE_DAY_MS,
                "challenge_window_ms": 2 * 60 * 60 * 1_000u64,
                "resolution_timeout_ms": ONE_DAY_MS,
                "liveness_fallback": "refund_requester",
                "permitted_rulings": ["requester_wins", "worker_wins", "split", "redo"],
                "dispute_bond_bps": 500
            }
        }))
        .deposit(NearToken::from_yoctonear(
            principal + storage_deposit.parse::<u128>()?,
        ))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    worker
        .call(&settlement_id, "deliver")
        .args_json(json!({
            "order_mandate_sha256": order_id,
            "manifest_sha256": bytes32(0x33),
        }))
        .transact()
        .await?
        .into_result()?;
    customer
        .call(&settlement_id, "open_dispute")
        .args_json(json!({
            "order_mandate_sha256": order_id,
            "case_id_sha256": case_id,
        }))
        .deposit(NearToken::from_yoctonear(principal / 20))
        .transact()
        .await?
        .into_result()?;

    let order: Value = sandbox
        .view(&settlement_id, "get_order")
        .args_json(json!({ "order_mandate_sha256": order_id }))
        .await?
        .json()?;
    let issued_at_ms = order["dispute"]["opened_at_ms"]
        .as_u64()
        .context("missing dispute opened_at_ms")?;
    let policy_hash_vec: Vec<u8> = serde_json::from_value(order["verifier_policy_sha256"].clone())?;
    let policy_hash: [u8; 32] = policy_hash_vec.try_into().expect("32-byte policy hash");
    let verdict = [0x55; 32];
    let nonce = [0x66; 32];
    let digest = execution_digest(
        settlement_id.as_str(),
        &order_id,
        &case_id,
        "requester_wins",
        &verdict,
        issued_at_ms,
        &policy_hash,
        &nonce,
    );

    let target_ms = issued_at_ms + 2 * 60 * 60 * 1_000 + 1;
    let before_probe_ms = sandbox.view_block().await?.timestamp() / 1_000_000;
    sandbox.fast_forward(100).await?;
    let after_probe_ms = sandbox.view_block().await?.timestamp() / 1_000_000;
    let millis_per_block = after_probe_ms.saturating_sub(before_probe_ms).max(1) / 100;
    let mut current_ms = after_probe_ms;
    for _ in 0..3 {
        if current_ms > target_ms {
            break;
        }
        let remaining_ms = target_ms - current_ms;
        let blocks = remaining_ms.div_ceil(millis_per_block.max(1)) + 100;
        sandbox.fast_forward(blocks).await?;
        current_ms = sandbox.view_block().await?.timestamp() / 1_000_000;
    }
    anyhow::ensure!(
        current_ms > target_ms,
        "sandbox failed to advance beyond the signed challenge window"
    );

    relayer
        .call(&settlement_id, "submit_ruling")
        .args_json(json!({
            "order_mandate_sha256": order_id,
            "ruling": { "kind": "requester_wins" },
            "verdict_sha256": verdict,
            "issued_at_ms": issued_at_ms,
            "nonce": nonce,
            "signatures": [
                verdict_signature(&jurors[1], &digest),
                verdict_signature(&jurors[2], &digest),
            ],
        }))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?
        .into_result()?;

    let requester_claim: String = sandbox
        .view(&settlement_id, "claim_of")
        .args_json(json!({ "account_id": customer.id() }))
        .await?
        .json()?;
    assert_eq!(requester_claim.parse::<u128>()?, principal + principal / 20);
    relayer
        .call(&settlement_id, "withdraw_claim")
        .args_json(json!({ "account_id": customer.id() }))
        .gas(Gas::from_tgas(80))
        .transact()
        .await?
        .into_result()?;
    let remaining_claim: String = sandbox
        .view(&settlement_id, "claim_of")
        .args_json(json!({ "account_id": customer.id() }))
        .await?
        .json()?;
    assert_eq!(remaining_claim, "0");
    Ok(())
}
