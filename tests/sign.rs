#![cfg(all(test, feature = "e2e"))]

use blueprint::keygen::{KeygenEventHandler, KEYGEN_JOB_ID};
use blueprint::sign::{SignEventHandler, SIGN_JOB_ID};
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::field::BoundedString;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use blueprint_sdk::testing::utils::tangle::OutputValue;
use frost_blueprint as blueprint;
use blueprint::FrostContext;
use blueprint_sdk as sdk;
use frost_core::Ciphersuite;
use sdk::logging;
use sdk::testing::tempfile;
use sdk::testing::utils::harness::TestHarness;
use sdk::testing::utils::tangle::TangleTestHarness;
use sdk::testing::utils::tangle::InputValue;
use tokio::time::timeout;

const N: usize = 3;
const T: usize = N / 2 + 1;

#[tokio::test(flavor = "multi_thread")]
async fn sign_e2e() -> color_eyre::Result<()> {
    color_eyre::install()?;
    logging::setup_log();

    logging::info!("Running FROST blueprint test");
    let test_timeout = std::time::Duration::from_secs(60);
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;
    let exit_after_registration = false;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) =
        harness.setup_services::<N>(exit_after_registration).await?;
    test_env.initialize().await?;
    let handles = test_env.node_handles().await;

    for handle in &handles {
        let env = handle.gadget_config().await;

        // Create blueprint-specific context
        let blueprint_ctx = FrostContext::new(env.clone()).await?;

        // Create the event handlers
        let keygen = KeygenEventHandler::new(&env, blueprint_ctx.clone()).await?;
        let sign = SignEventHandler::new(&env, blueprint_ctx).await?;

        handle.add_job(keygen).await;
        handle.add_job(sign).await;
    }

    test_env.start().await?;

    let ciphersuite = InputValue::String(BoundedString(BoundedVec(
        frost_ed25519::Ed25519Sha512::ID.to_string().into_bytes(),
    )));
    let threshold = InputValue::Uint16(T as u16);

    logging::info!("Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}",);

    // Execute job and verify result
    let job = harness
        .submit_job(service_id, KEYGEN_JOB_ID, vec![ciphersuite, threshold])
        .await?;
    let keygen_call_id = job.call_id;
    logging::info!(
        "Submitted KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id} has call id {keygen_call_id}"
    );
    // Execute job and verify result
    let results = timeout(
        test_timeout,
        harness.wait_for_job_execution(service_id, job),
    )
    .await??;
    assert_eq!(results.service_id, service_id);

    logging::info!("Submitting SIGN job {SIGN_JOB_ID} with service ID {service_id}",);

    let msg = InputValue::List(BoundedVec(
        b"Hello World!"
            .as_slice()
            .iter()
            .map(|x| InputValue::Uint8(*x))
            .collect(),
    ));
    let pubkey = results.result[0].clone();

    let job = harness
        .submit_job(service_id, SIGN_JOB_ID, vec![pubkey.clone(), msg])
        .await?;
    let sign_call_id = job.call_id;
    logging::info!(
        "Submitted SIGN job {SIGN_JOB_ID} with service ID {service_id} has call id {sign_call_id}"
    );

    let sign_results = timeout(
        test_timeout,
        harness.wait_for_job_execution(service_id, job),
    )
    .await??;
    assert_eq!(sign_results.service_id, service_id);

    // Verify signature
    let OutputValue::List(BoundedVec(signature)) = sign_results.result[0].clone() else {
        panic!("Expected signature to be a list of bytes");
    };
    let signature_bytes = signature
        .iter()
        .flat_map(|b| match b {
            InputValue::Uint8(x) => Some(*x),
            _ => None,
        })
        .collect::<Vec<u8>>();
    let OutputValue::List(BoundedVec(pubkey)) = pubkey else {
        panic!("Expected public key to be a list of bytes");
    };
    let pubkey_bytes = pubkey
        .iter()
        .flat_map(|b| match b {
            InputValue::Uint8(x) => Some(*x),
            _ => None,
        })
        .collect::<Vec<u8>>();
    let signature =
        frost_core::Signature::<frost_ed25519::Ed25519Sha512>::deserialize(&signature_bytes)
            .unwrap();

    let pubkey =
        frost_core::VerifyingKey::<frost_ed25519::Ed25519Sha512>::deserialize(&pubkey_bytes)
            .unwrap();

    assert!(pubkey.verify(b"Hello World!", &signature).is_ok());
    Ok(())
}
