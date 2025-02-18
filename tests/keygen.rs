//#![cfg(all(test, feature = "e2e"))]

use blueprint::keygen::{KeygenEventHandler, KEYGEN_JOB_ID};
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::field::BoundedString;
use blueprint_sdk::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use frost_blueprint as blueprint;
use blueprint::FrostContext;
use blueprint_sdk as sdk;
use frost_core::Ciphersuite;
use sdk::logging;
use sdk::testing::tempfile;
use sdk::testing::utils::harness::TestHarness;
use sdk::testing::utils::tangle::TangleTestHarness;
use sdk::testing::utils::tangle::{InputValue, OutputValue};

const N: usize = 3;
const T: usize = N / 2 + 1;
const CIPHERSUITE: &str = frost_ed25519::Ed25519Sha512::ID;

#[tokio::test(flavor = "multi_thread")]
async fn keygen_e2e() -> color_eyre::Result<()> {
    color_eyre::install()?;
    logging::setup_log();

    logging::info!("Running FROST blueprint test");
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = TangleTestHarness::setup(tmp_dir).await?;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) = harness.setup_services::<N>(false).await?;
    test_env.initialize().await?;
    // Get the alice node
    let handles = test_env.node_handles().await;

    let alice_handle = handles[0].clone();
    let alice_env = alice_handle.gadget_config().await;

    // Create blueprint-specific context
    let blueprint_ctx = FrostContext::new(alice_env.clone())?;

    // Create the event handlers
    let keygen = KeygenEventHandler::new(&alice_env, blueprint_ctx.clone()).await?;

    alice_handle.add_job(keygen).await;

    test_env.start().await?;

    let ciphersuite = InputValue::String(BoundedString(BoundedVec(
        CIPHERSUITE.to_string().into_bytes(),
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
    let results = harness.wait_for_job_execution(service_id, job).await?;
    assert_eq!(results.service_id, service_id);
    Ok(())
}
