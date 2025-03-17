#![cfg(all(test, feature = "e2e"))]
use blueprint_sdk as sdk;
use frost_blueprint as blueprint;

use frost_core::Ciphersuite;
use sdk::Job;
use sdk::serde::to_field;
use sdk::tangle::layers::TangleLayer;
use sdk::testing::{tempfile, utils::*};

use tokio::time::timeout;

const N: usize = 3;
const T: usize = N / 2 + 1;

#[tokio::test(flavor = "multi_thread")]
async fn keygen_e2e() -> color_eyre::Result<()> {
    color_eyre::install()?;
    setup_log();

    sdk::info!("Running FROST blueprint test");
    let test_timeout = std::time::Duration::from_secs(60);
    let tmp_dir = tempfile::TempDir::new()?;
    let harness = tangle::TangleTestHarness::setup(tmp_dir).await?;
    let exit_after_registration = false;

    // Setup service
    let (mut test_env, service_id, _blueprint_id) =
        harness.setup_services::<N>(exit_after_registration).await?;

    test_env.initialize().await?;
    let handles = test_env.node_handles().await;
    let mut contexts = Vec::new();
    for handle in &handles {
        let env = handle.gadget_config().await;

        let ctx = blueprint::FrostContext::new(env).await?;
        contexts.push(ctx);

        handle.add_job(blueprint::keygen.layer(TangleLayer)).await;
    }

    test_env.start_with_contexts(contexts).await?;

    let job_inputs = vec![
        to_field(frost_ed25519::Ed25519Sha512::ID)?,
        to_field(T as u16)?,
    ];
    let job = harness
        .submit_job(service_id, blueprint::KEYGEN_JOB_ID, job_inputs)
        .await?;

    sdk::info!(job.job, service_id, job.call_id, "Submitted KEYGEN job");
    let results = timeout(
        test_timeout,
        harness.wait_for_job_execution(service_id, job),
    )
    .await??;
    assert_eq!(results.service_id, service_id);

    Ok(())
}
