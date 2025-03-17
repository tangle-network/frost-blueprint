use blueprint_sdk as sdk;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::sp_core::SpSr25519;
use blueprint_sdk::crypto::tangle_pair_signer::TanglePairSigner;
use blueprint_sdk::keystore::backends::Backend;
use blueprint_sdk::tangle::consumer::TangleConsumer;
use blueprint_sdk::tangle::producer::TangleProducer;
use color_eyre::Result;
use frost_blueprint as blueprint;
use sdk::runner::BlueprintRunner;
use sdk::runner::config::BlueprintEnvironment;
use sdk::runner::tangle::config::TangleConfig;
use tracing::Instrument;

#[tokio::main]
#[tracing::instrument(name = "frost_blueprint", err)]
async fn main() -> Result<()> {
    color_eyre::install()?;
    setup_log();

    let env = BlueprintEnvironment::load()?;
    let config = TangleConfig::new(Default::default());

    // Signer
    let sr25519_signer = env.keystore().first_local::<SpSr25519>()?;
    let sr25519_pair = env.keystore().get_secret::<SpSr25519>(&sr25519_signer)?;
    let st25519_signer = TanglePairSigner::new(sr25519_pair.0);

    // Producer
    let tangle_client = env.tangle_client().await?;
    let tangle_producer =
        TangleProducer::finalized_blocks(tangle_client.rpc_client.clone()).await?;
    // Consumer
    let tangle_consumer = TangleConsumer::new(tangle_client.rpc_client.clone(), st25519_signer);

    let context = blueprint::FrostContext::new(env.clone()).await?;
    let router = sdk::Router::new()
        .route(blueprint::KEYGEN_JOB_ID, blueprint::keygen)
        .route(blueprint::SIGN_JOB_ID, blueprint::sign)
        .with_context(context);
    sdk::info!("Starting the event watcher ...");
    let result = BlueprintRunner::builder(config, env)
        .router(router)
        .producer(tangle_producer)
        .consumer(tangle_consumer)
        .run()
        .in_current_span()
        .await;
    if let Err(e) = result {
        sdk::error!("Runner failed! {e:?}");
    }
    Ok(())
}

pub fn setup_log() {
    use tracing_subscriber::util::SubscriberInitExt;

    let _ = tracing_subscriber::fmt::SubscriberBuilder::default()
        .without_time()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .finish()
        .try_init();
}
