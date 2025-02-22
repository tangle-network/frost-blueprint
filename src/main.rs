use blueprint_sdk as sdk;
use color_eyre::Result;
use frost_blueprint as blueprint;
use sdk::logging;
use sdk::runners::core::runner::BlueprintRunner;
use sdk::runners::tangle::tangle::TangleConfig;
use tracing::Instrument;

#[sdk::main(env)]
#[tracing::instrument(skip(env), name = "frost_blueprint", err)]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let config = TangleConfig::default();

    let context = blueprint::FrostContext::new(env.clone()).await?;

    let keygen = blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;
    let sign = blueprint::sign::SignEventHandler::new(&env, context.clone()).await?;

    logging::info!("Starting the event watcher ...");
    BlueprintRunner::new(config, env)
        .job(keygen)
        .job(sign)
        .run()
        .in_current_span()
        .await?;
    logging::info!("Exiting...");
    Ok(())
}
