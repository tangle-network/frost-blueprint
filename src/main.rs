use color_eyre::eyre;
use color_eyre::Result;
use frost_blueprint as blueprint;
use gadget_sdk::{
    self as sdk,
    runners::{tangle::TangleConfig, BlueprintConfig, BlueprintRunner},
};
use tracing::Instrument;

#[sdk::main(env)]
#[tracing::instrument(skip(env), name = "frost_blueprint", err)]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let tangle = env
        .protocol_specific
        .tangle()
        .map_err(|e| eyre::eyre!("Failed to get tangle configuration: {}", e))?;
    let config = TangleConfig::default();

    let context = blueprint::FrostContext::new(env.clone())?;

    let service_id = match tangle.service_id {
        Some(service_id) => service_id,
        None if config.requires_registration(&env).await? => {
            sdk::info!("Running in registration mode, so no service ID is required.");
            0
        }
        None => {
            sdk::error!("Service ID not found, exiting...");
            return Ok(());
        }
    };

    let client = env.client().await?;
    let signer = env.first_sr25519_signer()?;

    let keygen = blueprint::keygen::KeygenEventHandler {
        service_id,
        client: client.clone(),
        signer: signer.clone(),
        context: context.clone(),
    };

    let sign = blueprint::sign::SignEventHandler {
        service_id,
        client,
        signer,
        context,
    };

    sdk::info!("Starting the event watcher ...");
    BlueprintRunner::new(config, env)
        .job(keygen)
        .job(sign)
        .run()
        .in_current_span()
        .await?;
    sdk::info!("Exiting...");
    Ok(())
}
