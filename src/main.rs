use color_eyre::eyre;
use color_eyre::Result;
use frost_blueprint as blueprint;
use gadget_sdk::{
    self as sdk,
    runners::{tangle::TangleConfig, BlueprintConfig, BlueprintRunner},
};
use tracing::Instrument;

#[sdk::main(env)]
#[tracing::instrument(skip(env), name = "frost-blueprint", parent = env.span.clone(), err)]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let signer = env.first_sr25519_signer()?;
    let network_identity = {
        let ed25519 = env.first_ed25519_signer()?.signer().clone();
        sdk::libp2p::identity::Keypair::ed25519_from_bytes(ed25519.seed())?
    };
    let my_ecdsa_key = env.first_ecdsa_signer()?;
    let client = env.client().await?;
    let network_config = sdk::network::setup::NetworkConfig::new_service_network(
        network_identity,
        my_ecdsa_key.signer().clone(),
        env.bootnodes.clone(),
        env.target_addr,
        env.target_port,
        blueprint::NETWORK_PROTOCOL,
    );
    let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
        .map_err(|e| eyre::eyre!("Failed to start the network: {}", e))?;
    let tangle = env
        .protocol_specific
        .tangle()
        .map_err(|e| eyre::eyre!("Failed to get tangle configuration: {}", e))?;
    let config = TangleConfig::default();

    // Create your service context
    // Here you can pass any configuration or context that your service needs.
    let context = blueprint::ServiceContext::new(env.clone(), gossip_handle)?;

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
    // Create the event handler from the job
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
