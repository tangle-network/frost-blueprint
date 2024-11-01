use color_eyre::Result;
use frost_blueprint as blueprint;
use gadget_sdk::{
    self as sdk,
    runners::{tangle::TangleConfig, BlueprintRunner},
};
use sdk::tangle_subxt::*;
use tracing::Instrument;

#[sdk::main(env)]
async fn main() -> Result<()> {
    let span = env.span.clone();
    let _spanned = span.enter();
    let signer = env.first_sr25519_signer()?;
    let network_identity = {
        let ed25519 = env.first_ed25519_signer()?.signer().clone();
        sdk::libp2p::identity::Keypair::ed25519_from_bytes(ed25519.seed())?
    };
    let my_ecdsa_key = env.first_ecdsa_signer()?;
    let client = subxt::OnlineClient::from_url(&env.ws_rpc_endpoint).await?;
    let network_config = sdk::network::setup::NetworkConfig::new_service_network(
        network_identity,
        my_ecdsa_key.signer().clone(),
        env.bootnodes.clone(),
        env.bind_addr,
        env.bind_port,
        blueprint::NETWORK_PROTOCOL,
    );
    let gossip_handle = sdk::network::setup::start_p2p_network(network_config)?;
    let tangle = env.protocol_specific.tangle()?;

    let service_id = match tangle.service_id {
        Some(service_id) => service_id,
        None => {
            sdk::error!("Service ID not found, exiting...");
            return Ok(());
        }
    };

    // Create your service context
    // Here you can pass any configuration or context that your service needs.
    let context = blueprint::ServiceContext::new(env.clone(), gossip_handle)?;

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
    BlueprintRunner::new(TangleConfig::default(), env)
        .job(keygen)
        .job(sign)
        .run()
        .instrument(span.clone())
        .await?;
    sdk::info!("Exiting...");
    Ok(())
}
