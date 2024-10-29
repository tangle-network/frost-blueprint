use color_eyre::Result;
use frost_blueprint as blueprint;
use gadget_sdk as sdk;
use gadget_sdk::job_runner::MultiJobRunner;
use sdk::subxt_core::ext::sp_core::Pair;
use sdk::tangle_subxt::*;
use tangle_testnet_runtime::api::{self, runtime_types::tangle_primitives};

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

    if env.should_run_registration() {
        let preferences = tangle_primitives::services::OperatorPreferences {
            key: my_ecdsa_key.public().0,
            price_targets: tangle_primitives::services::PriceTargets {
                cpu: 0,
                mem: 0,
                storage_hdd: 0,
                storage_ssd: 0,
                storage_nvme: 0,
            },
        };
        let registration_args = vec![];
        let xt = api::tx()
            .services()
            .register(env.blueprint_id, preferences, registration_args);

        sdk::tx::tangle::send(&client, &signer, &xt).await?;
        return Ok(());
    }

    let service_id = env.service_id.expect("should exist");

    // Create your service context
    // Here you can pass any configuration or context that your service needs.
    let context = blueprint::ServiceContext {
        config: env.clone(),
        gossip_handle,
    };

    // Create the event handler from the job
    let keygen = blueprint::keygen::KeygenEventHandler {
        service_id,
        client,
        signer,
        context,
    };

    sdk::info!("Starting the event watcher ...");
    MultiJobRunner::new(env).job(keygen).run().await?;
    sdk::info!("Exiting...");
    Ok(())
}
