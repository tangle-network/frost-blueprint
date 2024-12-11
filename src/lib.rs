//! FROST Blueprint
use std::sync::Arc;

use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::contexts::MPCContext;
use gadget_sdk::keystore::TanglePairSigner;
use gadget_sdk::network::NetworkMultiplexer;
use gadget_sdk::subxt_core::ext::sp_core::ecdsa;

use gadget_sdk::subxt::tx::Signer;
use sdk::contexts::{KeystoreContext, ServicesContext, TangleClientContext};

/// FROST Keygen module
pub mod keygen;
/// Key-Value Storage module
mod kv;
/// FROST round-based module
pub mod rounds;
/// FROST Signing module
pub mod sign;

/// The network protocol for the FROST service
const NETWORK_PROTOCOL: &str = "/zcash/frost/1.0.0";

/// FROST Service Context that holds all the necessary context for the service
/// to run
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext, MPCContext)]
pub struct FrostContext {
    /// The overreaching configuration for the service
    #[config]
    config: sdk::config::StdGadgetConfiguration,
    #[call_id]
    call_id: Option<u64>,
    /// The gossip handle for the network
    network_backend: Arc<NetworkMultiplexer>,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
    /// Account id
    #[allow(dead_code)]
    account_id: TanglePairSigner<ecdsa::Pair>,
}

impl FrostContext {
    /// Create a new service context
    pub fn new(config: sdk::config::StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_identity = {
            let ed25519 = *config.first_ed25519_signer()?.signer();
            sdk::libp2p::identity::Keypair::ed25519_from_bytes(ed25519.seed())?
        };
        let my_ecdsa_key = config.first_ecdsa_signer()?;
        let network_config = sdk::network::setup::NetworkConfig::new_service_network(
            network_identity,
            my_ecdsa_key.signer().clone(),
            config.bootnodes.clone(),
            config.target_port,
            NETWORK_PROTOCOL,
        );
        let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
            .map_err(|e| eyre::eyre!("Failed to start the network: {e:?}"))?;
        Ok(Self {
            #[cfg(not(feature = "kv-sled"))]
            store: Arc::new(kv::MemKVStore::new()),
            #[cfg(feature = "kv-sled")]
            store: match config.data_dir.as_ref() {
                Some(data_dir) => Arc::new(kv::SledKVStore::from_path(data_dir)?),
                None => Arc::new(kv::SledKVStore::in_memory()?),
            },
            call_id: None,
            config,
            account_id: my_ecdsa_key,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }
}
