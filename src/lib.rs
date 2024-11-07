//! FROST Blueprint

use std::sync::Arc;

use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::ctx::GossipNetworkContext;

use kv::SharedDynKVStore;
use sdk::ctx::{KeystoreContext, ServicesContext, TangleClientContext};

/// FROST Keygen module
pub mod keygen;
/// Key-Value Storage module
mod kv;
/// FROST round-based module
pub mod rounds;
/// FROST Signing module
pub mod sign;

#[cfg(test)]
mod test_utils;

/// The network protocol for the FROST service
const NETWORK_PROTOCOL: &str = "/zcash/frost/1.0.0";

/// FROST Service Context that holds all the necessary context for the service
/// to run
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct FrostContext {
    /// The overreaching configuration for the service
    #[config]
    config: sdk::config::StdGadgetConfiguration,
    /// The gossip handle for the network
    gossip_handle: sdk::network::gossip::GossipHandle,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
}

impl FrostContext {
    /// Create a new service context
    pub fn new(config: sdk::config::StdGadgetConfiguration) -> eyre::Result<Self> {
        let network_identity = {
            let ed25519 = config.first_ed25519_signer()?.signer().clone();
            sdk::libp2p::identity::Keypair::ed25519_from_bytes(ed25519.seed())?
        };
        let my_ecdsa_key = config.first_ecdsa_signer()?;
        let network_config = sdk::network::setup::NetworkConfig::new_service_network(
            network_identity,
            my_ecdsa_key.signer().clone(),
            config.bootnodes.clone(),
            config.target_addr,
            config.target_port,
            NETWORK_PROTOCOL,
        );
        let gossip_handle = sdk::network::setup::start_p2p_network(network_config)
            .map_err(|e| eyre::eyre!("Failed to start the network: {}", e))?;
        Ok(Self {
            #[cfg(not(feature = "kv-sled"))]
            store: Arc::new(kv::MemKVStore::new()),
            #[cfg(feature = "kv-sled")]
            store: match config.data_dir.as_ref() {
                Some(data_dir) => Arc::new(kv::SledKVStore::from_path(data_dir)?),
                None => Arc::new(kv::SledKVStore::in_memory()?),
            },
            config,
            gossip_handle,
        })
    }

    /// Get the key-value store
    pub fn store(&self) -> SharedDynKVStore<String, Vec<u8>> {
        self.store.clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &sdk::config::StdGadgetConfiguration {
        &self.config
    }

    /// Get the network protocol
    pub fn network_protocol(&self) -> &str {
        NETWORK_PROTOCOL
    }
}

impl GossipNetworkContext for FrostContext {
    fn gossip_network(&self) -> &gadget_sdk::network::gossip::GossipHandle {
        &self.gossip_handle
    }
}
