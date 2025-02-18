//! FROST Blueprint
use std::sync::Arc;

use blueprint_sdk as sdk;
use color_eyre::eyre;
use sdk::config::GadgetConfiguration;
use sdk::macros::contexts::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::networking::networking::NetworkMultiplexer;

use sdk::crypto::tangle_pair_signer::sp_core;

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
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct FrostContext {
    /// The overreaching configuration for the service
    #[config]
    config: GadgetConfiguration,
    /// The call id for the service
    #[call_id]
    call_id: Option<u64>,
    /// The gossip handle for the network
    network_backend: Arc<NetworkMultiplexer>,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
    /// Account id
    #[allow(dead_code)]
    account_id: sp_core::ecdsa::Pair,
}

impl FrostContext {
    /// Create a new service context
    pub fn new(config: GadgetConfiguration) -> eyre::Result<Self> {
        let mut network_config = config.libp2p_network_config(NETWORK_PROTOCOL)?;
        network_config.bind_port = random_port();
        let identity = network_config.secret_key.0.clone();
        let gossip_handle = sdk::networking::setup::start_p2p_network(network_config)?;

        Ok(Self {
            #[cfg(not(feature = "kv-sled"))]
            store: Arc::new(kv::MemKVStore::new()),
            #[cfg(feature = "kv-sled")]
            store: match config.data_dir.as_ref() {
                Some(data_dir) => Arc::new(kv::SledKVStore::from_path(data_dir)?),
                None => Arc::new(kv::SledKVStore::in_memory()?),
            },
            config,
            call_id: None,
            account_id: identity,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
        })
    }

    /// Get the call id for the service
    pub fn current_call_id(&self) -> eyre::Result<u64> {
        self.call_id.ok_or_else(|| eyre::eyre!("Call ID not set"))
    }
}

fn random_port() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen_range(10000..65535)
}
