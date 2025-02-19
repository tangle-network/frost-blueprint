//! FROST Blueprint
use std::sync::Arc;

use blueprint_sdk as sdk;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use color_eyre::eyre;
use sdk::config::GadgetConfiguration;
use sdk::macros::contexts::{KeystoreContext, ServicesContext, TangleClientContext};

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
const NETWORK_PROTOCOL: &str = "zcash/frost/1.0.0";

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
    /// The service handle for the networking.
    network_service_handle: NetworkServiceHandle,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
    /// Account id
    #[allow(dead_code)]
    account_id: sp_core::ecdsa::Pair,
}

impl FrostContext {
    /// Create a new service context
    pub fn new(config: GadgetConfiguration) -> eyre::Result<Self> {
        let network_config = config.libp2p_network_config(NETWORK_PROTOCOL)?;
        let identity = network_config.instance_secret_key.0.clone();
        let network_service_handle = config.libp2p_start_network(network_config)?;

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
            network_service_handle,
        })
    }

    /// Get the call id for the service
    pub fn current_call_id(&self) -> eyre::Result<u64> {
        self.call_id.ok_or_else(|| eyre::eyre!("Call ID not set"))
    }
}
