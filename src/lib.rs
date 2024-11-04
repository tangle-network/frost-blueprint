use std::sync::Arc;

use gadget_sdk as sdk;
use gadget_sdk::ctx::GossipNetworkContext;

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

pub const NETWORK_PROTOCOL: &str = "/zcash/frost/1.0.0";

/// The context that is passed to the service functions
#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct ServiceContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    pub gossip_handle: sdk::network::gossip::GossipHandle,
    pub store: kv::SharedDynKVStore<String, Vec<u8>>,
}

impl ServiceContext {
    /// Create a new service context
    pub fn new(
        config: sdk::config::StdGadgetConfiguration,
        gossip_handle: sdk::network::gossip::GossipHandle,
    ) -> Result<Self, std::io::Error> {
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
}

impl GossipNetworkContext for ServiceContext {
    fn gossip_network(&self) -> &gadget_sdk::network::gossip::GossipHandle {
        &self.gossip_handle
    }
}
