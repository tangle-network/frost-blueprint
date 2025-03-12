//! FROST Blueprint
use std::sync::Arc;

use blueprint_sdk as sdk;
use blueprint_sdk::clients::GadgetServicesClient;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::sp_core::{SpEcdsa, SpEcdsaPublic};
use blueprint_sdk::networking::AllowedKeys;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use color_eyre::eyre;
use sdk::crypto::tangle_pair_signer::sp_core;
use sdk::macros::context::{ServicesContext, TangleClientContext};
use sdk::runner::config::BlueprintEnvironment;

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

/// Job ID for [`keygen::keygen`] job.
pub const KEYGEN_JOB_ID: u8 = 0;
/// Job ID for [`sign::sign`] job.
pub const SIGN_JOB_ID: u8 = 1;

pub use keygen::keygen;
pub use sign::sign;

/// FROST Service Context that holds all the necessary context for the service
/// to run
#[derive(Clone, TangleClientContext, ServicesContext)]
pub struct FrostContext {
    #[config]
    pub config: BlueprintEnvironment,
    /// The service handle for the networking.
    network_service_handle: NetworkServiceHandle<SpEcdsa>,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
    /// Account id
    #[allow(dead_code)]
    account_id: sp_core::ecdsa::Pair,
    #[allow(dead_code)]
    update_allowed_keys: crossbeam_channel::Sender<AllowedKeys<SpEcdsa>>,
}

impl FrostContext {
    /// Create a new service context
    pub async fn new(config: BlueprintEnvironment) -> eyre::Result<Self> {
        let network_config = config.libp2p_network_config::<SpEcdsa>(NETWORK_PROTOCOL, false)?;
        let identity = network_config.instance_key_pair.0.clone();
        let service_operators = config.tangle_client().await?.get_operators().await?;
        let allowed_keys = service_operators
            .values()
            .map(|k| SpEcdsaPublic(*k))
            .collect();
        let (tx, rx) = crossbeam_channel::unbounded();
        let network_service_handle = config.libp2p_start_network(
            network_config,
            AllowedKeys::InstancePublicKeys(allowed_keys),
            rx,
        )?;

        Ok(Self {
            #[cfg(not(feature = "kv-sled"))]
            store: Arc::new(kv::MemKVStore::new()),
            #[cfg(feature = "kv-sled")]
            store: match config.data_dir.as_ref() {
                Some(data_dir) => Arc::new(kv::SledKVStore::from_path(data_dir)?),
                None => Arc::new(kv::SledKVStore::in_memory()?),
            },
            config,
            account_id: identity,
            network_service_handle,
            update_allowed_keys: tx,
        })
    }
}
