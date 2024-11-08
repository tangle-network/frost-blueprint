//! FROST Blueprint

use std::collections::BTreeMap;
use std::sync::Arc;

use color_eyre::eyre;
use gadget_sdk as sdk;
use gadget_sdk::network::{NetworkMultiplexer, StreamKey};
use gadget_sdk::subxt_core::ext::sp_core::{ecdsa, keccak_256};
use gadget_sdk::subxt_core::utils::AccountId32;

use kv::SharedDynKVStore;
use sdk::ctx::{KeystoreContext, ServicesContext, TangleClientContext};
use sdk::tangle_subxt::tangle_testnet_runtime::api;

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
    config: sdk::config::StdGadgetConfiguration,
    /// The gossip handle for the network
    network_backend: Arc<NetworkMultiplexer>,
    /// The key-value store for the service
    store: kv::SharedDynKVStore<String, Vec<u8>>,
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
            config,
            network_backend: Arc::new(NetworkMultiplexer::new(gossip_handle)),
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

    /// Get the current blueprint id
    pub fn blueprint_id(&self) -> eyre::Result<u64> {
        self.config()
            .protocol_specific
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|e| eyre::eyre!("Failed to get blueprint id: {e}"))
    }

    /// Get Current Service Operators' ECDSA Keys as a map.
    pub async fn current_service_operators_ecdsa_keys(
        &self,
    ) -> eyre::Result<BTreeMap<AccountId32, ecdsa::Public>> {
        let client = self.tangle_client().await?;
        let current_blueprint = self.blueprint_id()?;
        let current_service_op = self.current_service_operators(&client).await?;
        let storage = client.storage().at_latest().await?;
        let mut map = BTreeMap::new();
        for (operator, _) in current_service_op {
            let addr = api::storage()
                .services()
                .operators(current_blueprint, &operator);
            let maybe_pref = storage.fetch(&addr).await?;
            if let Some(pref) = maybe_pref {
                map.insert(operator, ecdsa::Public(pref.key));
            } else {
                return Err(eyre::eyre!(
                    "Failed to get operator's {operator} public ecdsa key"
                ));
            }
        }

        Ok(map)
    }

    /// Get the current call id for this job.
    pub async fn current_call_id(&self) -> Result<u64, eyre::Error> {
        let client = self.tangle_client().await?;
        let addr = api::storage().services().next_job_call_id();
        let storage = client.storage().at_latest().await?;
        let maybe_call_id = storage.fetch_or_default(&addr).await?;
        Ok(maybe_call_id.saturating_sub(1))
    }

    /// Get the network backend for keygen job
    pub fn keygen_network_backend(&self, call_id: u64) -> impl sdk::network::Network {
        self.network_backend.multiplex(StreamKey {
            task_hash: keccak_256(&[&b"keygen"[..], &call_id.to_le_bytes()[..]].concat()),
            round_id: -1,
        })
    }

    /// Get the network backend for signing job
    pub fn signing_network_backend(&self, call_id: u64) -> impl sdk::network::Network {
        self.network_backend.multiplex(StreamKey {
            task_hash: keccak_256(&[&b"signing"[..], &call_id.to_le_bytes()[..]].concat()),
            round_id: -1,
        })
    }
}
