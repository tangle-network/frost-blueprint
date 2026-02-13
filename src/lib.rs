pub mod keygen;
pub mod rounds;
pub mod sign;

use blueprint_sdk::alloy::sol;
use blueprint_sdk::clients::BlueprintServicesClient;
use blueprint_sdk::contexts::tangle::TangleClientContext;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::service_handle::NetworkServiceHandle;
use blueprint_sdk::runner::config::BlueprintEnvironment;
use blueprint_sdk::stores::local_database::LocalDatabase;
use blueprint_sdk::tangle::TangleLayer;
use blueprint_sdk::{Job, Router};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// The network protocol for the FROST service
const NETWORK_PROTOCOL: &str = "zcash/frost/1.0.0";

pub const JOB_KEYGEN: u8 = 0;
pub const JOB_SIGN: u8 = 1;

sol! {
    struct KeygenRequest { string ciphersuite; uint16 threshold; }
    struct KeygenResult { bytes public_key; }
    struct SignRequest { bytes pubkey; bytes msg; }
    struct SignResult { bytes signature; }
}

/// Global FROST context, initialized once at startup.
static FROST_CTX: OnceLock<FrostContext> = OnceLock::new();

/// Get the global FROST context. Panics if not initialized.
pub fn frost_ctx() -> &'static FrostContext {
    FROST_CTX.get().expect("FrostContext not initialized")
}

/// FROST Service Context
#[derive(Clone)]
pub struct FrostContext {
    pub env: BlueprintEnvironment,
    pub network_backend: NetworkServiceHandle<K256Ecdsa>,
    pub store: Arc<LocalDatabase<serde_json::Value>>,
}

impl FrostContext {
    /// Creates and globally initializes the FROST context.
    pub async fn init(env: &BlueprintEnvironment) -> Result<(), String> {
        let tangle_client = env.tangle_client().await.map_err(|e| e.to_string())?;

        let operators = tangle_client
            .get_operators()
            .await
            .map_err(|e| e.to_string())?;

        let operator_keys =
            blueprint_sdk::networking::service::AllowedKeys::<K256Ecdsa>::EvmAddresses(
                operators.keys().cloned().collect(),
            );

        let (_allowed_keys_tx, allowed_keys_rx) = crossbeam_channel::unbounded();

        let network_config = env
            .libp2p_network_config::<K256Ecdsa>(NETWORK_PROTOCOL, false)
            .map_err(|e| e.to_string())?;

        let network_backend = env
            .libp2p_start_network(network_config, operator_keys, allowed_keys_rx)
            .map_err(|e| e.to_string())?;

        let keystore_dir = PathBuf::from(&env.keystore_uri).join("frost.json");
        let store = Arc::new(
            LocalDatabase::open(keystore_dir).map_err(|e| format!("Failed to open store: {e}"))?,
        );

        let ctx = FrostContext {
            env: env.clone(),
            network_backend,
            store,
        };

        FROST_CTX
            .set(ctx)
            .map_err(|_| "FrostContext already initialized".to_string())
    }

    /// Returns the blueprint ID
    pub fn blueprint_id(&self) -> Result<u64, String> {
        self.env
            .protocol_settings
            .tangle()
            .map(|c| c.blueprint_id)
            .map_err(|err| format!("Blueprint ID not found: {err}"))
    }
}

pub fn router() -> Router {
    Router::new()
        .route(JOB_KEYGEN, keygen::keygen.layer(TangleLayer))
        .route(JOB_SIGN, sign::sign.layer(TangleLayer))
}
