use gadget_sdk as sdk;
use gadget_sdk::ctx::GossipNetworkContext;

use derive_more::TryFrom;
use sdk::ctx::{KeystoreContext, ServicesContext, TangleClientContext};

/// FROST Keygen module
pub mod keygen;

#[derive(Clone, KeystoreContext, TangleClientContext, ServicesContext)]
pub struct ServiceContext {
    #[config]
    pub config: sdk::config::StdGadgetConfiguration,
    pub gossip_handle: sdk::network::gossip::GossipHandle,
}

impl GossipNetworkContext for ServiceContext {
    fn gossip_network(&self) -> &gadget_sdk::network::gossip::GossipHandle {
        &self.gossip_handle
    }
}

/// All supported ciphersuites
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum CipherSuite {
    /// Ed25519 Ciphersuite from [`frost_ed25519`](https://docs.rs/frost-ed25519)
    Ed25519 = 0x00,
    /// Secp256k1 Ciphersuite from [`frost_secp256k1`](https://docs.rs/frost-secp256k1)
    Secp256k1 = 0x01,
}
