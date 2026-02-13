use std::collections::HashMap;

use crate::rounds::keygen as keygen_protocol;
use crate::{frost_ctx, KeygenRequest, KeygenResult};
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::{debug, info};
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, VerifyingKey};
use rand::rngs::OsRng;
use round_based::PartyIndex;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown ciphersuite: {0}")]
    UnknownCiphersuite(String),
    #[error("Self not in operators")]
    SelfNotInOperators,
    #[error("Frost error: {0}")]
    Frost(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl<C: Ciphersuite> From<frost_core::Error<C>> for Error {
    fn from(e: frost_core::Error<C>) -> Self {
        Error::Frost(e.to_string())
    }
}

impl<C: Ciphersuite> From<keygen_protocol::Error<C>> for Error {
    fn from(e: keygen_protocol::Error<C>) -> Self {
        Error::Protocol(e.to_string())
    }
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}

/// A KeygenEntry to store the keygen result.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct KeygenEntry<C: Ciphersuite> {
    pub key_pkg: KeyPackage<C>,
    pub pub_key_pkg: PublicKeyPackage<C>,
}

/// Run Keygen Protocol between the operators and return the public key.
pub async fn keygen(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<KeygenRequest>,
) -> Result<TangleResult<KeygenResult>, String> {
    let ciphersuite = request.ciphersuite.to_string();
    let threshold = request.threshold;

    let ctx = frost_ctx();

    // Get party info from connected peers
    let mut all_peers = ctx.network_backend.peers();
    let local_peer_id = ctx.network_backend.local_peer_id;
    if !all_peers.contains(&local_peer_id) {
        all_peers.push(local_peer_id);
    }
    all_peers.sort();

    let n = all_peers.len() as u16;
    let i = all_peers
        .iter()
        .position(|p| *p == local_peer_id)
        .ok_or_else(|| "Local peer not found in peer list".to_string())? as u16;

    let parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let rng = OsRng;

    let key = match ciphersuite.as_str() {
        frost_ed25519::Ed25519Sha512::ID => {
            keygen_internal::<frost_ed25519::Ed25519Sha512, _>(
                rng, i, n, threshold, &parties,
            )
            .await
            .map_err(|e| e.to_string())?
            .serialize()
            .map_err(|e| e.to_string())?
        }
        frost_secp256k1::Secp256K1Sha256::ID => {
            keygen_internal::<frost_secp256k1::Secp256K1Sha256, _>(
                rng, i, n, threshold, &parties,
            )
            .await
            .map_err(|e| e.to_string())?
            .serialize()
            .map_err(|e| e.to_string())?
        }
        _ => return Err(format!("Unknown ciphersuite: {ciphersuite}")),
    };

    Ok(TangleResult(KeygenResult {
        public_key: key.into(),
    }))
}

/// A generic keygen protocol over any ciphersuite.
async fn keygen_internal<C, R>(
    mut rng: R,
    i: u16,
    n: u16,
    t: u16,
    parties: &HashMap<PartyIndex, libp2p::PeerId>,
) -> Result<VerifyingKey<C>, Error>
where
    C: Ciphersuite + Send + Sync + Unpin,
    <<C as Ciphersuite>::Group as frost_core::Group>::Element: Send + Sync + Unpin,
    <<<C as Ciphersuite>::Group as frost_core::Group>::Field as frost_core::Field>::Scalar:
        Send + Sync + Unpin,
    R: rand::RngCore + rand::CryptoRng,
{
    let ctx = frost_ctx();

    info!("Starting FROST Keygen for party {i}, n={n}, t={t}, ciphersuite={}", C::ID);

    let network = RoundBasedNetworkAdapter::<keygen_protocol::Msg<C>, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        parties,
        crate::NETWORK_PROTOCOL,
    );
    let party = round_based::MpcParty::connected(network);

    let (key_package, public_key_package) =
        keygen_protocol::run::<R, C, _>(&mut rng, t, n, i, party, None).await?;
    let verifying_key = *public_key_package.verifying_key();
    let pubkey = hex::encode(verifying_key.serialize()?);
    debug!(%pubkey, "Keygen Done");

    let entry = serde_json::json!({
        "ciphersuite": C::ID,
        "entry": KeygenEntry {
            key_pkg: key_package,
            pub_key_pkg: public_key_package,
        },
    });

    // Save the keygen entry
    let _ = ctx.store.set(&pubkey, entry);

    Ok(verifying_key)
}
