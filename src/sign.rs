use crate::rounds::sign as sign_protocol;
use crate::{frost_ctx, SignRequest, SignResult};
use blueprint_sdk::crypto::hashing::sha2_256;
use blueprint_sdk::crypto::k256::K256Ecdsa;
use blueprint_sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use blueprint_sdk::tangle::extract::{Caller, TangleArg, TangleResult};
use blueprint_sdk::{debug, info};
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Signature};
use rand::rngs::OsRng;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use round_based::PartyIndex;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown ciphersuite: {0}")]
    UnknownCiphersuite(String),
    #[error("The Secret Share for that key is not found")]
    KeyNotFound,
    #[error("Self not in operators")]
    SelfNotInOperators,
    #[error("Self not in signers")]
    SelfNotInSigners,
    #[error("Verifiying Share not found")]
    VerifyingShareNotFound,
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Frost error: {0}")]
    Frost(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
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

impl<C: Ciphersuite> From<sign_protocol::Error<C>> for Error {
    fn from(e: sign_protocol::Error<C>) -> Self {
        Error::Protocol(e.to_string())
    }
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}

/// Run Signing Protocol using a previously generated key and a message.
pub async fn sign(
    Caller(_caller): Caller,
    TangleArg(request): TangleArg<SignRequest>,
) -> Result<TangleResult<SignResult>, String> {
    let pubkey = request.pubkey.to_vec();
    let msg = request.msg.to_vec();

    let ctx = frost_ctx();
    let pubkey_hex = hex::encode(&pubkey);

    let raw_info = ctx
        .store
        .get(&pubkey_hex)
        .map_err(|e| format!("Store error: {e}"))?
        .ok_or_else(|| "Key not found in store".to_string())?;

    let ciphersuite = raw_info["ciphersuite"]
        .as_str()
        .ok_or_else(|| "Missing ciphersuite in store entry".to_string())?;

    // Get party info from connected peers
    let mut all_peers = ctx.network_backend.peers();
    let local_peer_id = ctx.network_backend.local_peer_id;
    if !all_peers.contains(&local_peer_id) {
        all_peers.push(local_peer_id);
    }
    all_peers.sort();

    let n = all_peers.len() as u16;
    let my_index = all_peers
        .iter()
        .position(|p| *p == local_peer_id)
        .ok_or_else(|| "Local peer not found in peer list".to_string())? as u16;

    let all_parties: HashMap<PartyIndex, libp2p::PeerId> = all_peers
        .into_iter()
        .enumerate()
        .map(|(idx, peer_id)| (idx as PartyIndex, peer_id))
        .collect();

    let rng = OsRng;

    let res = match ciphersuite {
        frost_ed25519::Ed25519Sha512::ID => {
            let entry: crate::keygen::KeygenEntry<frost_ed25519::Ed25519Sha512> =
                serde_json::from_value(raw_info["entry"].clone())
                    .map_err(|e| e.to_string())?;
            signing_internal(
                rng,
                my_index,
                n,
                &all_parties,
                entry.key_pkg,
                entry.pub_key_pkg,
                msg,
            )
            .await
            .and_then(|s| s.serialize().map_err(|e| Error::Frost(Box::new(e))))
        }
        frost_secp256k1::Secp256K1Sha256::ID => {
            let entry: crate::keygen::KeygenEntry<frost_secp256k1::Secp256K1Sha256> =
                serde_json::from_value(raw_info["entry"].clone())
                    .map_err(|e| e.to_string())?;
            signing_internal(
                rng,
                my_index,
                n,
                &all_parties,
                entry.key_pkg,
                entry.pub_key_pkg,
                msg,
            )
            .await
            .and_then(|s| s.serialize().map_err(|e| Error::Frost(Box::new(e))))
        }
        _ => return Err(format!("Unknown ciphersuite: {ciphersuite}")),
    };

    match res {
        Ok(signature) => Ok(TangleResult(SignResult {
            signature: signature.into(),
        })),
        Err(Error::SelfNotInSigners) => {
            Err("Self not in signers list".to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// A generic signing protocol over a given ciphersuite.
async fn signing_internal<C, R>(
    mut rng: R,
    my_index: u16,
    _n: u16,
    all_parties: &HashMap<PartyIndex, libp2p::PeerId>,
    key_pkg: KeyPackage<C>,
    pub_key_pkg: PublicKeyPackage<C>,
    msg: Vec<u8>,
) -> Result<Signature<C>, Error>
where
    C: Ciphersuite + Send + Sync + Unpin,
    <<C as Ciphersuite>::Group as frost_core::Group>::Element: Send + Sync + Unpin,
    <<<C as Ciphersuite>::Group as frost_core::Group>::Field as frost_core::Field>::Scalar:
        Send + Sync + Unpin,
    R: rand::RngCore + rand::CryptoRng,
{
    let ctx = frost_ctx();
    let pub_key = pub_key_pkg.verifying_key().serialize()?;

    // Deterministic signer selection using hash of pubkey + msg
    let signers_seed = {
        let mut input = pub_key.clone();
        input.extend_from_slice(&msg);
        sha2_256(&input)
    };

    let t = *key_pkg.min_signers();
    let mut signers_rng = rand_chacha::ChaChaRng::from_seed(signers_seed);

    // Select t signers deterministically
    let signers: Vec<(u16, libp2p::PeerId)> = all_parties
        .iter()
        .map(|(&idx, &peer)| (idx, peer))
        .choose_multiple(&mut signers_rng, usize::from(t));

    let selected_parties: HashMap<PartyIndex, libp2p::PeerId> =
        signers.iter().cloned().collect();
    let signer_set: Vec<u16> = signers.iter().map(|(idx, _)| *idx).collect();

    // Find my position in the signer set
    let i = signer_set
        .iter()
        .position(|&x| x == my_index)
        .ok_or(Error::SelfNotInSigners)?;
    let i = i as u16;

    info!(
        "Starting FROST Signing for party {i}, t={t}, ciphersuite={}",
        C::ID
    );

    let network = RoundBasedNetworkAdapter::<sign_protocol::Msg<C>, K256Ecdsa>::new(
        ctx.network_backend.clone(),
        i,
        &selected_parties,
        crate::NETWORK_PROTOCOL,
    );

    let party = round_based::MpcParty::connected(network);
    let signature = sign_protocol::run::<R, C, _>(
        &mut rng,
        &key_pkg,
        &pub_key_pkg,
        &signer_set,
        &msg,
        party,
        None,
    )
    .await?;

    debug!(
        pubkey = %hex::encode(&pub_key),
        signature = %hex::encode(signature.serialize()?),
        msg = %hex::encode(&msg),
        "Signing Done"
    );
    Ok(signature)
}
