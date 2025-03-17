use crate::rounds::sign as sign_protocol;
use blueprint_sdk as sdk;
use color_eyre::eyre;
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Signature};
use futures::TryFutureExt;
use rand::SeedableRng;
use rand::seq::IteratorRandom;
use sdk::contexts::tangle::TangleClientContext;
use sdk::crypto::hashing::keccak_256;
use sdk::crypto::sp_core::SpEcdsaPublic;
use sdk::crypto::tangle_pair_signer::sp_core::ecdsa;
use sdk::extract::Context;
use sdk::keystore::backends::Backend;
use sdk::keystore::crypto::sp_core::SpEcdsa;
use sdk::networking::discovery::peers::VerificationIdentifierKey;
use sdk::networking::round_based_compat::RoundBasedNetworkAdapter;
use sdk::tangle::extract::{CallId, List, TangleArgs2, TangleResult};
use sdk::tangle_subxt::subxt::utils::AccountId32;
use std::collections::BTreeMap;

use crate::FrostContext;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown ciphersuite: {0}")]
    UnknwonCiphersuite(String),
    #[error("The Secret Share for that key is not found")]
    KeyNotFound,
    #[error("Self not in operators")]
    SelfNotInOperators,
    #[error("Self not in signers")]
    SelfNotInSigners,
    #[error("Verifiying Share not found")]
    VerifyingShareNotFound,
    #[error(transparent)]
    Subxt(#[from] sdk::tangle_subxt::subxt::Error),
    #[error(transparent)]
    Sdk(#[from] sdk::error::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Frost error: {0}")]
    Frost(String),
    #[error(transparent)]
    ToUnsigned16(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(color_eyre::eyre::Error),
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

/// Run Signing Protocol using a previously generated key and a message.
///
/// # Parameters
/// - `pubkey`: The public key generated by the [`crate::keygen::keygen`] protocol.
/// - `msg`: The message to sign.
///
/// # Returns
/// The Signature of the message hash (the hash function is defined by the ciphersuite).
///
/// # Errors
/// - `KeyNotFound`: If the secret share for the key is not found.
#[tracing::instrument(skip_all, err)]
pub async fn sign(
    CallId(current_call_id): CallId,
    Context(context): Context<FrostContext>,
    TangleArgs2(List(pubkey), List(msg)): TangleArgs2<List<u8>, List<u8>>,
) -> Result<TangleResult<List<u8>>, Error> {
    let pubkey_hex = hex::encode(&pubkey);
    let kv = context.store.clone();
    let raw_info = kv.get(&pubkey_hex)?.ok_or(Error::KeyNotFound)?;
    let info_json_value = serde_json::from_slice::<serde_json::Value>(&raw_info)?;
    let ciphersuite = info_json_value["ciphersuite"]
        .as_str()
        .ok_or(Error::KeyNotFound)?;

    let tangle_client = context
        .tangle_client()
        .map_err(|e| Error::Sdk(e.into()))
        .await?;

    let (_, operators) = tangle_client
        .get_party_index_and_operators()
        .map_err(|e| Error::Sdk(e.into()))
        .await?;

    let my_ecdsa = context
        .config
        .keystore()
        .first_local::<SpEcdsa>()
        .map_err(|e| Error::Other(e.into()))?;

    let rng = rand::rngs::OsRng;

    let res = match ciphersuite {
        frost_ed25519::Ed25519Sha512::ID => {
            let entry: crate::keygen::KeygenEntry<frost_ed25519::Ed25519Sha512> =
                serde_json::from_value(info_json_value["entry"].clone())?;
            signing_internal(
                rng,
                my_ecdsa.0,
                operators,
                entry.key_pkg,
                entry.pub_key_pkg,
                msg,
                current_call_id,
                &context,
            )
            .map_ok(|s| s.serialize().ok())
            .await
        }
        frost_secp256k1::Secp256K1Sha256::ID => {
            let entry: crate::keygen::KeygenEntry<frost_secp256k1::Secp256K1Sha256> =
                serde_json::from_value(info_json_value["entry"].clone())?;
            signing_internal(
                rng,
                my_ecdsa.0,
                operators,
                entry.key_pkg,
                entry.pub_key_pkg,
                msg,
                current_call_id,
                &context,
            )
            .map_ok(|s| s.serialize().ok())
            .await
        }
        _ => return Err(Error::UnknwonCiphersuite(ciphersuite.to_string())),
    };

    match res {
        Ok(Some(signature)) => Ok(TangleResult(signature.into())),
        Err(Error::SelfNotInSigners) => {
            // This is a special case where the signer is not in the signers list.
            // This is a valid case, as the signer is not required to be in the signers list.
            Err(Error::SelfNotInSigners)
        }
        Ok(None) => Err(Error::Other(eyre::eyre!("Signature serialization failed"))),
        Err(e) => Err(e),
    }
}

/// A generic signing protocol over a given ciphersuite.
#[tracing::instrument(skip(rng, key_pkg, pub_key_pkg, msg, context))]
#[allow(clippy::too_many_arguments)]
async fn signing_internal<C, R>(
    mut rng: R,
    my_ecdsa_key: ecdsa::Public,
    participants: BTreeMap<AccountId32, ecdsa::Public>,
    key_pkg: KeyPackage<C>,
    pub_key_pkg: PublicKeyPackage<C>,
    msg: Vec<u8>,
    call_id: u64,
    context: &FrostContext,
) -> Result<Signature<C>, Error>
where
    C: Ciphersuite + Send + Sync + Unpin,
    <<C as Ciphersuite>::Group as frost_core::Group>::Element: Send + Sync + Unpin,
    <<<C as Ciphersuite>::Group as frost_core::Group>::Field as frost_core::Field>::Scalar:
        Send + Sync + Unpin,
    R: rand::RngCore + rand::CryptoRng,
{
    let pub_key = pub_key_pkg.verifying_key().serialize()?;
    let signers_seed = {
        let mut key = pub_key.clone();
        key.extend_from_slice(&msg);
        keccak_256(&pub_key)
    };

    let t = *key_pkg.min_signers();

    let mut signers_rng = rand_chacha::ChaChaRng::from_seed(signers_seed);
    let signers = participants
        .iter()
        .enumerate()
        .map(|(i, (_, v))| (i as u16, *v))
        .choose_multiple(&mut signers_rng, usize::from(t));

    let selected_parties: BTreeMap<u16, _> = signers.into_iter().collect();
    let signers_ids: Vec<_> = selected_parties.keys().copied().collect();

    let i = selected_parties
        .iter()
        .position(|(_, v)| v == &my_ecdsa_key)
        .ok_or(Error::SelfNotInSigners)?;

    let i = u16::try_from(i)?;
    assert_eq!(
        signers_ids.len(),
        usize::from(*key_pkg.min_signers()),
        "Invalid number of signers"
    );

    let signing_task_hash = {
        let mut key = pub_key.clone();
        key.extend_from_slice(&msg);
        key.extend_from_slice(&call_id.to_be_bytes());
        key.extend_from_slice(&msg);
        keccak_256(&key)
    };

    let delivery = RoundBasedNetworkAdapter::new(
        context.network_service_handle.clone(),
        i,
        selected_parties
            .iter()
            .map(|(j, ecdsa)| {
                (
                    *j,
                    VerificationIdentifierKey::InstancePublicKey(SpEcdsaPublic(*ecdsa)),
                )
            })
            .collect(),
        hex::encode(signing_task_hash),
    );

    let party = round_based::MpcParty::connected(delivery);
    let signature = sign_protocol::run::<R, C, _>(
        &mut rng,
        &key_pkg,
        &pub_key_pkg,
        &signers_ids,
        &msg,
        party,
        None,
    )
    .await?;

    sdk::debug!(
        pubkey = %hex::encode(pub_key),
        signature = %hex::encode(signature.serialize()?),
        msg = %hex::encode(&msg),
        "Signing Done"
    );
    Ok(signature)
}
