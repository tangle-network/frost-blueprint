use crate::rounds::delivery;
use crate::rounds::sign as sign_protocol;
use crate::rounds::IdentifierWrapper;
use api::services::events::JobCalled;
use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Signature};
use gadget_sdk::network::Network;
use gadget_sdk::random::rand::seq::IteratorRandom;
use gadget_sdk::random::SeedableRng;
use gadget_sdk::subxt_core::ext::sp_core::keccak_256;
use gadget_sdk::{self as sdk, random};
use sdk::ctx::{GossipNetworkContext, ServicesContext, TangleClientContext};
use sdk::event_listener::tangle::{
    jobs::{services_post_processor, services_pre_processor},
    TangleEventListener,
};
use sdk::tangle_subxt::subxt::tx::Signer;
use sdk::tangle_subxt::tangle_testnet_runtime::api;

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
    #[error(transparent)]
    Config(#[from] sdk::config::Error),
    #[error("Protocol error: {0}")]
    Protocol(Box<dyn std::error::Error>),
    #[error("Frost error: {0}")]
    Frost(Box<dyn std::error::Error>),
    #[error(transparent)]
    ToUnsigned16(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl<C: Ciphersuite> From<frost_core::Error<C>> for Error {
    fn from(e: frost_core::Error<C>) -> Self {
        Error::Frost(Box::new(e))
    }
}

impl<C: Ciphersuite> From<sign_protocol::Error<C>> for Error {
    fn from(e: sign_protocol::Error<C>) -> Self {
        Error::Protocol(Box::new(e))
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
/// # Note
/// - `ciphersuite`: 0 for Ed25519, 1 for Secp256k1.
/// - `threshold`: The threshold of the keygen protocol should be less than the number of operators.
#[sdk::job(
    id = 1,
    params(pubkey, msg),
    result(_),
    event_listener(
        listener = TangleEventListener::<FrostContext, JobCalled>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    )
)]
#[tracing::instrument(skip_all, parent = context.config.span.clone(), err)]
pub async fn sign(pubkey: Vec<u8>, msg: Vec<u8>, context: FrostContext) -> Result<Vec<u8>, Error> {
    let pubkey_hex = hex::encode(&pubkey);
    let kv = context.store();
    let raw_info = kv.get(&pubkey_hex)?.ok_or(Error::KeyNotFound)?;
    let info_json_value = serde_json::from_slice::<serde_json::Value>(&raw_info)?;
    let ciphersuite = info_json_value["ciphersuite"]
        .as_str()
        .ok_or(Error::KeyNotFound)?;
    let client = context.tangle_client().await?;
    let operators_with_restake = context.current_service_operators(&client).await?;
    let my_key = context.config.first_sr25519_signer()?;
    let n = operators_with_restake.len();
    let i = operators_with_restake
        .iter()
        .map(|(op, _)| op)
        .position(|op| op == &my_key.account_id())
        .ok_or(Error::SelfNotInOperators)?;

    sdk::info!(%n, %i, %ciphersuite, "Signing");
    let net = context.gossip_network().clone();
    let rng = random::rand::rngs::OsRng;
    let signature = match ciphersuite {
        frost_ed25519::Ed25519Sha512::ID => {
            let entry: crate::keygen::KeygenEntry<frost_ed25519::Ed25519Sha512> =
                serde_json::from_value(info_json_value["entry"].clone())?;
            signing_internal(rng, net, entry.keypkg, entry.pubkeypkg, msg)
                .await?
                .serialize()?
        }
        frost_secp256k1::Secp256K1Sha256::ID => {
            let entry: crate::keygen::KeygenEntry<frost_secp256k1::Secp256K1Sha256> =
                serde_json::from_value(info_json_value["entry"].clone())?;
            signing_internal(rng, net, entry.keypkg, entry.pubkeypkg, msg)
                .await?
                .serialize()?
        }
        _ => return Err(Error::UnknwonCiphersuite(ciphersuite.to_string())),
    };

    Ok(signature)
}

/// A genaric signing protocol over a given ciphersuite.
#[tracing::instrument(skip(rng, net, key_pkg, pub_key_pkg, msg))]
async fn signing_internal<C, R, N>(
    mut rng: R,
    net: N,
    key_pkg: KeyPackage<C>,
    pub_key_pkg: PublicKeyPackage<C>,
    msg: Vec<u8>,
) -> Result<Signature<C>, Error>
where
    C: Ciphersuite + Send + Unpin,
    <<C as Ciphersuite>::Group as frost_core::Group>::Element: Send + Unpin,
    <<<C as Ciphersuite>::Group as frost_core::Group>::Field as frost_core::Field>::Scalar:
        Send + Unpin,
    R: random::RngCore + random::CryptoRng,
    N: Network + Unpin,
{
    let pub_key = pub_key_pkg.verifying_key().serialize()?;
    let signers_seed = {
        let mut key = pub_key.clone();
        key.extend_from_slice(&msg);
        keccak_256(&pub_key)
    };
    let n = pub_key_pkg.verifying_shares().len() as u16;
    let mut signers_rng = rand_chacha::ChaChaRng::from_seed(signers_seed);
    let t = *key_pkg.min_signers();
    let i = IdentifierWrapper(*key_pkg.identifier()).as_u16();
    let signers = (0..n).choose_multiple(&mut signers_rng, usize::from(t));

    if !signers.contains(&i) {
        return Err(Error::SelfNotInOperators);
    }
    assert_eq!(
        signers.len(),
        usize::from(*key_pkg.min_signers()),
        "Invalid number of signers"
    );
    let delivery = delivery::NetworkDeliveryWrapper::new(net, i);
    let party = round_based::MpcParty::connected(delivery);
    let signature = sign_protocol::run::<R, C, _>(
        &mut rng,
        &key_pkg,
        &pub_key_pkg,
        &signers,
        &msg,
        party,
        None,
    )
    .await?;

    sdk::debug!(
        %i,
        pubkey = %hex::encode(pub_key),
        signature = %hex::encode(signature.serialize()?),
        msg = %hex::encode(&msg),
        "Signing Done"
    );
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
    use api::runtime_types::tangle_primitives::services::field::BoundedString;
    use api::runtime_types::tangle_primitives::services::field::Field;
    use api::services::calls::types::call::Args;
    use blueprint_test_utils::test_ext::*;
    use blueprint_test_utils::*;
    use cargo_tangle::deploy::Opts;
    use frost_core::VerifyingKey;
    use gadget_sdk::error;
    use gadget_sdk::info;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn signing() {
        setup_log();
        let tangle = crate::test_utils::run_tangle().unwrap();
        let base_path = std::env::current_dir().expect("Failed to get current directory");
        let base_path = base_path
            .canonicalize()
            .expect("File could not be normalized");

        let manifest_path = base_path.join("Cargo.toml");

        let opts = Opts {
            pkg_name: option_env!("CARGO_BIN_NAME").map(ToOwned::to_owned),
            http_rpc_url: format!("http://127.0.0.1:{}", tangle.ws_port()),
            ws_rpc_url: format!("ws://127.0.0.1:{}", tangle.ws_port()),
            manifest_path,
            signer: None,
            signer_evm: None,
        };

        const N: usize = 2;
        const T: usize = N / 2 + 1;
        const CIPHERSUITE: &str = frost_ed25519::Ed25519Sha512::ID;

        new_test_ext_blueprint_manager::<N, 1, _, _, _>("", opts, run_test_blueprint_manager)
            .await
            .execute_with_async(move |client, handles, svcs| async move {
                // At this point, blueprint has been deployed, every node has registered
                // as an operator for the relevant services, and, all gadgets are running

                let keypair = handles[0].sr25519_id().clone();

                let service = svcs.services.last().unwrap();
                let service_id = service.id;
                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                info!("Submitting keygen job with params service ID: {service_id}, call ID: {call_id}");

                // Pass the arguments
                let ciphersuite = Field::String(BoundedString(BoundedVec(CIPHERSUITE.to_string().into_bytes())));
                let threshold = Field::Uint16(T as u16);
                let job_args = Args::from([ciphersuite, threshold]);

                // Next step: submit a job under that service/job id
                if let Err(err) =
                    submit_job(client, &keypair, service_id, crate::keygen::KEYGEN_JOB_ID, job_args).await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }

                // Step 2: wait for the job to complete
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, call_id, N)
                        .await
                        .expect("Failed to wait for job completion");

                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, call_id);
                let pubkey = match job_results.result[0].clone() {
                    Field::Bytes(bytes) => bytes.0,
                    _ => panic!("Expected bytes"),
                };
                let pubkey: VerifyingKey<frost_ed25519::Ed25519Sha512> = VerifyingKey::deserialize(&pubkey).expect("Failed to deserialize pubkey");
                let msg = Vec::from(b"Hello, FROST!");


                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                info!("Submitting signing job with params service ID: {service_id}, call ID: {call_id}");

                // Pass the arguments
                let pubkey_arg = Field::Bytes(BoundedVec(pubkey.serialize().unwrap()));
                let msg_arg = Field::Bytes(BoundedVec(msg.clone()));
                let job_args = Args::from([pubkey_arg, msg_arg]);

                // Next step: submit a job under that service/job id
                if let Err(err) =
                    submit_job(client, &keypair, service_id, crate::sign::SIGN_JOB_ID, job_args).await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }

                // Step 2: wait for the job to complete
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, call_id, T)
                        .await
                        .expect("Failed to wait for job completion");

                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, call_id);
                let signature = match job_results.result[0].clone() {
                    Field::Bytes(bytes) => bytes.0,
                    _ => panic!("Expected bytes"),
                };
                // Verify the signature.
                let signature: Signature<frost_ed25519::Ed25519Sha512> = Signature::deserialize(&signature).expect("Failed to deserialize signature");

                pubkey.verify(&msg, &signature).expect("Failed to verify signature");
            })
            .await
    }
}
