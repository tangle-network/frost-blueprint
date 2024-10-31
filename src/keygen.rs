use std::collections::BTreeMap;

use api::services::events::JobCalled;
use frost_core::keys::dkg::round1::Package as Round1Package;
use frost_core::keys::dkg::round2::Package as Round2Package;
use frost_core::keys::{dkg, KeyPackage, PublicKeyPackage};
use frost_core::{Ciphersuite, Identifier, VerifyingKey};
use gadget_sdk::network::{IdentifierInfo, Network};
use gadget_sdk::{self as sdk, random};
use sdk::ctx::{GossipNetworkContext, ServicesContext, TangleClientContext};
use sdk::event_listener::tangle::{
    jobs::{services_post_processor, services_pre_processor},
    TangleEventListener,
};
use sdk::tangle_subxt::subxt::tx::Signer;
use sdk::tangle_subxt::tangle_testnet_runtime::api;

use crate::ServiceContext;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown ciphersuite: {0}")]
    UnknwonCiphersuite(String),
    #[error("Self not in operators")]
    SelfNotInOperators,

    #[error(transparent)]
    Subxt(#[from] sdk::tangle_subxt::subxt::Error),
    #[error(transparent)]
    Sdk(#[from] sdk::error::Error),
    #[error(transparent)]
    Config(#[from] sdk::config::Error),
    #[error("Frost error: {0}")]
    Frost(Box<dyn std::error::Error>),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
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

/// Run Keygen Protocol between the operators and return the public key.
///
/// # Parameters
/// - `ciphersuite`: The ciphersuite to use in the keygen protocol
/// - `threshold`: The threshold of the keygen protocol.
/// # Returns
/// The public key generated by the keygen protocol.
///
/// # Errors
/// - `UnknwonCiphersuite`: The ciphersuite is not supported.
/// - `SelfNotInOperators`: The current operator is not in the operators.
///
/// # Note
/// - `ciphersuite`: The `ID` of the ciphersuite; oneof [`FROST-ED25519-SHA512-v1`, `FROST-secp256k1-SHA256-v1`].
/// - `threshold`: The threshold of the keygen protocol should be less than the number of operators.
#[sdk::job(
    id = 0,
    params(ciphersuite, threshold),
    result(_),
    event_listener(
        listener = TangleEventListener::<JobCalled, ServiceContext>,
        pre_processor = services_pre_processor,
        post_processor = services_post_processor,
    )
)]
pub async fn keygen(
    ciphersuite: String,
    threshold: u16,
    context: ServiceContext,
) -> Result<Vec<u8>, Error> {
    let client = context.tangle_client().await?;
    let operators_with_restake = context.current_service_operators(&client).await?;
    let my_key = context.config.first_sr25519_signer()?;
    let n = operators_with_restake.len();
    let i = operators_with_restake
        .iter()
        .map(|(op, _)| op)
        .position(|op| op == &my_key.account_id())
        .ok_or(Error::SelfNotInOperators)?
        .saturating_add(1);

    sdk::info!(%n, %i, %ciphersuite, "Keygen");
    let net = context.gossip_network();
    let rng = random::rand::rngs::OsRng;
    let kv = context.store.clone();
    let key = match ciphersuite.as_str() {
        frost_ed25519::Ed25519Sha512::ID => keygen_internal::<frost_ed25519::Ed25519Sha512, _, _>(
            rng,
            net,
            kv,
            threshold,
            u16::try_from(n)?,
            u16::try_from(i)?,
        )
        .await?
        .serialize()?,
        frost_secp256k1::Secp256K1Sha256::ID => {
            keygen_internal::<frost_secp256k1::Secp256K1Sha256, _, _>(
                rng,
                net,
                kv,
                threshold,
                u16::try_from(n)?,
                u16::try_from(i)?,
            )
            .await?
            .serialize()?
        }
        _ => return Err(Error::UnknwonCiphersuite(ciphersuite)),
    };

    Ok(key)
}

/// A KeygenEntry to store the keygen result.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct KeygenEntry<C: Ciphersuite> {
    pub keypkg: KeyPackage<C>,
    pub pubkeypkg: PublicKeyPackage<C>,
}

/// A genaric keygen protocol over any ciphersuite.
async fn keygen_internal<C: Ciphersuite, R: random::RngCore + random::CryptoRng, N: Network>(
    rng: R,
    net: &N,
    kv: crate::kv::SharedDynKVStore<String, Vec<u8>>,
    t: u16,
    n: u16,
    i: u16,
) -> Result<VerifyingKey<C>, Error> {
    let identifier_to_u16 = (1..=n)
        .map(|i| Identifier::try_from(i).map(|id| (id, i)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let identifier = frost_core::Identifier::try_from(i)?;
    assert_eq!(i, identifier_to_u16[&identifier]);
    let required_msgs = usize::from(n - 1);
    // Round 1 (Broadcast)
    sdk::debug!(%i, "Round 1");
    let (round1_secret_package, round1_package) = dkg::part1::<C, R>(identifier, n, t, rng)?;

    let round1_identifier_info = IdentifierInfo {
        block_id: None,
        session_id: None,
        retry_id: None,
        task_id: None,
    };
    let from = i;
    let to = None;
    let round1 = N::build_protocol_message::<Round1Package<C>>(
        round1_identifier_info.clone(),
        from,
        to,
        &round1_package,
        None,
        None,
    );
    net.send_message(round1).await?;

    sdk::debug!(%i, "Sent Round 1 Package");
    // Wait for all round1_package. (n - 1) round1_package.
    let mut round1_packages = BTreeMap::new();

    sdk::debug!(%i, "Waiting for Round 1 Messages");
    while let Some(msg) = net.next_message().await {
        let round1_package: Round1Package<C> = sdk::network::deserialize(&msg.payload)?;
        let from = frost_core::Identifier::try_from(msg.sender.user_id)?;
        assert_ne!(from, identifier, "Received its own Round 1 Package");
        let old = round1_packages.insert(from, round1_package);
        assert!(
            old.is_none(),
            "Received duplicate Round 2 Package from {}",
            msg.sender.user_id
        );

        sdk::debug!(
            %i,
            from = %msg.sender.user_id,
            recv = %round1_packages.len(),
            required = required_msgs,
            remaining = required_msgs - round1_packages.len(),
            "Received Round 1 Package"
        );

        if round1_packages.len() == required_msgs {
            break;
        }
    }

    // Round 1 is done.
    sdk::debug!(%i, "Round 1 Done");

    // Round 2 (P2P)
    sdk::debug!(%i, "Round 2");
    let (round2_secret_package, round2_packages) =
        dkg::part2(round1_secret_package, &round1_packages)?;

    for (to, round2_package) in round2_packages {
        let round2_identifier_info = IdentifierInfo {
            block_id: None,
            session_id: None,
            retry_id: None,
            task_id: None,
        };
        let from = i;
        let to = identifier_to_u16.get(&to).cloned();
        assert!(to.is_some(), "Unknown identifier: {:?}", to);
        let round2 = N::build_protocol_message::<Round2Package<C>>(
            round2_identifier_info.clone(),
            from,
            to,
            &round2_package,
            None,
            None,
        );
        net.send_message(round2).await?;
        sdk::debug!(%i, to = ?to, "Sent Round 2 Package P2P");
    }

    // Wait for all round2_package. (n - 1) round2_package.
    sdk::debug!(%i, "Waiting for Round 2 Messages");
    let mut round2_packages = BTreeMap::new();
    while let Some(msg) = net.next_message().await {
        let round2_package: Round2Package<C> = sdk::network::deserialize(&msg.payload)?;
        let from = frost_core::Identifier::try_from(msg.sender.user_id)?;
        assert_ne!(from, identifier, "Received its own Round 2 Package");
        let old = round2_packages.insert(from, round2_package);
        assert!(
            old.is_none(),
            "Received duplicate Round 2 Package from {}",
            msg.sender.user_id
        );

        sdk::debug!(
            %i,
            from = %msg.sender.user_id,
            recv = %round2_packages.len(),
            required = required_msgs,
            remaining = required_msgs - round2_packages.len(),
            "Received Round 2 Package"
        );

        if round2_packages.len() == required_msgs {
            break;
        }
    }

    // Round 2 is done.
    sdk::debug!(%i, "Round 2 Done");

    // Part 3, Offline.
    sdk::debug!(%i, "Round 3 (Offline)");
    let (key_package, public_key_package) =
        dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)?;

    sdk::debug!(%i, "Round 3 Done");
    let verifying_key = public_key_package.verifying_key().clone();
    let pubkey = hex::encode(verifying_key.serialize()?);
    sdk::debug!(
        %i,
        %pubkey,
        "Keygen Done"
    );
    let entry = serde_json::json!({
        "ciphersuite": C::ID,
        "entry": KeygenEntry {
            keypkg: key_package,
            pubkeypkg: public_key_package,
        },
    });
    // Save the keygen entry.
    kv.set(pubkey, serde_json::to_vec(&entry)?)?;
    Ok(verifying_key)
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
    use gadget_sdk::error;
    use gadget_sdk::info;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::needless_return)]
    async fn keygen() {
        setup_log();
        let base_path = std::env::current_dir().expect("Failed to get current directory");
        let base_path = base_path
            .canonicalize()
            .expect("File could not be normalized");

        let manifest_path = base_path.join("Cargo.toml");

        let opts = Opts {
            pkg_name: option_env!("CARGO_BIN_NAME").map(ToOwned::to_owned),
            http_rpc_url: "http://127.0.0.1:9944".to_string(),
            ws_rpc_url: "ws://127.0.0.1:9944".to_string(),
            manifest_path,
            signer: None,
            signer_evm: None,
        };

        const N: usize = 3;
        const T: usize = N / 2 + 1;
        const CIPHERSUITE: &str = frost_ed25519::Ed25519Sha512::ID;

        new_test_ext_blueprint_manager::<N, 1, (), _, _>((), opts, run_test_blueprint_manager)
            .await
            .execute_with_async(move |client, handles| async move {
                // At this point, blueprint has been deployed, every node has registered
                // as an operator for the relevant services, and, all gadgets are running

                let keypair = handles[0].sr25519_id().clone();

                let service_id = get_next_service_id(client)
                    .await
                    .expect("Failed to get next service id")
                    .saturating_sub(1);
                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);

                info!("Submitting job with params service ID: {service_id}, call ID: {call_id}");

                // Pass the arguments
                let ciphersuite = Field::String(BoundedString(BoundedVec(
                    CIPHERSUITE.to_string().into_bytes(),
                )));
                let threshold = Field::Uint16(T as u16);
                let job_args = Args::from([ciphersuite, threshold]);

                // Next step: submit a job under that service/job id
                if let Err(err) =
                    submit_job(client, &keypair, service_id, KEYGEN_JOB_ID, job_args).await
                {
                    error!("Failed to submit job: {err}");
                    panic!("Failed to submit job: {err}");
                }

                // Step 2: wait for the job to complete
                let job_results =
                    wait_for_completion_of_tangle_job(client, service_id, call_id, handles.len())
                        .await
                        .expect("Failed to wait for job completion");

                // Step 3: Get the job results, compare to expected value(s)
                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, call_id);
                assert!(matches!(job_results.result[0], Field::Bytes(_)));
            })
            .await
    }
}
