use std::collections::BTreeMap;

use api::services::events::JobCalled;
use frost_core::keys::dkg;
use frost_core::keys::dkg::round1::Package as Round1Package;
use frost_core::keys::dkg::round2::Package as Round2Package;
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

use crate::{CipherSuite, ServiceContext};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown ciphersuite: {0}")]
    UnknwonCiphersuite(u8),
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
}

impl<C: Ciphersuite> From<frost_core::Error<C>> for Error {
    fn from(e: frost_core::Error<C>) -> Self {
        Error::Frost(Box::new(e))
    }
}

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
    ciphersuite: u8,
    threshold: u16,
    context: ServiceContext,
) -> Result<Vec<u8>, Error> {
    let ciphersuite =
        CipherSuite::try_from(ciphersuite).map_err(|e| Error::UnknwonCiphersuite(e.input))?;
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

    let net = context.gossip_network();
    let rng = random::rand::rngs::OsRng;
    let key = match ciphersuite {
        CipherSuite::Ed25519 => keygen_internal::<frost_ed25519::Ed25519Sha512, _, _>(
            rng,
            net,
            threshold,
            u16::try_from(n)?,
            u16::try_from(i)?,
        )
        .await?
        .serialize()?,
        CipherSuite::Secp256k1 => keygen_internal::<frost_secp256k1::Secp256K1Sha256, _, _>(
            rng,
            net,
            threshold,
            u16::try_from(n)?,
            u16::try_from(i)?,
        )
        .await?
        .serialize()?,
    };

    Ok(key)
}

async fn keygen_internal<C: Ciphersuite, R: random::RngCore + random::CryptoRng, N: Network>(
    rng: R,
    net: &N,
    t: u16,
    n: u16,
    i: u16,
) -> Result<VerifyingKey<C>, Error> {
    let identifier_to_u16 = (1..=n)
        .map(|i| Identifier::try_from(i).map(|id| (id, i)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let identifier = frost_core::Identifier::try_from(i)?;
    assert_eq!(i, identifier_to_u16[&identifier]);
    // Round 1 (Broadcast)
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
    // Wait for all round1_package. (n - 1) round1_package.
    let mut round1_packages = BTreeMap::new();
    while let Some(msg) = net.next_message().await {
        let round1_package: Round1Package<C> = sdk::network::deserialize(&msg.payload)?;
        let from = frost_core::Identifier::try_from(msg.sender.user_id)?;
        round1_packages.insert(from, round1_package);

        if round1_packages.len() == n as usize - 1 {
            break;
        }
    }

    // Round 1 is done.

    // Round 2 (P2P)
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
        let to = Some(identifier_to_u16[&to]);
        let round2 = N::build_protocol_message::<Round2Package<C>>(
            round2_identifier_info.clone(),
            from,
            to,
            &round2_package,
            None,
            None,
        );
        net.send_message(round2).await?;
    }

    // Wait for all round2_package. (n - 1) round2_package.
    let mut round2_packages = BTreeMap::new();
    while let Some(msg) = net.next_message().await {
        let round2_package: Round2Package<C> = sdk::network::deserialize(&msg.payload)?;
        let from = frost_core::Identifier::try_from(msg.sender.user_id)?;
        round2_packages.insert(from, round2_package);

        if round2_packages.len() == n as usize - 1 {
            break;
        }
    }

    // Part 3, Offline.
    let (key_package, public_key_package) =
        dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)?;

    // TODO: Store key_package somewhere by the public key package.
    Ok(public_key_package.verifying_key().clone())
}

#[cfg(test)]
mod tests {
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
            pkg_name: option_env!("CARGO_PKG_NAME").map(ToOwned::to_owned),
            http_rpc_url: "http://127.0.0.1:9944".to_string(),
            ws_rpc_url: "ws://127.0.0.1:9944".to_string(),
            manifest_path,
            signer: None,
            signer_evm: None,
        };

        new_test_ext_blueprint_manager::<5, 1, (), _, _>((), opts, run_test_blueprint_manager)
            .await
            .execute_with_async(move |client, handles| async move {
                // At this point, blueprint has been deployed, every node has registered
                // as an operator for the relevant services, and, all gadgets are running

                // What's left: Submit a job, wait for the job to finish, then assert the job results
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
                let ciphersuite = Field::Uint8(CipherSuite::Ed25519 as u8);
                let threshold = Field::Uint8(3);
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
