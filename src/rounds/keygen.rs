use std::collections::BTreeMap;

use frost_core::keys::dkg::round2::Package as Round2Package;
use frost_core::keys::{dkg, PublicKeyPackage};
use frost_core::keys::{dkg::round1::Package as Round1Package, KeyPackage};
use frost_core::{Ciphersuite, Group, Identifier};
use gadget_sdk::random::rand;
use round_based::rounds_router::simple_store::RoundInput;
use round_based::rounds_router::RoundsRouter;
use round_based::{Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage, SinkExt};
use serde::{Deserialize, Serialize};

use crate::rounds::{IdentifierWrapper, IoError};

use super::trace::Tracer;

/// Protocol message
#[derive(Clone, Debug, PartialEq, ProtocolMessage, Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub enum Msg<C: Ciphersuite> {
    /// Round 1
    Round1(Round1Package<C>),
    /// Round 2
    Round2(Round2Package<C>),
}

/// Keygen protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("keygen protocol is failed to complete: {0}")]
pub struct Error<C: Ciphersuite>(#[cfg_attr(feature = "std", source)] Reason<C>);

/// Keygen protocol abort reason
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Reason<C: Ciphersuite> {
    /// Protocol was maliciously aborted by another party: {0}
    Aborted(#[cfg_attr(feature = "std", source)] KeygenAborted<C>),
    /// IO error: {0}
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred: {0}
    Bug(Bug),
}

super::impl_from! {
    impl<C: Ciphersuite> From for Error<C> {
        err: KeygenAborted<C> => Error(Reason::Aborted(err)),
        err: super::IoError => Error(Reason::IoError(err)),
        err: Bug => Error(Reason::Bug(err)),
    }
}

impl<C: Ciphersuite> From<KeygenAborted<C>> for Reason<C> {
    fn from(err: KeygenAborted<C>) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum KeygenAborted<C: Ciphersuite> {
    /// A party has aborted the protocol: {0}
    Frost(frost_core::Error<C>),
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Bug {
    /// Invalid party index, must be in range 1..=n
    InvalidPartyIndex,
    /// Invalid Protocol Parameters (1 <= t <= n)
    InvalidProtocolParameters,
}

/// Run FROST Keygen Protocol
pub async fn run<R, C, M>(
    rng: &mut R,
    t: u16,
    n: u16,
    i: u16,
    party: M,
    mut tracer: Option<&mut dyn Tracer>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error<C>>
where
    R: rand::RngCore + rand::CryptoRng,
    C: Ciphersuite + Send,
    M: Mpc<ProtocolMessage = Msg<C>>,
    <<C as Ciphersuite>::Group as Group>::Element: Send,
    <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar: Send,
{
    // Check protocol parameters
    if t < 1 || t > n {
        return Err(Bug::InvalidProtocolParameters.into());
    }
    tracer.protocol_begins();
    tracing::debug!(%n, %t, %i, "Keygen protocol started");
    let me = IdentifierWrapper::<C>::try_from(i).map_err(|_| Bug::InvalidPartyIndex)?;
    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut router = RoundsRouter::<Msg<C>>::builder();
    let round1 = router.add_round(RoundInput::<Round1Package<C>>::broadcast(i, n));
    let round2 = router.add_round(RoundInput::<Round2Package<C>>::p2p(i, n));
    let mut rounds = router.listen(incomings);
    // Round 1
    tracing::debug!(%n, %t, %i, "Round 1 started");
    tracer.round_begins();
    tracer.stage("Generate Own Secret package");
    let (round1_secret_package, round1_package) =
        dkg::part1::<C, _>(*me, n, t, rng).map_err(KeygenAborted::Frost)?;
    tracer.stage("Broadcast shares");
    tracing::debug!(%n, %t, %i, "Broadcasting round 1 package");
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(round1_package)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();
    tracing::debug!(%n, %t, %i, "Waiting for round 1 packages");
    tracer.receive_msgs();
    let other_packages = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?;
    tracing::debug!(%n, %t, %i, "Received round 1 packages");
    tracer.msgs_received();
    let round1_packages = other_packages
        .into_iter_indexed()
        .map(|(index, _, package)| {
            let party =
                IdentifierWrapper::<C>::try_from(index).map_err(|_| Bug::InvalidPartyIndex)?;
            Result::<_, Error<C>>::Ok((*party, package))
        })
        .collect::<Result<BTreeMap<Identifier<C>, _>, _>>()?;

    // Round 2
    tracer.round_begins();
    tracing::debug!(%n, %t, %i, "Round 2 started");
    tracer.stage("Generate Round2 packages");
    let (round2_secret_package, round2_packages) =
        dkg::part2(round1_secret_package, &round1_packages).map_err(KeygenAborted::Frost)?;
    let span = tracing::debug_span!("Sending round 2 packages");
    for (to, round2_package) in round2_packages {
        let _guard = span.enter();
        tracer.send_msg();
        let to = IdentifierWrapper(to).as_u16();
        tracing::debug!(%n, %t, %i, %to, "Sending to party");
        outgoings
            .send(Outgoing::p2p(to, Msg::Round2(round2_package)))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    drop(span);

    tracing::debug!(%n, %t, %i, "Waiting for round 2 packages");
    tracer.receive_msgs();
    let other_packages = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();
    tracing::debug!(%n, %t, %i, "Received round 2 packages");

    let round2_packages = other_packages
        .into_iter_indexed()
        .map(|(index, _, package)| {
            let party =
                IdentifierWrapper::<C>::try_from(index).map_err(|_| Bug::InvalidPartyIndex)?;
            Result::<_, Error<C>>::Ok((*party, package))
        })
        .collect::<Result<BTreeMap<Identifier<C>, _>, _>>()?;
    tracing::debug!(%n, %t, %i, "Part 3 started");
    tracer.named_round_begins("Part 3 (Offline)");
    tracer.stage("Generate Key Package");
    let (key_package, public_key_package) =
        dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)
            .map_err(KeygenAborted::Frost)?;
    tracing::debug!(%n, %t, %i, "Keygen protocol completed");
    tracer.protocol_ends();
    Ok((key_package, public_key_package))
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use crate::rounds::trace::PerfProfiler;

    use super::*;
    use blueprint_test_utils::setup_log;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use round_based::simulation::Simulation;
    use test_strategy::proptest;
    use test_strategy::Arbitrary;

    #[derive(Arbitrary, Debug, Clone, Copy)]
    struct TestInputArgs {
        #[strategy(3..20u16)]
        n: u16,
        #[strategy(2..#n)]
        t: u16,
    }

    #[derive(Arbitrary, Debug)]
    enum TestCase {
        Ed25519(TestInputArgs),
        Secp256k1(TestInputArgs),
    }

    #[proptest(async = "tokio", cases = 20)]
    async fn it_works(case: TestCase) {
        setup_log();
        match &case {
            TestCase::Ed25519(args) => run_keygen::<frost_ed25519::Ed25519Sha512>(args).await?,
            TestCase::Secp256k1(args) => {
                run_keygen::<frost_secp256k1::Secp256K1Sha256>(args).await?
            }
        }
    }

    async fn run_keygen<C>(args: &TestInputArgs) -> Result<(), TestCaseError>
    where
        C: Ciphersuite + Send + Unpin,
        <<C as Ciphersuite>::Group as Group>::Element: Send + Unpin,
        <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar: Send + Unpin,
    {
        let TestInputArgs { n, t } = *args;
        prop_assume!(frost_core::keys::validate_num_of_signers::<C>(t, n).is_ok());

        eprintln!("Running a {} {t}-out-of-{n} Keygen", C::ID);
        let mut simulation = Simulation::<Msg<C>>::new();
        let mut tasks = vec![];
        for i in 0..n {
            let party = simulation.add_party();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
                let mut tracer = PerfProfiler::new();
                let output = run(rng, t, n, i, party, Some(tracer.borrow_mut())).await?;
                let report = tracer.get_report().unwrap();
                eprintln!("Party {} report: {}\n", i, report);
                Result::<_, Error<C>>::Ok(output)
            });
            tasks.push(output);
        }

        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            outputs.push(task.await.unwrap());
        }
        let outputs = outputs.into_iter().collect::<Result<Vec<_>, _>>()?;
        // Assert that all parties outputed the same public key
        let (_, pubkey_pkg) = &outputs[0];
        for (_, other_pubkey_pkg) in outputs.iter().skip(1) {
            prop_assert_eq!(pubkey_pkg, other_pubkey_pkg);
        }

        Ok(())
    }
}
