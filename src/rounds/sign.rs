use std::collections::BTreeMap;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::round1::{commit, SigningCommitments};
use frost_core::round2::{sign, SignatureShare};
use frost_core::{
    aggregate, verify_signature_share, Ciphersuite, Group, Identifier, Signature, SigningPackage,
};
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
    Round1(SigningCommitments<C>),
    /// Round 2
    Round2(SignatureShare<C>),
}

/// Signing protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("signing protocol is failed to complete: {0}")]
pub struct Error<C: Ciphersuite>(#[cfg_attr(feature = "std", source)] Reason<C>);

/// Keygen protocol abort reason
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Reason<C: Ciphersuite> {
    /// Protocol was maliciously aborted by another party: {0}
    Aborted(#[cfg_attr(feature = "std", source)] SigningAborted<C>),
    /// IO error: {0}
    IoError(#[cfg_attr(feature = "std", source)] super::IoError),
    /// Bug occurred: {0}
    Bug(Bug),
}

super::impl_from! {
    impl<C: Ciphersuite> From for Error<C> {
        err: SigningAborted<C> => Error(Reason::Aborted(err)),
        err: super::IoError => Error(Reason::IoError(err)),
        err: Bug => Error(Reason::Bug(err)),
    }
}

impl<C: Ciphersuite> From<SigningAborted<C>> for Reason<C> {
    fn from(err: SigningAborted<C>) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
///
/// It _can be_ cryptographically proven, but we do not support it yet.
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SigningAborted<C: Ciphersuite> {
    /// A party has aborted the protocol: {0}
    Frost(frost_core::Error<C>),
    /// A party has aborted the protocol: {blames:?}
    InvalidSignatureShare {
        /// Invalid signature share from these
        /// parties
        blames: Vec<u16>,
    },
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Bug {
    /// Invalid party index, not in signer set
    InvalidPartyIndex,
    /// Invalid Protocol Parameters, signer set is less than minimum required.
    InvalidProtocolParameters,
    /// Verifing Share For Party is not found in the public key package.
    VerifyingShareNotFound,
}

/// Run FROST Signing protocol
#[tracing::instrument(
    target = "gadget",
    name = "sign",
    skip(rng, tracer, party, key_pkg, pub_key_pkg, msg),
    err
)]
pub async fn run<R, C, M>(
    rng: &mut R,
    key_pkg: &KeyPackage<C>,
    pub_key_pkg: &PublicKeyPackage<C>,
    signer_set: &[u16],
    msg: &[u8],
    party: M,
    mut tracer: Option<&mut dyn Tracer>,
) -> Result<Signature<C>, Error<C>>
where
    R: rand::RngCore + rand::CryptoRng,
    C: Ciphersuite + Send,
    M: Mpc<ProtocolMessage = Msg<C>>,
    <<C as Ciphersuite>::Group as Group>::Element: Send,
    <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar: Send,
{
    let t = *key_pkg.min_signers();
    let n = signer_set.len() as u16;
    if n < t {
        return Err(Bug::InvalidProtocolParameters.into());
    }

    let me = IdentifierWrapper(*key_pkg.identifier());
    let me = me.as_u16();
    // i is my index in the signer set
    let i = signer_set
        .iter()
        .position(|&x| x == me)
        .map(|i| i as u16)
        .ok_or(Bug::InvalidPartyIndex)?;

    tracer.protocol_begins();
    tracing::debug!("Signing protocol started");
    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut router = RoundsRouter::<Msg<C>>::builder();
    let round1 = router.add_round(RoundInput::<SigningCommitments<C>>::broadcast(i, n));
    let round2 = router.add_round(RoundInput::<SignatureShare<C>>::broadcast(i, n));
    let mut rounds = router.listen(incomings);
    // Round 1
    tracing::debug!("Round 1 started");
    tracer.round_begins();
    tracer.stage("Create Signing Commitments");
    let (signing_nonces, signing_commitments) = commit::<C, _>(key_pkg.signing_share(), rng);
    tracer.stage("Broadcast shares");
    tracing::debug!("Broadcasting round 1 package");
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round1(
            signing_commitments,
        )))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();
    tracing::debug!("Waiting for round 1 packages");
    tracer.receive_msgs();
    let other_packages = rounds
        .complete(round1)
        .await
        .map_err(IoError::receive_message)?;
    tracing::debug!("Received round 1 packages");
    tracer.msgs_received();
    let all_signing_commitments = other_packages
        .into_vec_including_me(signing_commitments)
        .into_iter()
        .enumerate()
        .map(|(index, package)| {
            let party_i = signer_set
                .get(index)
                .copied()
                .ok_or(Bug::InvalidPartyIndex)?;
            let party =
                IdentifierWrapper::<C>::try_from(party_i).map_err(|_| Bug::InvalidPartyIndex)?;
            Result::<_, Error<C>>::Ok((*party, package))
        })
        .collect::<Result<BTreeMap<Identifier<C>, _>, _>>()?;

    // Round 2
    tracer.round_begins();
    tracing::debug!("Round 2 started");
    tracer.stage("Create Signature Share");

    let signing_pkg = SigningPackage::new(all_signing_commitments, msg);

    let signature_share =
        sign::<C>(&signing_pkg, &signing_nonces, key_pkg).map_err(SigningAborted::Frost)?;
    tracing::debug!("Broadcasting round 2 package");
    tracer.stage("Broadcast signature share");
    tracer.send_msg();
    outgoings
        .send(Outgoing::broadcast(Msg::Round2(signature_share)))
        .await
        .map_err(IoError::send_message)?;
    tracer.msg_sent();

    tracing::debug!("Waiting for round 2 packages");
    tracer.receive_msgs();
    let other_packages = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracing::debug!("Received round 2 packages");
    tracer.msgs_received();

    let all_signature_shares = other_packages
        .into_vec_including_me(signature_share)
        .into_iter()
        .enumerate()
        .map(|(index, package)| {
            let party_i = signer_set
                .get(index)
                .copied()
                .ok_or(Bug::InvalidPartyIndex)?;
            let party =
                IdentifierWrapper::<C>::try_from(party_i).map_err(|_| Bug::InvalidPartyIndex)?;
            Result::<_, Error<C>>::Ok((*party, package))
        })
        .collect::<Result<BTreeMap<Identifier<C>, _>, _>>()?;

    // Verify signature shares
    tracer.stage("Verify signature shares");
    let mut blames = vec![];
    for (from, share) in all_signature_shares.iter() {
        let verifying_share = pub_key_pkg
            .verifying_shares()
            .get(from)
            .ok_or(Bug::VerifyingShareNotFound)?;
        let result = verify_signature_share(
            *from,
            verifying_share,
            share,
            &signing_pkg,
            key_pkg.verifying_key(),
        );
        if result.is_err() {
            let who = IdentifierWrapper(*from).as_u16();
            tracing::warn!(from = %who, "Failed to verify signature share");
            blames.push(who);
        }
    }
    if !blames.is_empty() {
        return Err(SigningAborted::InvalidSignatureShare { blames }.into());
    }
    tracer.stage("Aggregate signature shares");
    let signature = aggregate::<C>(&signing_pkg, &all_signature_shares, pub_key_pkg)
        .map_err(SigningAborted::Frost)?;
    // Done
    tracer.protocol_ends();
    Ok(signature)
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use crate::rounds::trace::PerfProfiler;

    use super::*;
    use blueprint_test_utils::setup_log;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::seq::IteratorRandom;
    use rand::SeedableRng;
    use round_based::simulation::Simulation;
    use test_strategy::proptest;
    use test_strategy::Arbitrary;

    #[derive(Arbitrary, Debug, Clone, Copy)]
    struct TestInputArgs {
        #[strategy(3..15u16)]
        n: u16,
        #[strategy(2..#n)]
        t: u16,
        msg: [u8; 32],
    }

    #[derive(Arbitrary, Debug)]
    enum TestCase {
        Ed25519(TestInputArgs),
        Secp256k1(TestInputArgs),
    }

    #[proptest(async = "tokio", cases = 20, fork = true)]
    async fn it_works(case: TestCase) {
        setup_log();
        match &case {
            TestCase::Ed25519(args) => run_signing::<frost_ed25519::Ed25519Sha512>(args).await?,
            TestCase::Secp256k1(args) => {
                run_signing::<frost_secp256k1::Secp256K1Sha256>(args).await?
            }
        }
    }

    async fn run_signing<C>(args: &TestInputArgs) -> Result<(), TestCaseError>
    where
        C: Ciphersuite + Send + Unpin + Sync,
        <<C as Ciphersuite>::Group as Group>::Element: Send + Unpin + Sync,
        <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar:
            Send + Unpin + Sync,
    {
        let TestInputArgs { n, t, msg } = *args;
        let keygen_output = run_keygen::<C>(args).await?;
        let public_key = keygen_output
            .values()
            .map(|(_, pkg)| pkg.clone())
            .next()
            .unwrap();
        let rng = &mut StdRng::from_seed(msg);
        let signers = keygen_output
            .into_iter()
            .choose_multiple(rng, usize::from(t));
        let signer_set = signers.iter().map(|(i, _)| *i).collect::<Vec<_>>();

        eprintln!("Running a {} {t}-out-of-{n} Signing", C::ID);
        let mut simulation = Simulation::<Msg<C>>::new();
        let mut tasks = vec![];
        for (i, (key_pkg, pub_key_pkg)) in signers {
            let party = simulation.add_party();
            let signer_set = signer_set.clone();
            let msg = msg.to_vec();
            let output = tokio::spawn(async move {
                let rng = &mut StdRng::seed_from_u64(u64::from(i + 1));
                let mut tracer = PerfProfiler::new();
                let output = run(
                    rng,
                    &key_pkg,
                    &pub_key_pkg,
                    &signer_set,
                    &msg,
                    party,
                    Some(tracer.borrow_mut()),
                )
                .await?;
                let report = tracer.get_report().unwrap();
                eprintln!("Party {} report: {}\n", i, report);
                Result::<_, Error<C>>::Ok((i, output))
            });
            tasks.push(output);
        }

        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            outputs.push(task.await.unwrap());
        }
        let outputs = outputs.into_iter().collect::<Result<BTreeMap<_, _>, _>>()?;
        // Assert that all parties produced a valid signature
        let signature = outputs.values().next().unwrap();
        C::verify_signature(&msg, signature, public_key.verifying_key())?;
        for other_signature in outputs.values().skip(1) {
            prop_assert_eq!(signature, other_signature);
        }

        Ok(())
    }

    async fn run_keygen<C>(
        args: &TestInputArgs,
    ) -> Result<BTreeMap<u16, (KeyPackage<C>, PublicKeyPackage<C>)>, TestCaseError>
    where
        C: Ciphersuite + Send + Unpin,
        <<C as Ciphersuite>::Group as Group>::Element: Send + Unpin,
        <<<C as Ciphersuite>::Group as Group>::Field as frost_core::Field>::Scalar: Send + Unpin,
    {
        use crate::rounds::keygen::*;

        let TestInputArgs { n, t, .. } = *args;
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
                Result::<_, Error<C>>::Ok((i, output))
            });
            tasks.push(output);
        }

        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            outputs.push(task.await.unwrap());
        }
        let outputs = outputs.into_iter().collect::<Result<BTreeMap<_, _>, _>>()?;
        // Assert that all parties outputed the same public key
        let (_, pubkey_pkg) = outputs.get(&0).unwrap();
        for (_, other_pubkey_pkg) in outputs.values().skip(1) {
            prop_assert_eq!(pubkey_pkg, other_pubkey_pkg);
        }

        Ok(outputs)
    }
}
