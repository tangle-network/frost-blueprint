use std::collections::BTreeMap;

use frost_core::keys::dkg::round2::Package as Round2Package;
use frost_core::keys::{KeyPackage, dkg::round1::Package as Round1Package};
use frost_core::keys::{PublicKeyPackage, dkg};
use frost_core::{Ciphersuite, Group, Identifier};
use round_based::rounds_router::simple_store::RoundInput;
use round_based::rounds_router::RoundsRouter;
use round_based::{Delivery, Mpc, MpcParty, Outgoing, ProtocolMessage};
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
#[tracing::instrument(name = "keygen", skip(rng, tracer, party), err)]
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
    tracing::debug!("Keygen protocol started");
    let me = IdentifierWrapper::<C>::try_from(i).map_err(|_| Bug::InvalidPartyIndex)?;
    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();
    let mut router = RoundsRouter::<Msg<C>>::builder();
    let round1 = router.add_round(RoundInput::<Round1Package<C>>::broadcast(i, n));
    let round2 = router.add_round(RoundInput::<Round2Package<C>>::p2p(i, n));
    let mut rounds = router.listen(incomings);
    // Round 1
    tracing::debug!("Round 1 started");
    tracer.round_begins();
    tracer.stage("Generate Own Secret package");
    let (round1_secret_package, round1_package) =
        dkg::part1::<C, _>(*me, n, t, rng).map_err(KeygenAborted::Frost)?;
    tracer.stage("Broadcast shares");
    tracing::debug!("Broadcasting round 1 package");
    tracer.send_msg();
    futures::SinkExt::send(&mut outgoings, Outgoing::broadcast(Msg::Round1(round1_package)))
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
    tracing::debug!("Round 2 started");
    tracer.stage("Generate Round2 packages");
    let (round2_secret_package, my_round2_packages) =
        dkg::part2(round1_secret_package, &round1_packages).map_err(KeygenAborted::Frost)?;
    let span = tracing::debug_span!("Sending round 2 packages");
    for (to, round2_package) in my_round2_packages {
        let _guard = span.enter();
        tracer.send_msg();
        let to = IdentifierWrapper(to).as_u16();
        tracing::debug!(%to, "Sending to party");
        futures::SinkExt::send(&mut outgoings, Outgoing::p2p(to, Msg::Round2(round2_package)))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();
    }
    drop(span);

    tracing::debug!("Waiting for round 2 packages");
    tracer.receive_msgs();
    let other_packages = rounds
        .complete(round2)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();

    let round2_packages = other_packages
        .into_iter_indexed()
        .map(|(index, _, package)| {
            let party =
                IdentifierWrapper::<C>::try_from(index).map_err(|_| Bug::InvalidPartyIndex)?;
            Result::<_, Error<C>>::Ok((*party, package))
        })
        .collect::<Result<BTreeMap<Identifier<C>, _>, _>>()?;
    tracing::debug!("Received round 2 packages");

    tracing::debug!("Part 3 started");
    tracer.named_round_begins("Part 3 (Offline)");
    tracer.stage("Generate Key Package");
    let (key_package, public_key_package) =
        dkg::part3(&round2_secret_package, &round1_packages, &round2_packages)
            .map_err(KeygenAborted::Frost)?;
    tracing::debug!("Keygen protocol completed");
    tracer.protocol_ends();
    Ok((key_package, public_key_package))
}
