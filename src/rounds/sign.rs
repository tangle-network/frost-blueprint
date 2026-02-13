use std::collections::BTreeMap;

use frost_core::keys::{KeyPackage, PublicKeyPackage};
use frost_core::round1::{SigningCommitments, commit};
use frost_core::round2::{SignatureShare, sign};
use frost_core::{
    Ciphersuite, Group, Identifier, Signature, SigningPackage, aggregate, verify_signature_share,
};
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
    futures::SinkExt::send(
        &mut outgoings,
        Outgoing::broadcast(Msg::Round1(signing_commitments)),
    )
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
    futures::SinkExt::send(
        &mut outgoings,
        Outgoing::broadcast(Msg::Round2(signature_share)),
    )
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
