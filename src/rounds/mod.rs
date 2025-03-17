/// FROST Keygen Protocol Rounds
pub mod keygen;
/// FROST Signing Protocol Rounds
pub mod sign;
/// Traces progress of protocol execution
pub mod trace;

mod std_error {
    #[cfg(feature = "std")]
    pub use std::error::Error as StdError;

    #[cfg(not(feature = "std"))]
    pub trait StdError: core::fmt::Display + core::fmt::Debug {}
    #[cfg(not(feature = "std"))]
    impl<E: core::fmt::Display + core::fmt::Debug> StdError for E {}
}
use std::convert::Infallible;

use frost_core::{Ciphersuite, Identifier};
use round_based::rounds_router::simple_store;
use round_based::rounds_router::{CompleteRoundError, errors as router_error};
pub use std_error::StdError;
pub type BoxedError = Box<dyn StdError + Send + Sync>;

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum IoError {
    /// send message: {0}
    SendMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    /// receive message: {0}
    ReceiveMessage(#[cfg_attr(feature = "std", source)] BoxedError),
    /// got eof while recieving messages
    ReceiveMessageEof,
    /// route received message (possibly malicious behavior): {0} ({0:?})
    RouteReceivedError(
        #[cfg_attr(feature = "std", source)]
        router_error::CompleteRoundError<simple_store::RoundInputError, Infallible>,
    ),
}

impl IoError {
    pub fn send_message<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self::SendMessage(Box::new(err))
    }

    pub fn receive_message<E: StdError + Send + Sync + 'static>(
        err: CompleteRoundError<simple_store::RoundInputError, E>,
    ) -> Self {
        match err {
            CompleteRoundError::Io(router_error::IoError::Io(e)) => {
                Self::ReceiveMessage(Box::new(e))
            }
            CompleteRoundError::Io(router_error::IoError::UnexpectedEof) => Self::ReceiveMessageEof,

            CompleteRoundError::ProcessMessage(e) => {
                Self::RouteReceivedError(CompleteRoundError::ProcessMessage(e))
            }
            CompleteRoundError::Other(e) => Self::RouteReceivedError(CompleteRoundError::Other(e)),
        }
    }
}

macro_rules! impl_from {
    (impl From for $target:ty {
        $($var:ident: $ty:ty => $new:expr),+,
    }) => {$(
        impl From<$ty> for $target {
            fn from($var: $ty) -> Self {
                $new
            }
        }
    )+};
    (impl<C: Ciphersuite> From for $target:ty {
        $($var:ident: $ty:ty => $new:expr),+,
    }) => {$(
        impl<C: Ciphersuite> From<$ty> for $target {
            fn from($var: $ty) -> Self {
                $new
            }
        }
    )+}
}

pub(crate) use impl_from;
/// A wrapper around an identifier that can be converted back and forth between
/// `Identifier` and `u16`.
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct IdentifierWrapper<C: Ciphersuite>(pub Identifier<C>);

impl<C: Ciphersuite> Copy for IdentifierWrapper<C> {}

impl<C: Ciphersuite> core::fmt::Debug for IdentifierWrapper<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<C: Ciphersuite> core::hash::Hash for IdentifierWrapper<C> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<C: Ciphersuite> Clone for IdentifierWrapper<C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: Ciphersuite> PartialEq for IdentifierWrapper<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<C: Ciphersuite> PartialOrd for IdentifierWrapper<C> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: Ciphersuite> Eq for IdentifierWrapper<C> {}

impl<C: Ciphersuite> Ord for IdentifierWrapper<C> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<C: Ciphersuite> std::ops::Deref for IdentifierWrapper<C> {
    type Target = Identifier<C>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: Ciphersuite> IdentifierWrapper<C> {
    /// Create a new `IdentifierWrapper` from a `u16`.
    pub fn new(i: u16) -> Self {
        Self::try_from(i).expect("u16 is always valid")
    }

    /// Get the inner `Identifier` as a `u16`.
    pub fn as_u16(&self) -> u16 {
        let bytes =
            <<C::Group as frost_core::Group>::Field as frost_core::Field>::little_endian_serialize(
                &self.0.to_scalar(),
            )
            .as_ref()
            .to_vec();
        tracing::trace!("Identifier bytes: 0x{}", hex::encode(&bytes));
        u16::from_le_bytes([bytes[0], bytes[1]]).saturating_sub(1)
    }
}

impl<C: Ciphersuite> TryFrom<u16> for IdentifierWrapper<C> {
    type Error = frost_core::Error<C>;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Identifier::try_from(value + 1).map(IdentifierWrapper)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_ed25519::Ed25519Sha512 as MockCiphersuite;

    #[test]
    fn test_new() {
        let non_zero = 1;
        let wrapper = IdentifierWrapper::<MockCiphersuite>::new(non_zero);
        assert_eq!(wrapper.as_u16(), 1);
    }

    #[test]
    fn test_new_zero() {
        let z = 0;
        let wrapper = IdentifierWrapper::<MockCiphersuite>::new(z);
        assert_eq!(wrapper.as_u16(), 0);
    }

    #[test]
    fn test_try_from() {
        let wrapper = IdentifierWrapper::<MockCiphersuite>::try_from(1).unwrap();
        assert_eq!(wrapper.as_u16(), 1);
    }

    #[test]
    fn test_from_frost_identifier() {
        let wrapper = IdentifierWrapper(Identifier::<MockCiphersuite>::try_from(1u16).unwrap());
        assert_eq!(wrapper.as_u16(), 0);

        let wrapper = IdentifierWrapper(Identifier::<MockCiphersuite>::try_from(2u16).unwrap());
        assert_eq!(wrapper.as_u16(), 1);
    }
}
