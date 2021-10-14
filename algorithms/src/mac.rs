//! Provides the MAC algorithms used by the SSH transport layer.

use definitions::algorithms::{internal, InvalidMacError, MacAlgorithm};

#[cfg(any(
    feature = "hmac-sha1",
    feature = "hmac-sha2-256",
    feature = "hmac-sha2-512"
))]
#[doc(hidden)]
mod hmac_sha;
#[cfg(any(
    feature = "hmac-sha1",
    feature = "hmac-sha2-256",
    feature = "hmac-sha2-512"
))]
#[doc(inline)]
pub use self::hmac_sha::*;

/// The message authentication algorithm that does not authenticate.
///
/// This is not a functional MAC algorithm, but is used
/// instead of a MAC algorithm during key exchange.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
#[non_exhaustive]
pub struct None {}

impl None {
    /// Creates a new `none` MAC algorithm.
    pub fn new() -> None {
        None {}
    }
}

impl MacAlgorithm for None {
    const NAME: &'static str = "none";

    const MAC_SIZE: usize = 0;

    const KEY_SIZE: usize = 0;

    fn load_key(&mut self, _key: &[u8]) {
        debug_assert_eq!(_key.len(), Self::KEY_SIZE);
    }

    fn unload_key(&mut self) {}

    fn compute(&mut self, _data: &[u8], _sequence_number: u32, result: &mut [u8]) {
        debug_assert_eq!(result.len(), Self::MAC_SIZE);
    }

    fn verify(
        &mut self,
        _data: &[u8],
        _sequence_number: u32,
        mac: &[u8],
    ) -> Result<(), InvalidMacError> {
        debug_assert_eq!(mac.len(), Self::MAC_SIZE);
        Ok(())
    }
}

/// Calls the `add` function with all MAC algorithms defined and enabled in this crate.
pub fn add_algorithms<F>(mut add: F)
where
    F: FnMut(internal::MacAlgorithmEntry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "hmac-sha2-256")]
    add(HmacSha2256::new().into());
    #[cfg(feature = "hmac-sha2-512")]
    add(HmacSha2512::new().into());
    #[cfg(feature = "hmac-sha1")]
    add(HmacSha1::new().into());
    add(None::new().into());
}
