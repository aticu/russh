//! Provides the MAC algorithms used by the SSH transport layer.

use russh_definitions::algorithms::{Algorithm, AlgorithmCategory, MacAlgorithm};

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

    /// Creates a new boxed `none` MAC algorithm.
    pub fn boxed() -> Box<dyn MacAlgorithm> {
        Box::new(None::new())
    }
}

impl Algorithm for None {
    fn name(&self) -> &'static str {
        "none"
    }

    fn category(&self) -> AlgorithmCategory {
        AlgorithmCategory::Mac
    }
}

impl MacAlgorithm for None {
    fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
        self
    }

    fn mac_size(&self) -> usize {
        0
    }

    fn key_size(&self) -> usize {
        0
    }

    fn load_key(&mut self, _key: &[u8]) {
        debug_assert_eq!(_key.len(), self.key_size());
    }

    fn unload_key(&mut self) {}

    fn compute(&mut self, _data: &[u8], _sequence_number: u32, result: &mut [u8]) {
        debug_assert_eq!(result.len(), self.mac_size());
    }

    fn verify(&mut self, _data: &[u8], _sequence_number: u32, mac: &[u8]) -> bool {
        debug_assert_eq!(mac.len(), self.mac_size());
        true
    }
}

/// Calls the `add` function with all MAC algorithms defined and enabled in this crate.
pub fn add_algorithms<Entry, F>(mut add: F)
where
    Box<dyn MacAlgorithm>: Into<Entry>,
    F: FnMut(Entry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "hmac-sha2-256")]
    add(HmacSha2256::boxed().into());
    #[cfg(feature = "hmac-sha2-512")]
    add(HmacSha2512::boxed().into());
    #[cfg(feature = "hmac-sha1")]
    add(HmacSha1::boxed().into());
    add(None::boxed().into());
}
