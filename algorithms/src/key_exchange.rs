//! Provides the key exchange algorithms used by the SSH transport layer.

use russh_common::algorithms::KeyExchangeAlgorithm;

#[cfg(feature = "curve25519-sha256")]
#[doc(hidden)]
mod curve25519_sha256;
#[cfg(feature = "curve25519-sha256")]
#[doc(inline)]
pub use self::curve25519_sha256::*;

/// Returns all the key exchange algorithms defined by this crate.
pub fn algorithms() -> Vec<Box<dyn KeyExchangeAlgorithm>> {
    let mut result: Vec<Box<dyn KeyExchangeAlgorithm>> = Vec::new();

    #[cfg(feature = "curve25519-sha256")]
    result.push(Curve25519Sha256::boxed());

    result
}
