//! Provides the key exchange algorithms used by the SSH transport layer.

use russh_definitions::algorithms::internal;

#[cfg(feature = "curve25519-sha256")]
#[doc(hidden)]
mod curve25519_sha256;
#[cfg(feature = "curve25519-sha256")]
#[doc(inline)]
pub use self::curve25519_sha256::*;

/// Calls the `add` function with all key exchange algorithms defined and enabled in this crate.
pub fn add_algorithms<F>(mut add: F)
where
    F: FnMut(internal::KeyExchangeAlgorithmEntry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "curve25519-sha256")]
    add(Curve25519Sha256::new().into());
}
