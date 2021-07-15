//! Provides the encryption algorithms used by the SSH transport layer.

use russh_definitions::algorithms::HostKeyAlgorithm;

#[cfg(feature = "ssh-ed25519")]
#[doc(hidden)]
mod ed25519;
#[cfg(feature = "ssh-ed25519")]
#[doc(inline)]
pub use self::ed25519::*;

/// Returns all the host key algorithms defined by this crate.
pub fn algorithms() -> Vec<Box<dyn HostKeyAlgorithm>> {
    let mut result: Vec<Box<dyn HostKeyAlgorithm>> = Vec::new();

    #[cfg(feature = "ssh-ed25519")]
    result.push(Ed25519::boxed());

    result
}
