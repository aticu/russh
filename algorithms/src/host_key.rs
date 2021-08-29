//! Provides the encryption algorithms used by the SSH transport layer.

use russh_definitions::algorithms::HostKeyAlgorithm;

#[cfg(feature = "ssh-ed25519")]
#[doc(hidden)]
mod ed25519;
#[cfg(feature = "ssh-ed25519")]
#[doc(inline)]
pub use self::ed25519::*;

/// Calls the `add` function with all host key algorithms defined and enabled in this crate.
pub fn add_algorithms<Entry, F>(mut add: F)
where
    Box<dyn HostKeyAlgorithm>: Into<Entry>,
    F: FnMut(Entry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "ssh-ed25519")]
    add(Ed25519::boxed().into());
}
