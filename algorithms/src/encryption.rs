//! Provides the encryption algorithms used by the SSH transport layer.

use russh_common::algorithms::{Algorithm, EncryptionAlgorithm};

#[cfg(any(feature = "aes128-ctr", feature = "aes192-ctr", feature = "aes256-ctr"))]
#[doc(hidden)]
mod aes_ctr;
#[cfg(any(feature = "aes128-ctr", feature = "aes192-ctr", feature = "aes256-ctr"))]
#[doc(inline)]
pub use self::aes_ctr::*;

/// The encryption algorithm that does nothing to the data.
///
/// This is not a functional encryption algorithm, but is used
/// instead of an encryption algorithm during key exchange.
#[derive(Debug, PartialEq, Eq)]
// This isn't a unit struct, to allow for future expansions of this.
pub struct None {}

impl None {
    /// Creates a new `none` encryption algorithm.
    pub fn new() -> None {
        None {}
    }

    /// Creates a new boxed `none` encryption algorithm.
    pub fn boxed() -> Box<None> {
        Box::new(None::new())
    }
}

impl Algorithm for None {
    fn name(&self) -> &'static str {
        "none"
    }
}

impl EncryptionAlgorithm for None {
    fn as_basic_algorithm(&self) -> &dyn Algorithm {
        self
    }

    fn cipher_block_size(&self) -> usize {
        1
    }

    fn key_size(&self) -> usize {
        0
    }

    fn iv_size(&self) -> usize {
        0
    }

    fn load_key(&mut self, _iv: &[u8], _key: &[u8]) {
        debug_assert_eq!(_key.len(), self.key_size());
        debug_assert_eq!(_iv.len(), self.iv_size());
    }

    fn unload_key(&mut self) {}

    fn encrypt_block(&mut self, _input: &mut [u8]) {
        debug_assert_eq!(_input.len(), self.cipher_block_size());
    }

    fn decrypt_block(&mut self, _input: &mut [u8]) {
        debug_assert_eq!(_input.len(), self.cipher_block_size());
    }
}

/// Returns all the encryption algorithms defined by this crate.
pub fn algorithms() -> Vec<Box<dyn EncryptionAlgorithm>> {
    let mut result: Vec<Box<dyn EncryptionAlgorithm>> = Vec::new();

    // This is the same order used by OpenSSH
    #[cfg(feature = "aes128-ctr")]
    result.push(Aes128Ctr::boxed());

    #[cfg(feature = "aes192-ctr")]
    result.push(Aes192Ctr::boxed());

    #[cfg(feature = "aes256-ctr")]
    result.push(Aes256Ctr::boxed());

    result.push(None::boxed());

    result
}
