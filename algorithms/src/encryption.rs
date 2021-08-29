//! Provides the encryption algorithms used by the SSH transport layer.

use russh_definitions::algorithms::{
    Algorithm, AlgorithmCategory, EncryptionAlgorithm, EncryptionContext,
};

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
#[derive(Debug, PartialEq, Eq, Default)]
// This isn't a unit struct, to allow for future expansions of this.
#[non_exhaustive]
pub struct None {}

impl None {
    /// Creates a new `none` encryption algorithm.
    pub fn new() -> None {
        None {}
    }

    /// Creates a new boxed `none` encryption algorithm.
    pub fn boxed() -> Box<dyn EncryptionAlgorithm> {
        Box::new(None::new())
    }
}

impl Algorithm for None {
    fn name(&self) -> &'static str {
        "none"
    }

    fn category(&self) -> AlgorithmCategory {
        AlgorithmCategory::Encryption
    }
}

impl EncryptionAlgorithm for None {
    fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
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

    fn encrypt_packet(&mut self, _context: EncryptionContext) {}

    fn decrypt_packet(&mut self, mut context: EncryptionContext) -> usize {
        context.unprocessed_part().len()
    }
}

/// Calls the `add` function with all encryption algorithms defined and enabled in this crate.
pub fn add_algorithms<Entry, F>(mut add: F)
where
    Box<dyn EncryptionAlgorithm>: Into<Entry>,
    F: FnMut(Entry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "aes128-ctr")]
    add(Aes128Ctr::boxed().into());
    #[cfg(feature = "aes192-ctr")]
    add(Aes192Ctr::boxed().into());
    #[cfg(feature = "aes256-ctr")]
    add(Aes256Ctr::boxed().into());
    add(None::boxed().into());
}
