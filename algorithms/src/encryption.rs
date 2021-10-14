//! Provides the encryption algorithms used by the SSH transport layer.

use definitions::algorithms::{
    internal, EncryptionAlgorithm, EncryptionContext, PlainEncryptionAlgorithm,
};

#[cfg(feature = "chacha20poly1305_at_openssh_com")]
#[doc(hidden)]
mod chacha20poly1305;

#[cfg(feature = "chacha20poly1305_at_openssh_com")]
#[doc(inline)]
pub use self::chacha20poly1305::*;

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
#[derive(Debug, PartialEq, Eq, Default, Clone)]
// This isn't a unit struct, to allow for future expansions of this.
#[non_exhaustive]
pub struct None {}

impl None {
    /// Creates a new `none` encryption algorithm.
    pub fn new() -> None {
        None {}
    }
}

impl EncryptionAlgorithm for None {
    type AlgorithmType = PlainEncryptionAlgorithm;

    const NAME: &'static str = "none";
    const CIPHER_BLOCK_SIZE: usize = 1;
    const KEY_SIZE: usize = 0;
    const IV_SIZE: usize = 0;

    fn load_key(&mut self, _iv: &[u8], _key: &[u8]) {
        debug_assert_eq!(_key.len(), Self::KEY_SIZE);
        debug_assert_eq!(_iv.len(), Self::IV_SIZE);
    }

    fn unload_key(&mut self) {}

    fn encrypt_packet(&mut self, _context: EncryptionContext) {}

    fn decrypt_packet(&mut self, mut context: EncryptionContext) -> usize {
        context.unprocessed_part().len()
    }
}

/// Calls the `add` function with all encryption algorithms defined and enabled in this crate.
pub fn add_algorithms<F>(mut add: F)
where
    F: FnMut(internal::EncryptionAlgorithmEntry),
{
    // This is the same order used by OpenSSH
    #[cfg(feature = "chacha20poly1305_at_openssh_com")]
    add(ChaCha20Poly1305::new().into());
    #[cfg(feature = "aes128-ctr")]
    add(Aes128Ctr::new().into());
    #[cfg(feature = "aes192-ctr")]
    add(Aes192Ctr::new().into());
    #[cfg(feature = "aes256-ctr")]
    add(Aes256Ctr::new().into());
    add(None::new().into());
}
