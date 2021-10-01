//! Defines the `EncryptionAlgorithm` trait.

use super::InvalidMacError;
use std::{
    fmt,
    ops::{Deref, DerefMut},
};

mod context;

// TODO: Remove this allow once this issue is fixed: https://github.com/rust-lang/rust/issues/64762
#[allow(unreachable_pub)]
pub use context::EncryptionContext;

/// A private module to implement the `Sealed` trait.
mod private {
    /// An empty trait that can only be implemented in this crate.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

/// Differentiates between the different types of encryption algorithms.
///
/// As the trait itself is not implementable by users,
///
/// This trait is sealed, meaning it is impossible to implement for types external to this crate.
pub trait EncryptionAlgorithmType: private::Sealed {
    /// The size of the MAC used by the encryption algorithm.
    ///
    /// This will be `Some(size)` for encryption algorithms which perform a MAC computation
    /// themselves, where `size` is the size of the computed MAC.
    ///
    /// If the encryption algorithm does not perform any MAC computations, this will be `None`.
    const MAC_SIZE: Option<usize>;

    /// The result of the decryption operation.
    ///
    /// This will be `Result<usize, InvalidMacError>` for encryption algorithms which perform a MAC
    /// computation and `usize` for other algorithms.
    type DecryptionResult;

    /// Converts the decryption result to the universal result type.
    fn convert_result(val: Self::DecryptionResult) -> Result<usize, InvalidMacError>;
}

/// The algorithm type for a plain encryption algorithm.
///
/// This is an encryption algorithm which does not perform any MAC computations.
#[derive(Debug)]
pub struct PlainEncryptionAlgorithm;

impl private::Sealed for PlainEncryptionAlgorithm {}
impl EncryptionAlgorithmType for PlainEncryptionAlgorithm {
    const MAC_SIZE: Option<usize> = None;
    type DecryptionResult = usize;

    fn convert_result(val: usize) -> Result<usize, InvalidMacError> {
        Ok(val)
    }
}

/// The algorithm type for a MAC computing encryption algorithm.
///
/// This is an encryption algorithm which performs MAC computations in addition to encrypting the
/// data, as combining these steps can provide additional security.
#[derive(Debug)]
pub struct MacComputingEncryptionAlgorithm<const MAC_SIZE: usize>;

impl<const MAC_SIZE: usize> private::Sealed for MacComputingEncryptionAlgorithm<MAC_SIZE> {}
impl<const MAC_SIZE: usize> EncryptionAlgorithmType for MacComputingEncryptionAlgorithm<MAC_SIZE> {
    const MAC_SIZE: Option<usize> = Some(MAC_SIZE);
    type DecryptionResult = Result<usize, InvalidMacError>;

    fn convert_result(val: Result<usize, InvalidMacError>) -> Result<usize, InvalidMacError> {
        val
    }
}

/// Describes an encryption algorithm.
pub trait EncryptionAlgorithm {
    /// The type of the encryption algorithm.
    ///
    /// This can either be `PlainEncryptionAlgorithm` for encryption algorithm which do not perform
    /// any MAC computations or `MacComputingEncryptionAlgorithm<MAC_SIZE>` for encryption
    /// algorithms which perform a MAC computation.
    type AlgorithmType: EncryptionAlgorithmType;

    /// The name of the encryption algorithm.
    const NAME: &'static str;

    /// The size of the smallest amount of data that can be encrypted.
    const CIPHER_BLOCK_SIZE: usize;

    /// The size, in bytes, of the key used by this algorithm.
    const KEY_SIZE: usize;

    /// The size, in bytes, of the iv used by this algorithm.
    const IV_SIZE: usize;

    /// Loads a new key to use for the algorithm.
    ///
    /// After the first call to `load_key`, the transport layer implementation guarantees, that
    /// `unload_key` is be called, before `load_key` is called again.
    ///
    /// # Panics
    /// The function may panic if
    /// - `key.len() != Self::KEY_SIZE`
    /// - `iv.len() != Self::IV_SIZE`
    /// - there was a previous call to `self.load_key`, but no call to `self.unload_key` after it
    fn load_key(&mut self, iv: &[u8], key: &[u8]);

    /// Unloads the key that was previously loaded.
    ///
    /// This should overwrite the memory where the key was stored with a predictable value (such as
    /// zero) to avoid the key being readable for longer than necessary.
    ///
    /// # Panics
    /// The function may panic if `load_key` has not been called since the last call to
    /// `unload_key`.
    fn unload_key(&mut self);

    /// Encrypts a packet.
    ///
    /// # Panics
    /// The function may panic if
    /// - `load_key` has not been called previously
    /// - the packet length is not at least the minimum packet length of 16
    /// - the amount of data provided is less than the packet length and the MAC size
    /// - the whole packet size (excluding the MAC) is not a multiple of 8 or
    /// `Self::CIPHER_BLOCK_SIZE`, whichever is larger
    fn encrypt_packet(&mut self, context: EncryptionContext);

    /// Decrypts a packet as far as possible.
    ///
    /// The return type  depends on the `AlgorithmType` and is either `usize` or `Result<usize,
    /// InvalidMacError>`.
    /// The `usize` in both types is the number of bytes that have been decrypted.
    ///
    /// A correct implementation of this algorithm must make as much progress in one call to
    /// `decrypt_packet` as possible.
    ///
    /// # Panics
    /// The function may panic if `self.load_key` has not been called previously.
    fn decrypt_packet(
        &mut self,
        context: EncryptionContext,
    ) -> <Self::AlgorithmType as EncryptionAlgorithmType>::DecryptionResult;
}

/// A runtime description of an encryption algorithm.
///
/// This allows representing different encryption algorithms with the same type.
///
/// It is mostly intended for internal use.
pub struct EncryptionAlgorithmEntry {
    /// The name of the encryption algorithm.
    pub name: &'static str,
    /// The size of the smallest amount of data that can be encrypted.
    pub cipher_block_size: usize,
    /// The size, in bytes, of the key used by this algorithm.
    pub key_size: usize,
    /// The size, in bytes, of the iv used by this algorithm.
    pub iv_size: usize,
    /// The size of the MAC, in bytes, if the algorithm computes the MAC.
    pub mac_size: Option<usize>,
    /// The algorithm itself.
    #[doc(hidden)]
    algorithm: Box<dyn DynEncryptionAlgorithm>,
}

impl fmt::Debug for EncryptionAlgorithmEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("EncryptionAlgorithmEntry")
            .field("name", &self.name)
            .field("cipher_block_size", &self.cipher_block_size)
            .field("key_size", &self.key_size)
            .field("iv_size", &self.iv_size)
            .field("mac_size", &self.mac_size)
            .finish_non_exhaustive()
    }
}

impl EncryptionAlgorithmEntry {
    /// Returns `true` if the encryption algorithm computes a MAC as part of the encryption.
    pub fn computes_mac(&self) -> bool {
        self.mac_size.is_some()
    }
}

impl<T> From<T> for EncryptionAlgorithmEntry
where
    T: EncryptionAlgorithm + 'static,
{
    fn from(alg: T) -> Self {
        EncryptionAlgorithmEntry {
            name: <T as EncryptionAlgorithm>::NAME,
            cipher_block_size: <T as EncryptionAlgorithm>::CIPHER_BLOCK_SIZE,
            key_size: <T as EncryptionAlgorithm>::KEY_SIZE,
            iv_size: <T as EncryptionAlgorithm>::IV_SIZE,
            mac_size:
                <<T as EncryptionAlgorithm>::AlgorithmType as EncryptionAlgorithmType>::MAC_SIZE,
            algorithm: Box::new(alg),
        }
    }
}

impl Deref for EncryptionAlgorithmEntry {
    type Target = dyn DynEncryptionAlgorithm;

    fn deref(&self) -> &Self::Target {
        &*self.algorithm
    }
}

impl DerefMut for EncryptionAlgorithmEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.algorithm
    }
}

/// A trait object friendly version of the [`EncryptionAlgorithm`] trait.
///
/// **DO NOT IMPLEMENT THIS TRAIT MANUALLY.**
/// Implement the [`EncryptionAlgorithm`] trait instead.
///
/// This trait is mainly intended for internal use and automatically implemented for all types
/// implementing the [`EncryptionAlgorithm`] trait.
pub trait DynEncryptionAlgorithm {
    /// See [`EncryptionAlgorithm::load_key`].
    fn load_key(&mut self, iv: &[u8], key: &[u8]);

    /// See [`EncryptionAlgorithm::unload_key`].
    fn unload_key(&mut self);

    /// See [`EncryptionAlgorithm::encrypt_packet`].
    fn encrypt_packet(&mut self, context: EncryptionContext);

    /// See [`EncryptionAlgorithm::decrypt_packet`].
    fn decrypt_packet(&mut self, context: EncryptionContext) -> Result<usize, InvalidMacError>;
}

impl<T: EncryptionAlgorithm> DynEncryptionAlgorithm for T {
    fn load_key(&mut self, iv: &[u8], key: &[u8]) {
        <Self as EncryptionAlgorithm>::load_key(self, iv, key)
    }

    fn unload_key(&mut self) {
        <Self as EncryptionAlgorithm>::unload_key(self)
    }

    fn encrypt_packet(&mut self, context: EncryptionContext) {
        <Self as EncryptionAlgorithm>::encrypt_packet(self, context)
    }

    fn decrypt_packet(&mut self, context: EncryptionContext) -> Result<usize, InvalidMacError> {
        <<Self as EncryptionAlgorithm>::AlgorithmType as EncryptionAlgorithmType>::convert_result(
            <Self as EncryptionAlgorithm>::decrypt_packet(self, context),
        )
    }
}
