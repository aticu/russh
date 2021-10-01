//! Defines the `MacAlgorithm` trait.

use super::InvalidMacError;
use std::{
    fmt,
    ops::{Deref, DerefMut},
};

/// Describes a message authentication algorithm.
pub trait MacAlgorithm {
    /// The name of the MAC algorithm.
    const NAME: &'static str;

    /// The size, in bytes, of the MAC signature used.
    const MAC_SIZE: usize;

    /// The size, in bytes, of the key used for calculating the MAC.
    const KEY_SIZE: usize;

    /// Loads the key required for this MAC algorithm.
    ///
    /// # Panics
    /// The function may panic if `key.len() != Self::KEY_LEN`.
    fn load_key(&mut self, key: &[u8]);

    /// Unloads the key that was previously loaded.
    ///
    /// This should overwrite the memory where the key was stored with a predictable value (such as
    /// zero) to avoid the key being readable for longer than necessary.
    fn unload_key(&mut self);

    /// Computes the MAC of the given data.
    ///
    /// The result should be written to `result`.
    ///
    /// # Panics
    /// The function may panic if `result.len() != Self::MAC_SIZE`.
    fn compute(&mut self, data: &[u8], sequence_number: u32, result: &mut [u8]);

    /// Verifies if the given MAC matches the given data.
    ///
    /// It is recommended to implement this function manually to avoid allocations if possible.
    /// However be careful to use constant time equality checks, otherwise your implementation will
    /// be vulnerable to timing side channel attacks. The default implementation already does this.
    ///
    /// # Panics
    /// The function may panic if `mac.len() != Self::MAC_SIZE`.
    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        mac: &[u8],
    ) -> Result<(), InvalidMacError> {
        debug_assert_eq!(mac.len(), Self::MAC_SIZE);

        let mut result = vec![0; Self::MAC_SIZE];

        self.compute(data, sequence_number, &mut result[..]);

        #[inline(never)]
        fn not_equal(a: &[u8], b: &[u8]) -> u8 {
            let mut res = 0;

            for i in 0..a.len() {
                res |= a[i] ^ b[i];
            }

            res
        }

        if not_equal(&result, mac) == 0 {
            Ok(())
        } else {
            Err(InvalidMacError::MacMismatch)
        }
    }
}

/// A runtime description of a MAC algorithm.
///
/// This allows representing different MAC algorithms with the same type.
///
/// It is mostly intended for internal use.
pub struct MacAlgorithmEntry {
    /// The name of the MAC algorithm.
    pub name: &'static str,
    /// The size, in bytes, of the MAC signature used.
    pub mac_size: usize,
    /// The size, in bytes, of the key used for calculating the MAC.
    pub key_size: usize,
    /// The algorithm itself.
    #[doc(hidden)]
    algorithm: Box<dyn DynMacAlgorithm>,
}

impl fmt::Debug for MacAlgorithmEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MacAlgorithmEntry")
            .field("name", &self.name)
            .field("mac_size", &self.mac_size)
            .field("key_size", &self.key_size)
            .finish_non_exhaustive()
    }
}

impl<T> From<T> for MacAlgorithmEntry
where
    T: MacAlgorithm + 'static,
{
    fn from(alg: T) -> Self {
        MacAlgorithmEntry {
            name: <T as MacAlgorithm>::NAME,
            mac_size: <T as MacAlgorithm>::MAC_SIZE,
            key_size: <T as MacAlgorithm>::KEY_SIZE,
            algorithm: Box::new(alg),
        }
    }
}

impl Deref for MacAlgorithmEntry {
    type Target = dyn DynMacAlgorithm;

    fn deref(&self) -> &Self::Target {
        &*self.algorithm
    }
}

impl DerefMut for MacAlgorithmEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.algorithm
    }
}

/// A trait object friendly version of the [`MacAlgorithm`] trait.
///
/// **DO NOT IMPLEMENT THIS TRAIT MANUALLY.**
/// Implement the [`MacAlgorithm`] trait instead.
///
/// This trait is mainly intended for internal use and automatically implemented for all types
/// implementing the [`MacAlgorithm`] trait.
pub trait DynMacAlgorithm {
    /// See [`MacAlgorithm::load_key`].
    fn load_key(&mut self, key: &[u8]);

    /// See [`MacAlgorithm::unload_key`].
    fn unload_key(&mut self);

    /// See [`MacAlgorithm::compute`].
    fn compute(&mut self, data: &[u8], sequence_number: u32, result: &mut [u8]);

    /// See [`MacAlgorithm::verify`].
    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        mac: &[u8],
    ) -> Result<(), InvalidMacError>;
}

impl<T> DynMacAlgorithm for T
where
    T: MacAlgorithm,
{
    fn load_key(&mut self, key: &[u8]) {
        <Self as MacAlgorithm>::load_key(self, key)
    }

    fn unload_key(&mut self) {
        <Self as MacAlgorithm>::unload_key(self)
    }

    fn compute(&mut self, data: &[u8], sequence_number: u32, result: &mut [u8]) {
        <Self as MacAlgorithm>::compute(self, data, sequence_number, result)
    }

    fn verify(
        &mut self,
        data: &[u8],
        sequence_number: u32,
        mac: &[u8],
    ) -> Result<(), InvalidMacError> {
        <Self as MacAlgorithm>::verify(self, data, sequence_number, mac)
    }
}
