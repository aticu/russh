//! Defines the `MacAlgorithm` trait.

use std::{
    borrow::Cow,
    error::Error,
    fmt,
    ops::{Deref, DerefMut},
};

/// Describes a compression algorithm.
pub trait CompressionAlgorithm {
    /// The name of the MAC algorithm.
    const NAME: &'static str;

    /// Compresses the given data.
    ///
    /// This function receives the data in a `Cow::Borrowed` variant and may
    /// return a `Cow::Owned` variant if it changes the data.
    fn compress<'data>(&mut self, data: Cow<'data, [u8]>) -> Cow<'data, [u8]>;

    /// Decompresses the given data.
    ///
    /// This function receives the data in a `Cow::Borrowed` variant and may
    /// return a `Cow::Owned` variant if it changes the data.
    fn decompress<'data>(
        &mut self,
        data: Cow<'data, [u8]>,
    ) -> Result<Cow<'data, [u8]>, Box<dyn Error>>;
}

/// A runtime description of a compression algorithm.
///
/// This allows representing different compression algorithms with the same type.
///
/// It is mostly intended for internal use.
pub struct CompressionAlgorithmEntry {
    /// The name of the compression algorithm.
    pub name: &'static str,
    /// The algorithm itself.
    #[doc(hidden)]
    algorithm: Box<dyn DynCompressionAlgorithm>,
}

impl fmt::Debug for CompressionAlgorithmEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("CompressionAlgorithmEntry")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<T> From<T> for CompressionAlgorithmEntry
where
    T: CompressionAlgorithm + 'static,
{
    fn from(alg: T) -> Self {
        CompressionAlgorithmEntry {
            name: <T as CompressionAlgorithm>::NAME,
            algorithm: Box::new(alg),
        }
    }
}

impl Deref for CompressionAlgorithmEntry {
    type Target = dyn DynCompressionAlgorithm;

    fn deref(&self) -> &Self::Target {
        &*self.algorithm
    }
}

impl DerefMut for CompressionAlgorithmEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.algorithm
    }
}

/// A trait object friendly version of the [`CompressionAlgorithm`] trait.
///
/// **DO NOT IMPLEMENT THIS TRAIT MANUALLY.**
/// Implement the [`CompressionAlgorithm`] trait instead.
///
/// This trait is mainly intended for internal use and automatically implemented for all types
/// implementing the [`CompressionAlgorithm`] trait.
pub trait DynCompressionAlgorithm {
    /// See [`CompressionAlgorithm::compress`].
    fn compress<'data>(&mut self, data: Cow<'data, [u8]>) -> Cow<'data, [u8]>;

    /// See [`CompressionAlgorithm::decompress`].
    fn decompress<'data>(
        &mut self,
        data: Cow<'data, [u8]>,
    ) -> Result<Cow<'data, [u8]>, Box<dyn Error>>;
}

impl<T> DynCompressionAlgorithm for T
where
    T: CompressionAlgorithm,
{
    fn compress<'data>(&mut self, data: Cow<'data, [u8]>) -> Cow<'data, [u8]> {
        <Self as CompressionAlgorithm>::compress(self, data)
    }

    fn decompress<'data>(
        &mut self,
        data: Cow<'data, [u8]>,
    ) -> Result<Cow<'data, [u8]>, Box<dyn Error>> {
        <Self as CompressionAlgorithm>::decompress(self, data)
    }
}
