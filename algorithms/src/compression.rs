//! Provides the compression algorithms used by the SSH transport layer.

use russh_definitions::algorithms::{Algorithm, AlgorithmCategory, CompressionAlgorithm};
use std::{borrow::Cow, error::Error};

// TODO: implement at least one compression algorithm

/// The compression algorithm that does not compress.
///
/// This is used for sending uncompressed data.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
// This isn't a unit struct, to allow for future expansions of this.
#[non_exhaustive]
pub struct None {}

impl None {
    /// Creates a new `none` compression algorithm.
    pub fn new() -> None {
        None {}
    }

    /// Creates a new boxed `none` compression algorithm.
    pub fn boxed() -> Box<dyn CompressionAlgorithm> {
        Box::new(None::new())
    }
}

impl Algorithm for None {
    fn name(&self) -> &'static str {
        "none"
    }

    fn category(&self) -> AlgorithmCategory {
        AlgorithmCategory::Compression
    }
}

impl CompressionAlgorithm for None {
    fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
        self
    }

    fn compress<'data>(&mut self, data: Cow<'data, [u8]>) -> Cow<'data, [u8]> {
        data
    }

    fn decompress<'data>(
        &mut self,
        data: Cow<'data, [u8]>,
    ) -> Result<Cow<'data, [u8]>, Box<dyn Error>> {
        Ok(data)
    }
}

/// Calls the `add` function with all compression algorithms defined and enabled in this crate.
pub fn add_algorithms<Entry, F>(mut add: F)
where
    Box<dyn CompressionAlgorithm>: Into<Entry>,
    F: FnMut(Entry),
{
    // This is the same order used by OpenSSH
    add(None::boxed().into());
}
