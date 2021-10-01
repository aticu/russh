//! Provides the compression algorithms used by the SSH transport layer.

use russh_definitions::algorithms::{internal, CompressionAlgorithm};
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
}

impl CompressionAlgorithm for None {
    const NAME: &'static str = "none";

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
pub fn add_algorithms<F>(mut add: F)
where
    F: FnMut(internal::CompressionAlgorithmEntry),
{
    // This is the same order used by OpenSSH
    add(None::new().into());
}
