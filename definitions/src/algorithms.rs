//! Provides traits to define algorithms used in the transport layer.

use std::fmt;

pub use compression::CompressionAlgorithm;
pub use encryption::{
    EncryptionAlgorithm, EncryptionContext, MacComputingEncryptionAlgorithm,
    PlainEncryptionAlgorithm,
};
pub use host_key::HostKeyAlgorithm;
pub use key_exchange::{
    KeyExchangeAlgorithm, KeyExchangeAlgorithmError, KeyExchangeData, KeyExchangeHashFunction,
    KeyExchangeResponse,
};
pub use mac::MacAlgorithm;

mod compression;
mod encryption;
mod host_key;
mod key_exchange;
mod mac;

/// Internal implementation details that likely of little importance to library users.
///
/// They are made only public, because they're used across crate borders.
///
/// The only exception is are the [`DynHostKeyAlgorithm`](internal::DynHostKeyAlgorithm) trait and
/// the [`HostKeyAlgorithmEntry`](internal::HostKeyAlgorithmEntry) struct, which are used as
/// arguments to the [`KeyExchangeAlgorithm`] methods.
pub mod internal {
    pub use super::compression::{CompressionAlgorithmEntry, DynCompressionAlgorithm};
    pub use super::encryption::{
        DynEncryptionAlgorithm, EncryptionAlgorithmEntry, EncryptionAlgorithmType,
    };
    pub use super::host_key::{DynHostKeyAlgorithm, HostKeyAlgorithmEntry};
    pub use super::key_exchange::{DynKeyExchangeAlgorithm, KeyExchangeAlgorithmEntry};
    pub use super::mac::{DynMacAlgorithm, MacAlgorithmEntry};

    /// An implementation detail to allow using trait objects that implement `RngCore` and `CryptoRng`.
    // TODO: eventually remove this, if https://github.com/rust-random/rand/issues/1143 lands
    pub trait CryptoRngCore: rand::RngCore + rand::CryptoRng {}

    impl<T: rand::RngCore + rand::CryptoRng> CryptoRngCore for T {}
}

/// Describes the possible categories for algorithms.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AlgorithmCategory {
    /// A key exchange algorithm.
    KeyExchange,
    /// A host key algorithm.
    HostKey,
    /// An encryption algorithm.
    Encryption,
    /// A MAC algorithm.
    Mac,
    /// A compression algorithm.
    Compression,
}

/// Describes the direction of an algorithm.
///
/// This is used to determine which party is the sender and which party is the receiver.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AlgorithmDirection {
    /// The algorithm is used for client to server communication.
    ClientToServer,
    /// The algorithm is used for server to client communication.
    ServerToClient,
}

/// Describes an algorithm role in a connection.
///
/// This is the combination of an algorithm category with its direction, if it has one.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AlgorithmRole(pub AlgorithmCategory, pub Option<AlgorithmDirection>);

impl fmt::Display for AlgorithmRole {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.1 {
            Some(direction) => write!(f, "{:?} {:?}", self.0, direction),
            None => write!(f, "{:?}", self.0),
        }
    }
}

/// An error for situations where the MAC is invalid.
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidMacError {
    /// The computed MAC does not match the sent MAC.
    #[error("computed MAC does not match sent MAC")]
    MacMismatch,
}
