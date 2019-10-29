//! Contains built-in algorithm implementations.

use crate::algorithms::{
    CompressionAlgorithm, EncryptionAlgorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, MacAlgorithm,
};

// With default algorithms, simply include those

/// Returns a list of all builtin key exchange algorithms.
#[cfg(feature = "default-algorithms")]
pub fn key_exchange_algorithms() -> Vec<Box<dyn KeyExchangeAlgorithm>> {
    russh_algorithms::key_exchange::algorithms()
}

/// Returns a list of all builtin host key algorithms.
#[cfg(feature = "default-algorithms")]
pub fn host_key_algorithms() -> Vec<Box<dyn HostKeyAlgorithm>> {
    russh_algorithms::host_key::algorithms()
}

/// Returns a list of all builtin encryption algorithms.
#[cfg(feature = "default-algorithms")]
pub fn encryption_algorithms() -> Vec<Box<dyn EncryptionAlgorithm>> {
    russh_algorithms::encryption::algorithms()
}

/// Returns a list of all builtin MAC algorithms.
#[cfg(feature = "default-algorithms")]
pub fn mac_algorithms() -> Vec<Box<dyn MacAlgorithm>> {
    russh_algorithms::mac::algorithms()
}

/// Returns a list of all builtin compression algorithms.
#[cfg(feature = "default-algorithms")]
pub fn compression_algorithms() -> Vec<Box<dyn CompressionAlgorithm>> {
    russh_algorithms::compression::algorithms()
}

// Without default algorithms simply return no algorithms

/// Returns a list of all builtin key exchange algorithms.
#[cfg(not(feature = "default-algorithms"))]
pub fn key_exchange_algorithms() -> Vec<Box<dyn KeyExchangeAlgorithm>> {
    vec![]
}

/// Returns a list of all builtin host key algorithms.
#[cfg(not(feature = "default-algorithms"))]
pub fn host_key_algorithms() -> Vec<Box<dyn HostKeyAlgorithm>> {
    vec![]
}

/// Returns a list of all builtin encryption algorithms.
#[cfg(not(feature = "default-algorithms"))]
pub fn encryption_algorithms() -> Vec<Box<dyn EncryptionAlgorithm>> {
    vec![]
}

/// Returns a list of all builtin MAC algorithms.
#[cfg(not(feature = "default-algorithms"))]
pub fn mac_algorithms() -> Vec<Box<dyn MacAlgorithm>> {
    vec![]
}

/// Returns a list of all builtin compression algorithms.
#[cfg(not(feature = "default-algorithms"))]
pub fn compression_algorithms() -> Vec<Box<dyn CompressionAlgorithm>> {
    vec![]
}
