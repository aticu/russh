//! Contains built-in algorithm implementations.

use crate::algorithms::{
    AddIn, AlgorithmList, CompressionAlgorithmEntry, EncryptionAlgorithmEntry,
    HostKeyAlgorithmEntry, KeyExchangeAlgorithmEntry, MacAlgorithmEntry,
};

/// Returns a list of all builtin key exchange algorithms.
pub(crate) fn key_exchange_algorithms() -> AlgorithmList<KeyExchangeAlgorithmEntry> {
    let mut list = AlgorithmList::new();

    #[cfg(feature = "default-algorithms")]
    russh_algorithms::key_exchange::add_algorithms(|alg| {
        list.add_raw(alg, AddIn::Back).unwrap();
    });

    list
}

/// Returns a list of all builtin host key algorithms.
pub(crate) fn host_key_algorithms() -> AlgorithmList<HostKeyAlgorithmEntry> {
    let mut list = AlgorithmList::new();

    #[cfg(feature = "default-algorithms")]
    russh_algorithms::host_key::add_algorithms(|alg| {
        list.add_raw(alg, AddIn::Back).unwrap();
    });

    list
}

/// Returns a list of all builtin encryption algorithms.
pub(crate) fn encryption_algorithms() -> AlgorithmList<EncryptionAlgorithmEntry> {
    let mut list = AlgorithmList::new();

    #[cfg(feature = "default-algorithms")]
    russh_algorithms::encryption::add_algorithms(|alg| {
        list.add_raw(alg, AddIn::Back).unwrap();
    });

    list
}

/// Returns a list of all builtin MAC algorithms.
pub(crate) fn mac_algorithms() -> AlgorithmList<MacAlgorithmEntry> {
    let mut list = AlgorithmList::new();

    #[cfg(feature = "default-algorithms")]
    russh_algorithms::mac::add_algorithms(|alg| {
        list.add_raw(alg, AddIn::Back).unwrap();
    });

    list
}

/// Returns a list of all builtin compression algorithms.
pub(crate) fn compression_algorithms() -> AlgorithmList<CompressionAlgorithmEntry> {
    let mut list = AlgorithmList::new();

    #[cfg(feature = "default-algorithms")]
    russh_algorithms::compression::add_algorithms(|alg| {
        list.add_raw(alg, AddIn::Back).unwrap();
    });

    list
}
