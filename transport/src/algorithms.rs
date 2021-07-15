//! Provides traits for the needed types of algorithms.

use num_bigint::BigInt;
use russh_definitions::{
    algorithms::{
        AlgorithmCategory, AlgorithmDirection, AlgorithmRole, CompressionAlgorithm,
        EncryptionAlgorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, KeyExchangeHashFunction,
        MacAlgorithm,
    },
    ConnectionRole,
};
use std::borrow::Cow;

use crate::errors::{InvalidAlgorithmError, LoadHostKeyError};

mod key_expansion;

pub(crate) mod builtin;
pub(crate) mod helpers;

/// Contains the algorithms available for communication.
#[derive(Debug)]
pub(crate) struct AvailableAlgorithms {
    /// The available key exchange algorithms.
    pub(crate) kex: Vec<Box<dyn KeyExchangeAlgorithm>>,
    /// The available host key algorithms.
    pub(crate) host_key: Vec<Box<dyn HostKeyAlgorithm>>,
    /// The available encryption algorithms for client to server communication.
    pub(crate) encryption_c2s: Vec<Box<dyn EncryptionAlgorithm>>,
    /// The available encryption algorithms for server to client communication.
    pub(crate) encryption_s2c: Vec<Box<dyn EncryptionAlgorithm>>,
    /// The available MAC algorithms for client to server communication.
    pub(crate) mac_c2s: Vec<Box<dyn MacAlgorithm>>,
    /// The available MAC algorithms for server to client communication.
    pub(crate) mac_s2c: Vec<Box<dyn MacAlgorithm>>,
    /// The available compression algorithms for client to server communication.
    pub(crate) compression_c2s: Vec<Box<dyn CompressionAlgorithm>>,
    /// The available compression algorithms for server to client communication.
    pub(crate) compression_s2c: Vec<Box<dyn CompressionAlgorithm>>,
}

impl Default for AvailableAlgorithms {
    fn default() -> AvailableAlgorithms {
        AvailableAlgorithms {
            kex: builtin::key_exchange_algorithms(),
            host_key: builtin::host_key_algorithms(),
            encryption_c2s: builtin::encryption_algorithms(),
            encryption_s2c: builtin::encryption_algorithms(),
            mac_c2s: builtin::mac_algorithms(),
            mac_s2c: builtin::mac_algorithms(),
            compression_c2s: builtin::compression_algorithms(),
            compression_s2c: builtin::compression_algorithms(),
        }
    }
}

impl AvailableAlgorithms {
    /// Checks if all the contained algorithms are valid.
    pub(crate) fn all_algorithms_valid(&self) -> Result<(), InvalidAlgorithmError> {
        let algorithms = self.kex[..]
            .iter()
            .map(|a| a.as_basic_algorithm())
            .chain(self.host_key[..].iter().map(|a| a.as_basic_algorithm()))
            .chain(
                self.encryption_c2s[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.encryption_s2c[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(self.mac_c2s[..].iter().map(|a| a.as_basic_algorithm()))
            .chain(self.mac_s2c[..].iter().map(|a| a.as_basic_algorithm()))
            .chain(
                self.compression_c2s[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.compression_s2c[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            );

        for algorithm in algorithms {
            helpers::is_valid_algorithm(algorithm)?;
        }
        Ok(())
    }

    /// Returns the name of the first empty algorithm category.
    pub(crate) fn empty_algorithm_role(&self) -> Option<AlgorithmRole> {
        if self.kex.is_empty() {
            Some(AlgorithmRole(AlgorithmCategory::KeyExchange, None))
        } else if self.host_key.is_empty() {
            Some(AlgorithmRole(AlgorithmCategory::HostKey, None))
        } else if self.encryption_c2s.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.encryption_s2c.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.mac_c2s.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.mac_s2c.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.compression_c2s.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.compression_s2c.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else {
            None
        }
    }

    /// Returns the name of the first algorithm role with a missing required "none" algorithm.
    pub(crate) fn required_none_missing(&self) -> Option<AlgorithmRole> {
        if self.encryption_c2s.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.encryption_s2c.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.mac_c2s.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.mac_s2c.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.compression_c2s.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.compression_s2c.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else {
            None
        }
    }

    /// Clears all algorithms from the available algorithms.
    pub(crate) fn clear(&mut self) {
        self.kex.clear();
        self.host_key.clear();
        self.encryption_c2s.clear();
        self.encryption_s2c.clear();
        self.mac_c2s.clear();
        self.mac_s2c.clear();
        self.compression_c2s.clear();
        self.compression_s2c.clear();
    }

    /// Loads a host key into the given algorithm.
    ///
    /// # Panics
    /// May panic if called successfully more than once for the same algorithm.
    pub(crate) fn load_host_key(
        &mut self,
        algorithm: &str,
        key: &[u8],
    ) -> Result<(), LoadHostKeyError> {
        let alg = self
            .host_key
            .iter_mut()
            .find(|a| a.name() == algorithm)
            .ok_or_else(|| LoadHostKeyError::AlgorithmNotFound(algorithm.into()))?;

        alg.load_keypair(key)
            .map_err(|err| LoadHostKeyError::AlgorithmError(err))
    }

    /// Return a reference to the key exchange algorithm referenced by the given name.
    pub(crate) fn kex_by_name(&self, name: &str) -> Option<&dyn KeyExchangeAlgorithm> {
        self.kex.iter().find(|a| a.name() == name).map(|a| &**a)
    }

    /// Return a reference to the host key algorithm referenced by the given name.
    pub(crate) fn host_key_by_name(&self, name: &str) -> Option<&dyn HostKeyAlgorithm> {
        self.host_key
            .iter()
            .find(|a| a.name() == name)
            .map(|a| &**a)
    }

    /// Unloads the keys for the given chosen algorithms.
    pub(crate) fn unload_algorithm_keys(&mut self, chosen_algorithms: &ChosenAlgorithms) {
        let encryption_c2s = self
            .encryption_c2s
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_c2s)
            .expect("chosen algorithm exists in the available algorithms");
        let encryption_s2c = self
            .encryption_s2c
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_s2c)
            .expect("chosen algorithm exists in the available algorithms");
        let mac_c2s = if let Some(chosen_alg) = chosen_algorithms.mac_c2s {
            Some(
                self.mac_c2s
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };
        let mac_s2c = if let Some(chosen_alg) = chosen_algorithms.mac_s2c {
            Some(
                self.mac_s2c
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };

        encryption_c2s.unload_key();
        encryption_s2c.unload_key();
        if let Some(mac_c2s) = mac_c2s {
            mac_c2s.unload_key();
        }
        if let Some(mac_s2c) = mac_s2c {
            mac_s2c.unload_key();
        }
    }

    /// Loads the correct keys into the chosen algorithms.
    pub(crate) fn load_algorithm_keys(
        &mut self,
        chosen_algorithms: &ChosenAlgorithms,
        hash_fn: KeyExchangeHashFunction,
        shared_secret: &BigInt,
        exchange_hash: &[u8],
        session_id: &[u8],
    ) {
        let encryption_c2s = self
            .encryption_c2s
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_c2s)
            .expect("chosen algorithm exists in the available algorithms");
        let encryption_s2c = self
            .encryption_s2c
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_s2c)
            .expect("chosen algorithm exists in the available algorithms");
        let mac_c2s = if let Some(chosen_alg) = chosen_algorithms.mac_c2s {
            Some(
                self.mac_c2s
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };
        let mac_s2c = if let Some(chosen_alg) = chosen_algorithms.mac_s2c {
            Some(
                self.mac_s2c
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };

        let mut encryption_c2s_iv = vec![0; encryption_c2s.iv_size()];
        let mut encryption_s2c_iv = vec![0; encryption_s2c.iv_size()];
        let mut encryption_c2s_key = vec![0; encryption_c2s.key_size()];
        let mut encryption_s2c_key = vec![0; encryption_s2c.key_size()];
        let mut mac_c2s_key = vec![0; mac_c2s.as_ref().map(|a| a.key_size()).unwrap_or(0)];
        let mut mac_s2c_key = vec![0; mac_s2c.as_ref().map(|a| a.key_size()).unwrap_or(0)];

        let mut keys = key_expansion::Keys {
            encryption_c2s_iv: &mut encryption_c2s_iv,
            encryption_s2c_iv: &mut encryption_s2c_iv,
            encryption_c2s_key: &mut encryption_c2s_key,
            encryption_s2c_key: &mut encryption_s2c_key,
            mac_c2s_key: &mut mac_c2s_key,
            mac_s2c_key: &mut mac_s2c_key,
        };

        key_expansion::expand_keys(&mut keys, hash_fn, shared_secret, exchange_hash, session_id);

        encryption_c2s.load_key(keys.encryption_c2s_iv, keys.encryption_c2s_key);
        encryption_s2c.load_key(keys.encryption_s2c_iv, keys.encryption_s2c_key);
        if let Some(mac_c2s) = mac_c2s {
            mac_c2s.load_key(keys.mac_c2s_key);
        }
        if let Some(mac_s2c) = mac_s2c {
            mac_s2c.load_key(keys.mac_s2c_key);
        }
    }
}

/// Contains the algorithms chosen to be used at runtime.
#[derive(Debug)]
pub(crate) struct ChosenAlgorithms {
    /// The encryption algorithm for client to server communication.
    pub(crate) encryption_c2s: &'static str,
    /// The encryption algorithm for server to client communication.
    pub(crate) encryption_s2c: &'static str,
    /// The MAC algorithm for client to server communication.
    pub(crate) mac_c2s: Option<&'static str>,
    /// The MAC algorithm for server to client communication.
    pub(crate) mac_s2c: Option<&'static str>,
    /// The compression algorithm for client to server communication.
    pub(crate) compression_c2s: &'static str,
    /// The compression algorithm for server to client communication.
    pub(crate) compression_s2c: &'static str,
}

impl ChosenAlgorithms {
    /// Chooses the algorithms to use at the beginning of the connection.
    pub(crate) fn new() -> ChosenAlgorithms {
        ChosenAlgorithms {
            encryption_c2s: "none",
            encryption_s2c: "none",
            mac_c2s: Some("none"),
            mac_s2c: Some("none"),
            compression_c2s: "none",
            compression_s2c: "none",
        }
    }

    /// Returns the outgoing from the given connection role.
    pub(crate) fn outgoing_from<'a>(
        &self,
        connection_role: &ConnectionRole,
        algorithms: &'a mut AvailableAlgorithms,
    ) -> Option<PacketAlgorithms<'a>> {
        // TODO: This happens for every packet. Consider speeding it up, by saving the indices as
        // well.
        let encryption_algorithm = match connection_role {
            ConnectionRole::Client => algorithms
                .encryption_c2s
                .iter_mut()
                .find(|a| a.name() == self.encryption_c2s)
                .map(|a| &mut **a)?,
            ConnectionRole::Server => algorithms
                .encryption_s2c
                .iter_mut()
                .find(|a| a.name() == self.encryption_s2c)
                .map(|a| &mut **a)?,
        };

        let mac_needed = encryption_algorithm.mac_size().is_none();

        Some(match connection_role {
            ConnectionRole::Client => PacketAlgorithms {
                encryption: encryption_algorithm,
                mac: if mac_needed {
                    Some(
                        algorithms
                            .mac_c2s
                            .iter_mut()
                            .find(|a| Some(a.name()) == self.mac_c2s)
                            .map(|a| &mut **a)?,
                    )
                } else {
                    None
                },
                compression: algorithms
                    .compression_c2s
                    .iter_mut()
                    .find(|a| a.name() == self.compression_c2s)
                    .map(|a| &mut **a)?,
            },
            ConnectionRole::Server => PacketAlgorithms {
                encryption: encryption_algorithm,
                mac: if mac_needed {
                    Some(
                        algorithms
                            .mac_s2c
                            .iter_mut()
                            .find(|a| Some(a.name()) == self.mac_s2c)
                            .map(|a| &mut **a)?,
                    )
                } else {
                    None
                },
                compression: algorithms
                    .compression_s2c
                    .iter_mut()
                    .find(|a| a.name() == self.compression_s2c)
                    .map(|a| &mut **a)?,
            },
        })
    }
}

/// Contains the algorithm list used during initialization.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct AlgorithmList<'a> {
    /// The key exchange algorithms available.
    pub(crate) kex: Vec<Cow<'a, str>>,
    /// The host key algorithms available.
    pub(crate) host_key: Vec<Cow<'a, str>>,
    /// The encryption algorithms available for client to server communication.
    pub(crate) encryption_c2s: Vec<Cow<'a, str>>,
    /// The encryption algorithms available for server to client communication.
    pub(crate) encryption_s2c: Vec<Cow<'a, str>>,
    /// The MAC algorithms available for client to server communication.
    pub(crate) mac_c2s: Vec<Cow<'a, str>>,
    /// The MAC algorithms available for server to client communication.
    pub(crate) mac_s2c: Vec<Cow<'a, str>>,
    /// The compression algorithms available for client to server communication.
    pub(crate) compression_c2s: Vec<Cow<'a, str>>,
    /// The compression algorithms available for server to client communication.
    pub(crate) compression_s2c: Vec<Cow<'a, str>>,
}

impl AlgorithmList<'static> {
    /// Creates the algorithm list from the available algorithms.
    pub(crate) fn from_available(
        available_algorithms: &AvailableAlgorithms,
        allow_none_algorithms: bool,
    ) -> AlgorithmList<'static> {
        AlgorithmList {
            kex: available_algorithms
                .kex
                .iter()
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            host_key: available_algorithms
                .host_key
                .iter()
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            encryption_c2s: available_algorithms
                .encryption_c2s
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            encryption_s2c: available_algorithms
                .encryption_s2c
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            mac_c2s: available_algorithms
                .mac_c2s
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            mac_s2c: available_algorithms
                .mac_s2c
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            compression_c2s: available_algorithms
                .compression_c2s
                .iter()
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            compression_s2c: available_algorithms
                .compression_s2c
                .iter()
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
        }
    }
}

/// Bundles the three algorithms used for handling regular packets.
pub(crate) struct PacketAlgorithms<'a> {
    /// The encryption algorithm used for the packets.
    pub(crate) encryption: &'a mut dyn EncryptionAlgorithm,
    /// The MAC algorithm used for the packets, if different from the encryption algorithm.
    pub(crate) mac: Option<&'a mut dyn MacAlgorithm>,
    /// The compression algorithm used for the packets.
    pub(crate) compression: &'a mut dyn CompressionAlgorithm,
}
