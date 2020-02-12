//! Provides traits for the needed types of algorithms.

use num_bigint::BigInt;
use russh_common::{
    algorithms::{
        AlgorithmCategory, AlgorithmDirection, AlgorithmRole, CompressionAlgorithm,
        EncryptionAlgorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, KeyExchangeHashFunction,
        MacAlgorithm,
    },
    ConnectionRole,
};
use std::{borrow::Cow, fmt};

use crate::errors::{InvalidAlgorithmError, LoadHostKeyError};

mod key_expansion;

pub(crate) mod builtin;
pub(crate) mod helpers;

/// Contains the algorithms available for communication.
pub(crate) struct AvailableAlgorithms {
    /// The available key exchange algorithms.
    pub(crate) kex: Vec<Box<dyn KeyExchangeAlgorithm>>,
    /// The available host key algorithms.
    pub(crate) host_key: Vec<Box<dyn HostKeyAlgorithm>>,
    /// The available encryption algorithms for client to server communication.
    pub(crate) encryption_client_to_server: Vec<Box<dyn EncryptionAlgorithm>>,
    /// The available encryption algorithms for server to client communication.
    pub(crate) encryption_server_to_client: Vec<Box<dyn EncryptionAlgorithm>>,
    /// The available MAC algorithms for client to server communication.
    pub(crate) mac_client_to_server: Vec<Box<dyn MacAlgorithm>>,
    /// The available MAC algorithms for server to client communication.
    pub(crate) mac_server_to_client: Vec<Box<dyn MacAlgorithm>>,
    /// The available compression algorithms for client to server communication.
    pub(crate) compression_client_to_server: Vec<Box<dyn CompressionAlgorithm>>,
    /// The available compression algorithms for server to client communication.
    pub(crate) compression_server_to_client: Vec<Box<dyn CompressionAlgorithm>>,
}

impl fmt::Debug for AvailableAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AvailableAlgorithms")
            .field(
                "kex",
                &self.kex.iter().map(|a| a.name()).collect::<Vec<_>>(),
            )
            .field(
                "host_key",
                &self.host_key.iter().map(|a| a.name()).collect::<Vec<_>>(),
            )
            .field(
                "encryption_client_to_server",
                &self
                    .encryption_client_to_server
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .field(
                "encryption_server_to_client",
                &self
                    .encryption_server_to_client
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .field(
                "mac_client_to_server",
                &self
                    .mac_client_to_server
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .field(
                "mac_server_to_client",
                &self
                    .mac_server_to_client
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .field(
                "compression_client_to_server",
                &self
                    .compression_client_to_server
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .field(
                "compression_server_to_client",
                &self
                    .compression_server_to_client
                    .iter()
                    .map(|a| a.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for AvailableAlgorithms {
    fn default() -> AvailableAlgorithms {
        AvailableAlgorithms {
            kex: builtin::key_exchange_algorithms(),
            host_key: builtin::host_key_algorithms(),
            encryption_client_to_server: builtin::encryption_algorithms(),
            encryption_server_to_client: builtin::encryption_algorithms(),
            mac_client_to_server: builtin::mac_algorithms(),
            mac_server_to_client: builtin::mac_algorithms(),
            compression_client_to_server: builtin::compression_algorithms(),
            compression_server_to_client: builtin::compression_algorithms(),
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
                self.encryption_client_to_server[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.encryption_server_to_client[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.mac_client_to_server[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.mac_server_to_client[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.compression_client_to_server[..]
                    .iter()
                    .map(|a| a.as_basic_algorithm()),
            )
            .chain(
                self.compression_server_to_client[..]
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
        } else if self.encryption_client_to_server.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.encryption_server_to_client.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.mac_client_to_server.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.mac_server_to_client.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.compression_client_to_server.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.compression_server_to_client.is_empty() {
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
        if self
            .encryption_client_to_server
            .iter()
            .all(|a| a.name() != "none")
        {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self
            .encryption_server_to_client
            .iter()
            .all(|a| a.name() != "none")
        {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.mac_client_to_server.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.mac_server_to_client.iter().all(|a| a.name() != "none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self
            .compression_client_to_server
            .iter()
            .all(|a| a.name() != "none")
        {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self
            .compression_server_to_client
            .iter()
            .all(|a| a.name() != "none")
        {
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
        self.encryption_client_to_server.clear();
        self.encryption_server_to_client.clear();
        self.mac_client_to_server.clear();
        self.mac_server_to_client.clear();
        self.compression_client_to_server.clear();
        self.compression_server_to_client.clear();
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
        let encryption_client_to_server = self
            .encryption_client_to_server
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_client_to_server)
            .expect("chosen algorithm exists in the available algorithms");
        let encryption_server_to_client = self
            .encryption_server_to_client
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_server_to_client)
            .expect("chosen algorithm exists in the available algorithms");
        let mac_client_to_server = if let Some(chosen_alg) = chosen_algorithms.mac_client_to_server
        {
            Some(
                self.mac_client_to_server
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };
        let mac_server_to_client = if let Some(chosen_alg) = chosen_algorithms.mac_server_to_client
        {
            Some(
                self.mac_server_to_client
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };

        encryption_client_to_server.unload_key();
        encryption_server_to_client.unload_key();
        if let Some(mac_client_to_server) = mac_client_to_server {
            mac_client_to_server.unload_key();
        }
        if let Some(mac_server_to_client) = mac_server_to_client {
            mac_server_to_client.unload_key();
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
        let encryption_client_to_server = self
            .encryption_client_to_server
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_client_to_server)
            .expect("chosen algorithm exists in the available algorithms");
        let encryption_server_to_client = self
            .encryption_server_to_client
            .iter_mut()
            .find(|a| a.name() == chosen_algorithms.encryption_server_to_client)
            .expect("chosen algorithm exists in the available algorithms");
        let mac_client_to_server = if let Some(chosen_alg) = chosen_algorithms.mac_client_to_server
        {
            Some(
                self.mac_client_to_server
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };
        let mac_server_to_client = if let Some(chosen_alg) = chosen_algorithms.mac_server_to_client
        {
            Some(
                self.mac_server_to_client
                    .iter_mut()
                    .find(|a| a.name() == chosen_alg)
                    .expect("chosen algorithm exists in the available algorithms"),
            )
        } else {
            None
        };

        let mut encryption_client_to_server_iv = vec![0; encryption_client_to_server.iv_size()];
        let mut encryption_server_to_client_iv = vec![0; encryption_server_to_client.iv_size()];
        let mut encryption_client_to_server_key = vec![0; encryption_client_to_server.key_size()];
        let mut encryption_server_to_client_key = vec![0; encryption_server_to_client.key_size()];
        let mut mac_client_to_server_key = vec![
            0;
            mac_client_to_server
                .as_ref()
                .map(|a| a.key_size())
                .unwrap_or(0)
        ];
        let mut mac_server_to_client_key = vec![
            0;
            mac_server_to_client
                .as_ref()
                .map(|a| a.key_size())
                .unwrap_or(0)
        ];

        let mut keys = key_expansion::Keys {
            encryption_client_to_server_iv: &mut encryption_client_to_server_iv,
            encryption_server_to_client_iv: &mut encryption_server_to_client_iv,
            encryption_client_to_server_key: &mut encryption_client_to_server_key,
            encryption_server_to_client_key: &mut encryption_server_to_client_key,
            mac_client_to_server_key: &mut mac_client_to_server_key,
            mac_server_to_client_key: &mut mac_server_to_client_key,
        };

        key_expansion::expand_keys(&mut keys, hash_fn, shared_secret, exchange_hash, session_id);

        encryption_client_to_server.load_key(
            keys.encryption_client_to_server_iv,
            keys.encryption_client_to_server_key,
        );
        encryption_server_to_client.load_key(
            keys.encryption_server_to_client_iv,
            keys.encryption_server_to_client_key,
        );
        if let Some(mac_client_to_server) = mac_client_to_server {
            mac_client_to_server.load_key(keys.mac_client_to_server_key);
        }
        if let Some(mac_server_to_client) = mac_server_to_client {
            mac_server_to_client.load_key(keys.mac_server_to_client_key);
        }
    }
}

/// Contains the algorithms chosen to be used at runtime.
#[derive(Debug)]
pub(crate) struct ChosenAlgorithms {
    /// The encryption algorithm for client to server communication.
    pub(crate) encryption_client_to_server: &'static str,
    /// The encryption algorithm for server to client communication.
    pub(crate) encryption_server_to_client: &'static str,
    /// The MAC algorithm for client to server communication.
    pub(crate) mac_client_to_server: Option<&'static str>,
    /// The MAC algorithm for server to client communication.
    pub(crate) mac_server_to_client: Option<&'static str>,
    /// The compression algorithm for client to server communication.
    pub(crate) compression_client_to_server: &'static str,
    /// The compression algorithm for server to client communication.
    pub(crate) compression_server_to_client: &'static str,
}

impl ChosenAlgorithms {
    /// Chooses the algorithms to use at the beginning of the connection.
    pub(crate) fn new() -> ChosenAlgorithms {
        ChosenAlgorithms {
            encryption_client_to_server: "none",
            encryption_server_to_client: "none",
            mac_client_to_server: Some("none"),
            mac_server_to_client: Some("none"),
            compression_client_to_server: "none",
            compression_server_to_client: "none",
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
                .encryption_client_to_server
                .iter_mut()
                .find(|a| a.name() == self.encryption_client_to_server)
                .map(|a| &mut **a)?,
            ConnectionRole::Server => algorithms
                .encryption_server_to_client
                .iter_mut()
                .find(|a| a.name() == self.encryption_server_to_client)
                .map(|a| &mut **a)?,
        };

        let mac_needed = encryption_algorithm.mac_size().is_none();

        Some(match connection_role {
            ConnectionRole::Client => PacketAlgorithms {
                encryption: encryption_algorithm,
                mac: if mac_needed {
                    Some(
                        algorithms
                            .mac_client_to_server
                            .iter_mut()
                            .find(|a| Some(a.name()) == self.mac_client_to_server)
                            .map(|a| &mut **a)?,
                    )
                } else {
                    None
                },
                compression: algorithms
                    .compression_client_to_server
                    .iter_mut()
                    .find(|a| a.name() == self.compression_client_to_server)
                    .map(|a| &mut **a)?,
            },
            ConnectionRole::Server => PacketAlgorithms {
                encryption: encryption_algorithm,
                mac: if mac_needed {
                    Some(
                        algorithms
                            .mac_server_to_client
                            .iter_mut()
                            .find(|a| Some(a.name()) == self.mac_server_to_client)
                            .map(|a| &mut **a)?,
                    )
                } else {
                    None
                },
                compression: algorithms
                    .compression_server_to_client
                    .iter_mut()
                    .find(|a| a.name() == self.compression_server_to_client)
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
    pub(crate) encryption_client_to_server: Vec<Cow<'a, str>>,
    /// The encryption algorithms available for server to client communication.
    pub(crate) encryption_server_to_client: Vec<Cow<'a, str>>,
    /// The MAC algorithms available for client to server communication.
    pub(crate) mac_client_to_server: Vec<Cow<'a, str>>,
    /// The MAC algorithms available for server to client communication.
    pub(crate) mac_server_to_client: Vec<Cow<'a, str>>,
    /// The compression algorithms available for client to server communication.
    pub(crate) compression_client_to_server: Vec<Cow<'a, str>>,
    /// The compression algorithms available for server to client communication.
    pub(crate) compression_server_to_client: Vec<Cow<'a, str>>,
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
            encryption_client_to_server: available_algorithms
                .encryption_client_to_server
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            encryption_server_to_client: available_algorithms
                .encryption_server_to_client
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            mac_client_to_server: available_algorithms
                .mac_client_to_server
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            mac_server_to_client: available_algorithms
                .mac_server_to_client
                .iter()
                .filter(|a| allow_none_algorithms || a.name() != "none")
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            compression_client_to_server: available_algorithms
                .compression_client_to_server
                .iter()
                .map(|a| Cow::Borrowed(a.name()))
                .collect(),
            compression_server_to_client: available_algorithms
                .compression_server_to_client
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
