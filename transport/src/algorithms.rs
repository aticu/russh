//! Provides traits for the needed types of algorithms.

use num_bigint::BigInt;
use russh_definitions::algorithms::{
    AlgorithmCategory, AlgorithmDirection, AlgorithmRole, CompressionAlgorithm,
    EncryptionAlgorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, KeyExchangeHashFunction,
    MacAlgorithm,
};
use std::borrow::Cow;

use crate::errors::LoadHostKeyError;
pub(crate) use list::{AddIn, AlgorithmList};

mod key_expansion;
mod list;

pub(crate) mod builtin;
pub(crate) mod helpers;

impl list::Nameable for Box<dyn KeyExchangeAlgorithm> {
    fn name(&self) -> &'static str {
        self.as_basic_algorithm().name()
    }
}

impl list::Nameable for Box<dyn HostKeyAlgorithm> {
    fn name(&self) -> &'static str {
        self.as_basic_algorithm().name()
    }
}

impl list::Nameable for Box<dyn EncryptionAlgorithm> {
    fn name(&self) -> &'static str {
        self.as_basic_algorithm().name()
    }
}

impl list::Nameable for Box<dyn MacAlgorithm> {
    fn name(&self) -> &'static str {
        self.as_basic_algorithm().name()
    }
}

impl list::Nameable for Box<dyn CompressionAlgorithm> {
    fn name(&self) -> &'static str {
        self.as_basic_algorithm().name()
    }
}

/// The lists of available packet algorithms in one communication direction.
#[derive(Debug)]
pub(crate) struct OneWayPacketAlgorithms {
    /// The available encryption algorithms.
    pub(crate) encryption: AlgorithmList<Box<dyn EncryptionAlgorithm>>,
    /// The available MAC algorithms.
    pub(crate) mac: AlgorithmList<Box<dyn MacAlgorithm>>,
    /// The available compression algorithms.
    pub(crate) compression: AlgorithmList<Box<dyn CompressionAlgorithm>>,
}

impl Default for OneWayPacketAlgorithms {
    fn default() -> OneWayPacketAlgorithms {
        OneWayPacketAlgorithms {
            encryption: builtin::encryption_algorithms(),
            mac: builtin::mac_algorithms(),
            compression: builtin::compression_algorithms(),
        }
    }
}

impl OneWayPacketAlgorithms {
    pub(crate) fn current(&mut self) -> PacketAlgorithms {
        let encryption_algorithm = &mut **self.encryption.current();
        let mac_needed = encryption_algorithm.mac_size().is_none();

        PacketAlgorithms {
            encryption: encryption_algorithm,
            mac: if mac_needed {
                Some(&mut **self.mac.current())
            } else {
                None
            },
            compression: &mut **self.compression.current(),
        }
    }
}

/// Contains the algorithms available for communication.
#[derive(Debug)]
pub(crate) struct ConnectionAlgorithms {
    /// The available key exchange algorithms.
    pub(crate) kex: AlgorithmList<Box<dyn KeyExchangeAlgorithm>>,
    /// The available host key algorithms.
    pub(crate) host_key: AlgorithmList<Box<dyn HostKeyAlgorithm>>,
    /// The algorithms for client to server communication.
    pub(crate) c2s: OneWayPacketAlgorithms,
    /// The algorithms for server to client communication.
    pub(crate) s2c: OneWayPacketAlgorithms,
}

impl Default for ConnectionAlgorithms {
    fn default() -> ConnectionAlgorithms {
        ConnectionAlgorithms {
            kex: builtin::key_exchange_algorithms(),
            host_key: builtin::host_key_algorithms(),
            c2s: Default::default(),
            s2c: Default::default(),
        }
    }
}

impl ConnectionAlgorithms {
    /// Returns the name of the first empty algorithm category.
    pub(crate) fn empty_algorithm_role(&self) -> Option<AlgorithmRole> {
        if self.kex.is_empty() {
            Some(AlgorithmRole(AlgorithmCategory::KeyExchange, None))
        } else if self.host_key.is_empty() {
            Some(AlgorithmRole(AlgorithmCategory::HostKey, None))
        } else if self.c2s.encryption.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.s2c.encryption.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.c2s.mac.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.s2c.mac.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if self.c2s.compression.is_empty() {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if self.s2c.compression.is_empty() {
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
        if !self.c2s.encryption.contains_algorithm("none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if !self.s2c.encryption.contains_algorithm("none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Encryption,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if !self.c2s.mac.contains_algorithm("none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if !self.s2c.mac.contains_algorithm("none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ))
        } else if !self.c2s.compression.contains_algorithm("none") {
            Some(AlgorithmRole(
                AlgorithmCategory::Compression,
                Some(AlgorithmDirection::ClientToServer),
            ))
        } else if !self.s2c.compression.contains_algorithm("none") {
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
        self.c2s.encryption.clear();
        self.s2c.encryption.clear();
        self.c2s.mac.clear();
        self.s2c.mac.clear();
        self.c2s.compression.clear();
        self.s2c.compression.clear();
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
            .algorithm_mut(algorithm)
            .ok_or_else(|| LoadHostKeyError::AlgorithmNotFound(algorithm.into()))?;

        alg.load_keypair(key)
            .map_err(|err| LoadHostKeyError::AlgorithmError(err))
    }

    /// Unloads the keys for the given chosen algorithms.
    ///
    /// # Panics
    /// May panic if no algorithms were previously chosen or no algorithm keys were previously
    /// loaded.
    pub(crate) fn unload_algorithm_keys(&mut self) {
        let encryption_c2s = self.c2s.encryption.current();
        let encryption_s2c = self.s2c.encryption.current();
        let mac_c2s = if encryption_c2s.mac_size().is_none() {
            Some(self.c2s.mac.current())
        } else {
            None
        };
        let mac_s2c = if encryption_s2c.mac_size().is_none() {
            Some(self.s2c.mac.current())
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
    ///
    /// # Panics
    /// May panic if no algorithms were previously chosen.
    pub(crate) fn load_algorithm_keys(
        &mut self,
        chosen_algorithms: &ChosenAlgorithms,
        hash_fn: KeyExchangeHashFunction,
        shared_secret: &BigInt,
        exchange_hash: &[u8],
        session_id: &[u8],
    ) {
        self.c2s.encryption.choose(chosen_algorithms.encryption_c2s);
        self.s2c.encryption.choose(chosen_algorithms.encryption_s2c);
        let encryption_c2s = self.c2s.encryption.current();
        let encryption_s2c = self.s2c.encryption.current();
        let mac_c2s = if let Some(mac_c2s) = chosen_algorithms.mac_c2s {
            self.c2s.mac.choose(mac_c2s);
            Some(self.c2s.mac.current())
        } else {
            None
        };
        let mac_s2c = if let Some(mac_s2c) = chosen_algorithms.mac_s2c {
            self.s2c.mac.choose(mac_s2c);
            Some(self.s2c.mac.current())
        } else {
            None
        };
        self.c2s
            .compression
            .choose(chosen_algorithms.compression_c2s);
        self.s2c
            .compression
            .choose(chosen_algorithms.compression_s2c);

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
#[derive(Debug, Clone)]
pub(crate) struct ChosenAlgorithms<'name> {
    /// The encryption algorithm for client to server communication.
    pub(crate) encryption_c2s: &'name str,
    /// The encryption algorithm for server to client communication.
    pub(crate) encryption_s2c: &'name str,
    /// The MAC algorithm for client to server communication.
    pub(crate) mac_c2s: Option<&'name str>,
    /// The MAC algorithm for server to client communication.
    pub(crate) mac_s2c: Option<&'name str>,
    /// The compression algorithm for client to server communication.
    pub(crate) compression_c2s: &'name str,
    /// The compression algorithm for server to client communication.
    pub(crate) compression_s2c: &'name str,
}

impl Default for ChosenAlgorithms<'static> {
    fn default() -> ChosenAlgorithms<'static> {
        ChosenAlgorithms {
            encryption_c2s: "none",
            encryption_s2c: "none",
            mac_c2s: Some("none"),
            mac_s2c: Some("none"),
            compression_c2s: "none",
            compression_s2c: "none",
        }
    }
}

/// Picks the outgoing [`PacketAlgorithms`] from the given [`ConnectionAlgorithms`].
///
/// This is a macro to allow other parts of the `ConnectionAlgorithms` to be borrowed
/// independently.
macro_rules! outgoing_algorithms {
    ($connection_algorithms:expr, $connection_role:expr) => {
        match $connection_role {
            $crate::ConnectionRole::Client => $connection_algorithms.c2s.current(),
            $crate::ConnectionRole::Server => $connection_algorithms.s2c.current(),
        }
    };
}

/// Picks the incoming [`PacketAlgorithms`] from the given [`ConnectionAlgorithms`].
///
/// This is a macro to allow other parts of the `ConnectionAlgorithms` to be borrowed
/// independently.
macro_rules! incoming_algorithms {
    ($connection_algorithms:expr, $connection_role:expr) => {
        match $connection_role {
            $crate::ConnectionRole::Client => $connection_algorithms.s2c.current(),
            $crate::ConnectionRole::Server => $connection_algorithms.c2s.current(),
        }
    };
}

/// Contains the algorithm list used during initialization.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct AlgorithmNameList<'a> {
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

impl AlgorithmNameList<'static> {
    /// Creates the algorithm list from the available algorithms.
    pub(crate) fn from_available(
        available_algorithms: &ConnectionAlgorithms,
        allow_none_algorithms: bool,
    ) -> AlgorithmNameList<'static> {
        AlgorithmNameList {
            kex: available_algorithms.kex.to_name_list(true),
            host_key: available_algorithms.host_key.to_name_list(true),
            encryption_c2s: available_algorithms
                .c2s
                .encryption
                .to_name_list(allow_none_algorithms),
            encryption_s2c: available_algorithms
                .s2c
                .encryption
                .to_name_list(allow_none_algorithms),
            mac_c2s: available_algorithms
                .c2s
                .mac
                .to_name_list(allow_none_algorithms),
            mac_s2c: available_algorithms
                .s2c
                .mac
                .to_name_list(allow_none_algorithms),
            compression_c2s: available_algorithms.c2s.compression.to_name_list(true),
            compression_s2c: available_algorithms.s2c.compression.to_name_list(true),
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
