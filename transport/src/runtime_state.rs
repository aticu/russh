//! Implements a structure to hold the runtime state.

use num_bigint::BigInt;
use rand::RngCore;
use russh_common::{
    algorithms::{HostKeyAlgorithm, KeyExchangeAlgorithm},
    ConnectionRole,
};
use std::fmt;

use crate::{
    algorithms::{AlgorithmList, AvailableAlgorithms, ChosenAlgorithms, PacketAlgorithms},
    version::VersionInformation,
};

/// Contains state that will be needed at runtime.
pub(crate) struct RuntimeState {
    /// The version information for the handler.
    version_info: VersionInformation,
    /// The list of available algorithms.
    ///
    /// This exists to preverse the original algorithms order, while having the ability
    /// to move algorithms out of the `AvailableAlgorithms`.
    algorithm_list: AlgorithmList<'static>,
    /// The algorithms that are chosen to be used.
    chosen_algorithms: ChosenAlgorithms,
    /// The algorithms that are available.
    available_algorithms: AvailableAlgorithms,
    /// The role of the handler in the connection.
    connection_role: ConnectionRole,
    /// The random number generator used for the connection.
    rng: Box<dyn RngCore>,
}

impl fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RuntimeState")
            .field("version_info", &self.version_info)
            .field("algorithm_list", &self.algorithm_list)
            .field("chosen_algorithms", &self.chosen_algorithms)
            .field("available_algorithms", &self.available_algorithms)
            .field("connection_role", &self.connection_role)
            .field("rng", &"opaque rng")
            .finish()
    }
}

// TODO: Consider refactoring to allow splitting the sender and the receiver
// Also consider how this would affect things like re-keying and other semi-synchronous operations
impl RuntimeState {
    /// Creates a new runtime state.
    pub(crate) fn new(
        version_info: VersionInformation,
        available_algorithms: AvailableAlgorithms,
        connection_role: ConnectionRole,
        rng: Box<dyn RngCore>,
        allow_none_algorithms: bool,
    ) -> RuntimeState {
        RuntimeState {
            version_info,
            algorithm_list: AlgorithmList::from_available(
                &available_algorithms,
                allow_none_algorithms,
            ),
            chosen_algorithms: ChosenAlgorithms::new(),
            available_algorithms,
            connection_role,
            rng,
        }
    }

    /// Returns the local version information.
    pub(crate) fn local_version_info(&self) -> &VersionInformation {
        &self.version_info
    }

    /// Returns the rng to use for operations requiring randomness.
    pub(crate) fn rng(&mut self) -> &mut dyn RngCore {
        &mut *self.rng
    }

    /// Returns the list of available algorithms.
    pub(crate) fn algorithm_list(&self) -> &AlgorithmList<'static> {
        &self.algorithm_list
    }

    /// Returns the role in the connection.
    pub(crate) fn connection_role(&self) -> &ConnectionRole {
        &self.connection_role
    }

    /// Returns the algorithms used by the partner to encode our input.
    pub(crate) fn input_algorithms(&mut self) -> PacketAlgorithms {
        let role = self.connection_role().other();
        self.chosen_algorithms
            .outgoing_from(&role, &mut self.available_algorithms)
            .expect("chosen algorithms should exists")
    }

    /// Returns the algorithms used to encode our output.
    pub(crate) fn output_algorithms_and_rng(&mut self) -> (PacketAlgorithms, &mut dyn RngCore) {
        let role = *self.connection_role();
        (
            self.chosen_algorithms
                .outgoing_from(&role, &mut self.available_algorithms)
                .expect("chosen algorithms should exists"),
            &mut *self.rng,
        )
    }

    /// Returns a reference to the available algorithms.
    pub(crate) fn available_algorithms(&self) -> &AvailableAlgorithms {
        &self.available_algorithms
    }

    /// Takes both the key exchange and the host key algorithms requested and returns them.
    pub(crate) fn take_kex_and_host_key(
        &mut self,
        kex: &str,
        host_key: &str,
    ) -> Option<(Box<dyn KeyExchangeAlgorithm>, Box<dyn HostKeyAlgorithm>)> {
        let kex_index = self
            .available_algorithms
            .kex
            .iter()
            .enumerate()
            .find(|(_, a)| a.name() == kex)
            .map(|(index, _)| index)?;

        let host_key_index = self
            .available_algorithms
            .host_key
            .iter()
            .enumerate()
            .find(|(_, a)| a.name() == host_key)
            .map(|(index, _)| index)?;

        let kex = self.available_algorithms.kex.remove(kex_index);
        let host_key = self.available_algorithms.host_key.remove(host_key_index);

        Some((kex, host_key))
    }

    /// Returns the kex and host key algorithms to the available algorithms.
    pub(crate) fn return_kex_and_host_key(
        &mut self,
        kex: Box<dyn KeyExchangeAlgorithm>,
        host_key: Box<dyn HostKeyAlgorithm>,
    ) {
        let kex_index = self
            .algorithm_list
            .kex
            .iter()
            .enumerate()
            .find(|(_, name)| &kex.name() == name)
            .map(|(index, _)| index)
            .expect("returned algorithm should be in algorithm list");

        let host_key_index = self
            .algorithm_list
            .host_key
            .iter()
            .enumerate()
            .find(|(_, name)| &host_key.name() == name)
            .map(|(index, _)| index)
            .expect("returned algorithm should be in algorithm list");

        self.available_algorithms.kex.insert(kex_index, kex);
        self.available_algorithms
            .host_key
            .insert(host_key_index, host_key);
    }

    /// Changes the chosen algorithms and loads new keys for the new algorithms.
    pub(crate) fn change_algorithms(
        &mut self,
        chosen_algorithms: ChosenAlgorithms,
        hash_fn: fn(&[u8]) -> Vec<u8>,
        shared_secret: &BigInt,
        exchange_hash: &[u8],
        session_id: &[u8],
    ) {
        self.available_algorithms
            .unload_algorithm_keys(&self.chosen_algorithms);
        self.available_algorithms.load_algorithm_keys(
            &chosen_algorithms,
            hash_fn,
            shared_secret,
            exchange_hash,
            session_id,
        );

        self.chosen_algorithms = chosen_algorithms;
    }
}
