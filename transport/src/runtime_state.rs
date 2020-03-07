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

    /// Returns access to the data necessary for a key exchange.
    ///
    /// This, in combination with the `start` method of the returned struct, allows simultaneous
    /// mutable access to the `RuntimeState` and the required algorithms that normally live inside
    /// it.
    pub(crate) fn key_exchange(&mut self, kex: &str, host_key: &str) -> Option<KeyExchangeAccess> {
        let kex_index = self
            .available_algorithms
            .kex
            .iter()
            .position(|a| a.name() == kex)?;

        let host_key_index = self
            .available_algorithms
            .host_key
            .iter()
            .position(|a| a.name() == host_key)?;

        let kex_alg = self.available_algorithms.kex.remove(kex_index);
        let host_key_alg = self.available_algorithms.host_key.remove(host_key_index);

        Some(KeyExchangeAccess {
            kex_index,
            host_key_index,
            kex_alg: Some(kex_alg),
            host_key_alg: Some(host_key_alg),
            runtime_state: self,
        })
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

/// Grants access to the data required for a key exchange.
pub(crate) struct KeyExchangeAccess<'a> {
    /// The original index of the key exchange algorithm.
    ///
    /// This is used to determine where to return the algorithm to.
    kex_index: usize,
    /// The original index of the host key algorithm.
    ///
    /// This is used to determine where to return the algorithm to.
    host_key_index: usize,
    /// The key exchange algorithm used for the exchange.
    kex_alg: Option<Box<dyn KeyExchangeAlgorithm>>,
    /// The host key algorithm used for the exchange.
    host_key_alg: Option<Box<dyn HostKeyAlgorithm>>,
    /// The runtime state used for the exchange.
    runtime_state: &'a mut RuntimeState,
}

impl Drop for KeyExchangeAccess<'_> {
    fn drop(&mut self) {
        self.runtime_state
            .available_algorithms
            .kex
            .insert(self.kex_index, self.kex_alg.take().unwrap());

        self.runtime_state
            .available_algorithms
            .host_key
            .insert(self.host_key_index, self.host_key_alg.take().unwrap());
    }
}

impl KeyExchangeAccess<'_> {
    /// Returns the data necessary for a key exchange.
    ///
    /// The returned `&mut RuntimeState` is equivalent to the `RuntimeState` used to create the
    /// `KeyExchangeAccess`, except that the `KeyExchangeAlgorithm` and `HostKeyAlgorithm` are
    /// missing from that `RuntimeState`.
    pub(crate) fn start(
        &mut self,
    ) -> (
        &mut dyn KeyExchangeAlgorithm,
        &mut dyn HostKeyAlgorithm,
        &mut RuntimeState,
    ) {
        (
            &mut **self.kex_alg.as_mut().unwrap(),
            &mut **self.host_key_alg.as_mut().unwrap(),
            self.runtime_state,
        )
    }
}
