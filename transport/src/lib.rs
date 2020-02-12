//! Provides an abstraction for the SSH transport layer.
//!
//! This library aims to be as lightweight and as general purpose as possible,
//! while maintaining a flexible API.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(unreachable_pub)]

#[macro_use]
extern crate err_derive;

use rand::{rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use russh_common::algorithms::{
    CompressionAlgorithm, EncryptionAlgorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, MacAlgorithm,
};
use std::{borrow::Cow, fmt};

use crate::{
    algorithms::AvailableAlgorithms,
    errors::{
        BuildError, CommunicationError, InvalidAlgorithmError, LoadHostKeyError,
        ServiceRequestError,
    },
    input_handler::InputHandler,
    output_handler::{OutputHandler, PacketFlusher},
    protocol::ProtocolHandler,
    runtime_state::RuntimeState,
};

pub use input_handler::InputStream;
pub use output_handler::OutputStream;
pub use russh_common::ConnectionRole;
pub use version::VersionInformation;

mod algorithms;
mod input_handler;
mod output_handler;
mod parser;
mod protocol;
mod runtime_state;
#[cfg(test)]
mod test_helpers;
mod version;
mod writer;

pub mod constants;
pub mod errors;

// TODO: track movement of sensitive data (e.g. keys) in memory and make sure it is zeroed, repeat
// for algorithm implementations
// TODO: document default-algorithms feature and its consequences for the none algorithms
// TODO: use the TCP_NODELAY option when later introducing network handlers

static_assertions::assert_cfg!(
    not(target_pointer_width = "16"),
    "16-bit platforms are not supported by russh."
);

/// A handler for the SSH transport layer.
pub struct Handler<Input: InputStream, Output: OutputStream> {
    /// The handler for the transport layer protocol.
    protocol_handler: ProtocolHandler<Input, Output>,
}

impl<Input: InputStream, Output: OutputStream> fmt::Debug for Handler<Input, Output> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handler {{ /* fields omitted */ }}")
    }
}

impl<Input: InputStream, Output: OutputStream> Handler<Input, Output> {
    /// Receives the next packet from the other party.
    pub async fn next_packet<'a>(&'a mut self) -> Result<Cow<'a, [u8]>, CommunicationError> {
        self.protocol_handler.next_user_packet().await
    }

    //TODO: Consider exposing `partner_version_info`

    /// Sends a packet with the given data to the other party.
    ///
    /// # Packet length
    /// Receivers of SSH packets are only required to be able to handle a payload length of 32768,
    /// so first check that the receiver is able to handle larger packets, if you want to send a
    /// packet with `data.len() > 32768`.
    ///
    /// # Panics
    /// This function may panic if the total packet length does not fit into a `u32`.
    pub fn send_packet(
        &mut self,
        data: &[u8],
    ) -> Result<PacketFlusher<Output>, CommunicationError> {
        self.protocol_handler.send_user_packet(data)
    }

    /// Sends a service request to the other party.
    pub async fn service_request(&mut self, service: &[u8]) -> Result<(), ServiceRequestError> {
        // TODO: Consider using a different API to allow service requests
        self.protocol_handler.service_request(service).await
    }
}

/// A builder for an `Handler`.
// TODO: document a lot more here
// TODO: document algorithm precedence
pub struct Builder<Input: InputStream, Output: OutputStream> {
    /// The version information for the SSH transport handler.
    version_info: Option<VersionInformation>,
    /// The the algorithms available to use during communications.
    available_algorithms: AvailableAlgorithms,
    /// The source where the input for the ssh transport layer will come from.
    input: Input,
    /// The sink where the output of the ssh transport layer will be written to.
    output: Output,
    /// The role the handler will have in the connection.
    connection_role: ConnectionRole,
    /// The distribution used for packet padding lengths.
    padding_length_distribution: Option<Box<dyn FnMut(&mut dyn RngCore) -> u8>>,
    /// The random number generator used for any required randomness.
    rng: Option<Box<dyn RngCore>>,
    /// Whether to allow "none" algorithms for encryption and MAC.
    allow_none_algorithms: bool,
}

impl<Input: InputStream + fmt::Debug, Output: OutputStream + fmt::Debug> fmt::Debug
    for Builder<Input, Output>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Builder")
            .field("version_info", &self.version_info)
            .field("available_algorithms", &self.available_algorithms)
            .field("input", &self.input)
            .field("output", &self.output)
            .field("connection_role", &self.connection_role)
            .field(
                "padding_length_distribution",
                match &self.padding_length_distribution {
                    Some(_) => &Some("opaque function"),
                    None => &None::<&'static str>,
                },
            )
            .field(
                "padding_length_distribution",
                match &self.rng {
                    Some(_) => &Some("opaque rng"),
                    None => &None::<&'static str>,
                },
            )
            .field("allow_none_algorithms", &self.allow_none_algorithms)
            .finish()
    }
}

impl<Input: InputStream, Output: OutputStream> Builder<Input, Output> {
    // TODO: change most methods to take &mut self instead of self
    // TODO: allow changing of the software version sent
    /// Creates a new builder with sensible default values.
    pub fn new(input: Input, output: Output, connection_role: ConnectionRole) -> Self {
        // TODO: handle languages
        Builder {
            version_info: None,
            available_algorithms: Default::default(),
            input,
            output,
            connection_role,
            padding_length_distribution: None,
            rng: None,
            allow_none_algorithms: false,
        }
    }

    /// Adds a new algorithm to the builder.
    fn add_algorithm<A, P, V>(
        mut self,
        validation_fn: V,
        algorithm: A,
        push_fn: P,
    ) -> Result<Self, (Self, InvalidAlgorithmError)>
    where
        V: FnOnce(&A) -> Result<(), InvalidAlgorithmError>,
        P: FnOnce(&mut Self, Box<A>),
    {
        match validation_fn(&algorithm) {
            Ok(()) => {
                push_fn(&mut self, Box::new(algorithm));

                Ok(self)
            }
            Err(err) => Err((self, err)),
        }
    }

    /// Clears all algorithms from the builder.
    ///
    /// Note that this also clears the "none" algorithms used during the connection setup.
    /// These need to be provided to be able to form a connection.
    ///
    /// An implementation of these can be found in the `russh-algorithms` crate.
    pub fn clear_algorithms(mut self) -> Self {
        self.available_algorithms.clear();

        self
    }

    /// Adds a new key exchange algorithm.
    pub fn add_key_exchange_algorithm<A: KeyExchangeAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| builder.available_algorithms.kex.insert(0, a),
        )
    }

    /// Adds a new host key algorithm.
    pub fn add_host_key_algorithm<A: HostKeyAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| builder.available_algorithms.host_key.insert(0, a),
        )
    }

    /// Adds a new encryption algorithm.
    pub fn add_encryption_algorithm<A: EncryptionAlgorithm + Clone + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .encryption_client_to_server
                    .insert(0, a.clone());
                builder
                    .available_algorithms
                    .encryption_server_to_client
                    .insert(0, a);
            },
        )
    }

    /// Adds a new encryption algorithm for client to server communication.
    pub fn add_encryption_algorithm_client_to_server<A: EncryptionAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .encryption_client_to_server
                    .insert(0, a)
            },
        )
    }

    /// Adds a new encryption algorithm for server to client communication.
    pub fn add_encryption_algorithm_server_to_client<A: EncryptionAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .encryption_server_to_client
                    .insert(0, a)
            },
        )
    }

    /// Adds a new MAC algorithm.
    pub fn add_mac_algorithm<A: MacAlgorithm + Clone + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .mac_client_to_server
                    .insert(0, a.clone());
                builder
                    .available_algorithms
                    .mac_server_to_client
                    .insert(0, a);
            },
        )
    }

    /// Adds a new MAC algorithm for client to server communication.
    pub fn add_mac_algorithm_client_to_server<A: MacAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .mac_client_to_server
                    .insert(0, a)
            },
        )
    }

    /// Adds a new MAC algorithm for server to client communication.
    pub fn add_mac_algorithm_server_to_client<A: MacAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .mac_server_to_client
                    .insert(0, a)
            },
        )
    }

    /// Adds a new compression algorithm.
    pub fn add_compression_algorithm<A: CompressionAlgorithm + Clone + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .compression_client_to_server
                    .insert(0, a.clone());
                builder
                    .available_algorithms
                    .compression_server_to_client
                    .insert(0, a);
            },
        )
    }

    /// Adds a new compression algorithm for client to server communication.
    pub fn add_compression_algorithm_client_to_server<A: CompressionAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .compression_client_to_server
                    .insert(0, a)
            },
        )
    }

    /// Adds a new compression algorithm for server to client communication.
    pub fn add_compression_algorithm_server_to_client<A: CompressionAlgorithm + 'static>(
        self,
        algorithm: A,
    ) -> Result<Self, (Self, InvalidAlgorithmError)> {
        self.add_algorithm(
            |a| algorithms::helpers::is_valid_algorithm(a),
            algorithm,
            |builder, a| {
                builder
                    .available_algorithms
                    .compression_server_to_client
                    .insert(0, a)
            },
        )
    }

    /// Loads a host key for the given algorithm.
    ///
    /// # Panics
    /// May panic if called again for the same algorithm after a successful call.
    pub fn load_host_key(mut self, algorithm: &str, key: &[u8]) -> Result<Self, LoadHostKeyError> {
        self.available_algorithms.load_host_key(algorithm, key)?;

        Ok(self)
    }

    /// Sets the distribution for random padding lengths.
    ///
    /// Note that the returned value of the function should be the number of "padding blocks",
    /// which consist of a number of bytes equal to the cipher block size or 8,
    /// whichever is higher.
    ///
    /// It is also advised to use the
    /// [`MAX_EXTRA_PADDING_BLOCKS`](/constants/const.MAX_EXTRA_PADDING_BLOCKS) constant in the
    /// distribution function to determine the maximum value.
    /// If a number greater than the permissible number of extra blocks is returned, the maximum
    /// permissible number will be used.
    pub fn padding_length_distribution<D: FnMut(&mut dyn RngCore) -> u8 + 'static>(
        self,
        dist: D,
    ) -> Self {
        Builder {
            padding_length_distribution: Some(Box::new(dist)),
            ..self
        }
    }

    /// Sets the random number generator.
    pub fn rng<NewRng: RngCore + CryptoRng + 'static>(self, rng: NewRng) -> Builder<Input, Output> {
        Builder {
            rng: Some(Box::new(rng)),
            ..self
        }
    }

    /// Sets if `none` MAC and encryption algorithms should be allowed.
    ///
    /// They are disabled by default and it is strongly encouraged to keep them disabled.
    pub fn allow_none_algorithms(self, allow: bool) -> Self {
        Builder {
            allow_none_algorithms: allow,
            ..self
        }
    }

    /// Creates an `Handler` from the configured builder.
    pub async fn build(self) -> Result<Handler<Input, Output>, BuildError> {
        self.available_algorithms
            .all_algorithms_valid()
            .map_err(|err| BuildError::InvalidAlgorithm(err))?;

        if let Some(role) = self.available_algorithms.empty_algorithm_role() {
            return Err(BuildError::EmptyAlgorithmRole(role));
        }

        if let Some(role) = self.available_algorithms.required_none_missing() {
            return Err(BuildError::RequiredNoneAlgorithmMissing(role));
        }

        let runtime_state = RuntimeState::new(
            self.version_info.unwrap_or_default(),
            self.available_algorithms,
            self.connection_role,
            self.rng.unwrap_or_else(|| Box::new(StdRng::from_entropy())),
            self.allow_none_algorithms,
        );

        ProtocolHandler::new(
            runtime_state,
            InputHandler::new(self.input),
            OutputHandler::new(self.output, self.padding_length_distribution),
        )
        .await
        .map_err(|err| BuildError::Initialization(err))
        .map(|protocol_handler| Handler { protocol_handler })
    }
}

// TODO: Uncomment tests
/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_builder_works() {
        assert!(Builder::new().build().is_ok());
    }
}
*/
