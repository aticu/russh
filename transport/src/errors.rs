//! Defines all the errors that can occur in the transport layer.

pub use russh_common::{
    algorithms::{AlgorithmCategory, AlgorithmRole, KeyExchangeAlgorithmError},
    parser_primitives::ParseError,
};

use std::{error::Error, io};

use crate::version::VersionInformation;

/// There was an error during communication.
#[derive(Debug, Error)]
pub enum CommunicationError {
    /// The input reached its end.
    ///
    /// No more packets will be received after this error.
    #[error(display = "end of input reached")]
    EndOfInput,
    /// There was an IO error while sending or receiving a packet.
    #[error(display = "an io error occured: {}", _0)]
    Io(io::Error),
    /// A received packet had an invalid format.
    #[error(display = "a packet had an invalid format")]
    InvalidFormat,
    /// The MAC on a received packet was invalid.
    #[error(display = "a received MAC was invalid")]
    InvalidMac,
    /// A received packet could not be decompressed successfully.
    #[error(display = "decompression unsuccessful: {}", _0)]
    InvalidCompression(Box<dyn Error>),
    /// A protocol internal packet was sent by user code.
    ///
    /// All protocol internal packets are handled by the
    /// `SSHTransportHandler`.
    ///
    /// If you wish to handle these yourself, you could try forking
    /// this library and modifying the handler code.
    #[error(display = "you tried to send a transport layer packet, which is not supported")]
    ProtocolInternalPacketSent,
}

/// There was an error during initialization.
#[derive(Debug, Error)]
pub enum InitializationError {
    /// There was an error while sending or receiving a packet during initialization.
    #[error(display = "a communication error occurred: {}", _0)]
    Communication(CommunicationError),
    /// The protocol version used by the connection partner is unsupported.
    #[error(
        display = "the ssh version used by the other party (`{}`) is not supported",
        _0
    )]
    UnsupportedProtocolVersion(VersionInformation),
    /// There was an error during the initial key exchange.
    ///
    /// # Note
    /// `CommunicationError`s that occur during the initial key exchange are reported
    /// as `InitializationError::Communication(_)` instead of
    /// `InitializationError::KeyExchange(KeyExchangeProcedureError::Communication(_))`.
    #[error(display = "key exchange unsuccessful: {}", _0)]
    KeyExchange(KeyExchangeProcedureError),
}

/// There was an error during the key exchange procedure.
#[derive(Debug, Error)]
pub enum KeyExchangeProcedureError {
    /// There was an error while sending or receiving a packet during key exchange.
    #[error(display = "a communication error occurred: {}", _0)]
    Communication(CommunicationError),
    /// No algorithm was found for the given algorithm role.
    #[error(display = "{}: no suitable algorithm found", _0)]
    NoAlgorithmFound(AlgorithmRole),
    /// There was an error while performing the key exchange algorithm.
    #[error(display = "{}", _0)]
    KeyExchangeAlgorithmError(KeyExchangeAlgorithmError),
    /// A non key exchange related packet was received in the wrong moment.
    #[error(display = "non key exchange packet received during key exchange")]
    NonKeyExchangePacketReceived,
    /// No `SSH_MSG_NEWKEYS` was received, when it was required.
    #[error(display = "the other party did not acknowledge the key exchange")]
    NoNewkeysPacket,
}

/// There was an error while loading a host key.
#[derive(Debug, Error)]
pub enum LoadHostKeyError {
    /// There was an error while loading the keys into the algorithm.
    ///
    /// This is most likely due to an invalid host key.
    #[error(display = "host keys could not be loaded: {}", _0)]
    AlgorithmError(Box<dyn Error>),
    /// The algorithm for which the keys should be loaded could not be found.
    #[error(display = "host key algorithm could not be found: {}", _0)]
    AlgorithmNotFound(String),
}

/// Describes the errors that can occur while building an SSHTransportHandler.
#[derive(Debug, Error)]
pub enum BuildError {
    /// The building failed due to an invalid algorithm.
    #[error(display = "invalid algorithm used: {}", _0)]
    InvalidAlgorithm(InvalidAlgorithmError),
    /// The given algorithm category had no algorithms in it.
    #[error(display = "{}: no algorithm found", _0)]
    EmptyAlgorithmRole(AlgorithmRole),
    /// The given algorithm category requires a "none" algorithm, but none was given.
    #[error(display = "{}: no  \"none\" algorithm found", _0)]
    RequiredNoneAlgorithmMissing(AlgorithmRole),
    /// There was an error during the initialization of the connection.
    #[error(display = "error initializing the connection: {}", _0)]
    Initialization(InitializationError),
}

/// Describes the errors that can occur while requesting a service.
#[derive(Debug, Error)]
pub enum ServiceRequestError {
    /// There was an error while sending or receiving a packet during the sevice request.
    #[error(display = "a communication error occurred: {}", _0)]
    Communication(CommunicationError),
    /// A packet was sent with an invalid format.
    #[error(display = "the service request reply packet had an invalid format")]
    InvalidFormat,
    /// A service other than the requested one was accepted.
    #[error(
        display = "a service other than the requested one was accepted: {:?}",
        _0
    )]
    WrongServiceAccepted(Vec<u8>),
}

/// The software version was illegal according to the specification.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum IllegalVersionError {
    /// The proposed version contained a non-ascii character.
    #[error(display = "the version can only contain ascii characters")]
    NonAscii(usize),
    /// The proposed version contained a whitespace character.
    #[error(display = "the version cannot contain whitespace characters")]
    Whitespace(usize),
    /// The proposed version contained a non printable character.
    #[error(display = "the version can only contain printable characters")]
    NonPrintable(usize),
    /// The proposed version contained the `'-'` character.
    #[error(display = "the version cannot contain the '-' character")]
    Minus(usize),
}

/// Contains the reason why an algorithm is invalid.
#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum InvalidAlgorithmError {
    /// The algorithm name is invalid.
    #[error(
        display = "algorithm name {:?} is invalid: {}",
        algorithm_name,
        name_error
    )]
    InvalidName {
        /// The name of the invalid algorithm.
        algorithm_name: String,
        /// The category for which the algorithm is invalid.
        algorithm_category: AlgorithmCategory,
        /// The reason the name is invalid.
        name_error: InvalidNameError,
    },
}

/// Contains the reason why an algorithm name is invalid.
#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum InvalidNameError {
    /// The name was empty.
    #[error(display = "algorithm name was empty")]
    EmptyName,
    /// The name was too long.
    #[error(display = "algorithm name was too long")]
    TooLong,
    /// The name contained more than one `'@'` character.
    #[error(display = "algorithm name contained too many '@' symbols")]
    TooManyAtSymbols,
    /// The name contained a comma.
    #[error(display = "algorithm name contained the ',' character")]
    CommaUsed,
    /// The name contained the given non ascii character.
    #[error(display = "algorithm name contained a non ascii character: {:?}", _0)]
    NonAscii(char),
    /// The name contained the given whitespace character.
    #[error(display = "algorithm name contained a whitespace character")]
    Whitespace(char),
    /// The name contained the given non printable character.
    #[error(display = "algorithm name contained a non printable character")]
    NonPrintable(char),
    /// The domain in the algorithm name is not a valid domain.
    #[error(display = "algorithm name contained an invalid domain")]
    InvalidDomain,
}
