//! Defines all the errors that can occur in the transport layer.

pub use definitions::{
    algorithms::{AlgorithmCategory, AlgorithmRole, InvalidMacError, KeyExchangeAlgorithmError},
    ParseError,
};

use std::{error::Error, io};

use crate::version::VersionInformation;

/// There was an error during communication.
#[derive(Debug, thiserror::Error)]
pub enum CommunicationError {
    /// The input reached its end.
    ///
    /// No more packets will be received after this error.
    #[error("end of input reached")]
    EndOfInput,
    /// There was an IO error while sending or receiving a packet.
    #[error("an io error occured: {0}")]
    Io(#[from] io::Error),
    /// There was an error parsing an incoming packet.
    #[error("an incoming packet was invalid: {0}")]
    InvalidIncomingPacket(Box<dyn Error>),
    /// A received packet had an invalid format.
    #[error("a packet had an invalid format")]
    InvalidFormat,
    /// A received packet had an invalid padding.
    #[error("a packet had an invalid padding")]
    InvalidPadding,
    /// The MAC on a received packet was invalid.
    #[error("a received MAC was invalid: {0}")]
    InvalidMac(#[from] InvalidMacError),
    /// A received packet could not be decompressed successfully.
    #[error("decompression unsuccessful: {0}")]
    InvalidCompression(Box<dyn Error>),
    /// A protocol internal packet was sent by user code.
    ///
    /// All protocol internal packets are handled by the
    /// `SSHTransportHandler`.
    ///
    /// If you wish to handle these yourself, you could try forking
    /// this library and modifying the handler code.
    #[error("you tried to send a transport layer packet, which is not supported")]
    ProtocolInternalPacketSent,
}

/// There was an error during initialization.
#[derive(Debug, thiserror::Error)]
pub enum InitializationError {
    /// There was an error while sending or receiving a packet during initialization.
    #[error("a communication error occurred: {0}")]
    Communication(#[from] CommunicationError),
    /// The protocol version used by the connection partner is unsupported.
    #[error("the ssh version used by the other party (`{0}`) is not supported")]
    UnsupportedProtocolVersion(VersionInformation),
    /// There was an error during the initial key exchange.
    ///
    /// # Note
    /// `CommunicationError`s that occur during the initial key exchange are reported
    /// as `InitializationError::Communication(_)` instead of
    /// `InitializationError::KeyExchange(KeyExchangeProcedureError::Communication(_))`.
    #[error("key exchange unsuccessful: {0}")]
    KeyExchange(KeyExchangeProcedureError),
}

impl From<IncomingPacketError> for InitializationError {
    fn from(err: IncomingPacketError) -> Self {
        InitializationError::Communication(CommunicationError::InvalidIncomingPacket(Box::new(err)))
    }
}

/// There was an error during the key exchange procedure.
#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeProcedureError {
    /// There was an error while sending or receiving a packet during key exchange.
    #[error("a communication error occurred: {0}")]
    Communication(#[from] CommunicationError),
    /// No algorithm was found for the given algorithm role.
    #[error("{0}: no suitable algorithm found")]
    NoAlgorithmFound(AlgorithmRole),
    /// There was an error while performing the key exchange algorithm.
    #[error("{0}")]
    KeyExchangeAlgorithmError(KeyExchangeAlgorithmError),
    /// A non key exchange related packet was received in the wrong moment.
    #[error("non key exchange packet received during key exchange")]
    NonKeyExchangePacketReceived,
    /// No `SSH_MSG_NEWKEYS` was received, when it was required.
    #[error("the other party did not acknowledge the key exchange")]
    NoNewkeysPacket,
}

impl From<IncomingPacketError> for KeyExchangeProcedureError {
    fn from(err: IncomingPacketError) -> Self {
        KeyExchangeProcedureError::Communication(CommunicationError::InvalidIncomingPacket(
            Box::new(err),
        ))
    }
}

/// There was an error while loading a host key.
#[derive(Debug, thiserror::Error)]
pub enum LoadHostKeyError {
    /// There was an error while loading the keys into the algorithm.
    ///
    /// This is most likely due to an invalid host key.
    #[error("host keys could not be loaded: {0}")]
    AlgorithmError(Box<dyn Error>),
    /// The algorithm for which the keys should be loaded could not be found.
    #[error("host key algorithm could not be found: {0}")]
    AlgorithmNotFound(String),
}

/// Describes the errors that can occur while building an SSHTransportHandler.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The given algorithm category had no algorithms in it.
    #[error("{0}: no algorithm found")]
    EmptyAlgorithmRole(AlgorithmRole),
    /// The given algorithm category requires a "none" algorithm, but none was given.
    #[error("{0}: no  \"none\" algorithm found")]
    RequiredNoneAlgorithmMissing(AlgorithmRole),
    /// There was an error during the initialization of the connection.
    #[error("error initializing the connection: {0}")]
    Initialization(InitializationError),
}

/// Describes the errors that can occur while requesting a service.
#[derive(Debug, thiserror::Error)]
pub enum ServiceRequestError {
    /// There was an error while sending or receiving a packet during the sevice request.
    #[error("a communication error occurred: {0}")]
    Communication(#[from] CommunicationError),
    /// A packet was sent with an invalid format.
    #[error("the service request reply packet had an invalid format")]
    InvalidFormat,
    /// A service other than the requested one was accepted.
    #[error("a service other than the requested one was accepted: {0:?}")]
    WrongServiceAccepted(Vec<u8>),
}

impl From<IncomingPacketError> for ServiceRequestError {
    fn from(err: IncomingPacketError) -> Self {
        ServiceRequestError::Communication(CommunicationError::InvalidIncomingPacket(Box::new(err)))
    }
}

/// The software version was illegal according to the specification.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IllegalVersionError {
    /// The proposed version contained a non-ascii character.
    #[error("the version can only contain ascii characters")]
    NonAscii(usize),
    /// The proposed version contained a whitespace character.
    #[error("the version cannot contain whitespace characters")]
    Whitespace(usize),
    /// The proposed version contained a non printable character.
    #[error("the version can only contain printable characters")]
    NonPrintable(usize),
    /// The proposed version contained the `'-'` character.
    #[error("the version cannot contain the '-' character")]
    Minus(usize),
}

/// Contains the reason why an algorithm name is invalid.
#[derive(Debug, PartialEq, Eq, Clone, thiserror::Error)]
pub enum InvalidNameError {
    /// The name was empty.
    #[error("algorithm name was empty")]
    EmptyName,
    /// The name was too long.
    #[error("algorithm name was too long")]
    TooLong,
    /// The name contained more than one `'@'` character.
    #[error("algorithm name contained too many '@' symbols")]
    TooManyAtSymbols,
    /// The name contained a comma.
    #[error("algorithm name contained the ',' character")]
    CommaUsed,
    /// The name contained the given non ascii character.
    #[error("algorithm name contained a non ascii character: {0:?}")]
    NonAscii(char),
    /// The name contained the given whitespace character.
    #[error("algorithm name contained a whitespace character")]
    Whitespace(char),
    /// The name contained the given non printable character.
    #[error("algorithm name contained a non printable character")]
    NonPrintable(char),
    /// The domain in the algorithm name is not a valid domain.
    #[error("algorithm name contained an invalid domain")]
    InvalidDomain,
}

/// Describes the reasons why an incoming packet could be invalid.
#[derive(Debug, thiserror::Error)]
pub(crate) enum IncomingPacketError {
    /// The packet could not be parsed.
    #[error("the packet doesn't have a valid format")]
    Format,
    /// The packet had invalid padding.
    #[error("the packet has an invalid amount of padding")]
    Padding,
    /// The packet had an invalid MAC.
    #[error("the packet had an invalid MAC: {0}")]
    Mac(InvalidMacError),
    /// The packet could not be decompressed.
    #[error("the packet could not be decompressed: {0}")]
    Compression(Box<dyn Error>),
}
