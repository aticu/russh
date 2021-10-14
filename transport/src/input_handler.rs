//! Implements a handler for input from the partner.

use std::{borrow::Cow, cmp::max};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    algorithms::PacketAlgorithms,
    constants::READ_SIZE,
    errors::{CommunicationError, ParseError, ParseIncomingPacketError},
    parser::ParserInputStream,
    version::VersionInformation,
};

/// A trait to represent the input to the SSH transport layer.
pub trait InputStream: AsyncRead + Unpin {}

impl<T: AsyncRead + Unpin> InputStream for T {}

/// Handles all the input from the partner of the communication.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InputHandler {
    /// The parser of the input handler.
    packet_parser: ParserInputStream,
    /// The number of packets that have arrived (modulo 32 bits).
    sequence_number: u32,
}

impl InputHandler {
    /// Creates a new handler for all input from the partner of the communication.
    pub(crate) fn new() -> InputHandler {
        InputHandler {
            packet_parser: ParserInputStream::new(),
            sequence_number: 0,
        }
    }

    /// Reads more data from the source and passes it to the parser.
    pub(crate) async fn read_more_data<I: InputStream>(
        &mut self,
        input: &mut I,
    ) -> Result<usize, CommunicationError> {
        let buf = self.packet_parser.reserve(READ_SIZE);

        let size = input.read(buf).await.map_err(CommunicationError::Io)?;

        if size == 0 {
            return Err(CommunicationError::EndOfInput);
        }

        self.packet_parser.indicate_used(size);

        Ok(size)
    }

    /// Initializes the input stream by reading the initialization string.
    ///
    /// If the buffer does not contain all of the initialization, `Ok(None)` is returned.
    pub(crate) fn initialize(
        &mut self,
    ) -> Result<Option<(VersionInformation, Vec<u8>)>, CommunicationError> {
        match self.packet_parser.parse_initialization() {
            Ok(res) => {
                self.packet_parser.remove_old_data();

                Ok(Some(res))
            }
            Err(ParseIncomingPacketError::ParseError(ParseError::Incomplete)) => Ok(None),
            Err(ParseIncomingPacketError::ParseError(ParseError::Invalid)) => {
                Err(CommunicationError::InvalidFormat)
            }
            Err(ParseIncomingPacketError::InvalidMac(_)) => unreachable!(),
        }
    }

    /// Reads the next packet from the buffer and returns it.
    ///
    /// If the buffer does not contain all of the next input packet, `Ok(None)` is returned.
    pub(crate) fn read_packet(
        &mut self,
        algorithms: PacketAlgorithms<'_>,
    ) -> Result<Option<Cow<'_, [u8]>>, CommunicationError> {
        self.packet_parser.remove_old_data();

        let mac_len = algorithms
            .mac
            .as_ref()
            .map(|alg| alg.mac_size)
            .unwrap_or_else(|| {
                algorithms.encryption.mac_size.expect(
                    "encryption algorithm is authenticated when no MAC algorithm is present",
                )
            });

        if !self
            .packet_parser
            .is_packet_ready(algorithms.encryption, mac_len, self.sequence_number)
            .map_err(|err| match err {
                ParseIncomingPacketError::InvalidMac(err) => CommunicationError::InvalidMac(err),
                _ => unreachable!(),
            })?
        {
            return Ok(None);
        }

        let packet = match self.packet_parser.parse_packet(
            algorithms.encryption,
            algorithms.mac,
            mac_len,
            self.sequence_number,
        ) {
            Ok(parsed_packet) => Ok(parsed_packet),
            Err(ParseIncomingPacketError::ParseError(ParseError::Invalid)) => {
                Err(CommunicationError::InvalidFormat)
            }
            Err(ParseIncomingPacketError::InvalidMac(err)) => {
                Err(CommunicationError::InvalidMac(err))
            }
            Err(ParseIncomingPacketError::ParseError(ParseError::Incomplete)) => unreachable!(),
        }?;

        self.sequence_number = self.sequence_number.wrapping_add(1);

        // TODO: implement ETM MAC algorithms
        // if implemented, add this to the check here
        let len_modifier = if algorithms.encryption.computes_mac() {
            4
        } else {
            0
        };
        if (packet.whole_packet.len() - len_modifier)
            % max(algorithms.encryption.cipher_block_size, 8)
            != 0
        {
            return Err(CommunicationError::InvalidPadding);
        }

        algorithms
            .compression
            .decompress(Cow::Borrowed(packet.payload))
            .map(Some)
            .map_err(|err| CommunicationError::InvalidCompression(err))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use sha2::digest::Digest;

    use super::*;
    use crate::{
        algorithms::{ChosenAlgorithms, ConnectionAlgorithms},
        test_helpers::FakeNetworkInput,
        ConnectionRole,
    };

    #[test]
    fn next_packet_encrypted() {
        let packet_data = b"SSH-2.0-test@1.0\r\n\x5c\xd0\x42\x56\x97\x03\x81\x0b\xd3\x11\x81\xa1\x2c\x6e\xe3\xb5\x54\x85\xfe\x4e\x5b\x3e\x02\xc1\x32\x26\x6c\xe8\xf0\xae\x85\xc3\xa3\xa4\xb7\xb1\xc3\x4e\xed\x4e\x93\x73\xa4\x03\x49\x7e\xd2\x69\x33\x6d\xa7\xd3\x6a\xd4\xba\x57\x9c\xc3\xa3\x30\x7f\xd9\x33\xbc\xf5\xbd\x41\x8e\xc3\x4d\xbe\x5b\xf5\xb2\x7f\xe3\x0f\xdb\x95\x9f\xa1\x2f\x58\x68\xa6\x0e\xa0\x85\x6d\x27\x7f\x5e\xbc\x5d\x58\x94".to_vec();
        // use the payload:
        // b"\x00\x00\x00\x1c\x10testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10\x12\xa8\x5b\x0e\x78\x50\x35\x00";
        let packet_len = packet_data.len();

        let mut fake_input = FakeNetworkInput::new(packet_data, packet_len);

        let mut input_handler = InputHandler::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        let chosen_algorithms = ChosenAlgorithms {
            encryption_c2s: "none",
            encryption_s2c: "aes128-ctr",
            mac_c2s: Some("none"),
            mac_s2c: Some("hmac-sha2-512"),
            compression_c2s: "none",
            compression_s2c: "none",
        };

        connection_algorithms.unload_algorithm_keys();
        connection_algorithms.load_algorithm_keys(
            &chosen_algorithms,
            |message| sha2::Sha256::digest(message).to_vec(),
            &BigInt::from_signed_bytes_be(&[0x42; 16][..]),
            &[0x11; 16][..],
            &[0x11; 16][..],
        );

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.read_more_data(&mut fake_input).await.unwrap(),
                packet_len
            );
            assert_eq!(
                input_handler.initialize().unwrap().unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert_eq!(
                input_handler
                    .read_packet(incoming_algorithms!(
                        connection_algorithms,
                        ConnectionRole::Client
                    ))
                    .unwrap()
                    .unwrap(),
                b"testpayload".to_vec()
            );

            assert!(matches!(
                input_handler.read_packet(incoming_algorithms!(
                    connection_algorithms,
                    ConnectionRole::Client
                )),
                Ok(None)
            ));
        });
    }

    #[test]
    fn next_packet_success() {
        let packet_data = b"SSH is a protocol\r\nSSH-2.0-test@1.0\r\n\x00\x00\x00\x14\x08testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10\x00\x00\x00\x14\x08othertester\x74\xaf\xf9\x04\x7e\x39\x92\x11".to_vec();
        let packet_len = packet_data.len();

        let mut fake_input = FakeNetworkInput::new(packet_data, packet_len);

        let mut input_handler = InputHandler::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.read_more_data(&mut fake_input).await.unwrap(),
                packet_len
            );
            assert_eq!(
                input_handler.initialize().unwrap().unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert_eq!(
                input_handler
                    .read_packet(incoming_algorithms!(
                        connection_algorithms,
                        ConnectionRole::Client
                    ))
                    .unwrap()
                    .unwrap(),
                b"testpayload".to_vec()
            );

            assert_eq!(
                input_handler
                    .read_packet(incoming_algorithms!(
                        connection_algorithms,
                        ConnectionRole::Client
                    ))
                    .unwrap()
                    .unwrap(),
                b"othertester".to_vec()
            );

            assert!(matches!(
                input_handler.read_packet(incoming_algorithms!(
                    connection_algorithms,
                    ConnectionRole::Client
                )),
                Ok(None)
            ));
        });
    }

    #[test]
    fn next_packet_failure() {
        let packet_data =
            b"SSH is a protocol\r\nSSH-2.0-test@1.0\r\n\x00\x00\x00\x0e\x02testpayload\x73\xae"
                .to_vec();
        let packet_len = packet_data.len();

        let mut fake_input = FakeNetworkInput::new(packet_data, packet_len);

        let mut input_handler = InputHandler::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.read_more_data(&mut fake_input).await.unwrap(),
                packet_len
            );
            assert_eq!(
                input_handler.initialize().unwrap().unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert!(matches!(
                input_handler.read_packet(incoming_algorithms!(
                    connection_algorithms,
                    ConnectionRole::Client
                )),
                Err(CommunicationError::InvalidFormat)
            ));
        });
    }
}
