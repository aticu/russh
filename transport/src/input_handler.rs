//! Implements a handler for input from the partner.

use std::{borrow::Cow, cmp::max};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    constants::READ_SIZE,
    errors::{CommunicationError, ParseError, ParseIncomingPacketError},
    parser::ParserInputStream,
    runtime_state::RuntimeState,
    version::VersionInformation,
};

/// A trait to represent the input to the SSH transport layer.
pub trait InputStream: AsyncRead + Unpin {}

impl<T: AsyncRead + Unpin> InputStream for T {}

/// Handles all the input from the partner of the communication.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InputHandler<Input: InputStream> {
    /// The parser of the input handler.
    packet_parser: ParserInputStream,
    /// The source where the data originates.
    input: Input,
    /// The number of packets that have arrived (modulo 32 bits).
    sequence_number: u32,
}

impl<Input: InputStream> InputHandler<Input> {
    /// Creates a new handler for all input from the partner of the communication.
    pub(crate) fn new(input: Input) -> InputHandler<Input> {
        InputHandler {
            packet_parser: ParserInputStream::new(),
            input,
            sequence_number: 0,
        }
    }

    /// Reads more data from the source and passes it to the parser.
    async fn read_more_data(&mut self) -> Result<usize, CommunicationError> {
        let buf = self.packet_parser.reserve(READ_SIZE);

        let size = self
            .input
            .read(buf)
            .await
            .map_err(|err| CommunicationError::Io(err))?;

        if size == 0 {
            return Err(CommunicationError::EndOfInput);
        }

        self.packet_parser.indicate_used(size);

        Ok(size)
    }

    /// Initializes the input stream by reading the initialization string.
    pub(crate) async fn initialize(
        &mut self,
    ) -> Result<(VersionInformation, Vec<u8>), CommunicationError> {
        loop {
            match self.packet_parser.parse_initialization() {
                Ok(res) => {
                    self.packet_parser.remove_old_data();

                    break Ok(res);
                }
                Err(ParseIncomingPacketError::ParseError(ParseError::Incomplete)) => {
                    self.read_more_data().await?;

                    continue;
                }
                Err(ParseIncomingPacketError::ParseError(ParseError::Invalid)) => {
                    break Err(CommunicationError::InvalidFormat)
                }
                Err(ParseIncomingPacketError::InvalidMac) => unreachable!(),
            }
        }
    }

    /// Reads the next packet from the input and returns it.
    ///
    /// # Note
    /// This will probably fail if `self.initialize` was not called previously.
    pub(crate) async fn next_packet<'a>(
        &'a mut self,
        runtime_state: &mut RuntimeState,
    ) -> Result<Cow<'a, [u8]>, CommunicationError> {
        self.packet_parser.remove_old_data();

        let algorithms = runtime_state.input_algorithms();
        let mac_len = algorithms
            .mac
            .as_ref()
            .map(|alg| alg.mac_size())
            .unwrap_or_else(|| {
                algorithms.encryption.mac_size().expect(
                    "encryption algorithm is authenticated when no MAC algorithm is present",
                )
            });

        while !self
            .packet_parser
            .is_packet_ready(algorithms.encryption, mac_len, self.sequence_number)
            .map_err(|err| match err {
                ParseIncomingPacketError::InvalidMac => CommunicationError::InvalidMac,
                _ => unreachable!(),
            })?
        {
            self.read_more_data().await?;
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
            Err(ParseIncomingPacketError::InvalidMac) => Err(CommunicationError::InvalidMac),
            Err(ParseIncomingPacketError::ParseError(ParseError::Incomplete)) => unreachable!(),
        }?;

        self.sequence_number = self.sequence_number.wrapping_add(1);

        // TODO: implement ETM MAC algorithms
        // if implemented, add this to the check here
        let packet_len_counts_to_padding = algorithms.encryption.mac_size().is_some();
        let len_modifier = if packet_len_counts_to_padding { 4 } else { 0 };
        if (packet.whole_packet.len() - len_modifier)
            % max(algorithms.encryption.cipher_block_size(), 8)
            != 0
        {
            return Err(CommunicationError::InvalidPadding);
        }

        algorithms
            .compression
            .decompress(Cow::Borrowed(packet.payload))
            .map_err(|err| CommunicationError::InvalidCompression(err))
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::digest::Digest;

    use super::*;
    use crate::{
        algorithms::{AvailableAlgorithms, ChosenAlgorithms},
        runtime_state::RuntimeState,
        test_helpers::FakeNetworkInput,
        ConnectionRole,
    };

    #[test]
    fn next_packet_encrypted() {
        let packet_data = b"SSH-2.0-test@1.0\r\n\x5c\xd0\x42\x56\x97\x03\x81\x0b\xd3\x11\x81\xa1\x2c\x6e\xe3\xb5\x54\x85\xfe\x4e\x5b\x3e\x02\xc1\x32\x26\x6c\xe8\xf0\xae\x85\xc3\xa3\xa4\xb7\xb1\xc3\x4e\xed\x4e\x93\x73\xa4\x03\x49\x7e\xd2\x69\x33\x6d\xa7\xd3\x6a\xd4\xba\x57\x9c\xc3\xa3\x30\x7f\xd9\x33\xbc\xf5\xbd\x41\x8e\xc3\x4d\xbe\x5b\xf5\xb2\x7f\xe3\x0f\xdb\x95\x9f\xa1\x2f\x58\x68\xa6\x0e\xa0\x85\x6d\x27\x7f\x5e\xbc\x5d\x58\x94".to_vec();
        // use the payload:
        // b"\x00\x00\x00\x1c\x10testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10\x12\xa8\x5b\x0e\x78\x50\x35\x00";

        let fake_input = FakeNetworkInput::new(packet_data, 1);

        let mut input_handler = InputHandler::new(fake_input);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::new("test").unwrap(),
            AvailableAlgorithms::default(),
            ConnectionRole::Client,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        let chosen_algorithms = ChosenAlgorithms {
            encryption_c2s: "none",
            encryption_s2c: "aes128-ctr",
            mac_c2s: Some("none"),
            mac_s2c: Some("hmac-sha2-512"),
            compression_c2s: "none",
            compression_s2c: "none",
        };

        runtime_state.change_algorithms(
            chosen_algorithms,
            |message| sha2::Sha256::digest(message).to_vec(),
            &BigInt::from_signed_bytes_be(&[0x42; 16][..]),
            &[0x11; 16][..],
            &[0x11; 16][..],
        );

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.initialize().await.unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert_eq!(
                input_handler
                    .next_packet(&mut runtime_state)
                    .await
                    .expect("packet exists"),
                b"testpayload".to_vec()
            );

            assert!(matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            ));
        });
    }

    #[test]
    fn next_packet_success() {
        let packet_data = b"SSH is a protocol\r\nSSH-2.0-test@1.0\r\n\x00\x00\x00\x14\x08testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10\x00\x00\x00\x14\x08othertester\x74\xaf\xf9\x04\x7e\x39\x92\x11".to_vec();

        let fake_input = FakeNetworkInput::new(packet_data, 1);

        let mut input_handler = InputHandler::new(fake_input);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::new("test").unwrap(),
            AvailableAlgorithms::default(),
            ConnectionRole::Client,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.initialize().await.unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert_eq!(
                input_handler
                    .next_packet(&mut runtime_state)
                    .await
                    .expect("packet exists"),
                b"testpayload".to_vec()
            );

            assert_eq!(
                input_handler
                    .next_packet(&mut runtime_state)
                    .await
                    .expect("packet exists"),
                b"othertester".to_vec()
            );

            assert!(matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            ));
        });
    }

    #[test]
    fn next_packet_failure() {
        let packet_data =
            b"SSH is a protocol\r\nSSH-2.0-test@1.0\r\n\x00\x00\x00\x0e\x02testpayload\x73\xae"
                .to_vec();

        let fake_input = FakeNetworkInput::new(packet_data, 8);

        let mut input_handler = InputHandler::new(fake_input);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::default(),
            AvailableAlgorithms::default(),
            ConnectionRole::Client,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.initialize().await.unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert!(matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::InvalidFormat)
            ));
        });
    }
}
