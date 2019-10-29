//! Implements a handler for input from the partner.

use std::{borrow::Cow, cmp::max};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    algorithms::PacketAlgorithms,
    constants::READ_SIZE,
    errors::{CommunicationError, ParseError},
    parser::{ParsedPacket, ParserInputStream},
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
                Err(ParseError::Incomplete) => {
                    self.read_more_data().await?;

                    continue;
                }
                Err(ParseError::Invalid) => break Err(CommunicationError::InvalidFormat),
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

        let mut algorithms = runtime_state.input_algorithms();
        let mac_len = algorithms.mac.mac_size();

        while !self
            .packet_parser
            .is_packet_ready(algorithms.encryption, mac_len)
        {
            self.read_more_data().await?;
        }

        let packet = match self
            .packet_parser
            .parse_packet(algorithms.encryption, mac_len)
        {
            Ok(parsed_packet) => Ok(parsed_packet),
            Err(ParseError::Invalid) => Err(CommunicationError::InvalidFormat),
            Err(ParseError::Incomplete) => unreachable!(),
        }?;

        handle_parsed_packet(packet, &mut self.sequence_number, &mut algorithms)
    }
}

/// Handles a parsed packet and
fn handle_parsed_packet<'data>(
    packet: ParsedPacket<'data>,
    sequence_number: &mut u32,
    algorithms: &mut PacketAlgorithms,
) -> Result<Cow<'data, [u8]>, CommunicationError> {
    if packet.whole_packet.len() % max(algorithms.encryption.cipher_block_size(), 8) != 0 {
        return Err(CommunicationError::InvalidFormat);
    }

    if !algorithms
        .mac
        .verify(packet.whole_packet, *sequence_number, packet.mac)
    {
        return Err(CommunicationError::InvalidMac);
    }

    *sequence_number = (*sequence_number).wrapping_add(1);

    algorithms
        .compression
        .decompress(Cow::Borrowed(packet.payload))
        .map_err(|err| CommunicationError::InvalidCompression(err))
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;
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
        let packet_data = b"SSH-2.0-test@1.0\r\n\xdf\xef\xb2\xf9\x9b\x10\x15\x38\x9c\x67\x7a\x97\xd8\xa5\x5b\x7b\x3f\xac\xa4\x26\x5f\xa4\x7b\x15\x8c\xbc\xe4\xb4\xa0\x9d\x7e\x41\x62\xab\x68\x5d\x3c\x3a\x6e\xe0\xcd\x27\x63\x2f\x67\xf1\x6f\x92\xeb\x37\xa3\x48\x77\x55\x08\xd4\x4f\x6e\xe7\xd7\xa5\xda\x0c\x04\xc1\xfb\x49\xab\x18\x06\x8c\xc1\xb2\x86\xc2\x8a\xeb\xda\xbd\x9f\x74\x21\x8e\x97\x33\xd9\x8a\xbf\x77\x61\x83\x58\x42\xad\x2c\x81".to_vec();
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
            encryption_client_to_server: "none",
            encryption_server_to_client: "aes128-ctr",
            mac_client_to_server: "none",
            mac_server_to_client: "hmac-sha2-512",
            compression_client_to_server: "none",
            compression_server_to_client: "none",
        };

        runtime_state.change_algorithms(
            chosen_algorithms,
            |message| sha2::Sha256::digest(message).to_vec(),
            &[0x42; 16][..],
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

            assert_matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            );
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

            assert_matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            );
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

            assert_matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::InvalidFormat)
            );
        });
    }
}
