//! Implements a handler to output to the partner.

use std::{borrow::Cow, fmt, io};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    algorithms::PacketAlgorithms,
    padding_length::{self, PaddingLengthDistribution},
    version::VersionInformation,
    writer::WriterOutputStream,
    CryptoRngCore,
};

/// A trait to represent the input to the SSH transport layer.
pub trait OutputStream: AsyncWrite + Unpin {}

impl<T: AsyncWrite + Unpin> OutputStream for T {}

/// Handles all the output to the partner of the communication.
pub(crate) struct OutputHandler {
    /// The writer where packets are prepared for sending.
    packet_writer: WriterOutputStream,
    /// The number of packets that have been sent (modulo 32 bits).
    sequence_number: u32,
    /// The padding length distribution to be used.
    padding_length_distribution: Box<PaddingLengthDistribution>,
}

impl fmt::Debug for OutputHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OutputHandler")
            .field("packet_writer", &self.packet_writer)
            .field("sequence_number", &self.sequence_number)
            .field("padding_length_distribution", &"opaque function")
            .finish()
    }
}

impl OutputHandler {
    /// Creates a new handler for output.
    pub(crate) fn new(
        padding_length_distribution: Option<Box<PaddingLengthDistribution>>,
    ) -> OutputHandler {
        OutputHandler {
            packet_writer: WriterOutputStream::new(),
            sequence_number: 0,
            padding_length_distribution: padding_length_distribution
                .unwrap_or_else(|| padding_length::default_distribution()),
        }
    }

    /// Initializes the output by writing the initialization string.
    pub(crate) fn initialize(&mut self, version_info: &VersionInformation) {
        self.packet_writer.write_version_info(version_info);
    }

    /// Sends a packet to the output.
    ///
    /// # Panics
    /// This function may panic, if the total length of the packet does not fit into a `u32`.
    pub(crate) fn write_packet(
        &mut self,
        payload: &[u8],
        algorithms: PacketAlgorithms,
        rng: &mut dyn CryptoRngCore,
    ) {
        let compressed = algorithms.compression.compress(Cow::Borrowed(payload));

        self.packet_writer.write_packet(
            &compressed,
            algorithms.encryption,
            algorithms.mac,
            self.sequence_number,
            rng,
            &mut *self.padding_length_distribution,
        );

        self.sequence_number = self.sequence_number.wrapping_add(1);
    }

    /// Flushes the buffered data to the given output stream.
    pub(crate) async fn flush_into<O: OutputStream>(&mut self, output: &mut O) -> io::Result<()> {
        let buf = self.packet_writer.written_data();

        if !buf.is_empty() {
            output.write_all(buf).await?;

            let len = buf.len();
            self.packet_writer.remove_to(len);
        }

        output.flush().await
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        algorithms::ConnectionAlgorithms,
        input::InputBuffer,
        test_helpers::{FakeNetworkInput, FakeNetworkOutput},
        ConnectionRole,
    };

    #[test]
    fn write_packet_none() {
        let mut fake_output = FakeNetworkOutput::new(1);

        let mut output_handler = OutputHandler::new(None);
        let mut rng = Box::new(ChaCha20Rng::from_seed(Default::default()));
        let version_info = VersionInformation::new("test").unwrap();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            output_handler.initialize(&version_info);

            output_handler.write_packet(
                b"this is an important message",
                outgoing_algorithms!(connection_algorithms, ConnectionRole::Client),
                &mut rng,
            );

            assert!(matches!(
                output_handler.flush_into(&mut fake_output).await,
                Ok(())
            ));
        });

        assert_eq!(fake_output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x24\x07this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d"[..]);

        futures::executor::block_on(async {
            output_handler.write_packet(
                b"one more message",
                outgoing_algorithms!(connection_algorithms, ConnectionRole::Client),
                &mut rng,
            );

            assert!(matches!(
                output_handler.flush_into(&mut fake_output).await,
                Ok(())
            ));
        });

        assert_eq!(fake_output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x24\x07this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\x00\x00\x00\x1c\x0bone more message\xc3\x87\xb6\x69\xb2\xee\x65\x86\x9f\x07\xe7"[..]);
    }

    #[test]
    fn write_then_parse() {
        let mut fake_output = FakeNetworkOutput::new(1);

        let mut output_handler = OutputHandler::new(None);
        let mut rng = Box::new(ChaCha20Rng::from_seed(Default::default()));
        let version_info = VersionInformation::new("test").unwrap();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        let message = b"this is an important message";

        futures::executor::block_on(async {
            output_handler.initialize(&version_info);

            assert!(matches!(
                output_handler.flush_into(&mut fake_output).await,
                Ok(())
            ));

            output_handler.write_packet(
                message,
                outgoing_algorithms!(connection_algorithms, ConnectionRole::Client),
                &mut rng,
            );
            assert!(matches!(
                output_handler.flush_into(&mut fake_output).await,
                Ok(())
            ));
        });

        let written_bytes = fake_output.written().len();
        let mut fake_input = FakeNetworkInput::new(fake_output.written().to_owned(), written_bytes);

        let mut input_buffer = InputBuffer::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            assert_eq!(
                input_buffer.read_more_data(&mut fake_input).await.unwrap(),
                written_bytes
            );
            assert_eq!(
                input_buffer.parse_initialization().unwrap().unwrap(),
                (
                    VersionInformation::new("test").unwrap(),
                    b"SSH-2.0-test".to_vec()
                )
            );

            assert_eq!(
                input_buffer
                    .read_packet(incoming_algorithms!(
                        connection_algorithms,
                        ConnectionRole::Server
                    ))
                    .unwrap()
                    .unwrap(),
                message.to_vec()
            );

            assert!(matches!(
                input_buffer.read_packet(incoming_algorithms!(
                    connection_algorithms,
                    ConnectionRole::Server
                )),
                Ok(None)
            ));
        });
    }
}
