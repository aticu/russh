//! Implements a handler to output to the partner.

use std::{borrow::Cow, fmt, io};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    padding_length::{self, PaddingLengthDistribution},
    runtime_state::RuntimeState,
    version::VersionInformation,
    writer::WriterOutputStream,
};

/// A trait to represent the input to the SSH transport layer.
pub trait OutputStream: AsyncWrite + Unpin {}

impl<T: AsyncWrite + Unpin> OutputStream for T {}

/// Handles all the output to the partner of the communication.
pub(crate) struct OutputHandler<Output: OutputStream> {
    /// The writer where packets are prepared for sending.
    packet_writer: WriterOutputStream,
    /// The output to which packes will be sent.
    output: Output,
    /// The number of packets that have been sent (modulo 32 bits).
    sequence_number: u32,
    /// The padding length distribution to be used.
    padding_length_distribution: Box<PaddingLengthDistribution>,
}

impl<Output: OutputStream + fmt::Debug> fmt::Debug for OutputHandler<Output> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OutputHandler")
            .field("packet_writer", &self.packet_writer)
            .field("output", &self.output)
            .field("sequence_number", &self.sequence_number)
            .field("padding_length_distribution", &"opaque function")
            .finish()
    }
}

impl<Output: OutputStream> OutputHandler<Output> {
    /// Creates a new handler for output.
    pub(crate) fn new(
        output: Output,
        padding_length_distribution: Option<Box<PaddingLengthDistribution>>,
    ) -> OutputHandler<Output> {
        OutputHandler {
            packet_writer: WriterOutputStream::new(),
            output,
            sequence_number: 0,
            padding_length_distribution: padding_length_distribution
                .unwrap_or_else(|| padding_length::default_distribution()),
        }
    }

    /// Initializes the output by writing the initialization string.
    pub(crate) fn initialize(
        &mut self,
        version_info: &VersionInformation,
    ) -> PacketFlusher<Output> {
        self.packet_writer.write_version_info(version_info);

        PacketFlusher {
            packet_writer: &mut self.packet_writer,
            output: &mut self.output,
        }
    }

    /// Sends a packet to the output.
    ///
    /// # Panics
    /// This function may panic, if the total length of the packet does not fit into a `u32`.
    pub(crate) fn send_packet(
        &mut self,
        payload: &[u8],
        runtime_state: &mut RuntimeState,
    ) -> PacketFlusher<Output> {
        let (algorithms, rng) = runtime_state.output_algorithms_and_rng();

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

        PacketFlusher {
            packet_writer: &mut self.packet_writer,
            output: &mut self.output,
        }
    }
}

/// Allows flushing sent packages to the output stream.
///
/// # Note
/// While `PacketFlusher` is marked `must_use`, it can be safely ignored,
/// as long as the `flush` method is invoked on a `PacketFlusher` at a later point.
/// The `flush` method always flushes the entire unflushed stream.
#[must_use = "the data isn't sent until it is flushed"]
#[derive(Debug)]
pub struct PacketFlusher<'o, Output: OutputStream> {
    /// The packet writer where the data to flush sits.
    packet_writer: &'o mut WriterOutputStream,
    /// The output where the data should be flushed to.
    output: &'o mut Output,
}

impl<'o, Output: OutputStream> PacketFlusher<'o, Output> {
    /// Flushes the buffered data to the output stream.
    ///
    /// This is what you want to do in most cases, since the data will not reach the other party,
    /// if you don't flush.
    pub async fn flush(self) -> io::Result<()> {
        let buf = self.packet_writer.written_data();

        if !buf.is_empty() {
            self.output.write_all(buf).await?;

            let len = buf.len();
            self.packet_writer.remove_to(len);
        }

        self.output.flush().await
    }

    /// Does not flush the output.
    ///
    /// This method is a no-op. It just exists to make provide more context at the right place
    /// and to make code more readable.
    ///
    /// This is only useful, if you want to send many packets in rapid succession.
    /// Then you could not flush the first few packets and flush the last one to flush all the
    /// data at once.
    ///
    /// ```ignore
    /// for _ in 0..100 {
    ///     handler.send_packet(&[1, 2, 3]).dont_flush();
    /// }
    /// handler.send_packet(&[1, 2, 3]).flush();
    /// ```
    pub fn dont_flush(self) {}
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        algorithms::AvailableAlgorithms,
        errors::CommunicationError,
        input_handler::InputHandler,
        runtime_state::RuntimeState,
        test_helpers::{FakeNetworkInput, FakeNetworkOutput},
        ConnectionRole,
    };

    #[test]
    fn write_packet_none() {
        let fake_output = FakeNetworkOutput::new(1);

        let mut output_handler = OutputHandler::new(fake_output, None);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::new("test").unwrap(),
            AvailableAlgorithms::default(),
            ConnectionRole::Client,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        futures::executor::block_on(async {
            let flusher = output_handler.initialize(runtime_state.local_version_info());

            assert_eq!(flusher.output.written(), &[]);

            flusher.dont_flush();

            let flusher =
                output_handler.send_packet(b"this is an important message", &mut runtime_state);

            assert_eq!(flusher.output.written(), &[]);

            assert!(matches!(flusher.flush().await, Ok(())));
        });

        assert_eq!(output_handler.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x24\x07this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d"[..]);

        futures::executor::block_on(async {
            let flusher = output_handler.send_packet(b"one more message", &mut runtime_state);

            assert_eq!(flusher.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x24\x07this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d"[..]);

            assert!(matches!(flusher.flush().await, Ok(())));
        });

        assert_eq!(output_handler.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x24\x07this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\x00\x00\x00\x1c\x0bone more message\xc3\x87\xb6\x69\xb2\xee\x65\x86\x9f\x07\xe7"[..]);
    }

    #[test]
    fn write_then_parse() {
        let fake_output = FakeNetworkOutput::new(1);

        let mut output_handler = OutputHandler::new(fake_output, None);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::new("test").unwrap(),
            AvailableAlgorithms::default(),
            ConnectionRole::Client,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        let message = b"this is an important message";

        futures::executor::block_on(async {
            assert!(matches!(
                output_handler
                    .initialize(runtime_state.local_version_info())
                    .flush()
                    .await,
                Ok(())
            ));

            assert!(matches!(
                output_handler
                    .send_packet(message, &mut runtime_state)
                    .flush()
                    .await,
                Ok(())
            ));
        });

        let fake_input = FakeNetworkInput::new(output_handler.output.written().to_owned(), 1);

        let mut input_handler = InputHandler::new(fake_input);

        let mut runtime_state = RuntimeState::new(
            VersionInformation::new("test").unwrap(),
            AvailableAlgorithms::default(),
            ConnectionRole::Server,
            Box::new(ChaCha20Rng::from_seed(Default::default())),
            true,
        );

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.initialize().await.unwrap(),
                (
                    VersionInformation::new("test").unwrap(),
                    b"SSH-2.0-test".to_vec()
                )
            );

            assert_eq!(
                input_handler
                    .next_packet(&mut runtime_state)
                    .await
                    .expect("packet exists"),
                message.to_vec()
            );

            assert!(matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            ));
        });
    }
}
