//! Implements a handler to output to the partner.

use rand::{distributions::Distribution, RngCore};
use rand_distr::Gamma;
use std::{borrow::Cow, fmt, io};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    constants::MAX_EXTRA_PADDING_BLOCKS, runtime_state::RuntimeState, version::VersionInformation,
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
    padding_length_distribution: Box<dyn FnMut(&mut dyn RngCore) -> u8>,
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
        padding_length_distribution: Option<Box<dyn FnMut(&mut dyn RngCore) -> u8>>,
    ) -> OutputHandler<Output> {
        OutputHandler {
            packet_writer: WriterOutputStream::new(),
            output,
            sequence_number: 0,
            padding_length_distribution: padding_length_distribution
                .unwrap_or_else(|| default_padding_length_distribution()),
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

        if buf.len() != 0 {
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

/// Returns the distribution for packet lengths to be used by default.
///
/// Produces a distribution with the chance of 0 to 6 extra blocks being roughly 50%.
/// Each additional block is increasingly less likely.
/// The chances of additional blocks are roughly as follows (measured in 1_000_000
/// trials):
///
/// +----+----------+----+---------+----+---------+
/// | blk|   chance | blk|  chance | blk|  chance |
/// +----+----------+----+---------+----+---------+
/// |  0 | 18.0098% | 11 | 2.4851% | 22 | 1.1363% |
/// |  1 | 12.6859% | 12 | 2.2693% | 23 | 1.0517% |
/// |  2 |  8.3839% | 13 | 2.1098% | 24 | 0.9886% |
/// |  3 |  6.5598% | 14 | 1.9557% | 25 | 0.9417% |
/// |  4 |  5.4453% | 15 | 1.8157% | 26 | 0.8832% |
/// |  5 |  4.6806% | 16 | 1.6759% | 27 | 0.8255% |
/// |  6 |  4.0755% | 17 | 1.5661% | 28 | 0.7916% |
/// |  7 |  3.6174% | 18 | 1.4710% | 29 | 0.7443% |
/// |  8 |  3.3081% | 19 | 1.3680% | 30 | 0.6977% |
/// |  9 |  2.9330% | 20 | 1.2868% | 31 | 0.3224% |
/// | 10 |  2.7221% | 21 | 1.1922% |    |         |
/// +----+----------+----+---------+----+---------+
pub(crate) fn default_padding_length_distribution() -> Box<dyn FnMut(&mut dyn RngCore) -> u8> {
    let gamma = Gamma::new(0.5, 25.0).unwrap();

    Box::new(move |rng| {
        let mut float = gamma.sample(rng);
        while float > MAX_EXTRA_PADDING_BLOCKS as f64 {
            float = gamma.sample(rng);
        }

        // Make sure it's a valid u8
        float.max(0x00 as f64).min(0xff as f64).round() as u8
    })
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;
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

            assert_matches!(flusher.flush().await, Ok(()));
        });

        assert_eq!(output_handler.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x34\x17this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a"[..]);

        futures::executor::block_on(async {
            let flusher = output_handler.send_packet(b"one more message", &mut runtime_state);

            assert_eq!(flusher.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x34\x17this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a"[..]);

            assert_matches!(flusher.flush().await, Ok(()));
        });

        assert_eq!(output_handler.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x34\x17this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a\x00\x00\x00\x1c\x0bone more message\x98\xba\x97\x7c\x73\x2d\x08\x0d\xcb\x0f\x29"[..]);
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
            assert_matches!(
                output_handler
                    .initialize(runtime_state.local_version_info())
                    .flush()
                    .await,
                Ok(())
            );

            assert_matches!(
                output_handler
                    .send_packet(message, &mut runtime_state)
                    .flush()
                    .await,
                Ok(())
            );
        });

        assert_eq!(output_handler.output.written(), &b"SSH-2.0-test\r\n\x00\x00\x00\x34\x17this is an important message\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a"[..]);

        let fake_input = FakeNetworkInput::new(output_handler.output.written().to_owned(), 1);

        let mut input_handler = InputHandler::new(fake_input);

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

            assert_matches!(
                input_handler.next_packet(&mut runtime_state).await,
                Err(CommunicationError::EndOfInput)
            );
        });
    }
}
