//! Provides helpers for writing tests.
//!
//! Most notable are the `FakeNetworkInput` and `FakeNetworkOutput` types.

use std::{
    cmp::min,
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Acts as a fake network for input to the SSH transport layer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FakeNetworkInput {
    /// The data to be sent.
    input_data: Vec<u8>,
    /// The maximum amount of data that should be sent in one "packet".
    packet_size: usize,
}

impl FakeNetworkInput {
    /// Creates a fake network input from the given input data and the packet size.
    pub(crate) fn new(input_data: Vec<u8>, packet_size: usize) -> FakeNetworkInput {
        FakeNetworkInput {
            input_data,
            packet_size,
        }
    }
}

impl AsyncRead for FakeNetworkInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.input_data.len() > 0 {
            let amount_to_copy = min(min(self.input_data.len(), self.packet_size), buf.len());

            buf[..amount_to_copy].copy_from_slice(&self.input_data[..amount_to_copy]);

            self.input_data.drain(..amount_to_copy);

            Poll::Ready(Ok(amount_to_copy))
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

/// Acts as a fake network for output of the SSH transport layer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FakeNetworkOutput {
    /// The data that was sent.
    written_data: Vec<u8>,
    /// The maximum size that can be received at once.
    packet_size: usize,
    /// Indicate whether the writer has been shut down.
    is_shutdown: bool,
    /// The index of the first byte that was not flushed.
    flushed_to: usize,
}

impl FakeNetworkOutput {
    /// Creates a fake network output with the given maximum packet size.
    pub(crate) fn new(packet_size: usize) -> FakeNetworkOutput {
        FakeNetworkOutput {
            written_data: Vec::new(),
            packet_size,
            is_shutdown: false,
            flushed_to: 0,
        }
    }

    /// Returns a reference to the written data.
    pub(crate) fn written(&self) -> &[u8] {
        &self.written_data[..self.flushed_to]
    }
}

impl AsyncWrite for FakeNetworkOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.is_shutdown {
            Poll::Ready(Err(io::Error::new(
                ErrorKind::NotConnected,
                "connection closed",
            )))
        } else {
            let packet_size = self.packet_size;
            self.written_data
                .extend_from_slice(&buf[..min(packet_size, buf.len())]);

            Poll::Ready(Ok(min(buf.len(), packet_size)))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.is_shutdown {
            Poll::Ready(Err(io::Error::new(
                ErrorKind::NotConnected,
                "connection closed",
            )))
        } else {
            self.flushed_to = self.written_data.len();
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.is_shutdown {
            Poll::Ready(Err(io::Error::new(
                ErrorKind::NotConnected,
                "connection closed",
            )))
        } else {
            self.is_shutdown = true;

            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn simple_input() {
        let data: Vec<u8> = (0..175).collect();

        let mut fake_input = FakeNetworkInput::new(data.clone(), 50);

        let mut buf = [0; 100];

        futures::executor::block_on(async {
            assert_eq!(fake_input.read(&mut buf).await.ok(), Some(50));
            assert_eq!(&data[0..50], &buf[0..50]);

            assert_eq!(fake_input.read(&mut buf).await.ok(), Some(50));
            assert_eq!(&data[50..100], &buf[0..50]);

            assert_eq!(fake_input.read(&mut buf).await.ok(), Some(50));
            assert_eq!(&data[100..150], &buf[0..50]);

            assert_eq!(fake_input.read(&mut buf).await.ok(), Some(25));
            assert_eq!(&data[150..175], &buf[0..25]);
        });
    }

    #[test]
    fn simple_output() {
        let data: Vec<u8> = (0..175).collect();

        let mut fake_output = FakeNetworkOutput::new(50);

        futures::executor::block_on(async {
            assert_eq!(fake_output.write(&data[0..]).await.ok(), Some(50));
            assert_eq!(fake_output.written().len(), 0);
            assert!(matches!(fake_output.flush().await, Ok(())));
            assert_eq!(&data[0..50], &fake_output.written()[0..50]);

            assert_eq!(fake_output.write(&data[50..]).await.ok(), Some(50));
            assert_eq!(fake_output.written().len(), 50);
            assert!(matches!(fake_output.flush().await, Ok(())));
            assert_eq!(&data[50..100], &fake_output.written()[50..100]);

            assert_eq!(fake_output.write(&data[100..]).await.ok(), Some(50));
            assert_eq!(fake_output.written().len(), 100);
            assert!(matches!(fake_output.flush().await, Ok(())));
            assert_eq!(&data[100..150], &fake_output.written()[100..150]);

            assert_eq!(fake_output.write(&data[150..]).await.ok(), Some(25));
            assert_eq!(fake_output.written().len(), 150);
            assert!(matches!(fake_output.flush().await, Ok(())));
            assert_eq!(&data[150..175], &fake_output.written()[150..175]);

            assert_eq!(fake_output.written().len(), 175);
            assert!(matches!(fake_output.flush().await, Ok(())));
            assert_eq!(fake_output.written().len(), 175);

            assert!(matches!(fake_output.shutdown().await, Ok(())));

            assert_eq!(
                fake_output.write(&data).await.unwrap_err().kind(),
                ErrorKind::NotConnected
            );
            assert_eq!(
                fake_output.flush().await.unwrap_err().kind(),
                ErrorKind::NotConnected
            );
            assert_eq!(
                fake_output.shutdown().await.unwrap_err().kind(),
                ErrorKind::NotConnected
            );

            assert_eq!(fake_output.written().len(), 175);
        });
    }
}
