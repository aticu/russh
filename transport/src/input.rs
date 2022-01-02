//! Handles the input side of the SSH connection.

use definitions::{algorithms::InvalidMacError, ParseError, ParsedValue};
use std::{
    borrow::Cow,
    cmp::{max, min},
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    algorithms::{EncryptionAlgorithmEntry, EncryptionContext, PacketAlgorithms},
    constants::PACKET_LEN_SIZE,
    errors::{CommunicationError, IncomingPacketError},
    version::VersionInformation,
};

pub(crate) use self::parse::ParsedPacket;

mod parse;

/// Make some sanity checks to verify that the internal state is valid.
macro_rules! assert_valid_state {
    ($self:ident) => {
        debug_assert!($self.parsed_until <= $self.decrypted_until);
        debug_assert!($self.decrypted_until <= $self.initialized_until);
        debug_assert!($self.initialized_until <= $self.data.len());
    };
}

/// Handle the result of a parsing operation in a quick way.
macro_rules! parse {
    ($parser_call:expr) => {
        match $parser_call {
            Ok(val) => val,
            Err(ParseError::Incomplete) => return Ok(None),
            Err(ParseError::Invalid) => return Err(crate::errors::IncomingPacketError::Format),
        }
    };
}

/// The default size for data reads.
pub(crate) const READ_SIZE: usize = 0x1000;

/// A trait to represent the input to the SSH transport layer.
pub trait InputStream: AsyncRead + Unpin {}

impl<T: AsyncRead + Unpin> InputStream for T {}

/// Handles input tranformations and buffering.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InputBuffer {
    /// The underlying buffer.
    // This could also be implemented using `bytes::BytesMut`, but there does not seem to be
    // any significant advantage for this use case, since `Vec` does exactly what is required here.
    //
    // However, if performance problems arise, this could be benchmarked to verify that there is
    // no significant difference.
    data: Vec<u8>,
    /// The index of the first byte that has not yet been parsed.
    parsed_until: usize,
    /// The index of the first byte that has not yet been decrypted.
    decrypted_until: usize,
    /// The index of the first byte that has not yet been initialized.
    initialized_until: usize,
    /// The number of packets that have arrived (modulo 32 bits).
    sequence_number: u32,
}

impl InputBuffer {
    /// Creates a new empty input stream.
    pub(crate) fn new() -> InputBuffer {
        InputBuffer {
            data: Vec::new(),
            parsed_until: 0,
            decrypted_until: 0,
            initialized_until: 0,
            sequence_number: 0,
        }
    }

    /// Reserves at least `size` bytes for input and returns access to them.
    fn reserve(&mut self, size: usize) -> &mut [u8] {
        assert_valid_state!(self);

        let additional_capacity = self.data.len() - self.initialized_until;
        let space_needed = size.saturating_sub(additional_capacity);

        self.data.resize(self.data.len() + space_needed, 0);

        assert_valid_state!(self);

        &mut self.data[self.initialized_until..]
    }

    /// Reads more data from the source into the buffer.
    pub(crate) async fn read_more_data<I: InputStream>(
        &mut self,
        input: &mut I,
    ) -> Result<usize, CommunicationError> {
        assert_valid_state!(self);

        let buf = self.reserve(READ_SIZE);

        let size = input.read(buf).await.map_err(CommunicationError::Io)?;

        if size == 0 {
            return Err(CommunicationError::EndOfInput);
        }

        self.initialized_until += size;

        assert_valid_state!(self);

        Ok(size)
    }

    /// Parses the version information passed during initialization.
    ///
    /// This should not be called again, after the first `Ok(_)` was returned.
    pub(crate) fn parse_initialization(
        &mut self,
    ) -> Result<Option<(VersionInformation, Vec<u8>)>, IncomingPacketError> {
        assert_valid_state!(self);

        debug_assert_eq!(self.parsed_until, 0);
        debug_assert_eq!(self.decrypted_until, 0);

        let ParsedValue {
            value: (info, line, bytes_read),
            ..
        } = parse!(parse::initialization(&self.data[..self.initialized_until]));

        self.parsed_until = bytes_read;
        self.decrypted_until = bytes_read;

        let line = line.to_vec();

        self.remove_old_data();

        assert_valid_state!(self);

        Ok(Some((info, line)))
    }

    /// Advances the decryption of data to the index `to`.
    ///
    /// If there isn't enough data available the data is decrypted as far as possible.
    /// If there was progress made during decrypting, `Ok(true)` is returned, otherwise `Ok(false)`
    /// is returned unless an error is detected.
    fn decrypt(
        &mut self,
        to: usize,
        algorithm: &mut EncryptionAlgorithmEntry,
    ) -> Result<bool, InvalidMacError> {
        assert_valid_state!(self);

        let current_packet = &mut self.data[self.parsed_until..min(to, self.initialized_until)];
        let context = EncryptionContext::new(
            self.sequence_number,
            current_packet,
            self.decrypted_until - self.parsed_until,
        );

        let decrypted_at_start = self.decrypted_until;

        self.decrypted_until += algorithm.decrypt_packet(context)?;

        assert_valid_state!(self);

        Ok(self.decrypted_until > decrypted_at_start)
    }

    /// Decrypts the next packet.
    ///
    /// Returns `Ok(true)` if the packet is fully decrypted and ready to be parsed.
    ///
    /// This function returns an `InvalidMacError` since some encryption algorithms handle the MACS
    /// themselves and therefore a MAC error could happen during the decryption of the packet.
    fn decrypt_packet(
        &mut self,
        dec_algorithm: &mut EncryptionAlgorithmEntry,
        mac_len: usize,
    ) -> Result<bool, InvalidMacError> {
        assert_valid_state!(self);

        let block_size = dec_algorithm.cipher_block_size;
        let minimum_packet_length = max(block_size, 8);

        let packet_length = loop {
            if let Some(len) = self.parse_packet_length() {
                break len;
            }

            match self.decrypt(self.parsed_until + minimum_packet_length, dec_algorithm)? {
                true => continue,
                false => return Ok(false),
            }
        };

        let optional_mac_len = dec_algorithm.mac_size.unwrap_or(0);

        while self.decrypted_until < self.parsed_until + PACKET_LEN_SIZE + packet_length {
            match self.decrypt(
                self.parsed_until + PACKET_LEN_SIZE + packet_length + optional_mac_len,
                dec_algorithm,
            )? {
                true => continue,
                false => return Ok(false),
            }
        }

        assert_valid_state!(self);

        Ok(self.initialized_until >= self.parsed_until + PACKET_LEN_SIZE + packet_length + mac_len)
    }

    /// Parses the length of the current packet.
    fn parse_packet_length(&self) -> Option<usize> {
        match parse::packet_length(&self.data[self.parsed_until..self.decrypted_until]) {
            Ok(ParsedValue { value: length, .. }) => Some(length as usize),
            Err(ParseError::Incomplete) => None,
            Err(ParseError::Invalid) => unreachable!(),
        }
    }

    /// Parses the next available packet, if possible.
    ///
    /// Returns the parsed packet along with a reference to the sequence number for later access if
    /// enough data is available.
    // TODO: taint the parser once an error occurs
    fn parse_packet(
        &mut self,
        dec_algorithm: &mut EncryptionAlgorithmEntry,
        mac_len: usize,
    ) -> Result<Option<(ParsedPacket<'_>, &mut u32)>, IncomingPacketError> {
        assert_valid_state!(self);

        if !self
            .decrypt_packet(dec_algorithm, mac_len)
            .map_err(IncomingPacketError::Mac)?
        {
            return Ok(None);
        }

        // It's safe to unwrap here since the length must be parsable after the decryption of a
        // packet.
        let packet_length = self.parse_packet_length().unwrap();

        let packet_end = self.parsed_until + PACKET_LEN_SIZE + packet_length + mac_len;

        let ParsedValue { value: packet, .. } = parse!(parse::packet(
            &self.data[self.parsed_until..packet_end],
            mac_len
        ));

        self.decrypted_until = packet_end;
        self.parsed_until = self.decrypted_until;

        assert_valid_state!(self);

        Ok(Some((packet, &mut self.sequence_number)))
    }

    /// Shrinks the input to the smallest possible size.
    fn remove_old_data(&mut self) {
        assert_valid_state!(self);

        self.data.drain(..self.parsed_until);

        self.decrypted_until -= self.parsed_until;
        self.initialized_until -= self.parsed_until;
        self.parsed_until = 0;

        assert_valid_state!(self);
    }

    /// Reads the next packet from the buffer and returns it.
    ///
    /// If the buffer does not contain all of the next input packet, `Ok(None)` is returned.
    pub(crate) fn read_packet(
        &mut self,
        mut algorithms: PacketAlgorithms<'_>,
    ) -> Result<Option<Cow<'_, [u8]>>, IncomingPacketError> {
        self.remove_old_data();

        let mac_len = algorithms.mac_len();

        let (packet, sequence_number) = match self.parse_packet(algorithms.encryption, mac_len)? {
            Some(result) => result,
            None => return Ok(None),
        };

        verify_packet(&packet, *sequence_number, &mut algorithms)?;

        let result = algorithms
            .compression
            .decompress(Cow::Borrowed(packet.payload))
            .map(Some)
            .map_err(|err| IncomingPacketError::Compression(err));

        *sequence_number = sequence_number.wrapping_add(1);

        result
    }
}

/// Verifies that a parsed packet is valid.
///
/// This function verifies that
/// - the MAC is correct (if that wasn't already checked during decryption).
/// - the padding length is valid given the constraints.
fn verify_packet(
    packet: &ParsedPacket,
    packet_sequence_number: u32,
    algorithms: &mut PacketAlgorithms<'_>,
) -> Result<(), IncomingPacketError> {
    if let Some(mac_algorithm) = &mut algorithms.mac {
        mac_algorithm
            .verify(packet.whole_packet, packet_sequence_number, packet.mac)
            .map_err(IncomingPacketError::Mac)?;
    }

    // TODO: implement ETM MAC algorithms
    // if implemented, add this to the check here
    let len_modifier = if algorithms.encryption.computes_mac() {
        4
    } else {
        0
    };
    if (packet.whole_packet.len() - len_modifier) % max(algorithms.encryption.cipher_block_size, 8)
        != 0
    {
        return Err(IncomingPacketError::Padding);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use sha2::digest::Digest;

    use crate::{
        algorithms::{ChosenAlgorithms, ConnectionAlgorithms},
        test_helpers::FakeNetworkInput,
        ConnectionRole,
    };
    use algorithms::encryption;

    use super::*;

    #[test]
    fn decrypt_none() {
        let mut input_stream = InputBuffer::new();
        let mut algorithm = encryption::None::new().into();

        assert_eq!(input_stream.initialized_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(&input_stream.data, &[]);

        let buf = input_stream.reserve(50);
        assert_eq!(buf.len(), 50);
        (&mut buf[..8]).copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

        input_stream.initialized_until += 8;

        assert_eq!(input_stream.data.len(), 50);

        assert_eq!(input_stream.decrypt(2, &mut algorithm), Ok(true));
        assert_eq!(input_stream.decrypted_until, 2);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(4, &mut algorithm), Ok(true));
        assert_eq!(input_stream.decrypted_until, 4);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(8, &mut algorithm), Ok(true));
        assert_eq!(input_stream.decrypted_until, 8);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(9, &mut algorithm), Ok(false));
    }

    #[test]
    fn decrypt_packet_none() {
        let mut input_stream = InputBuffer::new();
        let mut dec_algorithm = encryption::None::new().into();

        let payload1 = b"some more testing data as payload";
        let padding1: [u8; 0x12] = rand::random();

        let payload2 = b"testpayload";
        let padding2: [u8; 0x08] = rand::random();

        let mut packet_data = Vec::new();

        packet_data.extend([0x00, 0x00, 0x00, 0x34, 0x12]);
        packet_data.extend(payload1);
        packet_data.extend(padding1);

        let midpoint = packet_data.len();

        packet_data.extend([0x00, 0x00, 0x00, 0x14, 0x08]);
        packet_data.extend(payload2);
        packet_data.extend(padding2);

        {
            let buf = input_stream.reserve(packet_data.len());

            (&mut buf[..10]).copy_from_slice(&packet_data[..10]);

            input_stream.initialized_until += 10;
        }

        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 10);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..6]).copy_from_slice(&packet_data[10..16]);

            input_stream.initialized_until += 6;
        }

        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 16);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..44]).copy_from_slice(&packet_data[16..60]);

            input_stream.initialized_until += 44;
        }

        assert_eq!(
            input_stream
                .parse_packet(&mut dec_algorithm, 0)
                .unwrap()
                .unwrap(),
            (
                ParsedPacket {
                    payload: payload1,
                    padding: &padding1,
                    whole_packet: &packet_data[..midpoint],
                    mac: &[][..],
                },
                &mut 0
            )
        );
        assert_eq!(input_stream.parsed_until, 56);
        assert_eq!(input_stream.decrypted_until, 56);
        assert_eq!(input_stream.data.len(), packet_data.len());

        input_stream.remove_old_data();
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.initialized_until, 4);
        assert_eq!(input_stream.data.len(), packet_data.len() - 56);

        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 4);
        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[0x00, 0x00, 0x00, 0x14][..]
        );

        {
            let buf = input_stream.reserve(0);

            buf.copy_from_slice(&packet_data[60..]);

            let data_written = buf.len();
            input_stream.initialized_until += data_written;
        }
        assert_eq!(
            input_stream
                .parse_packet(&mut dec_algorithm, 0)
                .unwrap()
                .unwrap(),
            (
                ParsedPacket {
                    payload: payload2,
                    padding: &padding2,
                    whole_packet: &packet_data[midpoint..],
                    mac: &[][..],
                },
                &mut 0
            )
        );
        assert_eq!(input_stream.parsed_until, 24);
        assert_eq!(input_stream.decrypted_until, 24);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));

        assert_eq!(input_stream.initialized_until, input_stream.data.len());
        input_stream.remove_old_data();
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.initialized_until, 0);
        assert_eq!(input_stream.data.len(), 0);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));
    }

    #[test]
    fn initialization_and_packet() {
        let mut input_stream = InputBuffer::new();
        let mut dec_algorithm = encryption::None::new().into();

        let comment = b"SSH is a protocol\r\n";
        let init = b"SSH-2.0-test@1.0\r\n";
        let payload = b"testpayload";
        let padding: [u8; 0x08] = rand::random();

        let mut packet_data = Vec::new();

        packet_data.extend(comment);
        packet_data.extend(init);

        let packet_start = packet_data.len();

        packet_data.extend([0x00, 0x00, 0x00, 0x14, 0x08]);
        packet_data.extend(payload);
        packet_data.extend(padding);

        {
            let buf = input_stream.reserve(packet_data.len());

            (&mut buf[..10]).copy_from_slice(&packet_data[..10]);

            input_stream.initialized_until += 10;
        }

        assert!(matches!(input_stream.parse_initialization(), Ok(None)));
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..20]).copy_from_slice(&packet_data[10..30]);

            input_stream.initialized_until += 20;
        }

        assert!(matches!(input_stream.parse_initialization(), Ok(None)));
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..10]).copy_from_slice(&packet_data[30..40]);

            input_stream.initialized_until += 10;
        }

        assert_eq!(
            input_stream.parse_initialization().unwrap().unwrap(),
            (
                VersionInformation::new("test@1.0").unwrap(),
                b"SSH-2.0-test@1.0".to_vec()
            )
        );
        // Parsing the initialization clears the old data from the buffer.
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);

        {
            let buf = input_stream.reserve(0);

            buf.copy_from_slice(&packet_data[40..]);

            let data_written = buf.len();
            input_stream.initialized_until += data_written;
        }

        assert_eq!(
            input_stream
                .parse_packet(&mut dec_algorithm, 0)
                .unwrap()
                .unwrap(),
            (
                ParsedPacket {
                    payload,
                    padding: &padding,
                    whole_packet: &packet_data[packet_start..],
                    mac: &[][..],
                },
                &mut 0
            )
        );
        // Subtract the length of the initialization part here
        assert_eq!(input_stream.parsed_until, packet_data.len() - 37);
        assert_eq!(input_stream.decrypted_until, packet_data.len() - 37);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));

        input_stream.remove_old_data();
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.data.len(), 0);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert!(matches!(
            input_stream.parse_packet(&mut dec_algorithm, 0),
            Ok(None)
        ));
    }

    #[test]
    fn next_packet_encrypted() {
        let packet_data = b"SSH-2.0-test@1.0\r\n\x5c\xd0\x42\x56\x97\x03\x81\x0b\xd3\x11\x81\xa1\x2c\x6e\xe3\xb5\x54\x85\xfe\x4e\x5b\x3e\x02\xc1\x32\x26\x6c\xe8\xf0\xae\x85\xc3\xa3\xa4\xb7\xb1\xc3\x4e\xed\x4e\x93\x73\xa4\x03\x49\x7e\xd2\x69\x33\x6d\xa7\xd3\x6a\xd4\xba\x57\x9c\xc3\xa3\x30\x7f\xd9\x33\xbc\xf5\xbd\x41\x8e\xc3\x4d\xbe\x5b\xf5\xb2\x7f\xe3\x0f\xdb\x95\x9f\xa1\x2f\x58\x68\xa6\x0e\xa0\x85\x6d\x27\x7f\x5e\xbc\x5d\x58\x94".to_vec();
        // use the payload:
        // b"\x00\x00\x00\x1c\x10testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10\x12\xa8\x5b\x0e\x78\x50\x35\x00";
        let packet_len = packet_data.len();

        let mut fake_input = FakeNetworkInput::new(packet_data, packet_len);

        let mut input_handler = InputBuffer::new();

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
                input_handler.parse_initialization().unwrap().unwrap(),
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

        let mut input_handler = InputBuffer::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.read_more_data(&mut fake_input).await.unwrap(),
                packet_len
            );
            assert_eq!(
                input_handler.parse_initialization().unwrap().unwrap(),
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

        let mut input_handler = InputBuffer::new();

        let mut connection_algorithms = ConnectionAlgorithms::default();

        futures::executor::block_on(async {
            assert_eq!(
                input_handler.read_more_data(&mut fake_input).await.unwrap(),
                packet_len
            );
            assert_eq!(
                input_handler.parse_initialization().unwrap().unwrap(),
                (
                    VersionInformation::new("test@1.0").unwrap(),
                    b"SSH-2.0-test@1.0".to_vec()
                )
            );

            assert!(matches!(
                dbg!(input_handler.read_packet(incoming_algorithms!(
                    connection_algorithms,
                    ConnectionRole::Client
                ))),
                Err(IncomingPacketError::Format)
            ));
        });
    }
}
