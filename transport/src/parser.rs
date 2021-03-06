//! Handles parsing of data from packages.
//!
//! This is the counter part to the `writer` module.

use russh_common::algorithms::{EncryptionAlgorithm, EncryptionContext, MacAlgorithm};
use std::cmp::{max, min};

use self::{
    initialization::parse_initialization,
    unencrypted_packet::{parse_unencrypted_packet, parse_unencrypted_packet_length},
};
use crate::{constants::PACKET_LEN_SIZE, errors::ParseError, version::VersionInformation};

pub(crate) use self::unencrypted_packet::ParsedPacket;

mod initialization;
mod unencrypted_packet;

/// Represents the input to the parser.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParserInputStream {
    /// The data that has been received so far.
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
}

impl ParserInputStream {
    /// Creates a new empty input stream.
    pub(crate) fn new() -> ParserInputStream {
        ParserInputStream {
            data: Vec::new(),
            parsed_until: 0,
            decrypted_until: 0,
            initialized_until: 0,
        }
    }

    /// This function makes some sanity checks to verify that the internal state is valid.
    #[cfg(debug_assertions)]
    fn assert_valid_state(&self) {
        assert!(self.parsed_until <= self.decrypted_until);
        assert!(self.decrypted_until <= self.initialized_until);
        assert!(self.initialized_until <= self.data.len());
    }

    /// Reserves at least `size` bytes for input and returns access to them.
    pub(crate) fn reserve(&mut self, size: usize) -> &mut [u8] {
        #[cfg(debug_assertions)]
        self.assert_valid_state();

        let additional_capacity = self.data.len() - self.initialized_until;
        let space_needed = size.saturating_sub(additional_capacity);

        self.data.resize(self.data.len() + space_needed, 0);

        &mut self.data[self.initialized_until..]
    }

    /// Indicates that `size` additional bytes are now filled with arrived packet data.
    ///
    /// # Panics
    /// This method may panic if more bytes are indicated as used than were previously reserved.
    pub(crate) fn indicate_used(&mut self, size: usize) {
        self.initialized_until += size;

        #[cfg(debug_assertions)]
        self.assert_valid_state();
    }

    /// Parses the version information passed during initialization.
    ///
    /// This should not be called again, after the first `Ok(_)` was returned.
    pub(crate) fn parse_initialization(
        &mut self,
    ) -> Result<(VersionInformation, Vec<u8>), ParseError> {
        debug_assert_eq!(self.parsed_until, 0);
        debug_assert_eq!(self.decrypted_until, 0);

        let (rest_data, info) = parse_initialization(&self.data[..self.initialized_until])
            .map_err(|err| match err {
                nom::Err::Incomplete(_) => ParseError::Incomplete,
                _ => ParseError::Invalid,
            })?;

        // This seems to be the best way to calculate the offset a slice (`self.data`) and its
        // subslice (`rest_data`). There also exists a `sublice_index` crate which performs this
        // exact calculation, but adding another dependency for this one use case is probably not
        // worth it.
        let bytes_read = rest_data.as_ptr() as usize - self.data.as_ptr() as usize;

        self.parsed_until = bytes_read;
        self.decrypted_until = bytes_read;

        Ok((info.0, info.1.to_vec()))
    }

    /// Advances the decryption of data to the index `to`.
    ///
    /// If there isn't enough data available the data is decrypted as far as possible.
    /// If there was progress made during decrypting, `Ok(true)` is returned, otherwise `Ok(false)`
    /// is returned unless an error is detected.
    fn decrypt(
        &mut self,
        to: usize,
        algorithm: &mut dyn EncryptionAlgorithm,
        packet_sequence_number: u32,
    ) -> Result<bool, ParseError> {
        #[cfg(debug_assertions)]
        self.assert_valid_state();

        let current_packet = &mut self.data[self.parsed_until..min(to, self.initialized_until)];
        let context = EncryptionContext::new(
            packet_sequence_number,
            current_packet,
            self.decrypted_until - self.parsed_until,
        );

        let decrypted_at_start = self.decrypted_until;

        if algorithm.mac_size().is_some() {
            match algorithm.authenticated_decrypt_packet(context) {
                Some(decrypted_bytes) => self.decrypted_until += decrypted_bytes,
                None => return Err(ParseError::InvalidMac),
            }
        } else {
            self.decrypted_until += algorithm.decrypt_packet(context);
        }

        Ok(self.decrypted_until > decrypted_at_start)
    }

    /// Parses the length of the current packet.
    fn parse_packet_length(&self) -> Result<usize, ParseError> {
        #[cfg(debug_assertions)]
        self.assert_valid_state();
        debug_assert!(self.decrypted_until >= self.parsed_until + PACKET_LEN_SIZE);

        let (_, packet_length) =
            parse_unencrypted_packet_length(&self.data[self.parsed_until..self.decrypted_until])?;

        Ok(packet_length as usize)
    }

    /// Checks if the packet is ready to be parsed.
    pub(crate) fn is_packet_ready(
        &mut self,
        dec_algorithm: &mut dyn EncryptionAlgorithm,
        mac_len: usize,
        packet_sequence_number: u32,
    ) -> Result<bool, ParseError> {
        #[cfg(debug_assertions)]
        self.assert_valid_state();

        let block_size = dec_algorithm.cipher_block_size();
        let minimum_packet_length = max(block_size, 8);

        while self.decrypted_until < self.parsed_until + PACKET_LEN_SIZE {
            match self.decrypt(
                self.parsed_until + minimum_packet_length,
                dec_algorithm,
                packet_sequence_number,
            ) {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(ParseError::InvalidMac) => return Err(ParseError::InvalidMac),
                Err(_) => unreachable!(),
            }
        }

        let packet_length = self
            .parse_packet_length()
            .expect("packet length should be parsable");

        let optional_mac_len = if let Some(mac_size) = dec_algorithm.mac_size() {
            mac_size
        } else {
            0
        };

        while self.decrypted_until < self.parsed_until + PACKET_LEN_SIZE + packet_length {
            match self.decrypt(
                self.parsed_until + PACKET_LEN_SIZE + packet_length + optional_mac_len,
                dec_algorithm,
                packet_sequence_number,
            ) {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(ParseError::InvalidMac) => return Err(ParseError::InvalidMac),
                Err(_) => unreachable!(),
            }
        }

        Ok(self.initialized_until >= self.parsed_until + PACKET_LEN_SIZE + packet_length + mac_len)
    }

    /// Parses the next available packet, if possible.
    // TODO: taint the parser once an error occurs
    pub(crate) fn parse_packet<'a>(
        &'a mut self,
        dec_algorithm: &mut dyn EncryptionAlgorithm,
        mac_algorithm: Option<&mut dyn MacAlgorithm>,
        mac_len: usize,
        packet_sequence_number: u32,
    ) -> Result<ParsedPacket<'a>, ParseError> {
        #[cfg(debug_assertions)]
        self.assert_valid_state();

        if !self.is_packet_ready(dec_algorithm, mac_len, packet_sequence_number)? {
            return Err(ParseError::Incomplete);
        }

        let packet_length = self
            .parse_packet_length()
            .expect("packet length should be parsable");

        let packet_end = self.parsed_until + PACKET_LEN_SIZE + packet_length + mac_len;

        let (_, packet) =
            parse_unencrypted_packet(&self.data[self.parsed_until..packet_end], mac_len).map_err(
                |err| match err {
                    ParseError::Incomplete => unreachable!(),
                    _ => ParseError::Invalid,
                },
            )?;

        self.decrypted_until += mac_len;
        self.parsed_until = self.decrypted_until;

        if let Some(mac_algorithm) = mac_algorithm {
            if !mac_algorithm.verify(packet.whole_packet, packet_sequence_number, packet.mac) {
                return Err(ParseError::InvalidMac);
            }
        }

        Ok(packet)
    }

    /// Shrinks the input to the smallest possible size.
    pub(crate) fn remove_old_data(&mut self) {
        #[cfg(debug_assertions)]
        self.assert_valid_state();

        self.data.drain(..self.parsed_until);

        self.decrypted_until -= self.parsed_until;
        self.initialized_until -= self.parsed_until;
        self.parsed_until = 0;
    }
}

#[cfg(test)]
mod tests {
    use russh_algorithms::encryption;

    use super::*;

    #[test]
    fn decrypt_none() {
        let mut input_stream = ParserInputStream::new();
        let mut algorithm = encryption::None::new();

        assert_eq!(input_stream.initialized_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(&input_stream.data, &[]);

        let buf = input_stream.reserve(50);
        assert_eq!(buf.len(), 50);
        (&mut buf[..8]).copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

        input_stream.indicate_used(8);

        assert_eq!(input_stream.data.len(), 50);

        assert_eq!(input_stream.decrypt(2, &mut algorithm, 0), Ok(true));
        assert_eq!(input_stream.decrypted_until, 2);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(4, &mut algorithm, 0), Ok(true));
        assert_eq!(input_stream.decrypted_until, 4);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(8, &mut algorithm, 0), Ok(true));
        assert_eq!(input_stream.decrypted_until, 8);
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(
            &input_stream.data[..input_stream.initialized_until],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );

        assert_eq!(input_stream.decrypt(9, &mut algorithm, 0), Ok(false));
    }

    #[test]
    fn decrypt_packet_none() {
        let mut input_stream = ParserInputStream::new();
        let mut dec_algorithm = encryption::None::new();

        let packet_data = &[
            0x00, 0x00, 0x00, 0x34, 0x12, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r', b'e',
            b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't', b'a', b' ',
            b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55, 0x73, 0xfd, 0xca,
            0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91, 0xa7, 0x35, 0x8f, 0xad, 0x74, 0x44,
            0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y', b'l', b'o',
            b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10,
        ];

        {
            let buf = input_stream.reserve(packet_data.len());

            (&mut buf[..10]).copy_from_slice(&packet_data[..10]);

            input_stream.indicate_used(10);
        }

        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 0),
            Err(ParseError::Incomplete)
        );
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 10);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..6]).copy_from_slice(&packet_data[10..16]);

            input_stream.indicate_used(6);
        }

        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 0),
            Err(ParseError::Incomplete)
        );
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 16);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..44]).copy_from_slice(&packet_data[16..60]);

            input_stream.indicate_used(44);
        }

        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 0),
            Ok(ParsedPacket {
                payload: b"some more testing data as payload",
                padding: &[
                    0x55, 0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91, 0xa7,
                    0x35, 0x8f, 0xad, 0x74, 0x44
                ],
                whole_packet: &[
                    0x00, 0x00, 0x00, 0x34, 0x12, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r',
                    b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't',
                    b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55,
                    0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91, 0xa7, 0x35,
                    0x8f, 0xad, 0x74, 0x44
                ],
                mac: &[]
            })
        );
        assert_eq!(input_stream.parsed_until, 56);
        assert_eq!(input_stream.decrypted_until, 56);
        assert_eq!(input_stream.data.len(), packet_data.len());

        input_stream.remove_old_data();
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.initialized_until, 4);
        assert_eq!(input_stream.data.len(), packet_data.len() - 56);

        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Err(ParseError::Incomplete)
        );
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 4);
        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[0x00, 0x00, 0x00, 0x14][..]
        );

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..]).copy_from_slice(&packet_data[60..]);

            let data_written = buf.len();
            input_stream.indicate_used(data_written);
        }
        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Ok(ParsedPacket {
                payload: b"testpayload",
                padding: &[0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10],
                whole_packet: &[
                    0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y', b'l',
                    b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10
                ],
                mac: &[]
            })
        );
        assert_eq!(input_stream.parsed_until, 24);
        assert_eq!(input_stream.decrypted_until, 24);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Err(ParseError::Incomplete)
        );

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
        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn initialization_and_packet() {
        let mut input_stream = ParserInputStream::new();
        let mut dec_algorithm = encryption::None::new();

        let packet_data = b"SSH is a protocol\r\nSSH-2.0-test@1.0\r\n\x00\x00\x00\x14\x08testpayload\x73\xae\xf8\x03\x7d\x38\x91\x10";

        {
            let buf = input_stream.reserve(packet_data.len());

            (&mut buf[..10]).copy_from_slice(&packet_data[..10]);

            input_stream.indicate_used(10);
        }

        assert_eq!(
            input_stream.parse_initialization(),
            Err(ParseError::Incomplete)
        );
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..20]).copy_from_slice(&packet_data[10..30]);

            input_stream.indicate_used(20);
        }

        assert_eq!(
            input_stream.parse_initialization(),
            Err(ParseError::Incomplete)
        );
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..10]).copy_from_slice(&packet_data[30..40]);

            input_stream.indicate_used(10);
        }

        assert_eq!(
            input_stream.parse_initialization(),
            Ok((
                VersionInformation::new("test@1.0").unwrap(),
                b"SSH-2.0-test@1.0".to_vec()
            ))
        );
        assert_eq!(input_stream.parsed_until, 37);
        assert_eq!(input_stream.decrypted_until, 37);

        {
            let buf = input_stream.reserve(0);

            (&mut buf[..]).copy_from_slice(&packet_data[40..]);

            let data_written = buf.len();
            input_stream.indicate_used(data_written);
        }

        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 0),
            Ok(ParsedPacket {
                payload: b"testpayload",
                padding: &[0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10],
                whole_packet: &[
                    0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y', b'l',
                    b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10
                ],
                mac: &[]
            })
        );
        assert_eq!(input_stream.parsed_until, packet_data.len());
        assert_eq!(input_stream.decrypted_until, packet_data.len());

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Err(ParseError::Incomplete)
        );

        input_stream.remove_old_data();
        assert_eq!(input_stream.parsed_until, 0);
        assert_eq!(input_stream.decrypted_until, 0);
        assert_eq!(input_stream.data.len(), 0);

        assert_eq!(
            &input_stream.data[input_stream.parsed_until..input_stream.initialized_until],
            &[][..]
        );
        assert_eq!(
            input_stream.parse_packet(&mut dec_algorithm, None, 0, 1),
            Err(ParseError::Incomplete)
        );
    }
}
