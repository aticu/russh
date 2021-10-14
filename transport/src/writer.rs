//! Handles aggragating of data into packages.
//!
//! This is the counter part to the `parser` module.

use definitions::{algorithms::internal::CryptoRngCore, write};
use std::{
    cmp::{max, min},
    convert::TryInto,
    io::{self, Write},
};

use crate::{
    algorithms::{EncryptionAlgorithmEntry, EncryptionContext, MacAlgorithmEntry},
    constants::{
        MAX_PADDING_SIZE, MIN_PACKET_LEN_ALIGN, MIN_PADDING_SIZE, PACKET_LEN_SIZE, PADDING_LEN_SIZE,
    },
    version::VersionInformation,
};

/// Writes the version information to the output.
pub(crate) fn write_version_info(
    input: &VersionInformation,
    output: &mut impl Write,
) -> io::Result<()> {
    write!(
        output,
        "SSH-{}-{}\r\n",
        input.protocol_version(),
        input.software_version()
    )
}

/// Handles writing packets to a stream that is ready for the network.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WriterOutputStream {
    /// The underlying stream where data is written to.
    data: Vec<u8>,
}

impl WriterOutputStream {
    /// Creates a new writer output stream.
    pub(crate) fn new() -> WriterOutputStream {
        WriterOutputStream { data: vec![] }
    }

    /// Generates a valid random padding length for the given payload.
    fn generate_padding_len(
        &self,
        payload_len: usize,
        align: usize,
        rng: &mut dyn CryptoRngCore,
        padding_distribution: &mut dyn FnMut(&mut dyn CryptoRngCore) -> u8,
        include_packet_length: bool,
    ) -> u8 {
        let optional_packet_len_size = if include_packet_length {
            PACKET_LEN_SIZE
        } else {
            0
        };

        // Each packet's length (including padding length) needs to be a multiple of `align`.
        let offset_to_next_alignment =
            align - ((payload_len + optional_packet_len_size + PADDING_LEN_SIZE) % align);

        let min_padding_len = if offset_to_next_alignment >= MIN_PADDING_SIZE {
            offset_to_next_alignment
        } else {
            offset_to_next_alignment + align
        };

        let max_padding_len = {
            let max_padding_unaligned = (MAX_PADDING_SIZE / align) * align;

            if offset_to_next_alignment + max_padding_unaligned > MAX_PADDING_SIZE {
                offset_to_next_alignment + max_padding_unaligned - align
            } else {
                offset_to_next_alignment + max_padding_unaligned
            }
        };

        let padding_len = max(
            min_padding_len,
            min(
                offset_to_next_alignment + padding_distribution(rng) as usize * align,
                max_padding_len,
            ),
        );

        padding_len
            .try_into()
            .expect("padding len should fit into u8")
    }

    /// Writes the header of the packet.
    fn write_header(&mut self, packet_len: u32, padding_len: u8) {
        write::uint32(packet_len, &mut self.data).expect("vec write cannot error");
        write::byte(padding_len, &mut self.data).expect("vec write cannot error");
    }

    /// Writes the payload of the packet.
    fn write_payload(&mut self, payload: &[u8]) {
        self.data.extend_from_slice(payload);
    }

    /// Writes the padding of the packet.
    fn write_padding(&mut self, padding_len: u8, rng: &mut dyn CryptoRngCore) {
        let padding_start = self.data.len();

        self.data.resize(padding_start + padding_len as usize, 0);
        rng.fill_bytes(&mut self.data[padding_start..]);
    }

    /// Writes the MAC of the packet.
    fn write_mac(
        &mut self,
        packet_start: usize,
        sequence_number: u32,
        mac_algorithm: &mut MacAlgorithmEntry,
    ) {
        let mac_start = self.data.len();
        let mac_len = mac_algorithm.mac_size;

        self.data.resize(mac_start + mac_len as usize, 0);
        let (packet_data, mac_data) =
            self.data[packet_start..].split_at_mut(mac_start - packet_start);

        mac_algorithm.compute(packet_data, sequence_number, mac_data);
    }

    /// Writes a packet with the given payload to the output stream.
    ///
    /// # Panics
    /// This function may panic if the total length of the packet does not fit into a `u32`.
    pub(crate) fn write_packet(
        &mut self,
        payload: &[u8],
        encryption_algorithm: &mut EncryptionAlgorithmEntry,
        mac_algorithm: Option<&mut MacAlgorithmEntry>,
        sequence_number: u32,
        rng: &mut dyn CryptoRngCore,
        distr: &mut dyn FnMut(&mut dyn CryptoRngCore) -> u8,
    ) {
        let align = max(MIN_PACKET_LEN_ALIGN, encryption_algorithm.cipher_block_size);
        // TODO: check for ETM here, once its implemented
        let include_packet_length = !encryption_algorithm.computes_mac();
        let padding_len: u8 =
            self.generate_padding_len(payload.len(), align, rng, distr, include_packet_length);
        let packet_len: u32 = (PADDING_LEN_SIZE + payload.len() + padding_len as usize)
            .try_into()
            .expect("packet size must fit into u32");
        let mac_len = mac_algorithm
            .as_ref()
            .map(|alg| alg.mac_size)
            .unwrap_or_else(|| {
                encryption_algorithm.mac_size.expect(
                    "encryption algorithm is authenticated when no MAC algorithm is present",
                )
            });

        let packet_start = self.data.len();
        self.data
            .reserve(packet_len as usize + PACKET_LEN_SIZE + mac_len);

        self.write_header(packet_len, padding_len);
        self.write_payload(payload);
        self.write_padding(padding_len, rng);

        let mac_start = self.data.len();
        if let Some(mac_algorithm) = mac_algorithm {
            self.write_mac(packet_start, sequence_number, mac_algorithm);
        }

        let optional_mac_len = if let Some(mac_size) = encryption_algorithm.mac_size {
            self.data.resize(mac_start + mac_size, 0);
            mac_size
        } else {
            0
        };

        encryption_algorithm.encrypt_packet(EncryptionContext::new(
            sequence_number,
            &mut self.data[packet_start..mac_start + optional_mac_len],
            0,
        ));
    }

    /// Writes the given version information to the output stream.
    pub(crate) fn write_version_info(&mut self, version_info: &VersionInformation) {
        write_version_info(version_info, &mut self.data).expect("vec write cannot error");
    }

    /// Returns all the non-removed data that has been written so far.
    ///
    /// This function is meant to be used to output the data to the network.
    /// Afterward the amound of data written to the network should be removed
    /// with `remove_to`.
    pub(crate) fn written_data(&self) -> &[u8] {
        &self.data
    }

    /// Removes data up to the given index.
    pub(crate) fn remove_to(&mut self, index: usize) {
        self.data.drain(..index);
    }
}

#[cfg(test)]
mod tests {
    use algorithms::{encryption, mac};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::padding_length;

    #[test]
    fn valid_padding_lengths() {
        // Seed it using a fixed value to ensure test stability (i.e. no errors from getting
        // entropy)
        let mut rng = ChaCha20Rng::from_seed(Default::default());
        let mut distr = padding_length::default_distribution();
        let writer = WriterOutputStream::new();

        for align in 8..256usize {
            if align.is_power_of_two() {
                for payload_len in 0..1000usize {
                    let generated_size =
                        writer.generate_padding_len(payload_len, align, &mut rng, &mut distr, true);
                    assert_eq!(
                        (PACKET_LEN_SIZE
                            + PADDING_LEN_SIZE
                            + payload_len
                            + generated_size as usize)
                            % align,
                        0,
                        "wrong padding for align {} and payload_len {}",
                        align,
                        payload_len
                    );
                }
            }
        }
    }

    #[test]
    fn append_packet_none() {
        // Seed it using a fixed value to ensure test stability (always the same values)
        let mut rng = ChaCha20Rng::from_seed(Default::default());
        let mut encryption_algorithm = encryption::None::new().into();
        let mut mac_algorithm = mac::None::new().into();
        let mut writer = WriterOutputStream::new();
        let mut distr = padding_length::default_distribution();

        assert_eq!(writer.data.len(), 0);

        writer.write_packet(
            b"some test data",
            &mut encryption_algorithm,
            Some(&mut mac_algorithm),
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(
            writer.written_data(),
            &b"\x00\x00\x00\x14\x05some test data\xa8\x36\xef\xcc\x8b"[..]
        );

        writer.write_packet(
            b"some other test data",
            &mut encryption_algorithm,
            Some(&mut mac_algorithm),
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(writer.written_data(), &b"\x00\x00\x00\x14\x05some test data\xa8\x36\xef\xcc\x8b\x00\x00\x00\x1c\x07some other test data\xc3\x87\xb6\x69\xb2\xee\x65"[..]);

        writer.remove_to(writer.written_data().len());

        assert_eq!(writer.written_data(), &b""[..]);

        writer.write_packet(
            b"a",
            &mut encryption_algorithm,
            Some(&mut mac_algorithm),
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(
            writer.written_data(),
            &b"\x00\x00\x00\x0c\x0aa\x12\xc6\x53\x3e\x32\xee\x7a\xed\x29\xb7"[..]
        );
    }
}
