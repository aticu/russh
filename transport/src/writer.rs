//! Handles aggragating of data into packages.
//!
//! This is the counter part to the parser module.

use rand::RngCore;
use russh_common::{
    algorithms::{EncryptionAlgorithm, MacAlgorithm},
    writer_primitives::{write_byte, write_uint32},
};
use std::{
    cmp::{max, min},
    convert::TryInto,
    io::{self, Write},
};

use crate::{
    constants::{MIN_PACKET_LEN_ALIGN, MIN_PADDING_SIZE, PACKET_LEN_SIZE, PADDING_LEN_SIZE},
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
        rng: &mut dyn RngCore,
        distr: &mut dyn FnMut(&mut dyn RngCore) -> u8,
    ) -> u8 {
        let offset_to_next_alignment =
            align - ((payload_len + PACKET_LEN_SIZE + PADDING_LEN_SIZE) % align);

        let min_padding_len = if offset_to_next_alignment >= MIN_PADDING_SIZE {
            offset_to_next_alignment
        } else {
            offset_to_next_alignment + align
        };
        let max_padding_len = {
            let unaligned = (0xff / align) * align;

            if unaligned + offset_to_next_alignment > 0xff {
                unaligned - align + offset_to_next_alignment
            } else {
                unaligned + offset_to_next_alignment
            }
        };

        let padding_len = min_padding_len
            + min(
                distr(rng) as usize,
                (max_padding_len - min_padding_len) / align,
            ) * align;

        padding_len
            .try_into()
            .expect("padding len should fit into u8")
    }

    /// Writes a packet with the given payload to the output stream.
    ///
    /// # Panics
    /// This function may panic if the total length of the packet does not fit into a `u32`.
    pub(crate) fn write_packet(
        &mut self,
        payload: &[u8],
        encryption_algorithm: &mut dyn EncryptionAlgorithm,
        mac_algorithm: &mut dyn MacAlgorithm,
        sequence_number: u32,
        rng: &mut dyn RngCore,
        distr: &mut dyn FnMut(&mut dyn RngCore) -> u8,
    ) {
        // First calculate the correct lengths
        let align = max(
            MIN_PACKET_LEN_ALIGN,
            encryption_algorithm.cipher_block_size(),
        );
        let padding_len: u8 = self.generate_padding_len(payload.len(), align, rng, distr);
        let packet_len: u32 = (PADDING_LEN_SIZE + payload.len() + padding_len as usize)
            .try_into()
            .expect("packet size must fit into u32");

        let packet_start = self.data.len();

        // Make enough room
        self.data
            .reserve(packet_len as usize + PACKET_LEN_SIZE + mac_algorithm.mac_size());

        // Write the header
        write_uint32(packet_len, &mut self.data).expect("vec write cannot error");
        write_byte(padding_len, &mut self.data).expect("vec write cannot error");

        // Write the data
        self.data.extend_from_slice(payload);

        // Write the padding
        let padding_start = self.data.len();
        self.data.resize(padding_start + padding_len as usize, 0);
        rng.fill_bytes(&mut self.data[padding_start..]);

        // Calculate the MAC
        let mac_start = self.data.len();
        self.data
            .resize(mac_start + mac_algorithm.mac_size() as usize, 0);
        let (packet_data, mac_data) =
            self.data[packet_start..].split_at_mut(mac_start - packet_start);
        mac_algorithm.compute(packet_data, sequence_number, mac_data);

        // Encrypt the whole_packet
        encryption_algorithm.encrypt_packet(&mut self.data[packet_start..mac_start]);
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
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use russh_algorithms::{encryption, mac};

    use super::*;
    use crate::output_handler::default_padding_length_distribution;

    #[test]
    fn valid_padding_lengths() {
        // Seed it using a fixed value to ensure test stability (i.e. no errors from getting
        // entropy)
        let mut rng = ChaCha20Rng::from_seed(Default::default());
        let mut distr = default_padding_length_distribution();
        let writer = WriterOutputStream::new();

        for align in 8..256usize {
            if align.is_power_of_two() {
                for payload_len in 0..1000usize {
                    let generated_size =
                        writer.generate_padding_len(payload_len, align, &mut rng, &mut distr);
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
        let mut encryption_algorithm = encryption::None::new();
        let mut mac_algorithm = mac::None::new();
        let mut writer = WriterOutputStream::new();
        let mut distr = default_padding_length_distribution();

        assert_eq!(writer.data.len(), 0);

        writer.write_packet(
            b"some test data",
            &mut encryption_algorithm,
            &mut mac_algorithm,
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(writer.written_data(), &b"\x00\x00\x00\x24\x15some test data\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8"[..]);

        writer.write_packet(
            b"some other test data",
            &mut encryption_algorithm,
            &mut mac_algorithm,
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(writer.written_data(), &b"\x00\x00\x00\x24\x15some test data\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\x00\x00\x00\x1c\x07some other test data\x98\xba\x97\x7c\x73\x2d\x08"[..]);

        writer.remove_to(writer.written_data().len());

        assert_eq!(writer.written_data(), &b""[..]);

        writer.write_packet(
            b"a",
            &mut encryption_algorithm,
            &mut mac_algorithm,
            0,
            &mut rng,
            &mut distr,
        );

        assert_eq!(writer.written_data(), &b"\x00\x00\x00\xcc\xcaa\xd5\x71\x33\xb0\x74\xd8\x39\xd5\x31\xed\x1f\x28\x51\x0a\xfb\x45\xac\xe1\x0a\x1f\x4b\x79\x4d\x6f\x2d\x09\xa0\xe6\x63\x26\x6c\xe1\xae\x7e\xd1\x08\x19\x68\xa0\x75\x8e\x71\x8e\x99\x7b\xd3\x62\xc6\xb0\xc3\x46\x34\xa9\xa0\xb3\x5d\x01\x27\x37\x68\x1f\x7b\x5d\x0f\x28\x1e\x3a\xfd\xe4\x58\xbc\x1e\x73\xd2\xd3\x13\xc9\xcf\x94\xc0\x5f\xf3\x71\x62\x40\xa2\x48\xf2\x13\x20\xa0\x58\xd7\xb3\x56\x6b\xd5\x20\xda\xaa\x3e\xd2\xbf\x0a\xc5\xb8\xb1\x20\xfb\x85\x27\x73\xc3\x63\x97\x34\xb4\x5c\x91\xa4\x2d\xd4\xcb\x83\xf8\x84\x0d\x2e\xed\xb1\x58\x13\x10\x62\xac\x3f\x1f\x2c\xf8\xff\x6d\xcd\x18\x56\xe8\x6a\x1e\x6c\x31\x67\x16\x7e\xe5\xa6\x88\x74\x2b\x47\xc5\xad\xfb\x59\xd4\xdf\x76\xfd\x1d\xb1\xe5\x1e\xe0\x3b\x1c\xa9\xf8\x2a\xca\x17\x3e\xdb\x8b\x72\x93\x47\x4e\xbe\x98\x0f\x90\x4d\x10\xc9\x16\x44\x2b\x47\x83\xa0\xe9\x84\x86\x0c"[..]);
    }
}
