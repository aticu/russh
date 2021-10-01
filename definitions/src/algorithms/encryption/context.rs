//! Defines the context used for encryption and decryption of packets.

/// Describes the encryption or decryption context of a packet.
#[derive(Debug)]
pub struct EncryptionContext<'packet> {
    /// The sequence number that the packet has.
    packet_sequence_number: u32,
    /// The data of the packet that is being processed.
    data: &'packet mut [u8],
    /// The offset of the first byte in the data that is not yet processed.
    processed_until: usize,
}

impl EncryptionContext<'_> {
    /// Creates a new `EncryptionContext` from the given data.
    pub fn new(
        packet_sequence_number: u32,
        data: &mut [u8],
        processed_until: usize,
    ) -> EncryptionContext {
        EncryptionContext {
            packet_sequence_number,
            data,
            processed_until,
        }
    }

    /// Returns the sequence number of the packet that is being processed.
    pub fn packet_sequence_number(&self) -> u32 {
        self.packet_sequence_number
    }

    /// Returns the part of the packet that was already processed.
    ///
    /// # Encryption
    /// If `EncryptionContext` is passed to `encrypt_packet`, this will always contain the entire
    /// packet, as the encryption always takes place in one pass.
    ///
    /// # Decryption
    /// If `EncryptionContext` is passed to `decrypt_packet`, this will be the part of the packet
    /// that was already decrypted.
    pub fn processed_part(&self) -> &[u8] {
        &self.data[..self.processed_until]
    }

    /// Returns all packet data in the context.
    ///
    /// **The processed part must be restored as it was when the encryption algorithm was called,
    /// before the encryption or decryption function returns.**
    ///
    /// This method should be used with caution, as the already decrypted data should not be
    /// changed.
    /// Some algorithms, such as "chacha20poly1305@openssh.com", however require access to the
    /// whole undecrypted packet for the MAC calculation.
    /// Reencrypting the decrypted part of the packet and restoring it later is a feasible solution
    /// in this case.
    ///
    /// # Encryption
    /// If `EncryptionContext` is passed to `encrypt_packet`, this will always contain the entire
    /// packet, as the encryption always takes place in one pass.
    ///
    /// # Decryption
    /// If `EncryptionContext` is passed to `decrypt_packet`, this will be the part of the packet
    /// that was already decrypted.
    pub fn all_data_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// Returns the part of the packet that has yet to be processed.
    ///
    /// # Encryption
    /// If `EncryptionContext` is passed to `encrypt_packet`, this will always be empty, as the
    /// encryption always takes place in one pass.
    ///
    /// # Decryption
    /// If `EncryptionContext` is passed to `decrypt_packet`, this will be the part of the packet
    /// that still needs to be decrypted.
    pub fn unprocessed_part(&mut self) -> &mut [u8] {
        &mut self.data[self.processed_until..]
    }

    /// Returns a reference to both the processed and the unprocessed part of the packet.
    pub fn all_data(&self) -> &[u8] {
        self.data
    }

    /// Marks that an additional `num_bytes` have been processed.
    pub fn mark_processed(&mut self, num_bytes: usize) {
        self.processed_until += num_bytes;
    }
}
