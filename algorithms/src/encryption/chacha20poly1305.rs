//! Provides an implementation of the "chacha20-poly1305@openssh.com" encryption algorithm.

use chacha20::{
    cipher::{NewCipher as _, StreamCipher as _, StreamCipherSeek as _},
    ChaCha20Legacy,
};
use poly1305::{
    universal_hash::{generic_array::GenericArray, NewUniversalHash as _},
    Poly1305,
};
use zeroize::Zeroize as _;

use std::{fmt, mem};

use russh_definitions::{
    algorithms::{Algorithm, AlgorithmCategory, EncryptionAlgorithm, EncryptionContext},
    parse, write,
};

/// The size of a MAC generated by `chacha20-poly1305`.
const MAC_SIZE: usize = 16;

/// The size of the encoded packet length.
const LEN_SIZE: usize = mem::size_of::<u32>();

/// Implements the `chacha20-poly1305@openssh.com` encryption algorithm.
///
/// The existence of this struct is controlled by the `chacha20-poly1305_at_openssh_com` feature.
#[derive(Default, Clone)]
pub struct ChaCha20Poly1305 {
    /// The keys used by the algorithms.
    keys: Option<[u8; 64]>,
}

impl ChaCha20Poly1305 {
    /// Creates a new `chacha20-poly1305@openssh.com` encryption algorithm.
    pub fn new() -> Self {
        Self { keys: None }
    }

    /// Creates a new boxed `chacha20-poly1305@openssh.com` encryption algorithm.
    pub fn boxed() -> Box<dyn EncryptionAlgorithm> {
        Box::new(Self::new())
    }

    /// Returns the key used to encrypt the packet lengths.
    ///
    /// # Panics
    /// This function will panic if no key was loaded.
    fn length_key(&self) -> &[u8] {
        &self.keys.as_ref().unwrap()[32..]
    }

    /// Returns the key used to encrypt the packet data.
    ///
    /// # Panics
    /// This function will panic if no key was loaded.
    fn data_key(&self) -> &[u8] {
        &self.keys.as_ref().unwrap()[..32]
    }

    /// Encrypts the given length of a packet.
    fn encrypt_packet_length(&self, packet: &mut [u8], packet_sequence_number: u32) {
        let mut cipher = ChaCha20Legacy::new_from_slices(
            self.length_key(),
            &generate_nonce(packet_sequence_number)[..],
        )
        .unwrap();

        cipher.apply_keystream(&mut packet[..LEN_SIZE]);

        // Safety
        //
        // Safe because the instance of the cipher is dropped immediately after it's zeroed and
        // therefore cannot be read in an invalid state.
        unsafe { zero_cipher(&mut cipher) };
        mem::drop(cipher);
    }

    /// Decrypts the given length of a packet.
    fn decrypt_packet_length(&self, packet: &mut [u8], packet_sequence_number: u32) {
        // Uses the fact that encryption and decryption for chacha20 is the same operation
        self.encrypt_packet_length(packet, packet_sequence_number)
    }
}

impl fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "`chacha20-poly1305@openssh.com` encryption algorithm")
    }
}

impl Algorithm for ChaCha20Poly1305 {
    fn name(&self) -> &'static str {
        "chacha20-poly1305@openssh.com"
    }

    fn category(&self) -> AlgorithmCategory {
        AlgorithmCategory::Encryption
    }
}

impl EncryptionAlgorithm for ChaCha20Poly1305 {
    fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
        self
    }

    fn cipher_block_size(&self) -> usize {
        1
    }

    fn key_size(&self) -> usize {
        64
    }

    fn iv_size(&self) -> usize {
        0
    }

    fn load_key(&mut self, iv: &[u8], key: &[u8]) {
        debug_assert_eq!(iv.len(), self.iv_size());

        if self.keys.is_some() {
            self.unload_key();
        }

        use std::convert::TryInto as _;
        assert!(self.keys.replace(key.try_into().unwrap()).is_none());
    }

    fn unload_key(&mut self) {
        self.keys.as_mut().unwrap().zeroize();
        self.keys.take();
    }

    fn encrypt_packet(&mut self, mut context: EncryptionContext) {
        let len = parse::uint32(context.unprocessed_part()).unwrap().value;

        assert_eq!(
            LEN_SIZE + len as usize + MAC_SIZE,
            context.unprocessed_part().len()
        );

        let packet_sequence_number = context.packet_sequence_number();

        self.encrypt_packet_length(context.unprocessed_part(), packet_sequence_number);

        let mut cipher = ChaCha20Legacy::new_from_slices(
            self.data_key(),
            &generate_nonce(packet_sequence_number)[..],
        )
        .unwrap();

        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);

        cipher.seek(64);
        cipher.apply_keystream(&mut context.unprocessed_part()[LEN_SIZE..LEN_SIZE + len as usize]);

        // Safety
        //
        // Safe because the instance of the cipher is dropped immediately after it's zeroed and
        // therefore cannot be read in an invalid state.
        unsafe { zero_cipher(&mut cipher) };
        mem::drop(cipher);

        let poly = Poly1305::new(&poly_key.into());
        poly_key.zeroize();

        let calculated_mac =
            poly.compute_unpadded(&context.unprocessed_part()[..LEN_SIZE + len as usize]);

        context.unprocessed_part()[LEN_SIZE + len as usize..]
            .copy_from_slice(&calculated_mac.into_bytes());
    }

    fn decrypt_packet(&mut self, _context: EncryptionContext) -> usize {
        unimplemented!()
    }

    fn mac_size(&self) -> Option<usize> {
        Some(MAC_SIZE)
    }

    fn authenticated_decrypt_packet(&mut self, mut context: EncryptionContext) -> Option<usize> {
        if context.processed_part().len() < LEN_SIZE && context.unprocessed_part().len() < LEN_SIZE
        {
            return Some(0);
        }

        let mut bytes_decrypted = 0;
        let packet_sequence_number = context.packet_sequence_number();

        if context.processed_part().len() < LEN_SIZE {
            self.decrypt_packet_length(&mut context.unprocessed_part(), packet_sequence_number);

            bytes_decrypted += LEN_SIZE;
            context.mark_processed(LEN_SIZE);
        }

        let len = parse::uint32(context.processed_part()).unwrap().value;

        // TODO: should usize or u32 be used for the comparison here? Check elsewhere for `as` too.
        if len + MAC_SIZE as u32 > context.unprocessed_part().len() as u32 {
            return Some(bytes_decrypted);
        }

        let mut cipher = ChaCha20Legacy::new_from_slices(
            self.data_key(),
            &generate_nonce(packet_sequence_number)[..],
        )
        .unwrap();

        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);

        // Reencrypt the packet length for the poly calculation, but keep the unencrypted version
        // around to restore it later
        use std::convert::TryInto as _;
        let decrypted_len_buf: [u8; LEN_SIZE] =
            context.processed_part()[..LEN_SIZE].try_into().unwrap();
        self.encrypt_packet_length(context.all_data_mut(), packet_sequence_number);

        let (packet, mac) = &mut context.all_data_mut()[..LEN_SIZE + len as usize + MAC_SIZE]
            .split_at_mut(LEN_SIZE + len as usize);

        let poly = Poly1305::new(&poly_key.into());
        poly_key.zeroize();
        let calculated_mac = poly.compute_unpadded(packet);

        if calculated_mac != GenericArray::from_slice(mac).into() {
            // Restore the decrypted packet length in the buffer before returning
            context.all_data_mut()[..LEN_SIZE].copy_from_slice(&decrypted_len_buf);
            return None;
        }

        // Perform the actual decryption with a block counter of one (offset of 64 in stream).
        cipher.seek(64);
        cipher.apply_keystream(&mut packet[LEN_SIZE..]);
        bytes_decrypted += packet.len();

        // Now restore the decrypted packet length in the buffer
        context.all_data_mut()[..LEN_SIZE].copy_from_slice(&decrypted_len_buf);

        // Safety
        //
        // Safe because the instance of the cipher is dropped immediately after it's zeroed and
        // therefore cannot be read in an invalid state.
        unsafe { zero_cipher(&mut cipher) };
        mem::drop(cipher);

        Some(bytes_decrypted)
    }
}

/// Generates the nonce for the encryption algorithms.
fn generate_nonce(packet_sequence_number: u32) -> [u8; mem::size_of::<u64>()] {
    let mut nonce_array = [0; mem::size_of::<u64>()];

    write::uint64(packet_sequence_number.into(), &mut &mut nonce_array[..]).unwrap();

    nonce_array
}

/// Zeroes the data of the cipher.
///
/// The cipher must be passed by reference to avoid making a copy of it.
///
/// # Safety
/// After calling the function the cipher should be dropped without using it.
unsafe fn zero_cipher(cipher: &mut ChaCha20Legacy) {
    // Make sure that dropping the instance does not affect anything
    static_assertions::assert_not_impl_all!(ChaCha20Legacy: Drop);

    let reinterpreted: &mut [u8; mem::size_of::<ChaCha20Legacy>()] = mem::transmute(cipher);

    reinterpreted.zeroize();
}
