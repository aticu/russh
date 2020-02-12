//! Provides and implementation of the "chacha20-poly1305@openssh.com" encryption algorithm.

use chacha20::{
    stream_cipher::{
        generic_array::GenericArray, NewStreamCipher, StreamCipher, SyncStreamCipher,
        SyncStreamCipherSeek,
    },
    ChaCha20Legacy,
};
use poly1305::{
    universal_hash::{self, UniversalHash},
    Poly1305,
};
use russh_common::{
    algorithms::{Algorithm, AlgorithmCategory, EncryptionAlgorithm, EncryptionContext},
    parser_primitives::parse_uint32,
    writer_primitives::write_uint64,
};
use std::{fmt, mem};

/// Implements the `chacha20-poly1305@openssh.com` encryption algorithm.
///
/// The existence of this struct is controlled by the `chacha20-poly1305@openssh.com` feature.
pub struct ChaCha20Poly1305 {
    /// The keys that the cipher uses when active.
    keys: Option<[u8; 64]>,
}

/// The size of a MAC generated by `chacha20-poly1305`.
const MAC_SIZE: usize = 16;

impl ChaCha20Poly1305 {
    /// Creates a new `chacha20-poly1305@openssh.com` encryption algorithm.
    pub fn new() -> Self {
        Self { keys: None }
    }

    /// Creates a new boxed `chacha20-poly1305@openssh.com` encryption algorithm.
    pub fn boxed() -> Box<Self> {
        Box::new(Self::new())
    }

    /// Encrypts the given length of a packet.
    fn encrypt_packet_length(&self, packet: &mut [u8], packet_sequence_number: u32) {
        debug_assert_eq!(packet.len(), mem::size_of::<u32>());

        let keys = self
            .keys
            .as_ref()
            .expect("keys were loaded before decryption");

        let nonce_array = generate_nonce(packet_sequence_number);

        let key = GenericArray::from_slice(&keys[32..]);
        let nonce = GenericArray::from_slice(&nonce_array);

        let mut cipher = ChaCha20Legacy::new(&key, &nonce);

        cipher.decrypt(&mut packet[..mem::size_of::<u32>()]);

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
    fn as_basic_algorithm(&self) -> &dyn Algorithm {
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

    fn load_key(&mut self, _iv: &[u8], key: &[u8]) {
        debug_assert_eq!(key.len(), self.key_size());

        let old_value = self.keys.replace([0; 64]);

        debug_assert!(old_value.is_none());

        let array = self
            .keys
            .as_mut()
            .expect("option that was just filled was actually filled");

        array.copy_from_slice(key);
    }

    fn unload_key(&mut self) {
        let array = self
            .keys
            .as_mut()
            .expect("keys were loaded before they are unloaded");

        for elem in array.iter_mut() {
            *elem = 0;
        }

        self.keys.take();
    }

    fn encrypt_packet(&mut self, mut context: EncryptionContext) {
        let len = parse_uint32(context.unprocessed_part())
            .expect("packet must be large enough")
            .1;

        debug_assert_eq!(
            len as usize + MAC_SIZE + 4,
            context.unprocessed_part().len()
        );

        let packet_sequence_number = context.packet_sequence_number();

        self.encrypt_packet_length(
            &mut context.unprocessed_part()[..mem::size_of::<u32>()],
            packet_sequence_number,
        );

        let mut cipher = {
            let keys = self
                .keys
                .as_ref()
                .expect("keys were loaded before decryption");

            let nonce_array = generate_nonce(packet_sequence_number);
            let key = GenericArray::from_slice(&keys[..32]);
            let nonce = GenericArray::from_slice(&nonce_array);

            ChaCha20Legacy::new(&key, &nonce)
        };

        let mut poly_key = [0u8; 32];

        cipher.apply_keystream(&mut poly_key);

        cipher.seek(64);

        cipher.apply_keystream(
            &mut context.unprocessed_part()
                [mem::size_of::<u32>()..mem::size_of::<u32>() + len as usize],
        );

        // Safety
        //
        // Safe because the instance of the cipher is dropped immediately after it's zeroed and
        // therefore cannot be read in an invalid state.
        unsafe { zero_cipher(&mut cipher) };
        mem::drop(cipher);

        let mut poly = Poly1305::new(GenericArray::from_slice(&poly_key));

        poly.update(&context.unprocessed_part()[..mem::size_of::<u32>() + len as usize]);

        let calculated_mac = poly.result();

        context.unprocessed_part()[mem::size_of::<u32>() + len as usize..]
            .copy_from_slice(&calculated_mac.into_bytes());
    }

    fn decrypt_packet(&mut self, _context: EncryptionContext) -> usize {
        unimplemented!()
    }

    fn mac_size(&self) -> Option<usize> {
        Some(MAC_SIZE)
    }

    fn authenticated_decrypt_packet(&mut self, mut context: EncryptionContext) -> Option<usize> {
        if context.processed_part().len() < mem::size_of::<u32>()
            && context.unprocessed_part().len() < mem::size_of::<u32>()
        {
            return Some(0);
        }

        let mut bytes_decrypted = 0;
        let packet_sequence_number = context.packet_sequence_number();

        if context.processed_part().len() < mem::size_of::<u32>() {
            self.decrypt_packet_length(
                &mut context.unprocessed_part()[..mem::size_of::<u32>()],
                packet_sequence_number,
            );

            bytes_decrypted += mem::size_of::<u32>();
            context.mark_processed(mem::size_of::<u32>());
        }

        debug_assert_eq!(context.processed_part().len(), mem::size_of::<u32>());

        let len = parse_uint32(context.processed_part())
            .expect("packet length can be parsed")
            .1;

        // TODO: should usize or u32 be used for the comparison here? Check elsewhere for `as` too.
        if len + MAC_SIZE as u32 <= context.unprocessed_part().len() as u32 {
            // If the whole packet does not arrived at once, the packet length still needs to be
            // decrypted because of the restriction that as much as possible must be decrypted in
            // one invocation of `authenticated_decrypt_packet`. Since the first invocation ends
            // after decrypting the length, all local variables are lost and therefore no local
            // copy of the encrypted version of the length can be stored. The easiest (and most
            // stable) option to get the encrypted packet length required for the MAC calculation
            // is to simply reencrypt it here. This is being implemented here.
            let len_array = {
                let mut array = [0u8; 4];

                for (target, source) in array.iter_mut().zip(context.processed_part().iter()) {
                    *target ^= *source;
                }

                self.encrypt_packet_length(&mut array[..], packet_sequence_number);

                array
            };

            let mut cipher = {
                let keys = self
                    .keys
                    .as_ref()
                    .expect("keys were loaded before decryption");

                let nonce_array = generate_nonce(packet_sequence_number);
                let key = GenericArray::from_slice(&keys[..32]);
                let nonce = GenericArray::from_slice(&nonce_array);

                ChaCha20Legacy::new(&key, &nonce)
            };

            let mut poly_key = [0u8; 32];

            cipher.apply_keystream(&mut poly_key);

            let (packet, mac) = &mut context.unprocessed_part()[..len as usize + MAC_SIZE]
                .split_at_mut(len as usize);

            let mut poly = Poly1305::new(GenericArray::from_slice(&poly_key));

            poly.update(&len_array);
            poly.update(packet);

            let calculated_mac = poly.result();

            if calculated_mac != universal_hash::Output::new(GenericArray::from_slice(mac).clone())
            {
                return None;
            }

            // Perform the actual decryption with a block counter of one (offset of 64 in stream).
            cipher.seek(64);
            cipher.apply_keystream(packet);
            bytes_decrypted += packet.len();

            // Safety
            //
            // Safe because the instance of the cipher is dropped immediately after it's zeroed and
            // therefore cannot be read in an invalid state.
            unsafe { zero_cipher(&mut cipher) };
            mem::drop(cipher);

            // TODO: use zeroize here to ensure that this won't get optimized away
            for byte in poly_key.iter_mut() {
                *byte = 0;
            }
        }

        Some(bytes_decrypted)
    }
}

/// Generates the nonce for the encryption algorithms.
fn generate_nonce(packet_sequence_number: u32) -> [u8; mem::size_of::<u64>()] {
    let mut nonce_array = [0; mem::size_of::<u64>()];

    write_uint64(packet_sequence_number.into(), &mut &mut nonce_array[..])
        .expect("write can't fail");

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

    for elem in reinterpreted.iter_mut() {
        *elem = 0;
    }
}
