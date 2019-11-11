//! Implements the key expansions for the encryption and MAC algorithms.

use num_bigint::BigInt;
use russh_common::{algorithms::KeyExchangeHashFunction, writer_primitives::write_mpint};

/// References the buffers where the keys are generated.
pub(super) struct Keys<'a> {
    /// The encryption IV used for client to server communication.
    pub(super) encryption_client_to_server_iv: &'a mut [u8],
    /// The encryption IV used for server to client communication.
    pub(super) encryption_server_to_client_iv: &'a mut [u8],
    /// The encryption key used for client to server communication.
    pub(super) encryption_client_to_server_key: &'a mut [u8],
    /// The encryption key used for server to client communication.
    pub(super) encryption_server_to_client_key: &'a mut [u8],
    /// The mac key used for client to server communication.
    pub(super) mac_client_to_server_key: &'a mut [u8],
    /// The mac key used for server to client communication.
    pub(super) mac_server_to_client_key: &'a mut [u8],
}

pub(super) fn expand_keys(
    keys: &mut Keys,
    hash_fn: KeyExchangeHashFunction,
    shared_secret: &BigInt,
    exchange_hash: &[u8],
    session_id: &[u8],
) {
    // `key_vec` is a vector constructed as
    // `HASH(shared_secret || exchange_hash || X || session_id)` according to section 7.2 of
    // RFC 4253
    //
    // X is one of `"A"`, `"B"`, `"C"`, `"D"`, `"E"` or `"F"`, depending on the algorithm.
    let (letter_offset, mut initial_key_vec) = {
        let mut key_vec = Vec::new();

        write_mpint(shared_secret, &mut key_vec).expect("vec writes cannot fail");
        key_vec.reserve_exact(exchange_hash.len() + 1 + session_id.len());
        key_vec.extend(exchange_hash);

        let letter_offset = key_vec.len();

        // This will be replaced with the correct value for the given algorithm.
        key_vec.extend(b"X");
        key_vec.extend(session_id);

        (letter_offset, key_vec)
    };

    let mut expanded_key_vec = None;

    let mut expand_into_slice = |slice: &mut [u8], letter: u8| {
        initial_key_vec[letter_offset] = letter;

        let mut vec = hash_fn(&initial_key_vec);
        expand_key(
            &mut vec,
            &mut expanded_key_vec,
            shared_secret,
            exchange_hash,
            slice.len(),
            hash_fn,
        );

        slice.copy_from_slice(&vec[..slice.len()]);
    };

    expand_into_slice(keys.encryption_client_to_server_iv, b'A');
    expand_into_slice(keys.encryption_server_to_client_iv, b'B');
    expand_into_slice(keys.encryption_client_to_server_key, b'C');
    expand_into_slice(keys.encryption_server_to_client_key, b'D');
    expand_into_slice(keys.mac_client_to_server_key, b'E');
    expand_into_slice(keys.mac_server_to_client_key, b'F');
}

/// Expands the given key to the needed size.
pub(super) fn expand_key(
    key: &mut Vec<u8>,
    expanded_key_vec: &mut Option<Vec<u8>>,
    shared_secret: &BigInt,
    exchange_hash: &[u8],
    len: usize,
    hash_fn: KeyExchangeHashFunction,
) {
    if key.len() >= len {
        return;
    }

    let key_vec = expanded_key_vec.get_or_insert_with(|| {
        let mut vec = Vec::new();

        write_mpint(shared_secret, &mut vec).expect("vec writes cannot fail");
        vec.extend(exchange_hash);

        vec
    });

    let start_len = key_vec.len();

    key_vec.extend(&key[..]);

    while key.len() < len {
        let hash = hash_fn(&key_vec);
        key.extend(&hash);
        key_vec.extend(&hash);
    }

    key_vec.truncate(start_len);
}
