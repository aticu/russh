//! Provides traits to define algorithms used in the transport layer.

use num_bigint::BigInt;
use rand::RngCore;
use std::{borrow::Cow, error::Error};

use crate::ConnectionRole;

/// Defines things which are common across all algorithm types.
pub trait Algorithm {
    /// Returns the name of the algorithm.
    ///
    /// The returned name should follow the restrictions for algorithm names in
    /// [RFC4351](https://tools.ietf.org/html/rfc4251#section-6).
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn name(&self) -> &'static str;
}

/// The data needed to perform a key exchange.
#[derive(Debug)]
pub struct KeyExchangeData<'a> {
    /// The identification string of the client.
    pub client_identification: &'a [u8],
    /// The identification string of the server.
    pub server_identification: &'a [u8],
    /// The `SSH_MSG_KEXINIT` packet of the client.
    pub client_kexinit: &'a [u8],
    /// The `SSH_MSG_KEXINIT` packet of the server.
    pub server_kexinit: &'a [u8],
}

/// Represents a response to a key exchange packet.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyExchangeResponse {
    /// The key exchange is finished.
    ///
    /// This means, that the key exchange algorithm can no longer control the traffic.
    Finished {
        /// The host key used by the server.
        ///
        /// This is only required for the client side of the key exchange.
        /// On the server side `None` should be returned.
        ///
        /// This can be used by the client to determine if the host key is known to belong to the
        /// server.
        host_key: Option<Vec<u8>>,
        /// The shared secret that was generated during the key exchange.
        shared_secret: BigInt,
        /// The exchange hash that was generated during the key exchange.
        exchange_hash: Vec<u8>,
        /// A final message to send, so the connection partner can finish the key exchange too.
        message: Option<Vec<u8>>,
    },
    /// The key exchange is continued by sending the contained packet to the partner.
    Packet(Vec<u8>),
}

/// The type of a hash function returned by a key exchange algorithm.
pub type KeyExchangeHashFunction = fn(&[u8]) -> Vec<u8>;

/// Describes a key exchange algorithm.
pub trait KeyExchangeAlgorithm: Algorithm {
    /// Required, because Rust doesn't implement upcasting.
    ///
    /// Should be implemented like this:
    ///
    /// ```ignore
    /// fn as_basic_algorithm(&self) -> &dyn Algorithm { self }
    /// ```
    fn as_basic_algorithm(&self) -> &dyn Algorithm;

    /// Whether the key exchange algorithm requires an encryption capable host key algorithm.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    ///
    /// # Note
    /// This and `self.requires_signature_capable_host_key_algorithm` may not both return true.
    fn requires_encryption_capable_host_key_algorithm(&self) -> bool;

    /// Whether the key exchange algorithm requires a signature capable host key algorithm.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    ///
    /// # Note
    /// This and `self.requires_encryption_capable_host_key_algorithm` may not both return true.
    fn requires_signature_capable_host_key_algorithm(&self) -> bool;

    /// Starts a new key exchange from the perspective of `role`.
    ///
    /// This method must reset any internal state such that a new key exchange can start.
    /// Implementations must be able to deal with this method being called at any point in the key
    /// exchange.
    ///
    /// If the `role` argument passed corresponds to the initating role of the key exchange,
    /// a packet to initiate a new key exchange should be returned.
    /// Otherwise only initialization should be performed.
    /// For example in the [Diffie-Hellman Key
    /// Exchange](https://tools.ietf.org/html/rfc4253#section-8), the client is the initiating
    /// role.
    fn start(
        &mut self,
        role: &ConnectionRole,
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut dyn HostKeyAlgorithm,
        rng: &mut dyn RngCore,
    ) -> Option<Vec<u8>>;

    /// Responds to the given key exchange message.
    ///
    /// If further message exchange is required for the key exchange to complete, the first
    /// such message is returned as `Ok(KeyExchangeResponse::Packet(_))`.
    ///
    /// If the key exchange finished successfully, `Ok(KeyExchangeResponse::Finished)` is returned.
    /// Otherwise an error is returned.
    ///
    /// # Note on the Connection role
    /// The connection role is not passed to this method.
    /// It should instead be saved from the role passed in `start`.
    ///
    /// The reasoning for this is, that it eliminates the need to care about starting a key
    /// exchange in a specific role and then changing the role mid-exchange when implmenenting the
    /// `KeyExchangeAlgorithm` trait.
    ///
    /// With this design the only way to change the role is to call `start`, which initiates a
    /// completely new key exchange.
    ///
    /// # Panics
    /// - This method may panic if `start` was not called before `respond`.
    fn respond(
        &mut self,
        message: &[u8],
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut dyn HostKeyAlgorithm,
        rng: &mut dyn RngCore,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError>;

    /// Returns the hash function used by this key exchange algorithm.
    ///
    /// Each key exchange method has a specified hash algorithm to generate the exchange hash.
    /// This is the algorithm that this method should return a hash function of.
    fn hash_fn(&self) -> KeyExchangeHashFunction;
}

/// Describes a host key algorithm.
pub trait HostKeyAlgorithm: Algorithm {
    /// Required, because Rust doesn't implement upcasting.
    ///
    /// Should be implemented like this:
    ///
    /// ```ignore
    /// fn as_basic_algorithm(&self) -> &dyn Algorithm { self }
    /// ```
    fn as_basic_algorithm(&self) -> &dyn Algorithm;

    /// The length of the signature generated by the `sign` operation.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn signature_length(&self) -> usize;

    /// Whether the host key algorithm is encryption capable.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    ///
    /// # Note
    /// At least one of `self.is_encryption_capable` or `self.is_signature_capable`
    /// must return `true`.
    fn is_encryption_capable(&self) -> bool;

    /// Whether the host key algorithm is signature capable.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    ///
    /// # Note
    /// At least one of `self.is_encryption_capable` or `self.is_signature_capable`
    /// must return `true`.
    fn is_signature_capable(&self) -> bool;

    /// Loads the given keypair into the key exchange algorithm.
    ///
    /// The encoding of the keypair is algorithm specific.
    ///
    /// # Panics
    /// This function may panic if a key was already loaded.
    fn load_keypair(&mut self, keypair: &[u8]) -> Result<(), Box<dyn Error>>;

    /// Returns the public key that was previously loaded using `load_keypair`.
    ///
    /// # Panics
    /// This function may panic if `load_keypair` was not previously called.
    fn public_key(&self) -> Vec<u8>;

    /// Signs the given message with the stored private key.
    ///
    /// The signature should be written to `signature`.
    ///
    /// # Panics
    /// This function may panic if
    /// - `load_keypair` was not previously called
    /// - `signature.len()` is not equal to `self.signature_length()`
    fn sign(&self, message: &[u8], signature: &mut [u8]);

    /// Checks if `signature` is of `message` and by `public_key`s private key.
    ///
    /// The encoding of the public key is algorithm specific. If the encoding is
    /// incorrect, this method must return false.
    ///
    /// # Note
    /// This method does *not* need `load_keypair` to be invoked previously and
    /// *may not* require it.
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool;
}

/// There was an error while performing the key exchange algorithm.
#[derive(Debug, Error)]
pub enum KeyExchangeAlgorithmError {
    /// A packet was sent with an invalid format.
    #[error(display = "a key exchange packet had an invalid format")]
    InvalidFormat,
    /// The host key the server sent was not valid.
    #[error(display = "the server sent an invalid host key")]
    InvalidHostKey,
    /// The signature sent by the server was invalid.
    #[error(display = "the server sent an invalid signature")]
    InvalidSignature,
    /// There was another error.
    ///
    /// This allows implementers of `KeyExchangeAlgorithm` more flexibility
    /// when reporting errors.
    #[error(display = "{}", _0)]
    Other(Box<dyn Error>),
}

/// Describes an encryption algorithm.
pub trait EncryptionAlgorithm: Algorithm {
    /// Required, because Rust doesn't implement upcasting.
    ///
    /// Should be implemented like this:
    ///
    /// ```ignore
    /// fn as_basic_algorithm(&self) -> &dyn Algorithm { self }
    /// ```
    fn as_basic_algorithm(&self) -> &dyn Algorithm;

    /// The size of the smallest amount of data that can be encrypted.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn cipher_block_size(&self) -> usize;

    /// The size, in bytes, of the key used by this algorithm.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn key_size(&self) -> usize;

    /// The size, in bytes, of the iv used by this algorithm.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn iv_size(&self) -> usize;

    /// Loads a new key to use for the algorithm.
    ///
    /// After the first call to `load_key`, for subsequent calls it is guaranteed, that
    /// `unload_key` will be called, before `load_key` is called.
    ///
    /// # Panics
    /// The function may panic if
    /// - `key.len() != self.key_size()`
    /// - `iv.len() != self.iv_size()`
    /// - there was a previous call to `self.load_key`, but no call to `self.unload_key` after it
    fn load_key(&mut self, iv: &[u8], key: &[u8]);

    /// Unloads the key that was previously loaded.
    ///
    /// This should overwrite the memory where the key was stored with a predictable value (such as
    /// zero) to avoid the key being readable for longer than necessary.
    ///
    /// # Panics
    /// The function may panic if `load_key` has not been called since the last call to
    /// `unload_key`.
    fn unload_key(&mut self);

    /// Encrypts a single block of data in place.
    ///
    /// # Panics
    /// The function may panic if
    /// - `input.len() != self.cipher_block_size()`
    /// - `self.load_key` has not been called previously
    fn encrypt_block(&mut self, input: &mut [u8]);

    /// Decrypts a single block of data in place.
    ///
    /// # Panics
    /// The function may panic if
    /// - `input.len() != self.cipher_block_size()`
    /// - `self.load_key` has not been called previously
    fn decrypt_block(&mut self, input: &mut [u8]);
}

/// Describes a message authentication algorithm.
pub trait MacAlgorithm: Algorithm {
    /// Required, because Rust doesn't implement upcasting.
    ///
    /// Should be implemented like this:
    ///
    /// ```ignore
    /// fn as_basic_algorithm(&self) -> &dyn Algorithm { self }
    /// ```
    fn as_basic_algorithm(&self) -> &dyn Algorithm;

    /// The size, in bytes, of the MAC signature used.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn mac_size(&self) -> usize;

    /// The size, in bytes, of the key used for calculating the MAC.
    ///
    /// The value returned by this function must always be the same, otherwise the
    /// SSH transport layer will not work as expected.
    fn key_size(&self) -> usize;

    /// Loads the key required for this MAC algorithm.
    ///
    /// # Panics
    /// The function may panic if `key.len() != self.key_len()`.
    fn load_key(&mut self, key: &[u8]);

    /// Unloads the key that was previously loaded.
    ///
    /// This should overwrite the memory where the key was stored with a predictable value (such as
    /// zero) to avoid the key being readable for longer than necessary.
    fn unload_key(&mut self);

    /// Computes the MAC of the given data.
    ///
    /// The result should be written to `result`.
    ///
    /// # Panics
    /// The function may panic if `result.len() != self.mac_size()`.
    fn compute(&mut self, data: &[u8], sequence_number: u32, result: &mut [u8]);

    /// Verifies if the given MAC matches the given data.
    ///
    /// It is recommended to implement this function manually to avoid allocations if possible.
    /// However be careful to use constant time equality checks, otherwise your implementation will
    /// be vulnerable to timing side channel attacks. The default implementation already does this.
    ///
    /// # Panics
    /// The function may panic if `mac.len() != self.mac_size()`.
    fn verify(&mut self, data: &[u8], sequence_number: u32, mac: &[u8]) -> bool {
        debug_assert_eq!(mac.len(), self.mac_size());

        let mut result = vec![0; self.mac_size()];

        self.compute(data, sequence_number, &mut result[..]);

        #[inline(never)]
        fn not_equal(a: &[u8], b: &[u8]) -> u8 {
            let mut res = 0;

            for i in 0..a.len() {
                res |= a[i] ^ b[i];
            }

            res
        }

        not_equal(&result, mac) == 0
    }
}

/// Describes a compression algorithm.
pub trait CompressionAlgorithm: Algorithm {
    /// Required, because Rust doesn't implement upcasting.
    ///
    /// Should be implemented like this:
    ///
    /// ```ignore
    /// fn as_basic_algorithm(&self) -> &dyn Algorithm { self }
    /// ```
    fn as_basic_algorithm(&self) -> &dyn Algorithm;

    /// Compresses the given data.
    ///
    /// This function receives the data in a `Cow::Borrowed` variant and may
    /// return a `Cow::Owned` variant if it changes the data.
    fn compress<'data>(&mut self, data: Cow<'data, [u8]>) -> Cow<'data, [u8]>;

    /// Decompresses the given data.
    ///
    /// This function receives the data in a `Cow::Borrowed` variant and may
    /// return a `Cow::Owned` variant if it changes the data.
    fn decompress<'data>(
        &mut self,
        data: Cow<'data, [u8]>,
    ) -> Result<Cow<'data, [u8]>, Box<dyn Error>>;
}
