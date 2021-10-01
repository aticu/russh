//! Defines the `KeyExchangeAlgorithm` trait.

use num_bigint::BigInt;
use rand::{CryptoRng, RngCore};
use std::{
    error::Error,
    fmt,
    ops::{Deref, DerefMut},
};

use crate::{
    algorithms::internal::{CryptoRngCore, HostKeyAlgorithmEntry},
    ConnectionRole,
};

// TODO: somehow handle implicit server authentication?

/// The data needed to perform a key exchange.
#[derive(Debug)]
pub struct KeyExchangeData<'data> {
    /// The identification string of the client.
    pub client_identification: &'data [u8],
    /// The identification string of the server.
    pub server_identification: &'data [u8],
    /// The `SSH_MSG_KEXINIT` packet of the client.
    pub client_kexinit: &'data [u8],
    /// The `SSH_MSG_KEXINIT` packet of the server.
    pub server_kexinit: &'data [u8],
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
pub trait KeyExchangeAlgorithm {
    /// The name of the key exchange algorithm.
    const NAME: &'static str;

    /// Whether the key exchange algorithm requires an encryption capable host key algorithm.
    const REQUIRES_ENCRYPTION_CAPABLE_HOST_KEY_ALGORITHM: bool;

    /// Whether the key exchange algorithm requires a signature capable host key algorithm.
    const REQUIRES_SIGNATURE_CAPABLE_HOST_KEY_ALGORITHM: bool;

    /// The hash function used by this key exchange algorithm to generate the exchange hash.
    const HASH_FUNCTION: KeyExchangeHashFunction;

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
    fn start<Rng: RngCore + CryptoRng + ?Sized>(
        &mut self,
        role: &ConnectionRole,
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut Rng,
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
    fn respond<Rng: RngCore + CryptoRng + ?Sized>(
        &mut self,
        message: &[u8],
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut Rng,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError>;
}

/// There was an error while performing the key exchange algorithm.
#[derive(Debug, thiserror::Error)]
pub enum KeyExchangeAlgorithmError {
    /// A packet was sent with an invalid format.
    #[error("a key exchange packet had an invalid format")]
    InvalidFormat,
    /// The host key the server sent was not valid.
    #[error("the server sent an invalid host key")]
    InvalidHostKey,
    /// The signature sent by the server was invalid.
    #[error("the server sent an invalid signature")]
    InvalidSignature,
    /// There was another error.
    ///
    /// This allows implementers of `KeyExchangeAlgorithm` more flexibility
    /// when reporting errors.
    #[error("{0}")]
    Other(Box<dyn Error>),
}

/// A runtime description of a key exchange algorithm.
///
/// This allows representing different key exchange algorithms with the same type.
///
/// It is mostly intended for internal use.
pub struct KeyExchangeAlgorithmEntry {
    /// The name of the key exchange algorithm.
    pub name: &'static str,
    /// Whether the key exchange algorithm requires an encryption capable host key algorithm.
    pub requires_encryption_capable_host_key_algorithm: bool,
    /// Whether the key exchange algorithm requires a signature capable host key algorithm.
    pub requires_signature_capable_host_key_algorithm: bool,
    /// The hash function used by this key exchange algorithm to generate the exchange hash.
    pub hash_function: KeyExchangeHashFunction,
    /// The algorithm itself.
    #[doc(hidden)]
    algorithm: Box<dyn DynKeyExchangeAlgorithm>,
}

impl fmt::Debug for KeyExchangeAlgorithmEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyExchangeAlgorithmEntry")
            .field("name", &self.name)
            .field(
                "requires_encryption_capable_host_key_algorithm",
                &self.requires_encryption_capable_host_key_algorithm,
            )
            .field(
                "requires_signature_capable_host_key_algorithm",
                &self.requires_signature_capable_host_key_algorithm,
            )
            .finish_non_exhaustive()
    }
}

impl<T> From<T> for KeyExchangeAlgorithmEntry
where
    T: KeyExchangeAlgorithm + 'static,
{
    fn from(alg: T) -> Self {
        KeyExchangeAlgorithmEntry {
            name: <T as KeyExchangeAlgorithm>::NAME,
            requires_encryption_capable_host_key_algorithm:
                <T as KeyExchangeAlgorithm>::REQUIRES_ENCRYPTION_CAPABLE_HOST_KEY_ALGORITHM,
            requires_signature_capable_host_key_algorithm:
                <T as KeyExchangeAlgorithm>::REQUIRES_SIGNATURE_CAPABLE_HOST_KEY_ALGORITHM,
            hash_function: <T as KeyExchangeAlgorithm>::HASH_FUNCTION,
            algorithm: Box::new(alg),
        }
    }
}

impl Deref for KeyExchangeAlgorithmEntry {
    type Target = dyn DynKeyExchangeAlgorithm;

    fn deref(&self) -> &Self::Target {
        &*self.algorithm
    }
}

impl DerefMut for KeyExchangeAlgorithmEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.algorithm
    }
}

/// A trait object friendly version of the [`KeyExchangeAlgorithm`] trait.
///
/// **DO NOT IMPLEMENT THIS TRAIT MANUALLY.**
/// Implement the [`KeyExchangeAlgorithm`] trait instead.
///
/// This trait is mainly intended for internal use and automatically implemented for all types
/// implementing the [`KeyExchangeAlgorithm`] trait.
pub trait DynKeyExchangeAlgorithm {
    /// See [`KeyExchangeAlgorithm::start`].
    fn start(
        &mut self,
        role: &ConnectionRole,
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut dyn CryptoRngCore,
    ) -> Option<Vec<u8>>;

    /// See [`KeyExchangeAlgorithm::respond`].
    fn respond(
        &mut self,
        message: &[u8],
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError>;
}

impl<T> DynKeyExchangeAlgorithm for T
where
    T: KeyExchangeAlgorithm,
{
    fn start(
        &mut self,
        role: &ConnectionRole,
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut dyn CryptoRngCore,
    ) -> Option<Vec<u8>> {
        <Self as KeyExchangeAlgorithm>::start(
            self,
            role,
            key_exchange_data,
            host_key_algorithm,
            rng,
        )
    }

    fn respond(
        &mut self,
        message: &[u8],
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut HostKeyAlgorithmEntry,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError> {
        <Self as KeyExchangeAlgorithm>::respond(
            self,
            message,
            key_exchange_data,
            host_key_algorithm,
            rng,
        )
    }
}
