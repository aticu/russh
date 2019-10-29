//! Implements the "cureve25519-sha256" key exchange algorithm.

use num_bigint::BigInt;
use rand::RngCore;
use russh_common::{
    algorithms::{
        Algorithm, HostKeyAlgorithm, KeyExchangeAlgorithm, KeyExchangeAlgorithmError,
        KeyExchangeData, KeyExchangeResponse,
    },
    message_numbers::{SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY},
    parser_primitives::{parse_byte, parse_string, ParseError},
    writer_primitives::{write_byte, write_mpint, write_string},
    ConnectionRole,
};
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// The "curve25519-sha256" key exchange algorithm.
pub struct Curve25519Sha256 {
    /// The secret key used for the key exchange.
    secret: Option<EphemeralSecret>,
    /// The connection role during the key exchange.
    role: Option<ConnectionRole>,
}

impl Curve25519Sha256 {
    /// Creates a new "curve25519-sha256" key exchange algorithm.
    pub fn new() -> Curve25519Sha256 {
        Curve25519Sha256 {
            secret: None,
            role: None,
        }
    }

    /// Creates a new boxed "curve25519-sha256" key exchange algorithm.
    pub fn boxed() -> Box<Curve25519Sha256> {
        Box::new(Curve25519Sha256::new())
    }
}

impl Algorithm for Curve25519Sha256 {
    fn name(&self) -> &'static str {
        "curve25519-sha256"
    }
}

impl KeyExchangeAlgorithm for Curve25519Sha256 {
    fn as_basic_algorithm(&self) -> &dyn Algorithm {
        self
    }

    fn requires_signature_capable_host_key_algorithm(&self) -> bool {
        true
    }

    fn requires_encryption_capable_host_key_algorithm(&self) -> bool {
        false
    }

    fn start(
        &mut self,
        role: &ConnectionRole,
        _key_exchange_data: &KeyExchangeData,
        _host_key_algorithm: &mut dyn HostKeyAlgorithm,
        rng: &mut dyn RngCore,
    ) -> Option<Vec<u8>> {
        self.role.replace(*role);
        match role {
            ConnectionRole::Client => {
                // Convert from a new rand rng to a rand 6.4 rng
                use rand6::SeedableRng as _;
                let mut rng = rand6::rngs::StdRng::from_seed({
                    let mut seed: <rand6::rngs::StdRng as rand6::SeedableRng>::Seed =
                        Default::default();
                    rng.fill_bytes(seed.as_mut());

                    seed
                });

                let secret = EphemeralSecret::new(&mut rng);
                let public = PublicKey::from(&secret);

                let packet = write_ecdh_init(public.as_bytes());

                self.secret.replace(secret);

                Some(packet)
            }
            ConnectionRole::Server => None,
        }
    }

    fn respond(
        &mut self,
        message: &[u8],
        key_exchange_data: &KeyExchangeData,
        host_key_algorithm: &mut dyn HostKeyAlgorithm,
        rng: &mut dyn RngCore,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError> {
        let role = self
            .role
            .expect("`start` should be called before `respond`");

        match role {
            ConnectionRole::Client => {
                let (host_key, public_key, signature) = parse_ecdh_reply(message)
                    .map_err(|_| KeyExchangeAlgorithmError::InvalidFormat)?;

                if public_key.len() != 32 {
                    return Err(KeyExchangeAlgorithmError::InvalidFormat);
                }

                let other_public = {
                    let mut array = [0; 32];

                    for (i, elem) in array.iter_mut().enumerate() {
                        *elem = public_key[i];
                    }

                    PublicKey::from(array)
                };

                let own_secret = self
                    .secret
                    .take()
                    .expect("`start` should be called before `respond`");
                let own_public = PublicKey::from(&own_secret);
                let shared_secret = own_secret.diffie_hellman(&other_public);
                let shared_secret_bigint =
                    BigInt::from_bytes_be(num_bigint::Sign::Plus, shared_secret.as_bytes());

                let (client_public, server_public) = match role {
                    ConnectionRole::Client => (own_public, other_public),
                    ConnectionRole::Server => (other_public, own_public),
                };

                let mut hasher = Sha256::new();
                write_string(key_exchange_data.client_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.server_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.client_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.server_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(host_key, &mut hasher).expect("hasher writes don't fail");
                write_string(client_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(server_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write_mpint(&shared_secret_bigint, &mut hasher).expect("hasher writes don't fail");

                let hash = hasher.result();

                if !host_key_algorithm.verify(&hash, signature, host_key) {
                    return Err(KeyExchangeAlgorithmError::InvalidSignature);
                }

                // TODO: verify that the shared secret consists of something other than zero bits
                // TODO: verify that key belongs to server

                let mut shared_secret_mpint = Vec::new();
                write_mpint(&shared_secret_bigint, &mut shared_secret_mpint)
                    .expect("vec writes don't fail");

                self.role = None;
                Ok(KeyExchangeResponse::Finished {
                    host_key: Some(host_key.to_vec()),
                    shared_secret: shared_secret_bigint,
                    exchange_hash: hash.to_vec(),
                    message: None,
                })
            }
            ConnectionRole::Server => {
                let public_key = parse_ecdh_init(message)
                    .map_err(|_| KeyExchangeAlgorithmError::InvalidFormat)?;

                if public_key.len() != 32 {
                    return Err(KeyExchangeAlgorithmError::InvalidFormat);
                }

                let other_public = {
                    let mut array = [0; 32];

                    for (i, elem) in array.iter_mut().enumerate() {
                        *elem = public_key[i];
                    }

                    PublicKey::from(array)
                };

                // Convert from a new rand rng to a rand 6.4 rng
                use rand6::SeedableRng as _;
                let mut rng = rand6::rngs::StdRng::from_seed({
                    let mut seed: <rand6::rngs::StdRng as rand6::SeedableRng>::Seed =
                        Default::default();
                    rng.fill_bytes(seed.as_mut());

                    seed
                });

                let secret = EphemeralSecret::new(&mut rng);
                let own_public = PublicKey::from(&secret);

                let shared_secret = secret.diffie_hellman(&other_public);
                let shared_secret_bigint =
                    BigInt::from_bytes_be(num_bigint::Sign::Plus, shared_secret.as_bytes());

                let (client_public, server_public) = match role {
                    ConnectionRole::Client => (own_public, other_public),
                    ConnectionRole::Server => (other_public, own_public),
                };

                let mut hasher = Sha256::new();
                write_string(key_exchange_data.client_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.server_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.client_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(key_exchange_data.server_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(&host_key_algorithm.public_key(), &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(client_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write_string(server_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write_mpint(&shared_secret_bigint, &mut hasher).expect("hasher writes don't fail");

                let hash = hasher.result();

                let mut signature = Vec::with_capacity(host_key_algorithm.signature_length());

                signature.resize(host_key_algorithm.signature_length(), 0);

                host_key_algorithm.sign(&hash, &mut signature);

                let packet = write_ecdh_reply(
                    &host_key_algorithm.public_key(),
                    own_public.as_bytes(),
                    &signature,
                );

                Ok(KeyExchangeResponse::Finished {
                    host_key: None,
                    shared_secret: shared_secret_bigint,
                    exchange_hash: hash.to_vec(),
                    message: Some(packet),
                })
            }
        }
    }

    fn hash_fn(&self) -> fn(&[u8]) -> Vec<u8> {
        |message| Sha256::digest(message).to_vec()
    }
}

impl fmt::Debug for Curve25519Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Curve25519Sha256 {{ /* fields omitted */ }}")
    }
}

/// Writes a `SSH_MSG_KEX_ECDH_REPLY` packet.
fn write_ecdh_reply(host_key: &[u8], public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    write_byte(SSH_MSG_KEX_ECDH_REPLY, &mut packet).expect("vec write never fails");
    write_string(host_key, &mut packet).expect("vec write never fails");
    write_string(public_key, &mut packet).expect("vec write never fails");
    write_string(signature, &mut packet).expect("vec write never fails");

    packet
}

/// Writes a `SSH_MSG_KEX_ECDH_INIT` packet.
fn write_ecdh_init(public_key: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();

    write_byte(SSH_MSG_KEX_ECDH_INIT, &mut packet).expect("vec write never fails");
    write_string(public_key, &mut packet).expect("vec write never fails");

    packet
}

/// Parses a `SSH_MSG_KEX_ECDH_REPLY` packet.
fn parse_ecdh_reply(message: &[u8]) -> Result<(&[u8], &[u8], &[u8]), ParseError> {
    let (rest, tag) = parse_byte(message)?;

    if tag != SSH_MSG_KEX_ECDH_REPLY {
        return Err(ParseError::Invalid);
    }

    let (rest, host_key) = parse_string(rest)?;
    let (rest, public_key) = parse_string(rest)?;
    let (_, signature) = parse_string(rest)?;

    Ok((host_key, public_key, signature))
}

/// Parses a `SSH_MSG_KEX_ECDH_INIT` packet.
fn parse_ecdh_init(message: &[u8]) -> Result<&[u8], ParseError> {
    let (rest, tag) = parse_byte(message)?;

    if tag != SSH_MSG_KEX_ECDH_INIT {
        return Err(ParseError::Invalid);
    }

    let (_, public_key) = parse_string(rest)?;

    Ok(public_key)
}
