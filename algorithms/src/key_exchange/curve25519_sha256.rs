//! Implements the "curve25519-sha256" key exchange algorithm.

use num_bigint::BigInt;
use russh_definitions::{
    algorithms::{
        Algorithm, AlgorithmCategory, HostKeyAlgorithm, KeyExchangeAlgorithm,
        KeyExchangeAlgorithmError, KeyExchangeData, KeyExchangeResponse,
    },
    consts::{SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY},
    write, ConnectionRole, CryptoRngCore, ParsedValue,
};
use sha2::{Digest, Sha256};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Implements the `curve25519-sha256` key exchange algorithm.
///
/// The existence of this struct is controlled by the `curve25519-sha256` feature.
#[derive(Default)]
pub struct Curve25519Sha256 {
    /// The secret key used for the key exchange.
    secret: Option<EphemeralSecret>,
    /// The connection role during the key exchange.
    role: Option<ConnectionRole>,
}

impl Curve25519Sha256 {
    /// Creates a new `curve25519-sha256` key exchange algorithm.
    pub fn new() -> Curve25519Sha256 {
        Curve25519Sha256 {
            secret: None,
            role: None,
        }
    }

    /// Creates a new boxed `curve25519-sha256` key exchange algorithm.
    pub fn boxed() -> Box<dyn KeyExchangeAlgorithm> {
        Box::new(Curve25519Sha256::new())
    }
}

impl Algorithm for Curve25519Sha256 {
    fn name(&self) -> &'static str {
        "curve25519-sha256"
    }

    fn category(&self) -> AlgorithmCategory {
        AlgorithmCategory::KeyExchange
    }
}

impl KeyExchangeAlgorithm for Curve25519Sha256 {
    fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
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
        rng: &mut dyn CryptoRngCore,
    ) -> Option<Vec<u8>> {
        self.role.replace(*role);
        match role {
            ConnectionRole::Client => {
                let secret = EphemeralSecret::new(rng);
                let public = PublicKey::from(&secret);

                use russh_definitions::Compose as _;
                let packet = MsgKexEcdhInit {
                    client_public_key: (&public.as_bytes()[..]).into(),
                    ..Default::default()
                }
                .compose_to_vec();

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
        rng: &mut dyn CryptoRngCore,
    ) -> Result<KeyExchangeResponse, KeyExchangeAlgorithmError> {
        let role = self
            .role
            .expect("`start` should be called before `respond`");

        match role {
            ConnectionRole::Client => {
                use russh_definitions::Parse;
                let ParsedValue {
                    value:
                        MsgKexEcdhReply {
                            server_host_key,
                            server_public_key,
                            exchange_hash_signature,
                            ..
                        },
                    ..
                } = MsgKexEcdhReply::parse(message)
                    //let (host_key, public_key, signature) = parse_ecdh_reply(message)
                    .map_err(|_| KeyExchangeAlgorithmError::InvalidFormat)?;

                if server_public_key.len() != 32 {
                    return Err(KeyExchangeAlgorithmError::InvalidFormat);
                }

                use std::convert::TryInto as _;
                let server_public_key: [u8; 32] = (&server_public_key[..]).try_into().unwrap();
                let other_public = PublicKey::from(server_public_key);

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
                write::string(key_exchange_data.client_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.server_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.client_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.server_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(&server_host_key, &mut hasher).expect("hasher writes don't fail");
                write::string(client_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(server_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write::mpint(&shared_secret_bigint, &mut hasher).expect("hasher writes don't fail");

                let hash = hasher.result();

                if !host_key_algorithm.verify(&hash, &exchange_hash_signature, &server_host_key) {
                    return Err(KeyExchangeAlgorithmError::InvalidSignature);
                }

                // TODO: verify that the shared secret consists of something other than zero bits
                // TODO: verify that key belongs to server

                let mut shared_secret_mpint = Vec::new();
                write::mpint(&shared_secret_bigint, &mut shared_secret_mpint)
                    .expect("vec writes don't fail");

                self.role = None;
                Ok(KeyExchangeResponse::Finished {
                    host_key: Some(server_host_key.to_vec()),
                    shared_secret: shared_secret_bigint,
                    exchange_hash: hash.to_vec(),
                    message: None,
                })
            }
            ConnectionRole::Server => {
                use russh_definitions::Parse as _;
                let ParsedValue {
                    value: init_msg, ..
                } = MsgKexEcdhInit::parse(message)
                    .map_err(|_| KeyExchangeAlgorithmError::InvalidFormat)?;

                if init_msg.client_public_key.len() != 32 {
                    return Err(KeyExchangeAlgorithmError::InvalidFormat);
                }

                use std::convert::TryInto as _;
                let public_key: [u8; 32] = (&init_msg.client_public_key[..]).try_into().unwrap();
                let other_public = { PublicKey::from(public_key) };

                let secret = EphemeralSecret::new(rng);
                let own_public = PublicKey::from(&secret);

                let shared_secret = secret.diffie_hellman(&other_public);
                let shared_secret_bigint =
                    BigInt::from_bytes_be(num_bigint::Sign::Plus, shared_secret.as_bytes());

                let (client_public, server_public) = match role {
                    ConnectionRole::Client => (own_public, other_public),
                    ConnectionRole::Server => (other_public, own_public),
                };

                let mut hasher = Sha256::new();
                write::string(key_exchange_data.client_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.server_identification, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.client_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(key_exchange_data.server_kexinit, &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(host_key_algorithm.public_key(), &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(client_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write::string(server_public.as_bytes(), &mut hasher)
                    .expect("hasher writes don't fail");
                write::mpint(&shared_secret_bigint, &mut hasher).expect("hasher writes don't fail");

                let hash = hasher.result();

                let mut signature = vec![0; host_key_algorithm.signature_length()];

                host_key_algorithm.sign(&hash, &mut signature);

                use russh_definitions::Compose as _;
                let packet = MsgKexEcdhReply {
                    server_host_key: host_key_algorithm.public_key().into(),
                    server_public_key: (&own_public.as_bytes()[..]).into(),
                    exchange_hash_signature: signature.into(),
                    ..Default::default()
                }
                .compose_to_vec();

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

russh_definitions::ssh_packet! {
    #[derive(Default)]
    struct MsgKexEcdhInit {
        byte     {SSH_MSG_KEX_ECDH_INIT}
        string   client_public_key
    }

    #[derive(Default)]
    struct MsgKexEcdhReply {
        byte     {SSH_MSG_KEX_ECDH_REPLY}
        string   server_host_key
        string   server_public_key
        string   exchange_hash_signature
    }
}
