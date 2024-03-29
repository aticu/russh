//! Provides an implementation of the "ssh-ed25519" host key algorithm.

use definitions::algorithms::HostKeyAlgorithm;
use ed25519_dalek::{
    ed25519::signature::Signature, Keypair, PublicKey, SignatureError, Signer, Verifier,
    SIGNATURE_LENGTH,
};
use std::{error::Error, fmt};

/// The prefix used for a signature.
///
/// The encoding of the signature is:
///
/// ```text,no_run
/// string "ssh-ed25519"
/// string signature
/// ```
const SIGNATURE_PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x40";

/// The prefix used for a public key.
///
/// The encoding of the public key is:
///
/// ```text,no_run
/// string "ssh-ed25519"
/// string public_key
/// ```
const PUBLIC_KEY_PREFIX: &[u8] = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20";

/// Implements the `ssh-ed25519` host key algorithm.
///
/// The existence of this struct is controlled by the `ssh-ed25519` feature.
#[derive(Debug, Default)]
pub struct Ed25519 {
    /// The keypair used to sign messages.
    keypair: Option<Keypair>,
    /// The public key in use.
    public_key: Option<Vec<u8>>,
}

impl Ed25519 {
    /// Creates a new `ssh-ed25519` host key algorithm.
    pub fn new() -> Ed25519 {
        Ed25519 {
            keypair: None,
            public_key: None,
        }
    }
}

/// A wrapper for `SignatureError` that implements `Error`.
#[derive(Debug)]
struct Ed25519SignatureError(SignatureError);

impl fmt::Display for Ed25519SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for Ed25519SignatureError {}

impl HostKeyAlgorithm for Ed25519 {
    const NAME: &'static str = "ssh-ed25519";
    const SIGNATURE_LENGTH: usize = SIGNATURE_PREFIX.len() + SIGNATURE_LENGTH;
    const IS_ENCRYPTION_CAPABLE: bool = false;
    const IS_SIGNATURE_CAPABLE: bool = true;

    fn load_keypair(&mut self, keypair: &[u8]) -> Result<(), Box<dyn Error>> {
        let keypair = Keypair::from_bytes(keypair).map_err(Ed25519SignatureError)?;

        let public_key = {
            let bytes = keypair.public.as_bytes();

            let mut vec = Vec::with_capacity(bytes.len() + PUBLIC_KEY_PREFIX.len());
            vec.extend(PUBLIC_KEY_PREFIX);
            vec.extend(bytes);

            vec
        };

        let old_public_key = self.public_key.replace(public_key);
        let old_keypair = self.keypair.replace(keypair);

        assert!(old_public_key.is_none());
        assert!(old_keypair.is_none());

        Ok(())
    }

    fn public_key(&self) -> &[u8] {
        self.public_key
            .as_ref()
            .expect("`load_keypair` was called successfully before `public_key`")
    }

    fn sign(&self, message: &[u8], signature: &mut [u8]) {
        let keypair = self
            .keypair
            .as_ref()
            .expect("`load_keypair` was called successfully before `sign`");

        let generated_signature = keypair.sign(message).to_bytes();

        (&mut signature[..SIGNATURE_PREFIX.len()]).copy_from_slice(SIGNATURE_PREFIX);
        (&mut signature[SIGNATURE_PREFIX.len()..]).copy_from_slice(&generated_signature[..]);
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
        if !signature.starts_with(SIGNATURE_PREFIX) || !public_key.starts_with(PUBLIC_KEY_PREFIX) {
            return false;
        }

        let public_key = match PublicKey::from_bytes(&public_key[PUBLIC_KEY_PREFIX.len()..]) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let signature = match Signature::from_bytes(&signature[SIGNATURE_PREFIX.len()..]) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        public_key.verify(message, &signature).is_ok()
    }
}
