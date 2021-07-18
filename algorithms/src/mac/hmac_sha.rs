//! Provides implementations of the "hmac-shaX(-XXX)" MAC algorithms.

use hmac::{
    crypto_mac::{
        generic_array::{typenum::Unsigned, GenericArray},
        MacResult,
    },
    digest::FixedOutput,
    Hmac, Mac,
};
use russh_definitions::algorithms::{Algorithm, AlgorithmCategory, MacAlgorithm};
use secstr::SecStr;

macro_rules! impl_hmac_sha {
    ($name_str:expr, $name:ident, $alg:ty, $key_size:expr) => {
        #[doc = "Implements the `"]
        #[doc = $name_str]
        #[doc = "` MAC algorithm."]
        #[doc = ""]
        #[doc = "The existence of this struct is controlled by the `"]
        #[doc = $name_str]
        #[doc = "` feature."]
        #[derive(Debug, Default)]
        pub struct $name {
            /// The key to use for the MAC computations.
            key: Option<SecStr>,
        }

        impl $name {
            #[doc = "Creates a new `"]
            #[doc = $name_str]
            #[doc = "` MAC algorithm."]
            pub fn new() -> $name {
                $name { key: None }
            }

            #[doc = "Creates a new boxed `"]
            #[doc = $name_str]
            #[doc = "` MAC algorithm."]
            pub fn boxed() -> Box<$name> {
                Box::new($name::new())
            }

            /// Performs the actual MAC calculation.
            fn calculate(
                &self,
                data: &[u8],
                sequence_number: u32,
            ) -> MacResult<<$alg as FixedOutput>::OutputSize> {
                let key = self.key.as_ref().expect("`load_key` was called before");

                let mut alg =
                    Hmac::<$alg>::new_varkey(key.unsecure()).expect("HMAC can take any input size");

                alg.input(&sequence_number.to_be_bytes());
                alg.input(data);

                alg.result()
            }
        }

        impl Algorithm for $name {
            fn name(&self) -> &'static str {
                $name_str
            }

            fn category(&self) -> AlgorithmCategory {
                AlgorithmCategory::Mac
            }
        }

        impl MacAlgorithm for $name {
            fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
                self
            }

            fn mac_size(&self) -> usize {
                <$alg as FixedOutput>::OutputSize::USIZE
            }

            fn key_size(&self) -> usize {
                $key_size
            }

            fn load_key(&mut self, key: &[u8]) {
                debug_assert_eq!(key.len(), self.key_size());

                self.key.replace(SecStr::from(key));
            }

            fn unload_key(&mut self) {
                self.key.take();
            }

            fn compute(&mut self, data: &[u8], sequence_number: u32, result: &mut [u8]) {
                debug_assert_eq!(result.len(), self.mac_size());

                result.copy_from_slice(&self.calculate(data, sequence_number).code());
            }

            fn verify(&mut self, data: &[u8], sequence_number: u32, mac: &[u8]) -> bool {
                debug_assert_eq!(mac.len(), self.mac_size());

                self.calculate(data, sequence_number)
                    == MacResult::new(*GenericArray::from_slice(mac))
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self::new()
            }
        }
    };
}

#[cfg(feature = "hmac-sha1")]
impl_hmac_sha!("hmac-sha1", HmacSha1, sha1::Sha1, 20);

#[cfg(feature = "hmac-sha2-256")]
impl_hmac_sha!("hmac-sha2-256", HmacSha2256, sha2::Sha256, 32);

#[cfg(feature = "hmac-sha2-512")]
impl_hmac_sha!("hmac-sha2-512", HmacSha2512, sha2::Sha512, 64);
