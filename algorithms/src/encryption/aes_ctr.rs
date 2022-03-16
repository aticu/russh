//! Provides implementations of the "aesXXX-ctr" encryption algorithms.

use definitions::algorithms::{EncryptionAlgorithm, EncryptionContext, PlainEncryptionAlgorithm};
use std::fmt;

macro_rules! impl_aes_ctr {
    ($name_str:expr, $name:ident, $alg:ty, $key_size:expr) => {
        #[doc = concat!("Implements the `", $name_str, "` encryption algorithm.")]
        #[doc = ""]
        #[doc = concat!("The existence of this struct is controlled by the `", $name_str, "` feature.")]
        #[derive(Default)]
        pub struct $name {
            /// Contains the algorithm implementation and the keys.
            ///
            /// This will be `None` as long as the keys aren't loaded.
            algorithm: Option<$alg>,
        }

        impl $name {
            #[doc = concat!("Creates a new `", $name_str, "` encryption algorithm.")]
            pub fn new() -> Self {
                $name { algorithm: None }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                // Hide implementation details and keys
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl EncryptionAlgorithm for $name {
            type AlgorithmType = PlainEncryptionAlgorithm;

            const NAME: &'static str = $name_str;
            const CIPHER_BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_size;
            const IV_SIZE: usize = 16;

            fn load_key(&mut self, iv: &[u8], key: &[u8]) {
                let key = <[u8; Self::KEY_SIZE]>::try_from(key).unwrap();
                let iv = <[u8; Self::IV_SIZE]>::try_from(iv).unwrap();

                use aes::cipher::KeyIvInit as _;
                let old_value = self.algorithm.replace(<$alg>::new(&key.into(), &iv.into()));

                debug_assert!(old_value.is_none());
            }

            fn unload_key(&mut self) {
                self.algorithm.take();
            }

            fn encrypt_packet(&mut self, mut context: EncryptionContext) {
                let alg = self
                    .algorithm
                    .as_mut()
                    .expect("algorithm was previously loaded");

                use aes::cipher::StreamCipher as _;
                alg.apply_keystream(context.unprocessed_part());
            }

            fn decrypt_packet(&mut self, mut context: EncryptionContext) -> usize {
                let alg = self
                    .algorithm
                    .as_mut()
                    .expect("algorithm was previously loaded");

                use aes::cipher::StreamCipher as _;
                alg.apply_keystream(context.unprocessed_part());

                context.unprocessed_part().len()
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self::new()
            }
        }
    };
}

#[cfg(feature = "aes128-ctr")]
impl_aes_ctr!("aes128-ctr", Aes128Ctr, ctr::Ctr128BE::<aes::Aes128>, 16);

#[cfg(feature = "aes192-ctr")]
impl_aes_ctr!("aes192-ctr", Aes192Ctr, ctr::Ctr128BE::<aes::Aes192>, 24);

#[cfg(feature = "aes256-ctr")]
impl_aes_ctr!("aes256-ctr", Aes256Ctr, ctr::Ctr128BE::<aes::Aes256>, 32);
