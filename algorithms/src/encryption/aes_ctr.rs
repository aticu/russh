//! Provides implementations of the "aesXXX-ctr" encryption algorithms.

use aes_ctr::stream_cipher::{generic_array::GenericArray, NewStreamCipher, StreamCipher};
use russh_common::algorithms::{
    Algorithm, AlgorithmCategory, EncryptionAlgorithm, EncryptionContext,
};
use std::mem;

macro_rules! impl_aes_ctr {
    ($name_str:expr, $name:ident, $alg:ty, $key_size:expr) => {
        // Make sure that the internal algorithm implementation used does not implement drop.
        //
        // The way the memory is currently cleared relies on the fact that no drop code is called,
        // because it would potentially see invalidated data.
        //
        // If this assertion ever fails, a new strategy must be chosen to ensure that keys are
        // cleared from memory, once they are unloaded.
        static_assertions::assert_not_impl_all!($alg: Drop);

        #[doc = "Implements the `"]
        #[doc = $name_str]
        #[doc = "` encryption algorithm."]
        #[doc = ""]
        #[doc = "The existence of this struct is controlled by the `"]
        #[doc = $name_str]
        #[doc = "` feature."]
        #[derive(Debug)]
        pub struct $name {
            /// Contains the algorithm implementation and the keys.
            ///
            /// This will be `None` as long as the keys aren't loaded.
            algorithm: Option<$alg>,
        }

        impl $name {
            #[doc = "Creates a new `"]
            #[doc = $name_str]
            #[doc = "` encryption algorithm."]
            pub fn new() -> Self {
                $name { algorithm: None }
            }

            #[doc = "Creates a new boxed `"]
            #[doc = $name_str]
            #[doc = "` encryption algorithm."]
            pub fn boxed() -> Box<Self> {
                Box::new(Self::new())
            }
        }

        impl Algorithm for $name {
            fn name(&self) -> &'static str {
                $name_str
            }

            fn category(&self) -> AlgorithmCategory {
                AlgorithmCategory::Encryption
            }
        }

        impl EncryptionAlgorithm for $name {
            fn as_basic_algorithm(&self) -> &(dyn Algorithm + 'static) {
                self
            }

            fn cipher_block_size(&self) -> usize {
                16
            }

            fn key_size(&self) -> usize {
                $key_size
            }

            fn iv_size(&self) -> usize {
                16
            }

            fn load_key(&mut self, iv: &[u8], key: &[u8]) {
                debug_assert_eq!(key.len(), self.key_size());
                debug_assert_eq!(iv.len(), self.iv_size());

                let key = GenericArray::from_slice(key);
                let nonce = GenericArray::from_slice(iv);

                let old_value = self.algorithm.replace(<$alg>::new(&key, &nonce));

                debug_assert!(old_value.is_none());
            }

            fn unload_key(&mut self) {
                // Reinterpret the algorithm as a byte array.
                // We need to do this in-place, otherwise we make additional copies of key.
                //
                // Safety
                // This is safe, because the cipher instance will be dropped before it can be read
                // again.
                let reinterpreted: &mut Option<[u8; mem::size_of::<$alg>()]> =
                    unsafe { mem::transmute(&mut self.algorithm) };

                let array = reinterpreted
                    .as_mut()
                    .expect("key was previously loaded for aes ctr algorithm");

                // Zero the array
                for elem in &mut array[..] {
                    *elem = 0;
                }

                // Then drop the algorithm to make sure it isn't used in it's invalid state.
                // This also signals that the algorithm is now unloaded.
                self.algorithm.take();
            }

            fn encrypt_packet(&mut self, mut context: EncryptionContext) {
                let alg = self
                    .algorithm
                    .as_mut()
                    .expect("algorithm was previously loaded");

                alg.encrypt(context.unprocessed_part());
            }

            fn decrypt_packet(&mut self, mut context: EncryptionContext) -> usize {
                let alg = self
                    .algorithm
                    .as_mut()
                    .expect("algorithm was previously loaded");

                alg.decrypt(context.unprocessed_part());

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
impl_aes_ctr!("aes128-ctr", Aes128Ctr, aes_ctr::Aes128Ctr, 16);

#[cfg(feature = "aes192-ctr")]
impl_aes_ctr!("aes192-ctr", Aes192Ctr, aes_ctr::Aes192Ctr, 24);

#[cfg(feature = "aes256-ctr")]
impl_aes_ctr!("aes256-ctr", Aes256Ctr, aes_ctr::Aes256Ctr, 32);
