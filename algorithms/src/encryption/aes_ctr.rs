//! Provides implementations of the "aesXXX-ctr" encryption algorithms.

use aes_ctr::stream_cipher::{generic_array::GenericArray, NewStreamCipher, StreamCipher};
use russh_definitions::algorithms::{
    EncryptionAlgorithm, EncryptionContext, PlainEncryptionAlgorithm,
};
use std::mem;
use zeroize::Zeroize;

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

        #[doc = concat!("Implements the `", $name_str, "` encryption algorithm.")]
        #[doc = ""]
        #[doc = concat!("The existence of this struct is controlled by the `", $name_str, "` feature.")]
        #[derive(Debug, Default)]
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

        impl EncryptionAlgorithm for $name {
            type AlgorithmType = PlainEncryptionAlgorithm;

            const NAME: &'static str = $name_str;
            const CIPHER_BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_size;
            const IV_SIZE: usize = 16;

            fn load_key(&mut self, iv: &[u8], key: &[u8]) {
                debug_assert_eq!(key.len(), Self::KEY_SIZE);
                debug_assert_eq!(iv.len(), Self::IV_SIZE);

                let key = GenericArray::from_slice(key);
                let nonce = GenericArray::from_slice(iv);

                let old_value = self.algorithm.replace(<$alg>::new(&key, &nonce));

                debug_assert!(old_value.is_none());
            }

            fn unload_key(&mut self) {
                let alg = self
                    .algorithm
                    .as_mut()
                    .expect("key was previously loaded for aes ctr algorithm");

                // Reinterpret the algorithm as a byte array.
                // We need to do this in-place, otherwise we make additional copies of key.
                //
                // Safety
                // This is safe, because the cipher instance will be dropped before it can be read
                // again.
                let reinterpreted: &mut [u8; mem::size_of::<$alg>()] =
                    unsafe { mem::transmute(alg) };

                // Zero the array
                reinterpreted.zeroize();

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
