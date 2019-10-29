//! Provides the algorithm implementations used by the SSH transport layer.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(unreachable_pub)]

pub mod compression;
pub mod encryption;
pub mod host_key;
pub mod key_exchange;
pub mod mac;

// TODO: Verify single features work
// TODO: add tests for algorithms
