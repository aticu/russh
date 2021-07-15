//! Provides common definitions used by all russh crates.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(unreachable_pub)]

pub mod algorithms;
pub mod message_numbers;
pub mod message_type;
pub mod parser_primitives;
pub mod writer_primitives;

/// Determines which role the handler has in the connection.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectionRole {
    /// The handler is the server in the connection.
    Server,
    /// The handler is the client in the connection.
    Client,
}

impl ConnectionRole {
    /// The other role that is participating in the connection.
    pub fn other(&self) -> ConnectionRole {
        match self {
            ConnectionRole::Server => ConnectionRole::Client,
            ConnectionRole::Client => ConnectionRole::Server,
        }
    }
}

/// An implementation detail to allow using trait objects that implement `RngCore` and `CryptoRng`.
// TODO: eventually remove this, if https://github.com/rust-random/rand/issues/1143 lands
pub trait CryptoRngCore: rand::RngCore + rand::CryptoRng {}

impl<T: rand::RngCore + rand::CryptoRng> CryptoRngCore for T {}
