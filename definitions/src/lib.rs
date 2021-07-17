//! Maps definitions from the SSH RFCs into the Rust type system.
//!
//! This includes
//! - constants defined in the RFCs ([`consts`] module)
//! - parsers and writers for the basic data types in SSH packets ([`parse`] and [`mod@write`]
//!   modules)
//! - automatic parser and composer generation for SSH packets ([`ssh_packet`] macro)

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(unreachable_pub)]

pub use parse::{Parse, ParseError, ParsedValue};
pub use write::Compose;

mod packet_macro;

pub mod algorithms;
pub mod consts;
pub mod parse;
pub mod write;

/// Determines which role the handler has in the connection.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConnectionRole {
    /// The code is acting as the server in the connection.
    Server,
    /// The code is acting as the client in the connection.
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
