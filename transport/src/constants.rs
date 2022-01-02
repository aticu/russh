//! Defines constants specified in SSH specification.

use std::mem::size_of;

/// The size, in bytes, of the packet length field of a packet.
pub(crate) const PACKET_LEN_SIZE: usize = size_of::<u32>();

/// The size, in bytes, of the padding length field of a packet.
pub(crate) const PADDING_LEN_SIZE: usize = size_of::<u8>();

/// The minimum padding size of a packet.
pub(crate) const MIN_PADDING_SIZE: usize = 4;

/// The maximum padding size of a packet.
pub(crate) const MAX_PADDING_SIZE: usize = 0xff;

/// The minimum size that the packet length must be a multiple of.
pub(crate) const MIN_PACKET_LEN_ALIGN: usize = 8;

/// The maximum number of extra padding blocks.
///
/// This should be used when creating a custom distribution function for
/// padding lengths.
///
/// Note that this refers to "padding blocks", which consist of a number of
/// bytes equal to the cipher block size or 8, whichever is higher.
pub const MAX_EXTRA_PADDING_BLOCKS: usize = MAX_PADDING_SIZE / MIN_PACKET_LEN_ALIGN;

/// The protocol version supported by this library.
pub const PROTOCOL_VERSION: &str = "2.0";
