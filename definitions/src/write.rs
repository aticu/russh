//! Writer functions for SSH primitives and a `Compose` trait to abstract over writable types.

use std::io::{self, Write};

// All the primitive parsers in this module are `#[inline]`, because they are small and will likely
// be combined and chained frequenly in `Compose` implementations.

/// Allows implementors to be written to an output [`std::io::Write`].
pub trait Compose: Sized {
    /// Writes `self` to `output`.
    fn compose(&self, output: &mut impl Write) -> std::io::Result<()>;

    /// Writes `self` to a new `Vec`.
    fn compose_to_vec(&self) -> Vec<u8> {
        let mut vec = Vec::new();

        self.compose(&mut vec).unwrap();

        vec
    }
}

/// Writes `input.len()` bytes to the output.
///
/// A byte represents an arbitrary 8-bit value (octet).
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
#[inline]
pub fn bytes(input: &[u8], output: &mut impl Write) -> io::Result<()> {
    output.write_all(input)
}

/// Writes a single byte to the output.
///
/// A byte represents an arbitrary 8-bit value (octet).
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
#[inline]
pub fn byte(input: u8, output: &mut impl Write) -> io::Result<()> {
    output.write_all(&[input][..])
}

/// Writes a boolean to the output.
///
/// A boolean value is stored as a single byte.  The value `0`
/// represents `false`, and the value `1` represents `true`.  All
/// non-zero values MUST be interpreted as `true`; however,
/// applications MUST NOT store values other than `0` and `1`.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn boolean(input: bool, output: &mut impl Write) -> io::Result<()> {
    byte(input.into(), output)
}

/// Writes a uint32 to the output.
///
/// Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// order of decreasing significance (network byte order).  For
/// example: the value `699921578` (`0x29b7f4aa`) is stored as
/// `29 b7 f4 aa`.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn uint32(input: u32, output: &mut impl Write) -> io::Result<()> {
    output.write_all(&input.to_be_bytes()[..])
}

/// Writes a uint64 to the output.
///
/// Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// the order of decreasing significance (network byte order).
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn uint64(input: u64, output: &mut impl Write) -> io::Result<()> {
    output.write_all(&input.to_be_bytes()[..])
}

/// Writes a string to the output.
///
/// Arbitrary length binary string.  Strings are allowed to contain
/// arbitrary binary data, including null characters and 8-bit
/// characters.  They are stored as a uint32 containing its length
/// (number of bytes that follow) and zero (= empty string) or more
/// bytes that are the value of the string.  Terminating null
/// characters are not used.
///
/// Strings are also used to store text.  In that case, US-ASCII is
/// used for internal names, and ISO-10646 UTF-8 for text that might
/// be displayed to the user.  The terminating null character SHOULD
/// NOT normally be stored in the string.  For example: the US-ASCII
/// string `"testing"` is represented as `00 00 00 07 t e s t i n g`.
/// The UTF-8 mapping does not alter the encoding of US-ASCII
/// characters.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
///
/// # Panics
///
/// This function will panic for input slices longer than `u32::MAX`,
/// as that is the longest value representable by an SSH string.
#[inline]
pub fn string(input: &[u8], output: &mut impl Write) -> io::Result<()> {
    use std::convert::TryInto as _;
    let len: u32 = input
        .len()
        .try_into()
        .expect("input string fits into an ssh string");

    uint32(len, output)?;
    bytes(input, output)
}

/// Writes an mpint to the output.
///
/// Represents multiple precision integers in two's complement format,
/// stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// have the value `1` as the most significant bit of the first byte of
/// the data partition.  If the most significant bit would be set for
/// a positive number, the number MUST be preceded by a zero byte.
/// Unnecessary leading bytes with the value `0` or `255` MUST NOT be
/// included.  The value zero MUST be stored as a string with zero
/// bytes of data.
///
/// By convention, a number that is used in modular computations in
/// Z_n SHOULD be represented in the range `0 <= x < n`.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
///
/// # Panics
///
/// This function will panic for numbers that have a representation
/// larger than 4GiB, as that these are not representable.
///
/// This should not be relevant in practice, as that would be numbers
/// roughly smaller than -2^(2^256) or larger than 2^(2^256).
#[inline]
pub fn mpint(input: &num_bigint::BigInt, output: &mut impl Write) -> io::Result<()> {
    let vec = if input.sign() == num_bigint::Sign::NoSign {
        Vec::new()
    } else {
        input.to_signed_bytes_be()
    };

    string(&vec[..], output)
}

/// Writes a name-list to the output.
///
/// A string containing a comma-separated list of names.  A name-list
/// is represented as a uint32 containing its length (number of bytes
/// that follow) followed by a comma-separated list of zero or more
/// names.  A name MUST have a non-zero length, and it MUST NOT
/// contain a comma (`","`).  As this is a list of names, all of the
/// elements contained are names and MUST be in US-ASCII.  Context may
/// impose additional restrictions on the names.  For example, the
/// names in a name-list may have to be a list of valid algorithm
/// identifiers , or a list of RFC3066 language tags.  The order of
/// the names in a name-list may or may not be significant.  Again,
/// this depends on the context in which the list is used.
/// Terminating null characters MUST NOT be used, neither for the
/// individual names, nor for the list as a whole.
///
/// See [RFC 4251 page 10](https://tools.ietf.org/html/rfc4251#page-10).
#[inline]
pub fn name_list<T: AsRef<str>>(input: &[T], output: &mut impl Write) -> io::Result<()> {
    use std::convert::TryInto as _;
    let total_len = input
        .iter()
        .fold(0, |acc: u32, s| {
            acc.checked_add(
                s.as_ref()
                    .len()
                    .try_into()
                    .expect("input fits into a name list"),
            )
            .expect("input fits into a name list")
        })
        .checked_add(
            input
                .len()
                .saturating_sub(1)
                .try_into()
                .expect("input fits into a name list"),
        ) // make room for the commas
        .expect("input fits into a name list");

    uint32(total_len, output)?;
    for (i, s) in input.iter().enumerate() {
        debug_assert_ne!(
            s.as_ref().len(),
            0,
            "zero length name not allowed in ssh name list"
        );
        debug_assert!(
            s.as_ref().chars().all(|c| c.is_ascii() && c != ','),
            "name must be only non-comma ascii characters in ssh name list"
        );

        if i != 0 {
            byte(b',', output)?;
        }
        bytes(s.as_ref().as_bytes(), output)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte() {
        let mut vec = b"data".to_vec();

        assert!(matches!(byte(0x32, &mut vec), Ok(())));
        assert_eq!(&vec[..], &[b'd', b'a', b't', b'a', 0x32][..]);

        assert!(matches!(byte(0x01, &mut vec), Ok(())));
        assert_eq!(&vec[..], &[b'd', b'a', b't', b'a', 0x32, 0x01][..]);

        for i in 0..=255 {
            let mut vec = Vec::new();
            assert!(matches!(byte(i, &mut vec), Ok(())));

            assert_eq!(&vec, &[i]);
        }
    }

    #[test]
    fn test_boolean() {
        let mut vec = b"data".to_vec();

        assert!(matches!(boolean(true, &mut vec), Ok(())));
        assert_eq!(&vec[..], &[b'd', b'a', b't', b'a', 0x01][..]);

        assert!(matches!(boolean(false, &mut vec), Ok(())));
        assert_eq!(&vec[..], &[b'd', b'a', b't', b'a', 0x01, 0x00][..]);
    }

    #[test]
    fn test_uint32() {
        let mut vec = b"data".to_vec();

        assert!(matches!(uint32(0x01020304, &mut vec), Ok(())));
        assert_eq!(
            &vec[..],
            &[b'd', b'a', b't', b'a', 0x01, 0x02, 0x03, 0x04][..]
        );

        assert!(matches!(uint32(0x04030201, &mut vec), Ok(())));
        assert_eq!(
            &vec[..],
            &[b'd', b'a', b't', b'a', 0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01][..]
        );
    }

    #[test]
    fn test_uint64() {
        let mut vec = b"data".to_vec();

        assert!(matches!(uint64(0x0102030405060708, &mut vec), Ok(())));
        assert_eq!(
            &vec[..],
            &[b'd', b'a', b't', b'a', 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..]
        );

        assert!(matches!(uint64(0x0807060504030201, &mut vec), Ok(())));
        assert_eq!(
            &vec[..],
            &[
                b'd', b'a', b't', b'a', 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x08, 0x07,
                0x06, 0x05, 0x04, 0x03, 0x02, 0x01
            ][..]
        );
    }

    #[test]
    fn test_string() {
        let mut vec = b"data".to_vec();

        assert!(matches!(string(b"testing", &mut vec), Ok(())));
        assert_eq!(&vec[..], &b"data\x00\x00\x00\x07testing"[..]);

        assert!(matches!(
            string(&[0x00, 0xff, 0x01, 0x02, 0x03, 0x04][..], &mut vec),
            Ok(())
        ));
        assert_eq!(
            &vec[..],
            &b"data\x00\x00\x00\x07testing\x00\x00\x00\x06\x00\xff\x01\x02\x03\x04"[..]
        );

        for i in 0..=255 {
            let mut vec = Vec::new();
            assert!(matches!(string(&[i], &mut vec), Ok(())));
            assert_eq!(&vec, &[0, 0, 0, 1, i]);
        }
    }

    #[test]
    fn test_mpint() {
        use num_bigint::BigInt;

        let mut vec = b"data".to_vec();

        assert!(matches!(
            mpint(&BigInt::parse_bytes(b"0", 16).unwrap(), &mut vec),
            Ok(())
        ));
        assert_eq!(
            &vec[..],
            &[b'd', b'a', b't', b'a', 0x00, 0x00, 0x00, 0x00][..]
        );

        assert!(matches!(
            mpint(
                &BigInt::parse_bytes(b"9a378f9b2e332a7", 16).unwrap(),
                &mut vec
            ),
            Ok(())
        ));
        assert_eq!(
            &vec[..],
            &[
                b'd', b'a', b't', b'a', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x09, 0xa3,
                0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7
            ][..]
        );

        vec.clear();

        assert!(matches!(
            mpint(&BigInt::parse_bytes(b"80", 16).unwrap(), &mut vec),
            Ok(())
        ));
        assert_eq!(&vec[..], &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80][..]);

        assert!(matches!(
            mpint(&BigInt::parse_bytes(b"-1234", 16).unwrap(), &mut vec),
            Ok(())
        ));
        assert_eq!(
            &vec[..],
            &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x02, 0xed, 0xcc][..]
        );

        vec.clear();

        assert!(matches!(
            mpint(&BigInt::parse_bytes(b"-deadbeef", 16).unwrap(), &mut vec),
            Ok(())
        ));
        assert_eq!(
            &vec[..],
            &[0x00, 0x00, 0x00, 0x05, 0xff, 0x21, 0x52, 0x41, 0x11][..]
        );
    }

    #[test]
    fn test_name_list() {
        let mut vec = b"data".to_vec();

        let empty_list: &[&'static str] = &[];

        assert!(matches!(name_list(empty_list, &mut vec), Ok(())));
        assert_eq!(&vec[..], &b"data\x00\x00\x00\x00"[..]);

        assert!(matches!(name_list(&["zlib"][..], &mut vec), Ok(())));
        assert_eq!(&vec[..], &b"data\x00\x00\x00\x00\x00\x00\x00\x04zlib"[..]);

        assert!(matches!(name_list(&["zlib", "none"][..], &mut vec), Ok(())));
        assert_eq!(
            &vec[..],
            &b"data\x00\x00\x00\x00\x00\x00\x00\x04zlib\x00\x00\x00\x09zlib,none"[..]
        );

        vec.clear();

        assert!(matches!(
            name_list(&["a", "b", "c", "d", "e"][..], &mut vec),
            Ok(())
        ));
        assert_eq!(&vec[..], &b"\x00\x00\x00\x09a,b,c,d,e"[..]);
    }
}
