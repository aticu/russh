//! Provides parsers for primitive types in SSH packets.
//!
//! The primitive types here are described in [RFC 4251](https://tools.ietf.org/html/rfc4251).

use nom::{
    bytes::streaming::take,
    number::streaming::{be_u32, be_u64, be_u8},
};
use num_bigint::BigInt;
use std::str::from_utf8;

/// The output of a successful parsing operation.
///
/// The first value in the tuple is the rest of the input, after the parsed value.
///
/// The second value is the result of the parsing operation.
pub type ParsedValue<'a, T> = (&'a [u8], T);

/// The errors that can happen during parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The parsed input was incomplete.
    ///
    /// More input is needed to parse successfully.
    Incomplete,
    /// The parsed input was invalid.
    Invalid,
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for ParseError {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Incomplete(_) => Self::Incomplete,
            nom::Err::Error(_) => Self::Invalid,
            nom::Err::Failure(_) => Self::Invalid,
        }
    }
}

/// The result of a parsing operation.
pub type ParseResult<'a, T> = Result<ParsedValue<'a, T>, ParseError>;

/// Parses a single byte from the input.
///
/// A byte represents an arbitrary 8-bit value (octet).  Fixed length
/// data is sometimes represented as an array of bytes, written
/// byte\[n\], where n is the number of bytes in the array.
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
pub fn parse_byte(input: &[u8]) -> ParseResult<u8> {
    be_u8(input).map_err(|e| e.into())
}

/// Parses a boolean from the input.
///
/// A boolean value is stored as a single byte.  The value 0
/// represents FALSE, and the value 1 represents TRUE.  All non-zero
/// values MUST be interpreted as TRUE; however, applications MUST NOT
/// store values other than 0 and 1.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
pub fn parse_boolean(input: &[u8]) -> ParseResult<bool> {
    let (input, byte) = be_u8(input)?;

    Ok((input, byte != 0))
}

/// Parses a uint32 from the input.
///
/// Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// order of decreasing significance (network byte order).  For
/// example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4
/// aa.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
pub fn parse_uint32(input: &[u8]) -> ParseResult<u32> {
    be_u32(input).map_err(|e| e.into())
}

/// Parses a uint64 from the input.
///
/// Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// the order of decreasing significance (network byte order).
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
pub fn parse_uint64(input: &[u8]) -> ParseResult<u64> {
    be_u64(input).map_err(|e| e.into())
}

/// Parses a string from the input.
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
/// string "testing" is represented as 00 00 00 07 t e s t i n g.  The
/// UTF-8 mapping does not alter the encoding of US-ASCII characters.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
pub fn parse_string(input: &[u8]) -> ParseResult<&[u8]> {
    let (rest, len) = parse_uint32(input)?;
    take(len)(rest).map_err(|e| e.into())
}

/// Parses an mpint from the input.
///
/// Represents multiple precision integers in two's complement format,
/// stored as a string, 8 bits per byte, MSB first.  Negative numbers
/// have the value 1 as the most significant bit of the first byte of
/// the data partition.  If the most significant bit would be set for
/// a positive number, the number MUST be preceded by a zero byte.
/// Unnecessary leading bytes with the value 0 or 255 MUST NOT be
/// included.  The value zero MUST be stored as a string with zero
/// bytes of data.
///
/// By convention, a number that is used in modular computations in
/// Z_n SHOULD be represented in the range 0 <= x < n.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
pub fn parse_mpint(input: &[u8]) -> ParseResult<BigInt> {
    let (input, string) = parse_string(input)?;

    if string.len() > 1 {
        if string[0] == 0 && (string[1] & 0x80) == 0 {
            // Unnecessary 0 byte
            return Err(ParseError::Invalid);
        } else if string[0] == 0xff && (string[1] & 0x80) == 0x80 {
            // Unnecessary 0xff byte
            return Err(ParseError::Invalid);
        }
    }

    Ok((input, BigInt::from_signed_bytes_be(string)))
}

/// Parses a name-list from the input.
///
/// A string containing a comma-separated list of names.  A name-list
/// is represented as a uint32 containing its length (number of bytes
/// that follow) followed by a comma-separated list of zero or more
/// names.  A name MUST have a non-zero length, and it MUST NOT
/// contain a comma (",").  As this is a list of names, all of the
/// elements contained are names and MUST be in US-ASCII.  Context may
/// impose additional restrictions on the names.  For example, the
/// names in a name-list may have to be a list of valid algorithm
/// identifiers (see Section 6 below), or a list of RFC3066 language
/// tags.  The order of the names in a name-list may or may not be
/// significant.  Again, this depends on the context in which the list
/// is used.  Terminating null characters MUST NOT be used, neither
/// for the individual names, nor for the list as a whole.
///
/// See [RFC 4251 page 10](https://tools.ietf.org/html/rfc4251#page-10).
pub fn parse_name_list(input: &[u8]) -> ParseResult<Vec<&str>> {
    let (input, string) = parse_string(input)?;

    if string.len() > 0 && (string[0] == b',' || string[string.len() - 1] == b',') {
        // No empty item should be in the list (i.e. no comma at start or end of list)
        return Err(ParseError::Invalid);
    }

    let mut iter = string.iter().peekable();

    while let Some(c) = iter.next() {
        if !(*c as char).is_ascii() {
            // All characters must be ascii
            return Err(ParseError::Invalid);
        }

        if *c == b',' && iter.peek() == Some(&&b',') {
            // No empty item should be in the list (i.e. no comma should follow a comma)
            return Err(ParseError::Invalid);
        }
    }

    if string.len() == 0 {
        Ok((input, vec![]))
    } else {
        let string = from_utf8(string).expect("ascii string should be valid utf8");

        Ok((input, string.split(',').collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte() {
        assert_eq!(parse_byte(&[0x32]), Ok((&[][..], 0x32)));
        assert_eq!(parse_byte(&[1, 2, 3]), Ok((&[2, 3][..], 1)));

        assert_eq!(parse_byte(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn boolean() {
        assert_eq!(parse_boolean(&[1, 2, 3]), Ok((&[2, 3][..], true)));
        assert_eq!(parse_boolean(&[0, 2, 3]), Ok((&[2, 3][..], false)));
        assert_eq!(parse_boolean(&[0]), Ok((&[][..], false)));
        assert_eq!(parse_boolean(&[0x32]), Ok((&[][..], true)));

        assert_eq!(parse_boolean(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn uint32() {
        assert_eq!(parse_uint32(&[1, 2, 3, 4]), Ok((&[][..], 0x01020304)));
        assert_eq!(
            parse_uint32(&[1, 2, 3, 4, 5, 6]),
            Ok((&[5, 6][..], 0x01020304))
        );
        assert_eq!(
            parse_uint32(&[4, 3, 2, 1, 0, 13]),
            Ok((&[0, 13][..], 0x04030201))
        );

        assert_eq!(parse_uint32(&[1]), Err(ParseError::Incomplete));
    }

    #[test]
    fn uint64() {
        assert_eq!(
            parse_uint64(&[1, 2, 3, 4, 5, 6, 7, 8]),
            Ok((&[][..], 0x0102030405060708))
        );
        assert_eq!(
            parse_uint64(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            Ok((&[9, 10][..], 0x0102030405060708))
        );
        assert_eq!(
            parse_uint64(&[8, 7, 6, 5, 4, 3, 2, 1, 0, 13]),
            Ok((&[0, 13][..], 0x0807060504030201))
        );

        assert_eq!(parse_uint64(&[1]), Err(ParseError::Incomplete));
    }

    #[test]
    fn string() {
        assert_eq!(
            parse_string(b"\x00\x00\x00\x07testing"),
            Ok((&[][..], &b"testing"[..]))
        );
        assert_eq!(
            parse_string(b"\x00\x00\x00\x07testing1234"),
            Ok((&b"1234"[..], &b"testing"[..]))
        );
        assert_eq!(
            parse_string(b"\x00\x00\x00\x07te\0ti\xffg1234"),
            Ok((&b"1234"[..], &b"te\0ti\xffg"[..]))
        );
        assert_eq!(
            parse_string(&[0, 0, 0, 4, 1, 2, 3, 4]),
            Ok((&[][..], &[1, 2, 3, 4][..]))
        );
        assert_eq!(
            parse_string(&[0, 0, 0, 0, 1, 2, 3, 4]),
            Ok((&[1, 2, 3, 4][..], &b""[..]))
        );

        assert_eq!(
            parse_string(&[0, 0, 0, 7, b't', b'e', b's', b't', b'i']),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn mpint() {
        assert_eq!(
            parse_mpint(&[0, 0, 0, 0]),
            Ok((&[][..], BigInt::parse_bytes(b"0", 16).unwrap()))
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
            Ok((
                &[][..],
                BigInt::parse_bytes(b"9a378f9b2e332a7", 16).unwrap()
            ))
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 2, 0x00, 0x80]),
            Ok((&[][..], BigInt::parse_bytes(b"80", 16).unwrap()))
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 2, 0xed, 0xcc]),
            Ok((&[][..], BigInt::parse_bytes(b"-1234", 16).unwrap()))
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11]),
            Ok((&[][..], BigInt::parse_bytes(b"-deadbeef", 16).unwrap()))
        );

        assert_eq!(
            parse_mpint(&[0, 0, 0, 5, 0xff, 0x81, 0x52, 0x41, 0x11]),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 5, 0x00, 0x21, 0x52, 0x41, 0x11]),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_mpint(&[0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41]),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn name_list() {
        assert_eq!(parse_name_list(b"\x00\x00\x00\x00"), Ok((&[][..], vec![])));
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x04zlib"),
            Ok((&[][..], vec!["zlib"]))
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x09zlib,none"),
            Ok((&[][..], vec!["zlib", "none"]))
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x09a,b,c,d,e"),
            Ok((&[][..], vec!["a", "b", "c", "d", "e"]))
        );

        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x05,zlib"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x05zlib,"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x05a,,bc"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x05a\xf0,bc"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse_name_list(b"\x00\x00\x00\x09zlib,n"),
            Err(ParseError::Incomplete)
        );
    }
}
