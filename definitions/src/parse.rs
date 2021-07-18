//! Parser functions for SSH primitives and a `Parse` trait to abstract over parsable types.

// All the primitive writers in this module are `#[inline]`, because they are small and will likely
// be combined and chained frequenly in `Parse` implementations.

/// Allows implementors to by parsed from a byte slice.
pub trait Parse<'input>: Sized + 'input {
    /// Parses the `Self` type from `input`.
    fn parse(input: &'input [u8]) -> Result<Self>;
}

/// Holds the result of a successful parse.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct ParsedValue<'data, T> {
    /// The value that was parsed.
    pub value: T,
    /// The rest of the input that was not consumed during the parse.
    pub rest_input: &'data [u8],
}

/// Communicates the reason why parsing was not successful.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, thiserror::Error)]
pub enum ParseError {
    /// Not enough data was available to complete the parse.
    #[error("not enough data available to complete the parse")]
    Incomplete,
    /// The input cannot be validly parsed into the expected structure.
    #[error("the parser input did not contain a valid value")]
    Invalid,
}

/// The result type of a parsing operation.
pub type Result<'data, T> = std::result::Result<ParsedValue<'data, T>, ParseError>;

/// Parses `N` bytes from the input.
///
/// A byte represents an arbitrary 8-bit value (octet).
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
#[inline]
pub fn bytes_const<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    bytes(input, N).map(|ParsedValue { value, rest_input }| {
        use std::convert::TryInto as _;
        ParsedValue {
            value: value
                .try_into()
                .expect("parse bytes returned the right number of bytes"),
            rest_input,
        }
    })
}

/// Parses `n` bytes from the input.
///
/// A byte represents an arbitrary 8-bit value (octet).
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
#[inline]
pub fn bytes(input: &[u8], n: usize) -> Result<&[u8]> {
    if input.len() < n {
        Err(ParseError::Incomplete)
    } else {
        Ok(ParsedValue {
            value: &input[..n],
            rest_input: &input[n..],
        })
    }
}

/// Parses a single byte from the input.
///
/// A byte represents an arbitrary 8-bit value (octet).
///
/// See [RFC 4251 page 8](https://tools.ietf.org/html/rfc4251#page-8).
#[inline]
pub fn byte(input: &[u8]) -> Result<u8> {
    if input.is_empty() {
        Err(ParseError::Incomplete)
    } else {
        Ok(ParsedValue {
            value: input[0],
            rest_input: &input[1..],
        })
    }
}

/// Parses a boolean from the input.
///
/// A boolean value is stored as a single byte.  The value `0`
/// represents `false`, and the value `1` represents `true`.  All
/// non-zero values MUST be interpreted as `true`; however,
/// applications MUST NOT store values other than `0` and `1`.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn boolean(input: &[u8]) -> Result<bool> {
    if input.is_empty() {
        Err(ParseError::Incomplete)
    } else {
        Ok(ParsedValue {
            value: input[0] != 0,
            rest_input: &input[1..],
        })
    }
}

/// Parses a uint32 from the input.
///
/// Represents a 32-bit unsigned integer.  Stored as four bytes in the
/// order of decreasing significance (network byte order).  For
/// example: the value `699921578` (`0x29b7f4aa`) is stored as
/// `29 b7 f4 aa`.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn uint32(input: &[u8]) -> Result<u32> {
    if input.len() < 4 {
        Err(ParseError::Incomplete)
    } else {
        use std::convert::TryInto as _;
        let as_array = input[0..4]
            .try_into()
            .expect("array has the right number of bytes");

        Ok(ParsedValue {
            value: u32::from_be_bytes(as_array),
            rest_input: &input[4..],
        })
    }
}

/// Parses a uint64 from the input.
///
/// Represents a 64-bit unsigned integer.  Stored as eight bytes in
/// the order of decreasing significance (network byte order).
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn uint64(input: &[u8]) -> Result<u64> {
    if input.len() < 8 {
        Err(ParseError::Incomplete)
    } else {
        use std::convert::TryInto as _;
        let as_array = input[0..8]
            .try_into()
            .expect("array has the right number of bytes");

        Ok(ParsedValue {
            value: u64::from_be_bytes(as_array),
            rest_input: &input[8..],
        })
    }
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
/// string `"testing"` is represented as `00 00 00 07 t e s t i n g`.
/// The UTF-8 mapping does not alter the encoding of US-ASCII
/// characters.
///
/// See [RFC 4251 page 9](https://tools.ietf.org/html/rfc4251#page-9).
#[inline]
pub fn string(input: &[u8]) -> Result<&[u8]> {
    let ParsedValue {
        value: len,
        rest_input,
    } = uint32(input)?;

    let ParsedValue { value, rest_input } = bytes(rest_input, len as usize)?;

    Ok(ParsedValue { value, rest_input })
}

/// Parses an mpint from the input.
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
#[inline]
pub fn mpint(input: &[u8]) -> Result<num_bigint::BigInt> {
    let ParsedValue {
        value: string,
        rest_input,
    } = string(input)?;

    if string.len() > 1 {
        let unnecessary_00_byte = string[0] == 0x00 && (string[1] & 0x80) == 0;
        let unnecessary_ff_byte = string[0] == 0xff && (string[1] & 0x80) > 0;
        if unnecessary_00_byte || unnecessary_ff_byte {
            return Err(ParseError::Invalid);
        }
    }

    Ok(ParsedValue {
        value: num_bigint::BigInt::from_signed_bytes_be(string),
        rest_input,
    })
}

/// Parses a name-list from the input.
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
pub fn name_list<'input, T>(input: &'input [u8]) -> Result<Vec<T>>
where
    &'input str: Into<T>,
{
    let ParsedValue {
        value: string,
        rest_input,
    } = string(input)?;

    if !string.is_empty() && (string[0] == b',' || string[string.len() - 1] == b',') {
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

    if string.is_empty() {
        Ok(ParsedValue {
            value: vec![],
            rest_input,
        })
    } else {
        let string = std::str::from_utf8(string).expect("ascii string should be valid utf8");

        Ok(ParsedValue {
            value: string.split(',').map(|string| string.into()).collect(),
            rest_input,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte() {
        for i in 0..=255 {
            assert_eq!(
                byte(&[i]),
                Ok(ParsedValue {
                    value: i,
                    rest_input: &[],
                })
            );
        }

        assert_eq!(
            byte(&[1, 2, 3]),
            Ok(ParsedValue {
                value: 1,
                rest_input: &[2, 3],
            })
        );

        assert_eq!(byte(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn test_boolean() {
        assert_eq!(
            boolean(&[1, 2, 3]),
            Ok(ParsedValue {
                value: true,
                rest_input: &[2, 3],
            })
        );
        assert_eq!(
            boolean(&[0, 2, 3]),
            Ok(ParsedValue {
                value: false,
                rest_input: &[2, 3],
            })
        );
        assert_eq!(
            boolean(&[0]),
            Ok(ParsedValue {
                value: false,
                rest_input: &[],
            })
        );

        for i in 1..=255 {
            assert_eq!(
                boolean(&[i]),
                Ok(ParsedValue {
                    value: true,
                    rest_input: &[],
                })
            );
        }

        assert_eq!(boolean(&[]), Err(ParseError::Incomplete));
    }

    #[test]
    fn test_uint32() {
        assert_eq!(
            uint32(&[1, 2, 3, 4]),
            Ok(ParsedValue {
                value: 0x01020304,
                rest_input: &[],
            })
        );
        assert_eq!(
            uint32(&[1, 2, 3, 4, 5, 6]),
            Ok(ParsedValue {
                value: 0x01020304,
                rest_input: &[5, 6],
            })
        );
        assert_eq!(
            uint32(&[4, 3, 2, 1, 0, 13]),
            Ok(ParsedValue {
                value: 0x04030201,
                rest_input: &[0, 13],
            })
        );
        assert_eq!(
            uint32(&[0x29, 0xb7, 0xf4, 0xaa]),
            Ok(ParsedValue {
                value: 0x29b7f4aa,
                rest_input: &[],
            })
        );

        assert_eq!(uint32(&[1, 2, 3]), Err(ParseError::Incomplete));
    }

    #[test]
    fn test_uint64() {
        assert_eq!(
            uint64(&[1, 2, 3, 4, 5, 6, 7, 8]),
            Ok(ParsedValue {
                value: 0x0102030405060708,
                rest_input: &[],
            })
        );
        assert_eq!(
            uint64(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            Ok(ParsedValue {
                value: 0x0102030405060708,
                rest_input: &[9, 10],
            })
        );
        assert_eq!(
            uint64(&[8, 7, 6, 5, 4, 3, 2, 1, 0, 13]),
            Ok(ParsedValue {
                value: 0x0807060504030201,
                rest_input: &[0, 13],
            })
        );

        assert_eq!(uint64(&[1]), Err(ParseError::Incomplete));
    }

    #[test]
    fn test_string() {
        assert_eq!(
            string(b"\x00\x00\x00\x07testing"),
            Ok(ParsedValue {
                value: &b"testing"[..],
                rest_input: &[],
            })
        );
        assert_eq!(
            string(b"\x00\x00\x00\x07testing1234"),
            Ok(ParsedValue {
                value: &b"testing"[..],
                rest_input: &b"1234"[..],
            })
        );
        assert_eq!(
            string(b"\x00\x00\x00\x07te\0ti\xffg1234"),
            Ok(ParsedValue {
                value: &b"te\0ti\xffg"[..],
                rest_input: &b"1234"[..],
            })
        );
        assert_eq!(
            string(&[0, 0, 0, 4, 1, 2, 3, 4]),
            Ok(ParsedValue {
                value: &[1, 2, 3, 4][..],
                rest_input: &[],
            })
        );
        assert_eq!(
            string(&[0, 0, 0, 0, 1, 2, 3, 4]),
            Ok(ParsedValue {
                value: &b""[..],
                rest_input: &[1, 2, 3, 4],
            })
        );

        for i in 0..=255 {
            assert_eq!(
                string(&[0, 0, 0, 1, i, 0x42]),
                Ok(ParsedValue {
                    value: &[i][..],
                    rest_input: &[0x42],
                })
            );
        }

        assert_eq!(
            string(b"\x00\x00\x00\x07testi"),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn test_mpint() {
        use num_bigint::BigInt;

        assert_eq!(
            mpint(&[0, 0, 0, 0]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"0", 16).unwrap(),
                rest_input: &[],
            })
        );
        assert_eq!(
            mpint(&[0, 0, 0, 0, 0]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"0", 16).unwrap(),
                rest_input: &[0],
            })
        );
        assert_eq!(
            mpint(&[0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"9a378f9b2e332a7", 16).unwrap(),
                rest_input: &[],
            })
        );
        assert_eq!(
            mpint(&[0, 0, 0, 2, 0x00, 0x80]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"80", 16).unwrap(),
                rest_input: &[],
            })
        );
        assert_eq!(
            mpint(&[0, 0, 0, 2, 0xed, 0xcc]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"-1234", 16).unwrap(),
                rest_input: &[],
            })
        );
        assert_eq!(
            mpint(&[0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11]),
            Ok(ParsedValue {
                value: BigInt::parse_bytes(b"-deadbeef", 16).unwrap(),
                rest_input: &[],
            })
        );

        assert_eq!(
            mpint(&[0, 0, 0, 5, 0xff, 0x81, 0x52, 0x41, 0x11]),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            mpint(&[0, 0, 0, 5, 0x00, 0x21, 0x52, 0x41, 0x11]),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            mpint(&[0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41]),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn test_name_list() {
        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x00"),
            Ok(ParsedValue {
                value: vec![],
                rest_input: &[],
            })
        );
        assert_eq!(
            name_list(b"\x00\x00\x00\x04zlib"),
            Ok(ParsedValue {
                value: vec!["zlib"],
                rest_input: &[],
            })
        );
        assert_eq!(
            name_list(b"\x00\x00\x00\x09zlib,none"),
            Ok(ParsedValue {
                value: vec!["zlib", "none"],
                rest_input: &[],
            })
        );
        assert_eq!(
            name_list(b"\x00\x00\x00\x09a,b,c,d,e"),
            Ok(ParsedValue {
                value: vec!["a", "b", "c", "d", "e"],
                rest_input: &[],
            })
        );

        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x05,zlib"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x05zlib,"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x05a,,bc"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x05a\xf0,bc"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            name_list::<&str>(b"\x00\x00\x00\x09zlib,n"),
            Err(ParseError::Incomplete)
        );
    }
}
