//! Parsers for the initialization and packets in the transport layer.
//!
//! The initialization sequence is described in
//! [RFC 4253](https://tools.ietf.org/html/rfc4253).

use definitions::parse::{self, ParseError, ParsedValue};

use crate::version::VersionInformation;

/// Parses either a `protoversion` or a `softwareversion`.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
fn version(input: &[u8]) -> parse::Result<&str> {
    for (i, &c) in input.iter().enumerate() {
        if !(c as char).is_ascii_graphic() || c == b'-' {
            if i == 0 {
                return Err(ParseError::Incomplete);
            }

            return Ok(ParsedValue {
                value: std::str::from_utf8(&input[..i]).unwrap(),
                rest_input: &input[i..],
            });
        }
    }

    Err(ParseError::Incomplete)
}

/// Parses the line containing the version information.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
fn version_line(input: &[u8]) -> parse::Result<(VersionInformation, &[u8])> {
    let line_end_index = input
        .windows(2)
        .enumerate()
        .find_map(|(i, window)| (window == b"\r\n").then(|| i))
        .ok_or(ParseError::Incomplete)?;
    if line_end_index + 2 > 255 {
        return Err(ParseError::Invalid);
    }
    let identification_string = &input[..line_end_index];

    let rest_input = match parse::bytes(input, 4)? {
        ParsedValue {
            value: b"SSH-",
            rest_input,
        } => rest_input,
        _ => return Err(ParseError::Invalid),
    };
    let ParsedValue {
        value: protocolversion,
        rest_input,
    } = version(rest_input).map_err(|_| ParseError::Invalid)?;
    let rest_input = match parse::byte(rest_input)? {
        ParsedValue {
            value: b'-',
            rest_input,
        } => rest_input,
        _ => return Err(ParseError::Invalid),
    };
    let ParsedValue {
        value: softwareversion,
        rest_input,
    } = version(rest_input).map_err(|_| ParseError::Invalid)?;

    if !rest_input.starts_with(b"\r\n") && !rest_input.starts_with(b" ") {
        return Err(ParseError::Invalid);
    }

    Ok(ParsedValue {
        value: (
            VersionInformation::new_unchecked(
                protocolversion.to_string(),
                softwareversion.to_string(),
            ),
            identification_string,
        ),
        rest_input: &input[line_end_index + 2..],
    })
}

/// Parses the whole initialization sequence.
///
/// This returns the version information, the whole version information line as a string and the
/// total number of bytes that were parsed, including the final "\r\n" (i.e. the number of bytes
/// that were in `input`, but that aren't in `rest_input` anymore).
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
pub(super) fn initialization(input: &[u8]) -> parse::Result<(VersionInformation, &[u8], usize)> {
    let mut start_index = 0;
    for line in input.split_inclusive(|&byte| byte == b'\n') {
        if line.starts_with(b"SSH-") {
            break;
        }
        start_index += line.len();
    }

    let ParsedValue {
        value: (version_info, line),
        rest_input,
    } = version_line(&input[start_index..])?;

    Ok(ParsedValue {
        value: (version_info, line, start_index + line.len() + 2),
        rest_input,
    })
}

/// A parsed packet of the SSH transport layer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedPacket<'data> {
    /// The payload of the packet.
    ///
    /// This is still compressed, if compression was negotiated.
    pub(crate) payload: &'data [u8],
    /// The random padding of the packet.
    pub(crate) padding: &'data [u8],
    /// The whole packet (excluding the MAC).
    ///
    /// This includes the header, payload and padding and therefore overlaps with other fields.
    /// It can be used to calculate the MAC all at once.
    pub(crate) whole_packet: &'data [u8],
    /// The MAC of the packet.
    pub(crate) mac: &'data [u8],
}

/// Parses the already unencrypted packet length.
pub(super) fn packet_length(input: &[u8]) -> parse::Result<u32> {
    parse::uint32(input)
}

/// Parses an already unencrypted packet.
pub(super) fn packet(input: &[u8], mac_len: usize) -> parse::Result<ParsedPacket> {
    let ParsedValue {
        value: packet_length,
        rest_input,
    } = packet_length(input)?;
    let ParsedValue {
        value: padding_length,
        rest_input,
    } = parse::byte(rest_input)?;

    if packet_length < 12 || padding_length < 4 || packet_length < padding_length as u32 + 1 {
        return Err(ParseError::Invalid);
    }

    let payload_length = packet_length - padding_length as u32 - 1;
    let ParsedValue {
        value: payload,
        rest_input,
    } = parse::bytes(rest_input, payload_length as usize)?;
    let ParsedValue {
        value: padding,
        rest_input,
    } = parse::bytes(rest_input, padding_length as usize)?;
    let ParsedValue {
        value: mac,
        rest_input,
    } = parse::bytes(rest_input, mac_len)?;

    Ok(ParsedValue {
        value: ParsedPacket {
            payload,
            padding,
            whole_packet: &input[..(4 + packet_length) as usize],
            mac,
        },
        rest_input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::ParseError, writer::write_version_info};

    #[test]
    fn single_version() {
        assert_eq!(
            version(b"2.0-"),
            Ok(ParsedValue {
                value: "2.0",
                rest_input: b"-",
            })
        );
        assert_eq!(
            version(b"stevesSSH1234 "),
            Ok(ParsedValue {
                value: "stevesSSH1234",
                rest_input: b" "
            })
        );
        assert_eq!(
            version(b"openSSH2.0\r\n"),
            Ok(ParsedValue {
                value: "openSSH2.0",
                rest_input: b"\r\n"
            })
        );

        assert_eq!(version(b"2.0"), Err(ParseError::Incomplete));
    }

    #[test]
    fn protocol_line() {
        assert_eq!(
            version_line(b"SSH-2.0-softvers.1.2\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..]
                ),
                rest_input: b"",
            })
        );
        assert_eq!(
            version_line(b"SSH-2.0-softvers.1.2 this is a comment\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2 this is a comment"[..]
                ),
                rest_input: b"",
            })
        );

        assert_eq!(
            version_line(b"SSH-"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            version_line(b"SSH-2.0"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            version_line(b"SSH-2.0-"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            version_line(b"SSH-2.0-s"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            version_line(b"SSH--softvers.1.2\r\n"),
            Err(ParseError::Invalid),
            "empty protocolversion"
        );
        assert_eq!(
            version_line(b"SSH-2.0-\r\n"),
            Err(ParseError::Invalid),
            "empty softwareversion"
        );
        assert_eq!(
            version_line(b"RSH-2.0-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "wrong tag at start"
        );
        assert_eq!(
            version_line(b"SSH-\xff2.0-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "non utf8 character"
        );
        assert_eq!(
            version_line(b"SSH-2.0\xff-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "non utf8 character"
        );
    }

    #[test]
    fn whole_initialization() {
        assert_eq!(
            initialization(b"SSH-2.0-OpenSSH_8.0\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("OpenSSH_8.0").unwrap(),
                    &b"SSH-2.0-OpenSSH_8.0"[..],
                    21,
                ),
                rest_input: b"",
            })
        );
        assert_eq!(
            initialization(b"SSH-2.0-softvers.1.2\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..],
                    22,
                ),
                rest_input: b"",
            })
        );
        assert_eq!(
            initialization(b"this\r\nis\nsome\nother stuff\r\nSSH-2.0-softvers.1.2\r\nmore data"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..],
                    49,
                ),
                rest_input: b"more data",
            })
        );

        assert_eq!(
            initialization(b"SSH-\r\nSSH-2.0-softvers.1.2\r\n"),
            Err(ParseError::Invalid),
            "incorrect \"SSH-\" line detected"
        );
    }

    #[test]
    fn own_version_info() {
        let version_info = VersionInformation::default();
        let mut vec = Vec::new();
        write_version_info(&version_info, &mut vec).unwrap();

        assert_eq!(
            initialization(&vec),
            Ok(ParsedValue {
                value: (version_info, &vec[..(vec.len() - 2)], vec.len()),
                rest_input: b"",
            })
        );
    }

    #[test]
    fn unencrypted_packet_length() {
        assert_eq!(
            packet_length(&[0x00, 0x00, 0x00, 0x30]),
            Ok(ParsedValue {
                value: 0x30,
                rest_input: &[]
            })
        );
        assert_eq!(
            packet_length(&[0x10, 0x02, 0x30, 0x04]),
            Ok(ParsedValue {
                value: 0x10023004,
                rest_input: &[]
            })
        );

        assert_eq!(
            packet_length(&[0x10, 0x02, 0x30]),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn unencrypted_packet() {
        assert_eq!(
            packet(
                &[
                    0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y', b'l',
                    b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10, 0x01, 0x02,
                    0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                ],
                4
            ),
            Ok(ParsedValue {
                value: ParsedPacket {
                    payload: b"testpayload",
                    padding: &[0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10],
                    whole_packet: &[
                        0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y',
                        b'l', b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10
                    ],
                    mac: &[0x01, 0x02, 0x03, 0x04],
                },
                rest_input: &[0x05, 0x06, 0x07, 0x08],
            })
        );
        assert_eq!(
            packet(
                &[
                    0x00, 0x00, 0x00, 0x34, 0x12, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r',
                    b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't',
                    b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55,
                    0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91, 0xa7, 0x35,
                    0x8f, 0xad, 0x74, 0x44, 0x01, 0x02, 0x03
                ],
                0
            ),
            Ok(ParsedValue {
                value: ParsedPacket {
                    payload: b"some more testing data as payload",
                    padding: &[
                        0x55, 0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91,
                        0xa7, 0x35, 0x8f, 0xad, 0x74, 0x44
                    ],
                    whole_packet: &[
                        0x00, 0x00, 0x00, 0x34, 0x12, b's', b'o', b'm', b'e', b' ', b'm', b'o',
                        b'r', b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd',
                        b'a', b't', b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o',
                        b'a', b'd', 0x55, 0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f,
                        0x83, 0x91, 0xa7, 0x35, 0x8f, 0xad, 0x74, 0x44
                    ],
                    mac: &[][..],
                },
                rest_input: &[0x01, 0x02, 0x03],
            })
        );
        assert_eq!(
            packet(
                &[
                    0x00, 0x00, 0x00, 0x0c, 0x0b, 0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee, 0x1a,
                    0x98, 0x7a, 0x03
                ],
                0
            ),
            Ok(ParsedValue {
                value: ParsedPacket {
                    payload: b"",
                    padding: &[0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee, 0x1a, 0x98, 0x7a, 0x03],
                    whole_packet: &[
                        0x00, 0x00, 0x00, 0x0c, 0x0b, 0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee,
                        0x1a, 0x98, 0x7a, 0x03
                    ],
                    mac: &[][..],
                },
                rest_input: &[],
            })
        );

        assert_eq!(
            packet(
                &[
                    0x00, 0x00, 0x00, 0x2c, 0x0a, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r',
                    b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't',
                    b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55,
                    0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b
                ],
                0
            ),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            packet(
                &[
                    0x00, 0x00, 0x00, 0x2c, 0x0a, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r',
                    b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't',
                    b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55,
                    0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x17, 0x41, 0xfa, 0x11, 0x7d
                ],
                4
            ),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            packet(&[0x00, 0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c], 0),
            Err(ParseError::Invalid)
        );
    }
}
