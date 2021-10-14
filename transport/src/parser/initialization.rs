//! Parses the initialization sequence of the SSH transport layer.
//!
//! The initialization sequence is described in
//! [RFC 4253](https://tools.ietf.org/html/rfc4253).

use definitions::parse::{self, ParseError, ParsedValue};

use crate::version::VersionInformation;

/// Parses either a `protoversion` or a `softwareversion`.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
fn parse_version(input: &[u8]) -> parse::Result<&str> {
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
fn parse_version_line(input: &[u8]) -> parse::Result<(VersionInformation, &[u8])> {
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
    } = parse_version(rest_input).map_err(|_| ParseError::Invalid)?;
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
    } = parse_version(rest_input).map_err(|_| ParseError::Invalid)?;

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
pub(in crate::parser) fn parse_initialization(
    input: &[u8],
) -> parse::Result<(VersionInformation, &[u8], usize)> {
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
    } = parse_version_line(&input[start_index..])?;

    Ok(ParsedValue {
        value: (version_info, line, start_index + line.len() + 2),
        rest_input,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::write_version_info;

    #[test]
    fn single_version() {
        assert_eq!(
            parse_version(b"2.0-"),
            Ok(ParsedValue {
                value: "2.0",
                rest_input: b"-",
            })
        );
        assert_eq!(
            parse_version(b"stevesSSH1234 "),
            Ok(ParsedValue {
                value: "stevesSSH1234",
                rest_input: b" "
            })
        );
        assert_eq!(
            parse_version(b"openSSH2.0\r\n"),
            Ok(ParsedValue {
                value: "openSSH2.0",
                rest_input: b"\r\n"
            })
        );

        assert_eq!(parse_version(b"2.0"), Err(ParseError::Incomplete));
    }

    #[test]
    fn protocol_line() {
        assert_eq!(
            parse_version_line(b"SSH-2.0-softvers.1.2\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..]
                ),
                rest_input: b"",
            })
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-softvers.1.2 this is a comment\r\n"),
            Ok(ParsedValue {
                value: (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2 this is a comment"[..]
                ),
                rest_input: b"",
            })
        );

        assert_eq!(
            parse_version_line(b"SSH-"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-s"),
            Err(ParseError::Incomplete),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH--softvers.1.2\r\n"),
            Err(ParseError::Invalid),
            "empty protocolversion"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-\r\n"),
            Err(ParseError::Invalid),
            "empty softwareversion"
        );
        assert_eq!(
            parse_version_line(b"RSH-2.0-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "wrong tag at start"
        );
        assert_eq!(
            parse_version_line(b"SSH-\xff2.0-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "non utf8 character"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0\xff-softvers.1.2 this is a comment\r\n"),
            Err(ParseError::Invalid),
            "non utf8 character"
        );
    }

    #[test]
    fn initialization() {
        assert_eq!(
            parse_initialization(b"SSH-2.0-OpenSSH_8.0\r\n"),
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
            parse_initialization(b"SSH-2.0-softvers.1.2\r\n"),
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
            parse_initialization(
                b"this\r\nis\nsome\nother stuff\r\nSSH-2.0-softvers.1.2\r\nmore data"
            ),
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
            parse_initialization(b"SSH-\r\nSSH-2.0-softvers.1.2\r\n"),
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
            parse_initialization(&vec),
            Ok(ParsedValue {
                value: (version_info, &vec[..(vec.len() - 2)], vec.len()),
                rest_input: b"",
            })
        );
    }
}
