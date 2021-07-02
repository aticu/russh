//! Parses the initialization sequence of the SSH transport layer.
//!
//! The initialization sequence is described in
//! [RFC 4253](https://tools.ietf.org/html/rfc4253).

use nom::{
    bytes::streaming::{tag, take_while1},
    character::streaming::{line_ending, not_line_ending},
    combinator::{map, map_res, opt, verify},
    multi::many_till,
    sequence::{terminated, tuple},
    IResult,
};

use crate::version::VersionInformation;

/// Parses either a `protoversion` or a `softwareversion`.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
fn parse_version(input: &[u8]) -> IResult<&[u8], &str> {
    map_res(
        take_while1(|c: u8| (c as char).is_ascii_graphic() && c != b'-'),
        |version| std::str::from_utf8(version),
    )(input)
}

/// Parses the line containing the version information.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
fn parse_version_line(input: &[u8]) -> IResult<&[u8], (VersionInformation, &[u8])> {
    let (_, identification_string) = terminated(not_line_ending, line_ending)(input)?;

    map(
        tuple((
            tag(b"SSH-"),
            parse_version,
            tag(b"-"),
            parse_version,
            opt(tuple((tag(b" "), not_line_ending))),
            line_ending,
        )),
        move |(_, protocolversion, _, softwareversion, _, _)| {
            (
                VersionInformation::new_unchecked(
                    protocolversion.to_string(),
                    softwareversion.to_string(),
                ),
                identification_string,
            )
        },
    )(input)
}

/// Parses the whole initialization sequence.
///
/// See [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).
pub(in crate::parser) fn parse_initialization(
    input: &[u8],
) -> IResult<&[u8], (VersionInformation, &[u8])> {
    map(
        many_till(
            verify(terminated(not_line_ending, line_ending), |line: &[u8]| {
                line.len() < 4 || &line[..4] != &b"SSH-"[..]
            }),
            parse_version_line,
        ),
        |(_, version)| version,
    )(input)
}

#[cfg(test)]
mod tests {
    use nom::{error::ErrorKind, Err::Incomplete, Needed};

    use std::num::NonZeroUsize;

    use super::*;
    use crate::writer::write_version_info;

    #[test]
    fn single_version() {
        assert_eq!(parse_version(b"2.0-"), Ok((&b"-"[..], "2.0")));
        assert_eq!(
            parse_version(b"stevesSSH1234 "),
            Ok((&b" "[..], "stevesSSH1234"))
        );
        assert_eq!(
            parse_version(b"openSSH2.0\r\n"),
            Ok((&b"\r\n"[..], "openSSH2.0"))
        );

        assert_eq!(
            parse_version(b"2.0"),
            Err(Incomplete(Needed::Size(NonZeroUsize::new(1).unwrap())))
        );
    }

    #[test]
    fn protocol_line() {
        assert_eq!(
            parse_version_line(b"SSH-2.0-softvers.1.2\r\n"),
            Ok((
                &b""[..],
                (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..]
                )
            ))
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-softvers.1.2 this is a comment\r\n"),
            Ok((
                &b""[..],
                (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2 this is a comment"[..]
                )
            ))
        );

        assert_eq!(
            parse_version_line(b"SSH-"),
            Err(Incomplete(Needed::Unknown)),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0"),
            Err(Incomplete(Needed::Unknown)),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-"),
            Err(Incomplete(Needed::Unknown)),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-s"),
            Err(Incomplete(Needed::Unknown)),
            "early end"
        );
        assert_eq!(
            parse_version_line(b"SSH--softvers.1.2\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"-softvers.1.2\r\n"[..],
                ErrorKind::TakeWhile1
            ))),
            "empty protocolversion"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0-\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"\r\n"[..],
                ErrorKind::TakeWhile1
            ))),
            "empty softwareversion"
        );
        assert_eq!(
            parse_version_line(b"RSH-2.0-softvers.1.2 this is a comment\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"RSH-2.0-softvers.1.2 this is a comment\r\n"[..],
                ErrorKind::Tag
            ))),
            "wrong tag at start"
        );
        assert_eq!(
            parse_version_line(b"SSH-\xff2.0-softvers.1.2 this is a comment\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"\xff2.0-softvers.1.2 this is a comment\r\n"[..],
                ErrorKind::TakeWhile1
            ))),
            "non utf8 character"
        );
        assert_eq!(
            parse_version_line(b"SSH-2.0\xff-softvers.1.2 this is a comment\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"\xff-softvers.1.2 this is a comment\r\n"[..],
                ErrorKind::Tag
            ))),
            "non utf8 character"
        );
    }

    #[test]
    fn initialization() {
        assert_eq!(
            parse_initialization(b"SSH-2.0-OpenSSH_8.0\r\n"),
            Ok((
                &b""[..],
                (
                    VersionInformation::new("OpenSSH_8.0").unwrap(),
                    &b"SSH-2.0-OpenSSH_8.0"[..]
                )
            ))
        );
        assert_eq!(
            parse_initialization(b"SSH-2.0-softvers.1.2\r\n"),
            Ok((
                &b""[..],
                (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..]
                )
            ))
        );
        assert_eq!(
            parse_initialization(b"this\r\nis\nsome\nother stuff\r\nSSH-2.0-softvers.1.2\r\n"),
            Ok((
                &b""[..],
                (
                    VersionInformation::new("softvers.1.2").unwrap(),
                    &b"SSH-2.0-softvers.1.2"[..]
                )
            ))
        );

        assert_eq!(
            parse_initialization(b"SSH-\r\nSSH-2.0-softvers.1.2\r\n"),
            Err(nom::Err::Error(nom::error::Error::new(
                &b"SSH-\r\nSSH-2.0-softvers.1.2\r\n"[..],
                ErrorKind::Verify
            ))),
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
            Ok((&b""[..], (version_info, &vec[..(vec.len() - 2)])))
        );
    }
}
