//! Allows for parsing of unencrypted packets.

use nom::bytes::streaming::take;
use russh_common::parser_primitives::{parse_byte, parse_uint32, ParseResult};

use crate::errors::ParseError;

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
    pub(crate) whole_packet: &'data [u8],
    /// The MAC used to verify the integrity of the packet.
    ///
    /// May be empty, if the "none" MAC algorithm is used.
    pub(crate) mac: &'data [u8],
}

/// Parses the already unencrypted packet length.
pub(in crate::parser) fn parse_unencrypted_packet_length(input: &[u8]) -> ParseResult<u32> {
    parse_uint32(input)
}

/// Parses an already unencrypted packet.
pub(in crate::parser) fn parse_unencrypted_packet(
    input: &[u8],
    mac_length: usize,
) -> ParseResult<ParsedPacket> {
    let (rest_input, packet_length) = parse_uint32(input)?;
    let (rest_input, padding_length) = parse_byte(rest_input)?;

    if packet_length < 12 || padding_length < 4 || packet_length < padding_length as u32 + 1 {
        return Err(ParseError::Invalid);
    }

    let payload_length = packet_length - padding_length as u32 - 1;
    let (rest_input, payload) = take(payload_length)(rest_input)?;
    let (rest_input, padding) = take(padding_length)(rest_input)?;

    let (rest_input, mac) = take(mac_length)(rest_input)?;

    Ok((
        rest_input,
        ParsedPacket {
            payload,
            padding,
            whole_packet: &input[..(4 + packet_length) as usize],
            mac,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ParseError;

    #[test]
    fn unencrypted_packet_length() {
        assert_eq!(
            parse_unencrypted_packet_length(&[0x00, 0x00, 0x00, 0x30]),
            Ok((&[][..], 0x30))
        );
        assert_eq!(
            parse_unencrypted_packet_length(&[0x10, 0x02, 0x30, 0x04]),
            Ok((&[][..], 0x10023004))
        );

        assert_eq!(
            parse_unencrypted_packet_length(&[0x10, 0x02, 0x30]),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn unencrypted_packet() {
        assert_eq!(
            parse_unencrypted_packet(
                &[
                    0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y', b'l',
                    b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10, 0x01, 0x02,
                    0x03, 0x04
                ],
                4
            ),
            Ok((
                &[][..],
                ParsedPacket {
                    payload: b"testpayload",
                    padding: &[0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10],
                    whole_packet: &[
                        0x00, 0x00, 0x00, 0x14, 0x08, b't', b'e', b's', b't', b'p', b'a', b'y',
                        b'l', b'o', b'a', b'd', 0x73, 0xae, 0xf8, 0x03, 0x7d, 0x38, 0x91, 0x10
                    ],
                    mac: &[0x01, 0x02, 0x03, 0x04]
                }
            ))
        );
        assert_eq!(
            parse_unencrypted_packet(
                &[
                    0x00, 0x00, 0x00, 0x34, 0x12, b's', b'o', b'm', b'e', b' ', b'm', b'o', b'r',
                    b'e', b' ', b't', b'e', b's', b't', b'i', b'n', b'g', b' ', b'd', b'a', b't',
                    b'a', b' ', b'a', b's', b' ', b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x55,
                    0x73, 0xfd, 0xca, 0x8e, 0x16, 0x4b, 0x8f, 0x03, 0x2f, 0x83, 0x91, 0xa7, 0x35,
                    0x8f, 0xad, 0x74, 0x44, 0x01, 0x02, 0x03
                ],
                0
            ),
            Ok((
                &[0x01, 0x02, 0x03][..],
                ParsedPacket {
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
                    mac: &[]
                }
            ))
        );
        assert_eq!(
            parse_unencrypted_packet(
                &[
                    0x00, 0x00, 0x00, 0x0c, 0x0b, 0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee, 0x1a,
                    0x98, 0x7a, 0x03
                ],
                0
            ),
            Ok((
                &[][..],
                ParsedPacket {
                    payload: b"",
                    padding: &[0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee, 0x1a, 0x98, 0x7a, 0x03],
                    whole_packet: &[
                        0x00, 0x00, 0x00, 0x0c, 0x0b, 0xd3, 0x00, 0x76, 0xbe, 0x13, 0xfe, 0xee,
                        0x1a, 0x98, 0x7a, 0x03
                    ],
                    mac: &[]
                }
            ))
        );

        assert_eq!(
            parse_unencrypted_packet(
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
            parse_unencrypted_packet(&[0x00, 0x00, 0x00, 0x03, 0x0a, 0x0b, 0x0c], 0),
            Err(ParseError::Invalid)
        );
    }
}
