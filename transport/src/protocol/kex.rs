//! Handles key exchange related protocol functions.

use nom::bytes::complete::{tag, take};
use num_bigint::BigInt;
use russh_common::{
    algorithms::{AlgorithmCategory, AlgorithmRole, HostKeyAlgorithm, KeyExchangeAlgorithm, KeyExchangeData, KeyExchangeResponse},
    message_numbers::SSH_MSG_KEXINIT,
    message_type::MessageType,
    parser_primitives::{parse_boolean, parse_name_list, parse_uint32},
    writer_primitives::{write_boolean, write_byte, write_name_list, write_uint32},
    ConnectionRole,
};
use std::{
    borrow::Cow,
    io::{self, Write},
};

use crate::{
    algorithms::{AlgorithmList, AvailableAlgorithms},
    errors::{CommunicationError, KeyExchangeProcedureError, ParseError},
    input_handler::{InputHandler, InputStream},
    output_handler::{OutputHandler, OutputStream},
    runtime_state::RuntimeState,
};

/// Represents the result of a key exchange.
pub(in crate::protocol) struct KeyExchangeResult {
    /// The host key of the server.
    ///
    /// `Some(_)` if we are the client and `None` if we are the server.
    pub(in crate::protocol) host_key: Option<Vec<u8>>,
    /// The shared secret that the key exchange produced.
    pub(in crate::protocol) shared_secret: BigInt,
    /// The exchange hash that the key exchange produced.
    pub(in crate::protocol) exchange_hash: Vec<u8>,
}

/// Performs the algorithm specific part of a key exchange.
pub(in crate::protocol) async fn algorithm_specific_exchange<
    Input: InputStream,
    Output: OutputStream,
>(
    kex_algorithm: &mut dyn KeyExchangeAlgorithm,
    host_key_algorithm: &mut dyn HostKeyAlgorithm,
    key_exchange_data: &KeyExchangeData<'_>,
    runtime_state: &mut RuntimeState,
    input_handler: &mut InputHandler<Input>,
    output_handler: &mut OutputHandler<Output>,
) -> Result<KeyExchangeResult, KeyExchangeProcedureError> {
    let role = *runtime_state.connection_role();

    if let Some(start_packet) = kex_algorithm.start(
        &role,
        key_exchange_data,
        host_key_algorithm,
        &mut runtime_state.rng(),
    ) {
        output_handler
            .send_packet(&start_packet, runtime_state)
            .flush()
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;
    }

    let (host_key, shared_secret, exchange_hash, message) = loop {
        let answer = input_handler
            .next_packet(runtime_state)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(err))?;

        if MessageType::from_message(&answer) != Some(MessageType::KeyExchangeMethodSpecific) {
            return Err(KeyExchangeProcedureError::NonKeyExchangePacketReceived);
        }

        match kex_algorithm.respond(
            &answer,
            key_exchange_data,
            host_key_algorithm,
            runtime_state.rng(),
        ) {
            Ok(KeyExchangeResponse::Finished {
                host_key,
                shared_secret,
                exchange_hash,
                message,
            }) => break (host_key, shared_secret, exchange_hash, message),
            Ok(KeyExchangeResponse::Packet(packet)) => {
                output_handler
                    .send_packet(&packet, runtime_state)
                    .flush()
                    .await
                    .map_err(|err| {
                        KeyExchangeProcedureError::Communication(CommunicationError::Io(err))
                    })?;
            }
            Err(err) => return Err(KeyExchangeProcedureError::KeyExchangeAlgorithmError(err)),
        }
    };

    if let Some(message) = message {
        output_handler
            .send_packet(&message, runtime_state)
            .flush()
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;
    }

    Ok(KeyExchangeResult {
        host_key,
        shared_secret,
        exchange_hash,
    })
}

/// Represents a SSH_MSG_KEXINIT packet.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::protocol) struct KexInitPacket<'a> {
    /// The random cookie in the packet.
    pub(in crate::protocol) cookie: [u8; 16],
    /// The algorithm list in the packet.
    pub(in crate::protocol) algorithm_list: AlgorithmList<'a>,
    /// Indicates if a guessed key exchange packet follows the SSH_MSG_KEXINIT packet.
    pub(in crate::protocol) first_kex_packet_follows: bool,
}

/// Parses a SSH_MSG_KEXINIT packet.
pub(in crate::protocol) fn parse_kexinit(input: &[u8]) -> Result<KexInitPacket, ParseError> {
    let (rest, _) = tag([SSH_MSG_KEXINIT])(input)?;

    let (rest, cookie) = take(16usize)(rest)?;
    let (rest, kex) = parse_name_list(rest)?;
    let (rest, host_key) = parse_name_list(rest)?;
    let (rest, encryption_client_to_server) = parse_name_list(rest)?;
    let (rest, encryption_server_to_client) = parse_name_list(rest)?;
    let (rest, mac_client_to_server) = parse_name_list(rest)?;
    let (rest, mac_server_to_client) = parse_name_list(rest)?;
    let (rest, compression_client_to_server) = parse_name_list(rest)?;
    let (rest, compression_server_to_client) = parse_name_list(rest)?;
    let (rest, _languages_client_to_server) = parse_name_list(rest)?;
    let (rest, _languages_server_to_client) = parse_name_list(rest)?;
    let (rest, first_kex_packet_follows) = parse_boolean(rest)?;
    let _ = parse_uint32(rest)?;

    let kex = kex.into_iter().map(|s| Cow::Borrowed(s)).collect();
    let host_key = host_key.into_iter().map(|s| Cow::Borrowed(s)).collect();
    let encryption_client_to_server = encryption_client_to_server
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();
    let encryption_server_to_client = encryption_server_to_client
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();
    let mac_client_to_server = mac_client_to_server
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();
    let mac_server_to_client = mac_server_to_client
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();
    let compression_client_to_server = compression_client_to_server
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();
    let compression_server_to_client = compression_server_to_client
        .into_iter()
        .map(|s| Cow::Borrowed(s))
        .collect();

    let mut cookie_array: [u8; 16] = Default::default();

    for i in 0..16 {
        cookie_array[i] = cookie[i];
    }

    Ok(KexInitPacket {
        cookie: cookie_array,
        algorithm_list: AlgorithmList {
            kex,
            host_key,
            encryption_client_to_server,
            encryption_server_to_client,
            mac_client_to_server,
            mac_server_to_client,
            compression_client_to_server,
            compression_server_to_client,
        },
        first_kex_packet_follows,
    })
}

/// Writes a SSH_MSG_KEXINIT packet.
pub(in crate::protocol) fn write_kexinit(
    packet: &KexInitPacket,
    output: &mut impl Write,
) -> io::Result<()> {
    write_byte(SSH_MSG_KEXINIT, output)?;
    output.write_all(&packet.cookie[..])?;

    write_name_list(&packet.algorithm_list.kex, output)?;
    write_name_list(&packet.algorithm_list.host_key, output)?;
    write_name_list(&packet.algorithm_list.encryption_client_to_server, output)?;
    write_name_list(&packet.algorithm_list.encryption_server_to_client, output)?;
    write_name_list(&packet.algorithm_list.mac_client_to_server, output)?;
    write_name_list(&packet.algorithm_list.mac_server_to_client, output)?;
    write_name_list(&packet.algorithm_list.compression_client_to_server, output)?;
    write_name_list(&packet.algorithm_list.compression_server_to_client, output)?;

    // TODO: deal with languages
    let language_list: &[&'static str] = &[];
    write_name_list(language_list, output)?;
    write_name_list(language_list, output)?;

    write_boolean(packet.first_kex_packet_follows, output)?;
    write_uint32(0, output)
}

/// Negotiates a key exchange algorithm to use.
pub(in crate::protocol) fn negotiate_algorithm(
    own_list: &AlgorithmList<'static>,
    other_list: &AlgorithmList,
    own_role: &ConnectionRole,
    available_algorithms: &AvailableAlgorithms,
) -> Result<&'static str, KeyExchangeProcedureError> {
    let own_kex_list = &own_list.kex;
    let other_kex_list = &other_list.kex;

    if own_kex_list.len() == 0 || other_kex_list.len() == 0 {
        return Err(KeyExchangeProcedureError::NoAlgorithmFound(
            AlgorithmRole(AlgorithmCategory::KeyExchange, None),
        ));
    }

    if own_kex_list[0] == other_kex_list[0] {
        match own_kex_list[0] {
            Cow::Borrowed(res) => return Ok(res),
            Cow::Owned(_) => unreachable!(),
        }
    }

    let (client_algorithms, server_algorithms) = match own_role {
        ConnectionRole::Client => (own_kex_list, other_kex_list),
        ConnectionRole::Server => (other_kex_list, own_kex_list),
    };

    for algorithm_name in client_algorithms {
        if !server_algorithms.contains(algorithm_name) {
            continue;
        }

        let algorithm = match available_algorithms.kex_by_name(algorithm_name) {
            Some(alg) => alg,
            None => continue,
        };

        if algorithm.requires_encryption_capable_host_key_algorithm() {
            let common_algorithm = own_list
                .host_key
                .iter()
                .filter(|alg| {
                    available_algorithms
                        .host_key_by_name(alg)
                        .map(|a| a.is_encryption_capable())
                        .unwrap_or(false)
                })
                .any(|alg| other_list.host_key.iter().any(|a| a == alg));

            if !common_algorithm {
                continue;
            }
        }

        if algorithm.requires_signature_capable_host_key_algorithm() {
            let common_algorithm = own_list
                .host_key
                .iter()
                .filter(|alg| {
                    available_algorithms
                        .host_key_by_name(alg)
                        .map(|a| a.is_signature_capable())
                        .unwrap_or(false)
                })
                .any(|alg| other_list.host_key.iter().any(|a| a == alg));

            if !common_algorithm {
                continue;
            }
        }

        for name in own_kex_list {
            if name == algorithm_name {
                match name {
                    Cow::Borrowed(res) => return Ok(res),
                    Cow::Owned(_) => unreachable!(),
                }
            }
        }

        unreachable!();
    }

    Err(KeyExchangeProcedureError::NoAlgorithmFound(
        AlgorithmRole(AlgorithmCategory::KeyExchange, None),
    ))
}

#[cfg(test)]
mod tests {
    use matches::assert_matches;

    use super::*;

    #[test]
    fn kexinit_packet() {
        let mut target = Vec::new();

        let list = AlgorithmList {
            kex: vec![
                "diffie-hellman-group1-sha1".into(),
                "diffie-hellman-group14-sha1".into(),
            ],
            host_key: vec!["ssh-dss".into(), "ssh-rsa".into()],
            encryption_client_to_server: vec!["aes128-cbc".into(), "none".into()],
            encryption_server_to_client: vec!["aes128-cbc".into(), "none".into()],
            mac_client_to_server: vec!["hmac-sha1".into(), "none".into()],
            mac_server_to_client: vec!["hmac-sha1".into(), "none".into()],
            compression_client_to_server: vec!["none".into(), "zlib".into()],
            compression_server_to_client: vec!["none".into()],
        };

        let packet = KexInitPacket {
            cookie: [42; 16],
            algorithm_list: list,
            first_kex_packet_follows: false,
        };

        assert_matches!(write_kexinit(&packet, &mut target), Ok(()));

        assert_eq!(
            &target[..],
            &[
                SSH_MSG_KEXINIT,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                42,
                0,
                0,
                0,
                54,
                b'd',
                b'i',
                b'f',
                b'f',
                b'i',
                b'e',
                b'-',
                b'h',
                b'e',
                b'l',
                b'l',
                b'm',
                b'a',
                b'n',
                b'-',
                b'g',
                b'r',
                b'o',
                b'u',
                b'p',
                b'1',
                b'-',
                b's',
                b'h',
                b'a',
                b'1',
                b',',
                b'd',
                b'i',
                b'f',
                b'f',
                b'i',
                b'e',
                b'-',
                b'h',
                b'e',
                b'l',
                b'l',
                b'm',
                b'a',
                b'n',
                b'-',
                b'g',
                b'r',
                b'o',
                b'u',
                b'p',
                b'1',
                b'4',
                b'-',
                b's',
                b'h',
                b'a',
                b'1',
                0,
                0,
                0,
                15,
                b's',
                b's',
                b'h',
                b'-',
                b'd',
                b's',
                b's',
                b',',
                b's',
                b's',
                b'h',
                b'-',
                b'r',
                b's',
                b'a',
                0,
                0,
                0,
                15,
                b'a',
                b'e',
                b's',
                b'1',
                b'2',
                b'8',
                b'-',
                b'c',
                b'b',
                b'c',
                b',',
                b'n',
                b'o',
                b'n',
                b'e',
                0,
                0,
                0,
                15,
                b'a',
                b'e',
                b's',
                b'1',
                b'2',
                b'8',
                b'-',
                b'c',
                b'b',
                b'c',
                b',',
                b'n',
                b'o',
                b'n',
                b'e',
                0,
                0,
                0,
                14,
                b'h',
                b'm',
                b'a',
                b'c',
                b'-',
                b's',
                b'h',
                b'a',
                b'1',
                b',',
                b'n',
                b'o',
                b'n',
                b'e',
                0,
                0,
                0,
                14,
                b'h',
                b'm',
                b'a',
                b'c',
                b'-',
                b's',
                b'h',
                b'a',
                b'1',
                b',',
                b'n',
                b'o',
                b'n',
                b'e',
                0,
                0,
                0,
                9,
                b'n',
                b'o',
                b'n',
                b'e',
                b',',
                b'z',
                b'l',
                b'i',
                b'b',
                0,
                0,
                0,
                4,
                b'n',
                b'o',
                b'n',
                b'e',
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ][..]
        );

        assert_eq!(parse_kexinit(&target), Ok(packet));
    }
}
