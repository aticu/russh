//! Handles key exchange related protocol functions.

use definitions::{
    algorithms::{AlgorithmCategory, AlgorithmRole, KeyExchangeData, KeyExchangeResponse},
    consts::{MessageType, SSH_MSG_KEXINIT},
    ConnectionRole, ParsedValue,
};
use num_bigint::BigInt;
use std::{
    borrow::Cow,
    io::{self, Write},
};

use crate::{
    algorithms::{AlgorithmNameList, ConnectionAlgorithms},
    errors::{CommunicationError, KeyExchangeProcedureError, ParseError},
    input::{InputBuffer, InputStream},
    output_handler::{OutputHandler, OutputStream},
    CryptoRngCore,
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
    key_exchange_data: &KeyExchangeData<'_>,
    connection_role: ConnectionRole,
    connection_algorithms: &mut ConnectionAlgorithms,
    rng: &mut dyn CryptoRngCore,
    (input_buffer, input): (&mut InputBuffer, &mut Input),
    (output_handler, output): (&mut OutputHandler, &mut Output),
) -> Result<KeyExchangeResult, KeyExchangeProcedureError> {
    let kex_algorithm = connection_algorithms.kex.current();
    let host_key_algorithm = connection_algorithms.host_key.current();

    if let Some(start_packet) =
        kex_algorithm.start(&connection_role, key_exchange_data, host_key_algorithm, rng)
    {
        output_handler.write_packet(
            &start_packet,
            outgoing_algorithms!(connection_algorithms, connection_role),
            rng,
        );
        output_handler
            .flush_into(output)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;
    }

    let (host_key, shared_secret, exchange_hash, message) = loop {
        let answer = loop {
            match input_buffer
                .read_packet(incoming_algorithms!(connection_algorithms, connection_role))?
            {
                Some(answer) => break answer,
                None => input_buffer.read_more_data(input).await?,
            };
        };

        if MessageType::from_message(&answer) != Some(MessageType::KeyExchangeMethodSpecific) {
            return Err(KeyExchangeProcedureError::NonKeyExchangePacketReceived);
        }

        match kex_algorithm.respond(&answer, key_exchange_data, host_key_algorithm, rng) {
            Ok(KeyExchangeResponse::Finished {
                host_key,
                shared_secret,
                exchange_hash,
                message,
            }) => break (host_key, shared_secret, exchange_hash, message),
            Ok(KeyExchangeResponse::Packet(packet)) => {
                output_handler.write_packet(
                    &packet,
                    outgoing_algorithms!(connection_algorithms, connection_role),
                    rng,
                );
                output_handler.flush_into(output).await.map_err(|err| {
                    KeyExchangeProcedureError::Communication(CommunicationError::Io(err))
                })?;
            }
            Err(err) => return Err(KeyExchangeProcedureError::KeyExchangeAlgorithmError(err)),
        }
    };

    if let Some(message) = message {
        output_handler.write_packet(
            &message,
            outgoing_algorithms!(connection_algorithms, connection_role),
            rng,
        );
        output_handler
            .flush_into(output)
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
pub(in crate::protocol) struct KexinitPacket<'a> {
    /// The random cookie in the packet.
    pub(in crate::protocol) cookie: [u8; 16],
    /// The algorithm list in the packet.
    pub(in crate::protocol) algorithm_list: AlgorithmNameList<'a>,
    /// Indicates if a guessed key exchange packet follows the SSH_MSG_KEXINIT packet.
    pub(in crate::protocol) first_kex_packet_follows: bool,
}

#[rustfmt::skip]
definitions::ssh_packet! {
    #[derive(Debug, Default)]
    struct RawKexinitPacket {
        byte         {SSH_MSG_KEXINIT}
        byte[16]     cookie
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       _reserved
    }
}

/// Parses a SSH_MSG_KEXINIT packet.
pub(in crate::protocol) fn parse_kexinit(input: &[u8]) -> Result<KexinitPacket, ParseError> {
    use definitions::Parse as _;
    let ParsedValue { value: packet, .. } = RawKexinitPacket::parse(input)?;

    Ok(KexinitPacket {
        cookie: packet.cookie,
        algorithm_list: AlgorithmNameList {
            kex: packet.kex_algorithms.into_owned(),
            host_key: packet.server_host_key_algorithms.into_owned(),
            encryption_c2s: packet.encryption_algorithms_client_to_server.into_owned(),
            encryption_s2c: packet.encryption_algorithms_server_to_client.into_owned(),
            mac_c2s: packet.mac_algorithms_client_to_server.into_owned(),
            mac_s2c: packet.mac_algorithms_server_to_client.into_owned(),
            compression_c2s: packet.compression_algorithms_client_to_server.into_owned(),
            compression_s2c: packet.compression_algorithms_server_to_client.into_owned(),
        },
        first_kex_packet_follows: packet.first_kex_packet_follows,
    })
}

/// Writes a SSH_MSG_KEXINIT packet.
pub(in crate::protocol) fn write_kexinit(
    packet: &KexinitPacket,
    output: &mut impl Write,
) -> io::Result<()> {
    use definitions::Compose as _;

    // TODO: deal with languages
    RawKexinitPacket {
        cookie: packet.cookie,
        kex_algorithms: (&packet.algorithm_list.kex[..]).into(),
        server_host_key_algorithms: (&packet.algorithm_list.host_key[..]).into(),
        encryption_algorithms_client_to_server: (&packet.algorithm_list.encryption_c2s[..]).into(),
        encryption_algorithms_server_to_client: (&packet.algorithm_list.encryption_s2c[..]).into(),
        mac_algorithms_client_to_server: (&packet.algorithm_list.mac_c2s[..]).into(),
        mac_algorithms_server_to_client: (&packet.algorithm_list.mac_s2c[..]).into(),
        compression_algorithms_client_to_server: (&packet.algorithm_list.compression_c2s[..])
            .into(),
        compression_algorithms_server_to_client: (&packet.algorithm_list.compression_s2c[..])
            .into(),
        first_kex_packet_follows: false,
        _reserved: 0,
        ..Default::default()
    }
    .compose(output)
}

/// Negotiates a key exchange algorithm to use.
pub(in crate::protocol) fn negotiate_algorithm<'names>(
    own_list: &'names AlgorithmNameList<'names>,
    other_list: &'names AlgorithmNameList<'names>,
    own_role: ConnectionRole,
    connection_algorithms: &ConnectionAlgorithms,
) -> Result<&'names str, KeyExchangeProcedureError> {
    let own_kex_list = &own_list.kex;
    let other_kex_list = &other_list.kex;

    if own_kex_list.is_empty() || other_kex_list.is_empty() {
        return Err(KeyExchangeProcedureError::NoAlgorithmFound(AlgorithmRole(
            AlgorithmCategory::KeyExchange,
            None,
        )));
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

    let shared_encryption_capable_host_key_algorithm = other_list.host_key.iter().any(|alg| {
        // if the algorithm is found in the `connection_algorithms`, it must also be present in
        // the own algorithm list
        connection_algorithms
            .host_key
            .algorithm(alg)
            .map(|a| a.is_encryption_capable)
            .unwrap_or(false)
    });

    let shared_signature_capable_host_key_algorithm = other_list.host_key.iter().any(|alg| {
        // if the algorithm is found in the `connection_algorithms`, it must also be present in
        // the own algorithm list
        connection_algorithms
            .host_key
            .algorithm(alg)
            .map(|a| a.is_signature_capable)
            .unwrap_or(false)
    });

    for algorithm_name in client_algorithms {
        if !server_algorithms.contains(algorithm_name) {
            continue;
        }

        let algorithm = match connection_algorithms.kex.algorithm(algorithm_name) {
            Some(alg) => alg,
            None => continue,
        };

        if algorithm.requires_encryption_capable_host_key_algorithm
            && !shared_encryption_capable_host_key_algorithm
        {
            continue;
        }

        if algorithm.requires_signature_capable_host_key_algorithm
            && !shared_signature_capable_host_key_algorithm
        {
            continue;
        }

        return Ok(algorithm_name);
    }

    Err(KeyExchangeProcedureError::NoAlgorithmFound(AlgorithmRole(
        AlgorithmCategory::KeyExchange,
        None,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kexinit_packet() {
        let mut target = Vec::new();

        let list = AlgorithmNameList {
            kex: vec![
                "diffie-hellman-group1-sha1".into(),
                "diffie-hellman-group14-sha1".into(),
            ],
            host_key: vec!["ssh-dss".into(), "ssh-rsa".into()],
            encryption_c2s: vec!["aes128-cbc".into(), "none".into()],
            encryption_s2c: vec!["aes128-cbc".into(), "none".into()],
            mac_c2s: vec!["hmac-sha1".into(), "none".into()],
            mac_s2c: vec!["hmac-sha1".into(), "none".into()],
            compression_c2s: vec!["none".into(), "zlib".into()],
            compression_s2c: vec!["none".into()],
        };

        let packet = KexinitPacket {
            cookie: [42; 16],
            algorithm_list: list,
            first_kex_packet_follows: false,
        };

        assert!(matches!(write_kexinit(&packet, &mut target), Ok(())));

        #[rustfmt::skip]
        assert_eq!(
            &target[..],
            &[
            SSH_MSG_KEXINIT,
            42, 42, 42, 42, 42, 42, 42, 42, // cookie
            42, 42, 42, 42, 42, 42, 42, 42,
            0, 0, 0, 54, // kex algorithms
            b'd', b'i', b'f', b'f', b'i', b'e', b'-', b'h', b'e', b'l', b'l', b'm', b'a', b'n',
            b'-', b'g', b'r', b'o', b'u', b'p', b'1', b'-', b's', b'h', b'a', b'1', b',', b'd',
            b'i', b'f', b'f', b'i', b'e', b'-', b'h', b'e', b'l', b'l', b'm', b'a', b'n', b'-',
            b'g', b'r', b'o', b'u', b'p', b'1', b'4', b'-', b's', b'h', b'a', b'1',
            0, 0, 0, 15, // server host key algorithms
            b's', b's', b'h', b'-', b'd', b's', b's', b',', b's', b's', b'h', b'-', b'r', b's',
            b'a',
            0, 0, 0, 15, // encryption c2s
            b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b'b', b'c', b',', b'n', b'o', b'n',
            b'e',
            0, 0, 0, 15, // encryption s2c
            b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b'b', b'c', b',', b'n', b'o', b'n',
            b'e',
            0, 0, 0, 14, // mac c2s
            b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1', b',', b'n', b'o', b'n', b'e',
            0, 0, 0, 14, // mac s2c
            b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1', b',', b'n', b'o', b'n', b'e',
            0, 0, 0, 9, // compression c2s
            b'n', b'o', b'n', b'e', b',', b'z', b'l', b'i', b'b',
            0, 0, 0, 4, // compression s2c
            b'n', b'o', b'n', b'e',
            0, 0, 0, 0, // languages c2s
            0, 0, 0, 0, // languages s2c
            0, // first kex packet follows
            0, 0, 0, 0 // reserved
                ][..]
                );

        assert_eq!(parse_kexinit(&target), Ok(packet));
    }
}
