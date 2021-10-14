//! Contains logic to decide which packets are sent when.

use definitions::{
    algorithms::{AlgorithmCategory, AlgorithmDirection, AlgorithmRole, KeyExchangeData},
    consts::{MessageType, SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST},
    parse, write, ConnectionRole, ParsedValue,
};
use rand::Rng;
use std::borrow::Cow;

use crate::{
    algorithms::{AlgorithmNameList, ChosenAlgorithms, ConnectionAlgorithms},
    errors::{
        CommunicationError, InitializationError, KeyExchangeProcedureError, ServiceRequestError,
    },
    input_handler::{InputHandler, InputStream},
    output_handler::{OutputHandler, OutputStream},
    version::VersionInformation,
    CryptoRngCore,
};

mod kex;

/// Handles all protocol interactions at the transport layer level.
pub(crate) struct ProtocolHandler<Input: InputStream, Output: OutputStream> {
    /// The handler for the input to the transport layer.
    input_handler: InputHandler,
    /// The source of the input.
    input: Input,
    /// The handler for the output of the transport layer.
    output_handler: OutputHandler,
    /// The output used by the transport layer.
    output: Output,
    /// The identification string of the other side.
    other_identification_string: Vec<u8>,
    /// The session identifier.
    ///
    /// After the first key exchange (i.e. after a successful call to `ProtocolHandler::new`)
    /// this is always `Some(_)`.
    session_id: Option<Vec<u8>>,
    /// The random number generator used for the connection.
    rng: Box<dyn CryptoRngCore>,
    /// The role of the handler in the connection.
    connection_role: ConnectionRole,
    /// The algorithms used by the SSH connection.
    connection_algorithms: ConnectionAlgorithms,
    /// The list of available algorithms.
    ///
    /// This exists to preverse the original algorithms order, while having the ability
    /// to move algorithms out of the `ConnectionAlgorithms`.
    algorithm_list: AlgorithmNameList<'static>,
    /// The version information for the handler.
    version_info: VersionInformation,
}
// TODO: Consider poisoning the handler if an error occurs during a critical operation

impl<Input: InputStream, Output: OutputStream> ProtocolHandler<Input, Output> {
    /// Checks if the packet is handled by the protocol layer.
    pub(crate) fn handles(data: &[u8]) -> bool {
        let message_type = MessageType::from_message(data);

        match message_type {
            Some(MessageType::Zero) => false,
            Some(MessageType::TransportLayerGeneric) => true,
            Some(MessageType::AlgorithmNegotiation) => true,
            Some(MessageType::KeyExchangeMethodSpecific) => true,
            Some(MessageType::UserAuthenticationGeneric) => false,
            Some(MessageType::UserAuthenticationMethodSpecific) => false,
            Some(MessageType::ConnectionProtocolGeneric) => false,
            Some(MessageType::ChannelRelated) => false,
            Some(MessageType::Reserved) => false,
            Some(MessageType::LocalExtension) => false,
            None => false,
        }
    }

    /// Receives the next packet that will be sent to the user.
    pub(crate) async fn next_user_packet(&mut self) -> Result<Vec<u8>, CommunicationError> {
        let packet = loop {
            match self.input_handler.read_packet(incoming_algorithms!(
                self.connection_algorithms,
                self.connection_role
            ))? {
                Some(packet) => break packet.to_vec(),
                None => self.input_handler.read_more_data(&mut self.input).await?,
            };
        };

        // TODO: filter transport layer packets

        Ok(packet)
    }

    /// Sends a packet from the user.
    ///
    /// # Panics
    /// This function may panic if the total packet length does not fit into a `u32`.
    pub(crate) async fn send_user_packet(&mut self, data: &[u8]) -> Result<(), CommunicationError> {
        if Self::handles(data) {
            Err(CommunicationError::ProtocolInternalPacketSent)
        } else {
            self.output_handler.write_packet(
                data,
                outgoing_algorithms!(self.connection_algorithms, self.connection_role),
                &mut self.rng,
            );
            self.output_handler.flush_into(&mut self.output).await?;

            Ok(())
        }
    }

    /// Initializes the connection up until the first key exchange is performed.
    pub(crate) async fn new(
        (mut input_handler, mut input): (InputHandler, Input),
        (mut output_handler, mut output): (OutputHandler, Output),
        rng: Box<dyn CryptoRngCore>,
        connection_role: ConnectionRole,
        connection_algorithms: ConnectionAlgorithms,
        allow_none_algorithms: bool,
        version_info: VersionInformation,
    ) -> Result<Self, InitializationError> {
        output_handler.initialize(&version_info);

        output_handler
            .flush_into(&mut output)
            .await
            .map_err(|err| InitializationError::Communication(CommunicationError::Io(err)))?;

        let (other_version_info, identification_string) = loop {
            match input_handler.initialize()? {
                Some(result) => break result,
                None => input_handler.read_more_data(&mut input).await?,
            };
        };
        if other_version_info.protocol_version() != "2.0" {
            return Err(InitializationError::UnsupportedProtocolVersion(
                other_version_info,
            ));
        }

        let algorithm_list =
            AlgorithmNameList::from_available(&connection_algorithms, allow_none_algorithms);

        let mut handler = ProtocolHandler {
            input_handler,
            input,
            output_handler,
            output,
            other_identification_string: identification_string,
            session_id: None,
            rng,
            connection_role,
            connection_algorithms,
            algorithm_list,
            version_info,
        };

        handler
            .perform_key_exchange()
            .await
            .map_err(|err| match err {
                KeyExchangeProcedureError::Communication(err) => {
                    InitializationError::Communication(err)
                }
                err => InitializationError::KeyExchange(err),
            })?;

        Ok(handler)
    }

    /// Performs a key exchange with the other side.
    async fn perform_key_exchange(&mut self) -> Result<(), KeyExchangeProcedureError> {
        // TODO: handle guess packets
        // TODO: consider sending guess packets?
        let local_kexinit = self.send_kexinit_packet().await?;

        let remote_kexinit = loop {
            match self.input_handler.read_packet(incoming_algorithms!(
                self.connection_algorithms,
                self.connection_role
            ))? {
                Some(remote_kexinit) => break remote_kexinit.to_vec(),
                None => self.input_handler.read_more_data(&mut self.input).await?,
            };
        };

        let kex::KexinitPacket {
            cookie: _,
            algorithm_list: other_list,
            // TODO: Handle guessed packages (first_kex_packet_follows)
            first_kex_packet_follows: _,
        } = kex::parse_kexinit(&remote_kexinit).map_err(|_| {
            KeyExchangeProcedureError::Communication(CommunicationError::InvalidFormat)
        })?;

        let role = self.connection_role;
        // TODO: handle encryption and mac combining algorithms

        let chosen_algorithms = negotiate_algorithms(
            self.connection_role,
            &mut self.connection_algorithms,
            &self.algorithm_list,
            &other_list,
        )?;

        let (hash_fn, kex_algorithm_result) = {
            let hash_fn = self.connection_algorithms.kex.current().hash_function;

            let local_identification_string = format!("{}", &self.version_info).into_bytes();
            let (client_identification, server_identification) = match role {
                ConnectionRole::Client => (
                    &local_identification_string,
                    &self.other_identification_string,
                ),
                ConnectionRole::Server => (
                    &self.other_identification_string,
                    &local_identification_string,
                ),
            };

            let (client_kexinit, server_kexinit) = match role {
                ConnectionRole::Client => (&local_kexinit, &remote_kexinit),
                ConnectionRole::Server => (&remote_kexinit, &local_kexinit),
            };

            let kex_data = KeyExchangeData {
                client_identification,
                server_identification,
                client_kexinit,
                server_kexinit,
            };

            let result = kex::algorithm_specific_exchange(
                &kex_data,
                self.connection_role,
                &mut self.connection_algorithms,
                &mut self.rng,
                (&mut self.input_handler, &mut self.input),
                (&mut self.output_handler, &mut self.output),
            )
            .await;

            (hash_fn, result)
        };

        let kex::KeyExchangeResult {
            host_key,
            shared_secret,
            exchange_hash,
        } = kex_algorithm_result?;
        // TODO: verify host key here
        let _ = host_key;

        self.output_handler.write_packet(
            &[SSH_MSG_NEWKEYS],
            outgoing_algorithms!(self.connection_algorithms, self.connection_role),
            &mut self.rng,
        );
        self.output_handler
            .flush_into(&mut self.output)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;

        let answer = loop {
            match self.input_handler.read_packet(incoming_algorithms!(
                self.connection_algorithms,
                self.connection_role
            ))? {
                Some(answer) => break answer,
                None => self.input_handler.read_more_data(&mut self.input).await?,
            };
        };

        if answer[..] != [SSH_MSG_NEWKEYS][..] {
            return Err(KeyExchangeProcedureError::NoNewkeysPacket);
        }

        // TODO: handle SSG_MSG_DISCONNECT

        if self.session_id.is_none() {
            self.session_id.replace(exchange_hash.clone());
        }

        let session_id = self.session_id.as_ref().unwrap();

        self.connection_algorithms.unload_algorithm_keys();
        self.connection_algorithms.load_algorithm_keys(
            &chosen_algorithms,
            hash_fn,
            &shared_secret,
            &exchange_hash,
            session_id,
        );

        Ok(())
    }

    /// Sends a `SSH_MSG_KEXINIT` to the partner.
    async fn send_kexinit_packet(&mut self) -> Result<Vec<u8>, KeyExchangeProcedureError> {
        let mut local_cookie: [u8; 16] = Default::default();
        self.rng.fill(&mut local_cookie[..]);

        let local_kexinit = kex::KexinitPacket {
            cookie: local_cookie,
            algorithm_list: self.algorithm_list.clone(),
            first_kex_packet_follows: false,
        };

        let mut local_kexinit_packet = Vec::new();
        kex::write_kexinit(&local_kexinit, &mut local_kexinit_packet)
            .expect("write operations on vec don't fail");

        self.output_handler.write_packet(
            &local_kexinit_packet,
            outgoing_algorithms!(self.connection_algorithms, self.connection_role),
            &mut self.rng,
        );
        self.output_handler
            .flush_into(&mut self.output)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;

        Ok(local_kexinit_packet)
    }

    /// Sends a packet from the user.
    pub(crate) async fn service_request(
        &mut self,
        service: &[u8],
    ) -> Result<(), ServiceRequestError> {
        let mut packet = Vec::new();

        write::byte(SSH_MSG_SERVICE_REQUEST, &mut packet).expect("vec writes don't fail");
        write::string(service, &mut packet).expect("vec writes don't fail");

        self.output_handler.write_packet(
            &packet,
            outgoing_algorithms!(self.connection_algorithms, self.connection_role),
            &mut self.rng,
        );
        self.output_handler
            .flush_into(&mut self.output)
            .await
            .map_err(|e| ServiceRequestError::Communication(CommunicationError::Io(e)))?;

        let answer = loop {
            match self.input_handler.read_packet(incoming_algorithms!(
                self.connection_algorithms,
                self.connection_role
            ))? {
                Some(answer) => break answer,
                None => self.input_handler.read_more_data(&mut self.input).await?,
            };
        };

        // TODO: possibly handle other packets in between, like SSG_MSG_IGNORE (this also applies
        // to other places)
        let ParsedValue {
            value: code,
            rest_input: rest_answer,
        } = parse::byte(&answer).map_err(|_| ServiceRequestError::InvalidFormat)?;

        if code != SSH_MSG_SERVICE_ACCEPT {
            return Err(ServiceRequestError::InvalidFormat);
        }

        let ParsedValue { value: name, .. } =
            parse::string(rest_answer).map_err(|_| ServiceRequestError::InvalidFormat)?;

        if name == service {
            Ok(())
        } else {
            Err(ServiceRequestError::WrongServiceAccepted(name.to_vec()))
        }
    }
}

/// Performs the algorithm negotiation.
fn negotiate_algorithms<'names>(
    connection_role: ConnectionRole,
    connection_algorithms: &mut ConnectionAlgorithms,
    own_list: &'names AlgorithmNameList<'names>,
    other_list: &'names AlgorithmNameList<'names>,
) -> Result<ChosenAlgorithms<'names>, KeyExchangeProcedureError> {
    let client_list = connection_role.pick(own_list, other_list);
    let server_list = connection_role.pick(other_list, own_list);

    let negotiate_packet_algorithms = |client_encryption,
                                       server_encryption,
                                       client_mac,
                                       server_mac,
                                       client_compression,
                                       server_compression,
                                       direction|
     -> Result<_, KeyExchangeProcedureError> {
        let encryption = negotiate_basic_algorithm(
            client_encryption,
            server_encryption,
            AlgorithmRole(AlgorithmCategory::Encryption, Some(direction)),
        )?;

        let mac_included = match direction {
            AlgorithmDirection::ClientToServer => &connection_algorithms.c2s,
            AlgorithmDirection::ServerToClient => &connection_algorithms.s2c,
        }
        .encryption
        .algorithm(encryption)
        .expect("chosen algorithm is available")
        .computes_mac();
        let mac = if !mac_included {
            Some(negotiate_basic_algorithm(
                client_mac,
                server_mac,
                AlgorithmRole(AlgorithmCategory::Mac, Some(direction)),
            )?)
        } else {
            None
        };

        let compression = negotiate_basic_algorithm(
            client_compression,
            server_compression,
            AlgorithmRole(AlgorithmCategory::Compression, Some(direction)),
        )?;

        Ok((encryption, mac, compression))
    };

    let (encryption_c2s, mac_c2s, compression_c2s) = negotiate_packet_algorithms(
        &client_list.encryption_c2s,
        &server_list.encryption_c2s,
        &client_list.mac_c2s,
        &server_list.mac_c2s,
        &client_list.compression_c2s,
        &server_list.compression_c2s,
        AlgorithmDirection::ClientToServer,
    )?;
    let (encryption_s2c, mac_s2c, compression_s2c) = negotiate_packet_algorithms(
        &client_list.encryption_s2c,
        &server_list.encryption_s2c,
        &client_list.mac_s2c,
        &server_list.mac_s2c,
        &client_list.compression_s2c,
        &server_list.compression_s2c,
        AlgorithmDirection::ServerToClient,
    )?;

    let kex_name =
        kex::negotiate_algorithm(own_list, other_list, connection_role, connection_algorithms)?;
    let host_key_name =
        negotiate_host_key_algorithm(client_list, server_list, connection_algorithms, kex_name)?;

    let chosen_algorithms = ChosenAlgorithms {
        encryption_c2s,
        encryption_s2c,
        mac_c2s,
        mac_s2c,
        compression_c2s,
        compression_s2c,
    };

    connection_algorithms.kex.choose(kex_name);
    connection_algorithms.host_key.choose(host_key_name);

    Ok(chosen_algorithms)
}

/// Negotiates a server host key algorithm.
fn negotiate_host_key_algorithm<'names>(
    client_list: &'names AlgorithmNameList<'names>,
    server_list: &'names AlgorithmNameList<'names>,
    connection_algorithms: &ConnectionAlgorithms,
    kex: &str,
) -> Result<&'names str, KeyExchangeProcedureError> {
    let kex_alg = connection_algorithms
        .kex
        .algorithm(kex)
        .expect("chosen key exchange algorithm should exist");

    client_list
        .host_key
        .iter()
        .filter(|name| {
            let host_key_alg = match connection_algorithms.host_key.algorithm(name) {
                Some(alg) => alg,
                None => return false,
            };

            (kex_alg.requires_encryption_capable_host_key_algorithm
                && host_key_alg.is_encryption_capable)
                || (kex_alg.requires_signature_capable_host_key_algorithm
                    && host_key_alg.is_signature_capable)
        })
        .find(|name| server_list.host_key.contains(name))
        .map(|name| &**name)
        .ok_or(KeyExchangeProcedureError::NoAlgorithmFound(AlgorithmRole(
            AlgorithmCategory::HostKey,
            None,
        )))
}

/// Negotiates an encryption, MAC or compression algorithm.
fn negotiate_basic_algorithm<'names>(
    client_list: &'names [Cow<'names, str>],
    server_list: &'names [Cow<'names, str>],
    role: AlgorithmRole,
) -> Result<&'names str, KeyExchangeProcedureError> {
    client_list
        .iter()
        .find(|name| server_list.contains(name))
        .map(|name| &**name)
        .ok_or(KeyExchangeProcedureError::NoAlgorithmFound(role))
}
