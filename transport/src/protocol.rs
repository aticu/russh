//! Contains logic to decide which packets are sent when.

use rand::Rng;
use russh_definitions::{
    algorithms::{AlgorithmCategory, AlgorithmDirection, AlgorithmRole, KeyExchangeData},
    message_numbers::{SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST},
    message_type::MessageType,
    parser_primitives::{parse_byte, parse_string},
    writer_primitives::{write_byte, write_string},
    ConnectionRole,
};
use std::borrow::Cow;

use crate::{
    algorithms::{AlgorithmList, AvailableAlgorithms, ChosenAlgorithms},
    errors::{
        CommunicationError, InitializationError, KeyExchangeProcedureError, ServiceRequestError,
    },
    input_handler::{InputHandler, InputStream},
    output_handler::{OutputHandler, OutputStream, PacketFlusher},
    runtime_state::RuntimeState,
};

mod kex;

/// Handles all protocol interactions at the transport layer level.
pub(crate) struct ProtocolHandler<Input: InputStream, Output: OutputStream> {
    /// The state that is used by the transport layer.
    runtime_state: RuntimeState,
    /// The handler for the input to the transport layer.
    input_handler: InputHandler<Input>,
    /// The handler for the output of the transport layer.
    output_handler: OutputHandler<Output>,
    /// The identification string of the other side.
    other_identification_string: Vec<u8>,
    /// The session identifier.
    ///
    /// After the first key exchange (i.e. after a successful call to `ProtocolHandler::new`)
    /// this is always `Some(_)`.
    session_id: Option<Vec<u8>>,
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
    pub(crate) async fn next_user_packet<'a>(
        &'a mut self,
    ) -> Result<Cow<'a, [u8]>, CommunicationError> {
        let packet = self
            .input_handler
            .next_packet(&mut self.runtime_state)
            .await?;

        // TODO: filter transport layer packets

        Ok(packet)
    }

    /// Sends a packet from the user.
    ///
    /// # Panics
    /// This function may panic if the total packet length does not fit into a `u32`.
    pub(crate) fn send_user_packet<'a>(
        &'a mut self,
        data: &[u8],
    ) -> Result<PacketFlusher<'a, Output>, CommunicationError> {
        if Self::handles(data) {
            Err(CommunicationError::ProtocolInternalPacketSent)
        } else {
            Ok(self
                .output_handler
                .send_packet(data, &mut self.runtime_state))
        }
    }

    /// Initializes the connection up until the first key exchange is performed.
    pub(crate) async fn new(
        runtime_state: RuntimeState,
        mut input_handler: InputHandler<Input>,
        mut output_handler: OutputHandler<Output>,
    ) -> Result<Self, InitializationError> {
        output_handler
            .initialize(runtime_state.local_version_info())
            .flush()
            .await
            .map_err(|err| InitializationError::Communication(CommunicationError::Io(err)))?;

        let (version_info, identification_string) = input_handler
            .initialize()
            .await
            .map_err(|err| InitializationError::Communication(err))?;
        if version_info.protocol_version() != "2.0" {
            return Err(InitializationError::UnsupportedProtocolVersion(
                version_info,
            ));
        }

        let mut handler = ProtocolHandler {
            runtime_state,
            input_handler,
            output_handler,
            other_identification_string: identification_string,
            session_id: None,
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

        let remote_kexinit = self
            .input_handler
            .next_packet(&mut self.runtime_state)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(err))?
            .to_vec();
        let kex::KexInitPacket {
            cookie: _,
            algorithm_list: other_list,
            // TODO: Handle guessed packages (first_kex_packet_follows)
            first_kex_packet_follows: _,
        } = kex::parse_kexinit(&remote_kexinit).map_err(|_| {
            KeyExchangeProcedureError::Communication(CommunicationError::InvalidFormat)
        })?;

        let role = *self.runtime_state.connection_role();
        // TODO: handle encryption and mac combining algorithms

        let (kex_name, host_key_name, chosen_algorithms) =
            negotiate_algorithms(&mut self.runtime_state, &other_list)?;

        let (hash_fn, kex_algorithm_result) = {
            let mut key_exchange = self
                .runtime_state
                .key_exchange(kex_name, host_key_name)
                .expect("chosen algorithms should exist in runtime state");
            let (kex_algorithm, host_key_algorithm, mut runtime_state) = key_exchange.start();

            let hash_fn = kex_algorithm.hash_fn();

            let local_identification_string =
                format!("{}", runtime_state.local_version_info()).into_bytes();
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
                &mut *kex_algorithm,
                &mut *host_key_algorithm,
                &kex_data,
                &mut runtime_state,
                &mut self.input_handler,
                &mut self.output_handler,
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

        self.output_handler
            .send_packet(&[SSH_MSG_NEWKEYS], &mut self.runtime_state)
            .flush()
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(CommunicationError::Io(err)))?;

        let answer = self
            .input_handler
            .next_packet(&mut self.runtime_state)
            .await
            .map_err(|err| KeyExchangeProcedureError::Communication(err))?;

        if &answer[..] != &[SSH_MSG_NEWKEYS][..] {
            return Err(KeyExchangeProcedureError::NoNewkeysPacket);
        }

        // TODO: handle SSG_MSG_DISCONNECT

        if self.session_id.is_none() {
            self.session_id.replace(exchange_hash.clone());
        }

        let session_id = self.session_id.as_ref().unwrap();

        self.runtime_state.change_algorithms(
            chosen_algorithms,
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
        self.runtime_state.rng().fill(&mut local_cookie[..]);

        let local_kexinit = kex::KexInitPacket {
            cookie: local_cookie,
            algorithm_list: self.runtime_state.algorithm_list().clone(),
            first_kex_packet_follows: false,
        };

        let mut local_kexinit_packet = Vec::new();
        kex::write_kexinit(&local_kexinit, &mut local_kexinit_packet)
            .expect("write operations on vec don't fail");

        self.output_handler
            .send_packet(&local_kexinit_packet, &mut self.runtime_state)
            .flush()
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

        write_byte(SSH_MSG_SERVICE_REQUEST, &mut packet).expect("vec writes don't fail");
        write_string(service, &mut packet).expect("vec writes don't fail");

        self.output_handler
            .send_packet(&packet, &mut self.runtime_state)
            .flush()
            .await
            .map_err(|e| ServiceRequestError::Communication(CommunicationError::Io(e)))?;

        let answer = self
            .input_handler
            .next_packet(&mut self.runtime_state)
            .await
            .map_err(|e| ServiceRequestError::Communication(e))?;

        // TODO: possibly handle other packets in between, like SSG_MSG_IGNORE (this also applies
        // to other places)
        let (rest_answer, code) =
            parse_byte(&answer).map_err(|_| ServiceRequestError::InvalidFormat)?;

        if code != SSH_MSG_SERVICE_ACCEPT {
            return Err(ServiceRequestError::InvalidFormat);
        }

        let (_, name) =
            parse_string(rest_answer).map_err(|_| ServiceRequestError::InvalidFormat)?;

        if name == service {
            Ok(())
        } else {
            Err(ServiceRequestError::WrongServiceAccepted(name.to_vec()))
        }
    }
}

/// Performs the algorithm negotiation.
fn negotiate_algorithms<'a>(
    runtime_state: &'a mut RuntimeState,
    other_list: &AlgorithmList,
) -> Result<(&'static str, &'static str, ChosenAlgorithms), KeyExchangeProcedureError> {
    let own_list = runtime_state.algorithm_list();
    let own_role = runtime_state.connection_role();
    let available_algorithms = runtime_state.available_algorithms();

    let encryption_c2s = negotiate_basic_algorithm(
        &own_list.encryption_c2s,
        &other_list.encryption_c2s,
        own_role,
        AlgorithmRole(
            AlgorithmCategory::Encryption,
            Some(AlgorithmDirection::ClientToServer),
        ),
    )?;
    let mac_c2s_needed = available_algorithms
        .encryption_c2s
        .iter()
        .find(|alg| alg.name() == encryption_c2s)
        .expect("chosen algorithm is available")
        .mac_size()
        .is_none();
    let mac_c2s = if mac_c2s_needed {
        Some(negotiate_basic_algorithm(
            &own_list.mac_c2s,
            &other_list.mac_c2s,
            own_role,
            AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ClientToServer),
            ),
        )?)
    } else {
        None
    };
    let compression_c2s = negotiate_basic_algorithm(
        &own_list.compression_c2s,
        &other_list.compression_c2s,
        own_role,
        AlgorithmRole(
            AlgorithmCategory::Compression,
            Some(AlgorithmDirection::ClientToServer),
        ),
    )?;

    let encryption_s2c = negotiate_basic_algorithm(
        &own_list.encryption_s2c,
        &other_list.encryption_s2c,
        own_role,
        AlgorithmRole(
            AlgorithmCategory::Encryption,
            Some(AlgorithmDirection::ServerToClient),
        ),
    )?;
    let mac_s2c_needed = available_algorithms
        .encryption_s2c
        .iter()
        .find(|alg| alg.name() == encryption_s2c)
        .expect("chosen algorithm is available")
        .mac_size()
        .is_none();
    let mac_s2c = if mac_s2c_needed {
        Some(negotiate_basic_algorithm(
            &own_list.mac_s2c,
            &other_list.mac_s2c,
            own_role,
            AlgorithmRole(
                AlgorithmCategory::Mac,
                Some(AlgorithmDirection::ServerToClient),
            ),
        )?)
    } else {
        None
    };
    let compression_s2c = negotiate_basic_algorithm(
        &own_list.compression_s2c,
        &other_list.compression_s2c,
        own_role,
        AlgorithmRole(
            AlgorithmCategory::Compression,
            Some(AlgorithmDirection::ServerToClient),
        ),
    )?;

    let kex_name = kex::negotiate_algorithm(own_list, other_list, own_role, available_algorithms)?;
    let host_key_name = negotiate_host_key_algorithm(
        own_list,
        other_list,
        own_role,
        available_algorithms,
        kex_name,
    )?;

    let chosen_algorithms = ChosenAlgorithms {
        encryption_c2s,
        encryption_s2c,
        mac_c2s,
        mac_s2c,
        compression_c2s,
        compression_s2c,
    };

    Ok((kex_name, host_key_name, chosen_algorithms))
}

/// Negotiates a server host key algorithm.
fn negotiate_host_key_algorithm(
    own_list: &AlgorithmList<'static>,
    other_list: &AlgorithmList,
    connection_role: &ConnectionRole,
    available_algorithms: &AvailableAlgorithms,
    kex: &str,
) -> Result<&'static str, KeyExchangeProcedureError> {
    let kex_alg = available_algorithms
        .kex_by_name(kex)
        .expect("chosen key exchange algorithm should exist");

    let (client_list, server_list) = match connection_role {
        ConnectionRole::Client => (&own_list.host_key, &other_list.host_key),
        ConnectionRole::Server => (&other_list.host_key, &own_list.host_key),
    };

    client_list
        .iter()
        .filter(|name| {
            let host_key_alg = match available_algorithms.host_key_by_name(name) {
                Some(alg) => alg,
                None => return false,
            };

            (kex_alg.requires_encryption_capable_host_key_algorithm()
                && host_key_alg.is_encryption_capable())
                || (kex_alg.requires_signature_capable_host_key_algorithm()
                    && host_key_alg.is_signature_capable())
        })
        .find(|name| server_list.contains(name))
        .map(|name| {
            for a in own_list.host_key.iter() {
                if a == name {
                    match a {
                        Cow::Borrowed(res) => return *res,
                        Cow::Owned(_) => unreachable!(),
                    }
                }
            }

            unreachable!()
        })
        .ok_or(KeyExchangeProcedureError::NoAlgorithmFound(AlgorithmRole(
            AlgorithmCategory::HostKey,
            None,
        )))
}

/// Negotiates an encryption, MAC or compression algorithm.
fn negotiate_basic_algorithm(
    own_list: &[Cow<'static, str>],
    other_list: &[Cow<str>],
    own_role: &ConnectionRole,
    role: AlgorithmRole,
) -> Result<&'static str, KeyExchangeProcedureError> {
    let (client_list, server_list) = match own_role {
        ConnectionRole::Client => (own_list, other_list),
        ConnectionRole::Server => (other_list, own_list),
    };

    client_list
        .iter()
        .find(|name| server_list.contains(name))
        .map(|name| {
            for n in own_list {
                if n == name {
                    match n {
                        Cow::Borrowed(res) => return *res,
                        Cow::Owned(_) => unreachable!(),
                    }
                }
            }

            unreachable!()
        })
        .ok_or(KeyExchangeProcedureError::NoAlgorithmFound(role))
}
