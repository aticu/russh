//! Contains constants for all the known message numbers used in the SSH protocol.

/// This message causes immediate termination of the connection.
pub const SSH_MSG_DISCONNECT: u8 = 1;

/// All implementations must understand and ignore this message at any time.
pub const SSH_MSG_IGNORE: u8 = 2;

/// The response message to an unrecognized message.
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;

/// The message is used for debugging purposes and may be ignored.
pub const SSH_MSG_DEBUG: u8 = 4;

/// The message is a service request by the client.
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;

/// The message indicates that the server accepted the service request.
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

/// The message is initializing a key exchange.
pub const SSH_MSG_KEXINIT: u8 = 20;

/// The message indicates successful keyexchange and initiates usage of new keys.
pub const SSH_MSG_NEWKEYS: u8 = 21;

/// The message indicates the initialization of an ECDH key exchange.
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;

/// The message indicates a response in an ECDH key exchange.
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// The message initiates a new user authentication.
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;

/// The message indicates a failure to authenticate the user using the given method.
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;

/// The message indicates successful user authentication.
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;

/// The message contains a banner to be displayed to the user during authentication.
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;

/// The message indicates a request that is independent from channels.
pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;

/// The message indicates that a request was successful.
pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;

/// The message indicates that a request failed.
pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

/// The message indicates the request to open a new channel.
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;

/// The message confirms the opening of a new channel.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;

/// The message indicates failure to open a new channel.
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;

/// The message indicates an adjustment of the window size of a channel.
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;

/// The message contains data for the channel.
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;

/// The message contains data of a different type for the channel.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;

/// The message indicates no more data will be sent over the channel.
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;

/// The message indicates a whish to close the channel.
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;

/// The message indicates a channel specific request.
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;

/// The message indicates that a channel specific request was successful.
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;

/// The message indicates that a channel specific request failed.
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// Describes the types of messages that the protocol specifies.
#[derive(Debug, PartialEq, Eq)]
pub enum MessageType {
    /// The message had `0` as the message number.
    ///
    /// The meaning of this is not specified in the RFC.
    Zero,
    /// The message is generic to the transport layer.
    ///
    /// This means messages such as "disconnect", "ignore" and "debug".
    TransportLayerGeneric,
    /// The message is used for algorithm negotiation.
    AlgorithmNegotiation,
    /// The message is used for the key exchange.
    ///
    /// # Note
    /// Message numbers in this range can have different meanings
    /// depending on the key exchange method used.
    KeyExchangeMethodSpecific,
    /// The message is used for general user authentication.
    UserAuthenticationGeneric,
    /// The message is used for user authentication.
    ///
    /// # Note
    /// Message numbers in this range can have different meanings
    /// depending on the user authentication method used.
    UserAuthenticationMethodSpecific,
    /// The message is used for the connection protocol.
    ConnectionProtocolGeneric,
    /// The message is used in channel based communication.
    ChannelRelated,
    /// The message number is reserved for a future extension.
    Reserved,
    /// The message number is in the private use ranger.
    LocalExtension,
}

impl From<u8> for MessageType {
    fn from(message_number: u8) -> Self {
        Self::from_number(message_number)
    }
}

impl MessageType {
    /// Returns the message type for the given message number.
    pub fn from_number(message_number: u8) -> MessageType {
        match message_number {
            0 => MessageType::Zero,
            1..=19 => MessageType::TransportLayerGeneric,
            20..=29 => MessageType::AlgorithmNegotiation,
            30..=49 => MessageType::KeyExchangeMethodSpecific,
            50..=59 => MessageType::UserAuthenticationGeneric,
            60..=79 => MessageType::UserAuthenticationMethodSpecific,
            80..=89 => MessageType::ConnectionProtocolGeneric,
            90..=127 => MessageType::ChannelRelated,
            128..=191 => MessageType::Reserved,
            192..=255 => MessageType::LocalExtension,
        }
    }

    /// Returns the message type for a non-empty message.
    pub fn from_message(message: &[u8]) -> Option<MessageType> {
        message.first().map(|num| MessageType::from_number(*num))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_message_numbers() {
        assert_eq!(
            MessageType::from_number(SSH_MSG_DISCONNECT),
            MessageType::TransportLayerGeneric
        );
        assert_eq!(
            MessageType::from_number(SSH_MSG_SERVICE_REQUEST),
            MessageType::TransportLayerGeneric
        );

        assert_eq!(
            MessageType::from_number(SSH_MSG_KEXINIT),
            MessageType::AlgorithmNegotiation
        );
        assert_eq!(
            MessageType::from_number(SSH_MSG_NEWKEYS),
            MessageType::AlgorithmNegotiation
        );

        assert_eq!(
            MessageType::from_number(SSH_MSG_USERAUTH_BANNER),
            MessageType::UserAuthenticationGeneric
        );

        assert_eq!(
            MessageType::from_number(SSH_MSG_CHANNEL_DATA),
            MessageType::ChannelRelated
        );
    }
}
