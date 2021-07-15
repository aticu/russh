//! Allows abstracting over different types of messages.

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
    use crate::message_numbers;

    #[test]
    fn standard_message_numbers() {
        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_DISCONNECT),
            MessageType::TransportLayerGeneric
        );
        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_SERVICE_REQUEST),
            MessageType::TransportLayerGeneric
        );

        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_KEXINIT),
            MessageType::AlgorithmNegotiation
        );
        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_NEWKEYS),
            MessageType::AlgorithmNegotiation
        );

        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_USERAUTH_BANNER),
            MessageType::UserAuthenticationGeneric
        );

        assert_eq!(
            MessageType::from_number(message_numbers::SSH_MSG_CHANNEL_DATA),
            MessageType::ChannelRelated
        );
    }
}
