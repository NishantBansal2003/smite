//! BOLT 2 `tx_complete` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `tx_complete` message (type 70).
///
/// Sent by either peer during interactive transaction construction to signal
/// that they have no more inputs or outputs to contribute.  The transaction
/// negotiation is complete once both peers have sent `tx_complete` in
/// succession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxComplete {
    /// The channel ID.
    pub channel_id: ChannelId,
}

impl TxComplete {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;

        Ok(Self { channel_id })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxComplete {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
        };
        let encoded = msg.encode();
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE);
    }

    #[test]
    fn roundtrip() {
        let original = TxComplete {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
        };
        let encoded = original.encode();
        let decoded = TxComplete::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxComplete::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxComplete::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        let mut data = vec![0xff; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let decoded = TxComplete::decode(&data).unwrap();
        assert_eq!(decoded.channel_id, ChannelId::new([0xff; CHANNEL_ID_SIZE]));
    }
}
