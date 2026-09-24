//! BOLT 2 `update_fee` message.

use super::BoltError;
use super::types::ChannelId;
use super::wire::WireFormat;

/// BOLT 2 `update_fee` message (type 134).
///
/// Sent by the channel funder to change the feerate of the commitment
/// transactions. Like an HTLC update, it only takes effect once committed by
/// `commitment_signed` and revoked by `revoke_and_ack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFee {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The new commitment feerate in satoshis per 1000 weight.
    pub feerate_per_kw: u32,
}

impl UpdateFee {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.feerate_per_kw.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let feerate_per_kw = WireFormat::read(&mut cursor)?;
        Ok(Self {
            channel_id,
            feerate_per_kw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn roundtrip() {
        let original = UpdateFee {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            feerate_per_kw: 2500,
        };
        let encoded = original.encode();
        // channel_id(32) + feerate_per_kw(4) = 36
        assert_eq!(encoded.len(), 36);
        assert_eq!(UpdateFee::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn decode_truncated_feerate() {
        let mut data = vec![0x42; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            UpdateFee::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }
}
