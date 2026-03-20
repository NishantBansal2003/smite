//! BOLT 2 channel ready message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;

/// Minimum wire-encoded size of a `channel_ready` message (excluding TLVs).
const CHANNEL_READY_WIRE_SIZE: usize = 65;

/// BOLT 2 `channel_ready` message (type 36).
///
/// Sent by each side once the funding transaction has sufficient
/// confirmations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReady {
    /// Channel ID (derived from the funding outpoint).
    pub channel_id: ChannelId,
    /// Second per-commitment point for the sender.
    pub second_per_commitment_point: secp256k1::PublicKey,
    /// `channel_ready_tlvs` — TLV stream (See BOLT 2).
    pub channel_ready_tlvs: TlvStream,
}

impl ChannelReady {
    /// Creates a `ChannelReady` with a valid `second_per_commitment_point`.
    #[must_use]
    pub fn new(channel_id: ChannelId, second_per_commitment_point: secp256k1::PublicKey) -> Self {
        Self {
            channel_id,
            second_per_commitment_point,
            channel_ready_tlvs: TlvStream::new(),
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHANNEL_READY_WIRE_SIZE);
        self.channel_id.encode(&mut out);
        out.extend_from_slice(&self.second_per_commitment_point.serialize());
        out.extend_from_slice(&self.channel_ready_tlvs.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns Truncated if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        if payload.len() < CHANNEL_READY_WIRE_SIZE {
            return Err(BoltError::Truncated {
                expected: CHANNEL_READY_WIRE_SIZE,
                actual: payload.len(),
            });
        }
        let mut cursor = payload;

        let channel_id = ChannelId::decode(&mut cursor)?;
        let second_per_commitment_point = consume_pubkey!(&mut cursor)?;
        let channel_ready_tlvs = TlvStream::decode(cursor)?;

        Ok(Self {
            channel_id,
            second_per_commitment_point,
            channel_ready_tlvs,
        })
    }
}
