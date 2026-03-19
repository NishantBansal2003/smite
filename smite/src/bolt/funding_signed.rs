//! BOLT 2 funding signed message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;

/// Size of a signature (64 bytes, compact encoding per BOLT).
const SIGNATURE_SIZE: usize = 64;

/// Minimum wire-encoded size of a `funding_signed` message (excluding TLVs).
const FUNDING_SIGNED_WIRE_SIZE: usize = 96;

/// BOLT 2 `funding_signed` message (type 35).
///
/// Sent by the acceptor after receiving `funding_created`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingSigned {
    /// Channel ID (derived from the funding outpoint).
    pub channel_id: ChannelId,
    /// Signature for the opener's initial commitment transaction.
    pub signature: [u8; SIGNATURE_SIZE],
    /// `funding_signed_tlvs` — TLV stream (See BOLT 2).
    pub funding_signed_tlvs: TlvStream,
}

impl FundingSigned {
    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns Truncated if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        if payload.len() < FUNDING_SIGNED_WIRE_SIZE {
            return Err(BoltError::Truncated {
                expected: FUNDING_SIGNED_WIRE_SIZE,
                actual: payload.len(),
            });
        }
        let mut cursor = payload;

        let channel_id = ChannelId::decode(&mut cursor)?;
        let signature = consume_bytes!(&mut cursor, SIGNATURE_SIZE);
        let funding_signed_tlvs = TlvStream::decode(cursor)?;

        Ok(Self {
            channel_id,
            signature,
            funding_signed_tlvs,
        })
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FUNDING_SIGNED_WIRE_SIZE);
        self.channel_id.encode(&mut out);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.funding_signed_tlvs.encode());
        out
    }
}
