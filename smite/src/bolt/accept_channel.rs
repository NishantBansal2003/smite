//! BOLT 2 accept channel message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, write_u16_be};

/// Minimum wire-encoded size of an `accept_channel` message (excluding TLVs).
const ACCEPT_CHANNEL_WIRE_SIZE: usize = 270;

/// BOLT 2 `accept_channel` message (type 33).
///
/// Sent by the channel acceptor in response to `open_channel`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptChannel {
    /// Temporary channel ID (must match `open_channel`).
    pub temporary_channel_id: ChannelId,
    /// Dust limit below which outputs should not be generated (satoshis).
    pub dust_limit_satoshis: u64,
    /// Maximum value of outstanding HTLCs the opener can offer (msat).
    pub max_htlc_value_in_flight_msat: u64,
    /// Minimum channel reserve the opener must maintain (satoshis).
    pub channel_reserve_satoshis: u64,
    /// Minimum HTLC value the acceptor will accept (millisatoshis).
    pub htlc_minimum_msat: u64,
    /// Minimum number of confirmations before the channel is considered open.
    pub minimum_depth: u32,
    /// Number of blocks the opener's to-self outputs must be delayed.
    pub to_self_delay: u16,
    /// Maximum number of outstanding HTLCs the opener can offer.
    pub max_accepted_htlcs: u16,
    /// Acceptor's funding pubkey.
    pub funding_pubkey: secp256k1::PublicKey,
    /// Acceptor's revocation basepoint.
    pub revocation_basepoint: secp256k1::PublicKey,
    /// Acceptor's payment basepoint.
    pub payment_basepoint: secp256k1::PublicKey,
    /// Acceptor's delayed payment basepoint.
    pub delayed_payment_basepoint: secp256k1::PublicKey,
    /// Acceptor's HTLC basepoint.
    pub htlc_basepoint: secp256k1::PublicKey,
    /// Acceptor's first per-commitment point.
    pub first_per_commitment_point: secp256k1::PublicKey,
    /// `accept_channel_tlvs` — TLV stream (See BOLT 2).
    pub accept_channel_tlvs: TlvStream,
}

impl AcceptChannel {
    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns Truncated if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        if payload.len() < ACCEPT_CHANNEL_WIRE_SIZE {
            return Err(BoltError::Truncated {
                expected: ACCEPT_CHANNEL_WIRE_SIZE,
                actual: payload.len(),
            });
        }
        let mut cursor = payload;

        let temporary_channel_id = ChannelId::decode(&mut cursor)?;
        let dust_limit_satoshis = consume!(&mut cursor, u64);
        let max_htlc_value_in_flight_msat = consume!(&mut cursor, u64);
        let channel_reserve_satoshis = consume!(&mut cursor, u64);
        let htlc_minimum_msat = consume!(&mut cursor, u64);
        let minimum_depth = consume!(&mut cursor, u32);
        let to_self_delay = consume!(&mut cursor, u16);
        let max_accepted_htlcs = consume!(&mut cursor, u16);
        let funding_pubkey = consume_pubkey!(&mut cursor)?;
        let revocation_basepoint = consume_pubkey!(&mut cursor)?;
        let payment_basepoint = consume_pubkey!(&mut cursor)?;
        let delayed_payment_basepoint = consume_pubkey!(&mut cursor)?;
        let htlc_basepoint = consume_pubkey!(&mut cursor)?;
        let first_per_commitment_point = consume_pubkey!(&mut cursor)?;
        let accept_channel_tlvs = TlvStream::decode_with_known(cursor, &[0])?;

        Ok(Self {
            temporary_channel_id,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            minimum_depth,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            accept_channel_tlvs,
        })
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACCEPT_CHANNEL_WIRE_SIZE);
        self.temporary_channel_id.encode(&mut out);
        out.extend_from_slice(&self.dust_limit_satoshis.to_be_bytes());
        out.extend_from_slice(&self.max_htlc_value_in_flight_msat.to_be_bytes());
        out.extend_from_slice(&self.channel_reserve_satoshis.to_be_bytes());
        out.extend_from_slice(&self.htlc_minimum_msat.to_be_bytes());
        out.extend_from_slice(&self.minimum_depth.to_be_bytes());
        write_u16_be(self.to_self_delay, &mut out);
        write_u16_be(self.max_accepted_htlcs, &mut out);
        out.extend_from_slice(&self.funding_pubkey.serialize());
        out.extend_from_slice(&self.revocation_basepoint.serialize());
        out.extend_from_slice(&self.payment_basepoint.serialize());
        out.extend_from_slice(&self.delayed_payment_basepoint.serialize());
        out.extend_from_slice(&self.htlc_basepoint.serialize());
        out.extend_from_slice(&self.first_per_commitment_point.serialize());
        out.extend_from_slice(&self.accept_channel_tlvs.encode());
        out
    }
}
