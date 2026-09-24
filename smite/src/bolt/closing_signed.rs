//! BOLT 2 `closing_signed` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;
use bitcoin::secp256k1::ecdsa::Signature;

/// TLV type for the fee range the sender accepts.
pub const TLV_FEE_RANGE: u64 = 1;

/// Size of the `fee_range` TLV value: `min_fee_satoshis` and
/// `max_fee_satoshis`, both `u64`.
const FEE_RANGE_SIZE: usize = 16;

/// BOLT 2 `closing_signed` message (type 39).
///
/// The legacy mutual close negotiation: once `shutdown` is exchanged and no
/// updates are pending, the funder proposes a fee for the closing transaction
/// and signs it, and the peers trade `closing_signed` until they agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosingSigned {
    /// The ID of the channel to be closed.
    pub channel_id: ChannelId,
    /// Proposed absolute fee for the closing transaction.
    pub fee_satoshis: u64,
    /// The sender's signature for the closing transaction at `fee_satoshis`.
    pub signature: Signature,
    /// Optional TLV extensions.
    pub tlvs: ClosingSignedTlvs,
}

/// TLV extensions for the `closing_signed` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClosingSignedTlvs {
    /// `(min_fee_satoshis, max_fee_satoshis)` the sender accepts, letting the
    /// receiver settle on a fee in one round trip.
    pub fee_range: Option<(u64, u64)>,
}

impl ClosingSigned {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.fee_satoshis.write(&mut out);
        self.signature.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some((min_fee_satoshis, max_fee_satoshis)) = self.tlvs.fee_range {
            let mut value = Vec::with_capacity(FEE_RANGE_SIZE);
            min_fee_satoshis.write(&mut value);
            max_fee_satoshis.write(&mut value);
            tlv_stream.add(TLV_FEE_RANGE, value);
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// the `fee_range` TLV, `TlvTrailingBytes` if the `fee_range` TLV is
    /// longer than its encoding, or `InvalidSignature` if the signature bytes
    /// are not a valid compact ECDSA signature.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let fee_satoshis = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode(cursor)?;
        let fee_range = tlv_stream
            .get(TLV_FEE_RANGE)
            .map(|data| {
                let mut value = data;
                let min_fee_satoshis = u64::read(&mut value)?;
                let max_fee_satoshis = u64::read(&mut value)?;
                if !value.is_empty() {
                    return Err(BoltError::TlvTrailingBytes {
                        tlv_type: TLV_FEE_RANGE,
                        expected: FEE_RANGE_SIZE,
                        actual: data.len(),
                    });
                }
                Ok((min_fee_satoshis, max_fee_satoshis))
            })
            .transpose()?;

        Ok(Self {
            channel_id,
            fee_satoshis,
            signature,
            tlvs: ClosingSignedTlvs { fee_range },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `ClosingSigned` message for testing.
    fn sample_closing_signed(fee_range: Option<(u64, u64)>) -> ClosingSigned {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let signature = secp.sign_ecdsa(&Message::from_digest([0xaa; 32]), &sk);

        ClosingSigned {
            channel_id: ChannelId::new([0xbb; CHANNEL_ID_SIZE]),
            fee_satoshis: 1000,
            signature,
            tlvs: ClosingSignedTlvs { fee_range },
        }
    }

    #[test]
    fn roundtrip() {
        let original = sample_closing_signed(None);
        let decoded = ClosingSigned::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_fee_range() {
        let original = sample_closing_signed(Some((500, 2000)));
        let decoded = ClosingSigned::decode(&original.encode()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_fee_range_trailing_bytes() {
        let mut encoded = sample_closing_signed(None).encode();
        // fee_range TLV: type 1, length 17, one byte too many.
        encoded.extend_from_slice(&[0x01, 0x11]);
        encoded.extend_from_slice(&[0x00; 17]);
        assert_eq!(
            ClosingSigned::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_FEE_RANGE,
                expected: FEE_RANGE_SIZE,
                actual: 17,
            })
        );
    }

    #[test]
    fn decode_fee_range_truncated() {
        let mut encoded = sample_closing_signed(None).encode();
        // fee_range TLV: type 1, length 8, missing max_fee_satoshis.
        encoded.extend_from_slice(&[0x01, 0x08]);
        encoded.extend_from_slice(&[0x00; 8]);
        assert_eq!(
            ClosingSigned::decode(&encoded),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 0,
            })
        );
    }
}
