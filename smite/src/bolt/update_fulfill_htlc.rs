//! BOLT 2 `update_fulfill_htlc` message.

use super::BoltError;
use super::attribution_data::AttributionData;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;

/// Size of a payment preimage in bytes.
const PAYMENT_PREIMAGE_SIZE: usize = 32;

/// TLV type for attribution data.
const TLV_ATTRIBUTION_DATA: u64 = 1;

/// BOLT 2 `update_fulfill_htlc` message (type 130).
///
/// Sent to fulfill an HTLC by providing the payment preimage.  Upon receiving
/// this message, the peer should remove the corresponding HTLC from the
/// commitment transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFulfillHtlc {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The HTLC ID being fulfilled.
    pub id: u64,
    /// The payment preimage (32 bytes).
    pub payment_preimage: [u8; PAYMENT_PREIMAGE_SIZE],
    /// Optional TLV extensions.
    pub tlvs: UpdateFulfillHtlcTlvs,
}

/// TLV extensions for the `update_fulfill_htlc` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateFulfillHtlcTlvs {
    /// Attribution data for failure attribution (TLV type 1).
    pub attribution_data: Option<AttributionData>,
}

impl UpdateFulfillHtlc {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.id.write(&mut out);
        self.payment_preimage.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(attr) = &self.tlvs.attribution_data {
            tlv_stream.add(TLV_ATTRIBUTION_DATA, attr.encode());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field,
    /// or TLV errors if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = WireFormat::read(&mut cursor)?;
        let id = WireFormat::read(&mut cursor)?;
        let payment_preimage = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        // attribution_data is type 1 (odd), so no known even types
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = UpdateFulfillHtlcTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            id,
            payment_preimage,
            tlvs,
        })
    }
}

impl UpdateFulfillHtlcTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if `attribution_data` has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let attribution_data = stream.get_as::<AttributionData>(TLV_ATTRIBUTION_DATA)?;
        Ok(Self { attribution_data })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;
    use crate::bolt::attribution_data::TruncatedHmac;

    fn sample_msg() -> UpdateFulfillHtlc {
        UpdateFulfillHtlc {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            id: 42,
            payment_preimage: [0xcd; PAYMENT_PREIMAGE_SIZE],
            tlvs: UpdateFulfillHtlcTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = UpdateFulfillHtlc {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            id: 1,
            payment_preimage: [0xab; PAYMENT_PREIMAGE_SIZE],
            tlvs: UpdateFulfillHtlcTlvs::default(),
        };
        let encoded = msg.encode();
        // channel_id(32) + id(8) + payment_preimage(32) = 72
        assert_eq!(encoded.len(), 72);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = UpdateFulfillHtlc::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_attribution_data() {
        let mut msg = sample_msg();
        msg.tlvs.attribution_data = Some(AttributionData {
            htlc_hold_times: [100; 20],
            truncated_hmacs: [TruncatedHmac([0xaa; 4]); 210],
        });
        let encoded = msg.encode();
        let decoded = UpdateFulfillHtlc::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_truncated_attribution_data() {
        let msg = sample_msg();
        let mut encoded = msg.encode();
        // add type 1 TLV (attribution data) with only 3 bytes
        encoded.push(0x01);
        encoded.push(0x03);
        encoded.extend_from_slice(&[0x00; 3]);
        assert_eq!(
            UpdateFulfillHtlc::decode(&encoded),
            // only three of four bytes of first hold_time
            Err(BoltError::Truncated {
                expected: 4,
                actual: 3,
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut msg = sample_msg();
        let mut encoded = msg.encode();
        // Append an unknown odd TLV (type 3, len 2, value 0xffff)
        encoded.extend_from_slice(&[0x03, 0x02, 0xff, 0xff]);
        let decoded = UpdateFulfillHtlc::decode(&encoded).unwrap();
        msg.tlvs = UpdateFulfillHtlcTlvs::default();
        assert_eq!(decoded.channel_id, msg.channel_id);
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.payment_preimage, msg.payment_preimage);
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        // Append an unknown even TLV (type 2, len 1, value 0x00)
        encoded.extend_from_slice(&[0x02, 0x01, 0x00]);
        assert!(matches!(
            UpdateFulfillHtlc::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        ));
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            UpdateFulfillHtlc::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_id() {
        // Full channel_id (32 bytes) + only 4 bytes of id
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            UpdateFulfillHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_truncated_preimage() {
        // Full channel_id (32 bytes) + full id (8 bytes) + only 16 bytes of preimage
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 8]);
        data.extend_from_slice(&[0xbb; 16]);
        assert_eq!(
            UpdateFulfillHtlc::decode(&data),
            Err(BoltError::Truncated {
                expected: PAYMENT_PREIMAGE_SIZE,
                actual: 16
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            UpdateFulfillHtlc::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
