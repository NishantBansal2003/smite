//! BOLT 2 `tx_init_rbf` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::{EmptyTlv, WireFormat};

/// TLV type for funding output contribution.
const TLV_FUNDING_OUTPUT_CONTRIBUTION: u64 = 0;

/// TLV type for require confirmed inputs.
const TLV_REQUIRE_CONFIRMED_INPUTS: u64 = 2;

/// BOLT 2 `tx_init_rbf` message (type 72).
///
/// Sent by the initiator to begin an RBF attempt for an interactive
/// transaction that has not yet confirmed.  The message carries the new
/// locktime and feerate that will apply to the replacement transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInitRbf {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// The locktime for the replacement transaction.
    pub locktime: u32,
    /// The feerate for the replacement transaction (satoshis per kilo-weight).
    pub feerate: u32,
    /// Optional TLV extensions.
    pub tlvs: TxInitRbfTlvs,
}

/// TLV extensions for the `tx_init_rbf` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxInitRbfTlvs {
    /// The amount the sender will contribute to the funding output (TLV type 0).
    ///
    /// Signed 64-bit integer; may be negative if the sender is removing funds.
    pub funding_output_contribution: Option<i64>,

    /// Whether the sender requires all inputs to be confirmed (TLV type 2).
    ///
    /// Presence of this TLV (even with empty value) signals the requirement.
    pub require_confirmed_inputs: bool,
}

impl TxInitRbf {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.locktime.write(&mut out);
        self.feerate.write(&mut out);

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(contribution) = self.tlvs.funding_output_contribution {
            tlv_stream.add(
                TLV_FUNDING_OUTPUT_CONTRIBUTION,
                contribution.to_be_bytes().to_vec(),
            );
        }
        if self.tlvs.require_confirmed_inputs {
            tlv_stream.add(TLV_REQUIRE_CONFIRMED_INPUTS, vec![]);
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
        let locktime = WireFormat::read(&mut cursor)?;
        let feerate = WireFormat::read(&mut cursor)?;

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode_with_known(
            cursor,
            &[
                TLV_FUNDING_OUTPUT_CONTRIBUTION,
                TLV_REQUIRE_CONFIRMED_INPUTS,
            ],
        )?;
        let tlvs = TxInitRbfTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            locktime,
            feerate,
            tlvs,
        })
    }
}

impl TxInitRbfTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if a TLV value has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let funding_output_contribution = stream.get_as::<i64>(TLV_FUNDING_OUTPUT_CONTRIBUTION)?;
        let require_confirmed_inputs = stream
            .get_as::<EmptyTlv>(TLV_REQUIRE_CONFIRMED_INPUTS)?
            .is_some();

        Ok(Self {
            funding_output_contribution,
            require_confirmed_inputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    fn sample_msg() -> TxInitRbf {
        TxInitRbf {
            channel_id: ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            locktime: 800_000,
            feerate: 5_000,
            tlvs: TxInitRbfTlvs::default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let msg = TxInitRbf {
            channel_id: ChannelId::new([0x42; CHANNEL_ID_SIZE]),
            locktime: 800_000,
            feerate: 5_000,
            tlvs: TxInitRbfTlvs::default(),
        };
        let encoded = msg.encode();
        // channel_id(32) + locktime(4) + feerate(4) = 40
        assert_eq!(encoded.len(), 40);
    }

    #[test]
    fn roundtrip() {
        let original = sample_msg();
        let encoded = original.encode();
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_with_funding_output_contribution() {
        let mut msg = sample_msg();
        msg.tlvs.funding_output_contribution = Some(500_000);
        let encoded = msg.encode();
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_with_negative_contribution() {
        let mut msg = sample_msg();
        msg.tlvs.funding_output_contribution = Some(-100_000);
        let encoded = msg.encode();
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_with_require_confirmed_inputs() {
        let mut msg = sample_msg();
        msg.tlvs.require_confirmed_inputs = true;
        let encoded = msg.encode();
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_with_all_tlvs() {
        let mut msg = sample_msg();
        msg.tlvs.funding_output_contribution = Some(1_000_000);
        msg.tlvs.require_confirmed_inputs = true;
        let encoded = msg.encode();
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let mut encoded = sample_msg().encode();
        // Append an unknown odd TLV (type 3, len 2, value 0xffff)
        encoded.extend_from_slice(&[0x03, 0x02, 0xff, 0xff]);
        let decoded = TxInitRbf::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_id, ChannelId::new([0xab; CHANNEL_ID_SIZE]));
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let mut encoded = sample_msg().encode();
        // Append an unknown even TLV (type 4, len 1, value 0x00)
        encoded.extend_from_slice(&[0x04, 0x01, 0x00]);
        assert!(matches!(
            TxInitRbf::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(4))
        ));
    }

    #[test]
    fn decode_reject_require_confirmed_inputs_trailing_bytes() {
        let mut encoded = sample_msg().encode();
        // type 2 (`require_confirmed_inputs`), len 1 — must be zero-length
        encoded.extend_from_slice(&[0x02, 0x01, 0xff]);
        assert_eq!(
            TxInitRbf::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_REQUIRE_CONFIRMED_INPUTS,
                expected: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            TxInitRbf::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_locktime() {
        // Full channel_id (32 bytes) + only 2 bytes of locktime
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 2]);
        assert_eq!(
            TxInitRbf::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_feerate() {
        // Full channel_id (32 bytes) + full locktime (4 bytes) + only 2 bytes of feerate
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00; 4]); // locktime
        data.extend_from_slice(&[0x00; 2]); // partial feerate
        assert_eq!(
            TxInitRbf::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }

    #[test]
    fn decode_truncated_funding_output_contribution() {
        let mut data = vec![0xaa; CHANNEL_ID_SIZE];
        data.extend_from_slice(&800_000u32.to_be_bytes()); // locktime
        data.extend_from_slice(&5_000u32.to_be_bytes()); // feerate
        // TLV type 0 (funding_output_contribution), length 4, only 4 bytes of value
        data.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            TxInitRbf::decode(&data),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn decode_empty() {
        assert_eq!(
            TxInitRbf::decode(&[]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 0
            })
        );
    }
}
