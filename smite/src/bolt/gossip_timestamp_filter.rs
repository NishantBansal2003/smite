//! BOLT 7 `gossip_timestamp_filter` message.

use super::BoltError;
use super::types::CHAIN_HASH_SIZE;
use super::wire::WireFormat;

/// BOLT 7 `gossip_timestamp_filter` message (type 265).
///
/// Allows a node to constrain future gossip messages to a specific range.
/// A node which wants any gossip messages has to send this, otherwise no
/// gossip messages would be received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipTimestampFilter {
    /// The 32-byte hash that uniquely identifies the chain for the gossip.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Lower bound (inclusive) of the timestamp range.
    pub first_timestamp: u32,
    /// Number of seconds in the range (exclusive upper bound).
    pub timestamp_range: u32,
}

impl GossipTimestampFilter {
    /// Creates a gossip timestamp filter.
    #[must_use]
    pub fn new(
        chain_hash: [u8; CHAIN_HASH_SIZE],
        first_timestamp: u32,
        timestamp_range: u32,
    ) -> Self {
        Self {
            chain_hash,
            first_timestamp,
            timestamp_range,
        }
    }

    /// Creates a filter that requests no gossip.
    ///
    /// Per BOLT 7: set `first_timestamp` to 0xFFFFFFFF and `timestamp_range` to 0.
    #[must_use]
    pub fn no_gossip(chain_hash: [u8; CHAIN_HASH_SIZE]) -> Self {
        Self {
            chain_hash,
            first_timestamp: u32::MAX,
            timestamp_range: 0,
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.first_timestamp.write(&mut out);
        self.timestamp_range.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let first_timestamp = WireFormat::read(&mut cursor)?;
        let timestamp_range = WireFormat::read(&mut cursor)?;
        Ok(Self {
            chain_hash,
            first_timestamp,
            timestamp_range,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bitcoin mainnet genesis block hash
    const BITCOIN_MAINNET: [u8; CHAIN_HASH_SIZE] = [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    #[test]
    fn new_creates_filter() {
        let filter = GossipTimestampFilter::new(BITCOIN_MAINNET, 1_000_000, 86400);
        assert_eq!(filter.chain_hash, BITCOIN_MAINNET);
        assert_eq!(filter.first_timestamp, 1_000_000);
        assert_eq!(filter.timestamp_range, 86400);
    }

    #[test]
    fn no_gossip_creates_no_gossip_filter() {
        let filter = GossipTimestampFilter::no_gossip(BITCOIN_MAINNET);
        assert_eq!(filter.chain_hash, BITCOIN_MAINNET);
        assert_eq!(filter.first_timestamp, u32::MAX);
        assert_eq!(filter.timestamp_range, 0);
    }

    #[test]
    fn encode_decode_roundtrip() {
        let filter = GossipTimestampFilter::new(BITCOIN_MAINNET, 1_234_567, 1_209_600);
        let encoded = filter.encode();
        let decoded = GossipTimestampFilter::decode(&encoded).unwrap();
        assert_eq!(filter, decoded);
    }

    #[test]
    fn encode_no_gossip_filter() {
        let filter = GossipTimestampFilter::no_gossip(BITCOIN_MAINNET);
        let encoded = filter.encode();
        assert_eq!(encoded.len(), 40);
        assert_eq!(encoded[..CHAIN_HASH_SIZE], BITCOIN_MAINNET);
        assert_eq!(encoded[32..36], u32::MAX.to_be_bytes());
        assert_eq!(encoded[36..40], 0u32.to_be_bytes());
    }

    #[test]
    fn decode_truncated_chain_hash() {
        let data = [0x00u8; 20];
        assert_eq!(
            GossipTimestampFilter::decode(&data),
            Err(BoltError::Truncated {
                expected: CHAIN_HASH_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_first_timestamp() {
        let data = [0x00u8; CHAIN_HASH_SIZE + 1];
        assert_eq!(
            GossipTimestampFilter::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_timestamp_range() {
        let data = [0x00u8; CHAIN_HASH_SIZE + 6];
        assert_eq!(
            GossipTimestampFilter::decode(&data),
            Err(BoltError::Truncated {
                expected: 4,
                actual: 2
            })
        );
    }
}
