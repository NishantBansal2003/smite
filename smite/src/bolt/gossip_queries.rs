//! BOLT 7 gossip query messages.
//!
//! `query_channel_range` asks which channels a peer knows in a block range and
//! is answered by one or more `reply_channel_range`; `query_short_channel_ids`
//! asks for the announcements of specific channels and is answered by the
//! announcements followed by `reply_short_channel_ids_end`.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::CHAIN_HASH_SIZE;
use super::wire::WireFormat;
use super::{SHORT_CHANNEL_ID_SIZE, ShortChannelId};

/// TLV type of `query_short_channel_ids`' `query_flags`.
const TLV_QUERY_FLAGS: u64 = 1;
/// TLV type of `query_channel_range`'s `query_option`.
const TLV_QUERY_OPTION: u64 = 1;
/// TLV type of `reply_channel_range`'s `timestamps_tlv`.
const TLV_TIMESTAMPS: u64 = 1;
/// TLV type of `reply_channel_range`'s `checksums_tlv`.
const TLV_CHECKSUMS: u64 = 3;

/// Encoding type of an `encoded_short_ids` field holding uncompressed ids.
const ENCODING_UNCOMPRESSED: u8 = 0;
/// Encoding type of an `encoded_short_ids` field holding zlib-deflated ids.
const ENCODING_ZLIB: u8 = 1;

/// A BOLT 7 `encoded_short_ids` field: an encoding type byte followed by the
/// `short_channel_id`s it encodes.
///
/// Only the uncompressed encoding is produced. A zlib-encoded field decodes to
/// its raw bytes rather than the ids it holds, so a peer's reply is accepted
/// and carried without smite having to inflate it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EncodedShortIds {
    /// The ids, empty when `raw` holds an encoding smite does not decode.
    pub short_channel_ids: Vec<ShortChannelId>,
    /// The undecoded payload of a non-zero encoding type, without its type
    /// byte.
    pub raw: Option<(u8, Vec<u8>)>,
}

impl EncodedShortIds {
    /// Creates an uncompressed field holding `short_channel_ids`.
    #[must_use]
    pub fn uncompressed(short_channel_ids: Vec<ShortChannelId>) -> Self {
        Self {
            short_channel_ids,
            raw: None,
        }
    }

    /// Encodes the field, including its length prefix and encoding type byte.
    ///
    /// # Panics
    ///
    /// Panics if the encoded field exceeds `u16::MAX` bytes.
    pub fn write_field(&self, out: &mut Vec<u8>) {
        let mut body = Vec::new();
        if let Some((encoding, bytes)) = &self.raw {
            body.push(*encoding);
            body.extend_from_slice(bytes);
        } else {
            body.push(ENCODING_UNCOMPRESSED);
            for scid in &self.short_channel_ids {
                scid.write(&mut body);
            }
        }
        u16::try_from(body.len())
            .expect("encoded_short_ids must not exceed u16::MAX bytes")
            .write(out);
        out.extend_from_slice(&body);
    }

    /// Decodes the field from `data`, consuming its length prefix and body.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the field is short or an uncompressed body is
    /// not a whole number of `short_channel_id`s.
    pub fn read_field(data: &mut &[u8]) -> Result<Self, BoltError> {
        let len = usize::from(u16::read(data)?);
        if data.len() < len || len == 0 {
            return Err(BoltError::Truncated {
                expected: len.max(1),
                actual: data.len(),
            });
        }
        let (body, rest) = data.split_at(len);
        *data = rest;

        let (encoding, mut ids) = (body[0], &body[1..]);
        if encoding != ENCODING_UNCOMPRESSED {
            return Ok(Self {
                short_channel_ids: Vec::new(),
                raw: Some((encoding, ids.to_vec())),
            });
        }
        if ids.len() % SHORT_CHANNEL_ID_SIZE != 0 {
            return Err(BoltError::Truncated {
                expected: SHORT_CHANNEL_ID_SIZE,
                actual: ids.len() % SHORT_CHANNEL_ID_SIZE,
            });
        }

        let mut short_channel_ids = Vec::with_capacity(ids.len() / SHORT_CHANNEL_ID_SIZE);
        while !ids.is_empty() {
            short_channel_ids.push(ShortChannelId::read(&mut ids)?);
        }
        Ok(Self {
            short_channel_ids,
            raw: None,
        })
    }

    /// Returns `true` if this field is zlib-encoded and was carried undecoded.
    #[must_use]
    pub fn is_zlib(&self) -> bool {
        matches!(self.raw, Some((ENCODING_ZLIB, _)))
    }
}

/// BOLT 7 `query_channel_range` message (type 263).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryChannelRange {
    /// Chain the query applies to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// First block of the queried range.
    pub first_blocknum: u32,
    /// Number of blocks in the queried range.
    pub number_of_blocks: u32,
    /// Optional TLV extensions.
    pub tlvs: QueryChannelRangeTlvs,
}

/// TLV extensions for `query_channel_range`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryChannelRangeTlvs {
    /// `query_option_flags`, a minimally encoded bigsize whose bits ask for
    /// timestamps (bit 0) and checksums (bit 1), kept as its raw TLV value.
    pub query_option: Option<Vec<u8>>,
}

impl QueryChannelRange {
    /// Returns the block after the last one this query asks about.
    #[must_use]
    pub fn end_blocknum(&self) -> u64 {
        u64::from(self.first_blocknum) + u64::from(self.number_of_blocks)
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.first_blocknum.write(&mut out);
        self.number_of_blocks.write(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(flags) = &self.tlvs.query_option {
            tlv_stream.add(TLV_QUERY_OPTION, flags.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, or
    /// a TLV error if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let first_blocknum = u32::read(&mut cursor)?;
        let number_of_blocks = u32::read(&mut cursor)?;

        let tlv_stream = TlvStream::decode(cursor)?;
        Ok(Self {
            chain_hash,
            first_blocknum,
            number_of_blocks,
            tlvs: QueryChannelRangeTlvs {
                query_option: tlv_stream.get(TLV_QUERY_OPTION).map(<[u8]>::to_vec),
            },
        })
    }
}

/// BOLT 7 `reply_channel_range` message (type 264).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyChannelRange {
    /// Chain the reply applies to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// First block of the replied range.
    pub first_blocknum: u32,
    /// Number of blocks in the replied range.
    pub number_of_blocks: u32,
    /// Whether this is the final reply to the query.
    pub sync_complete: u8,
    /// Channels the peer knows in the range.
    pub short_channel_ids: EncodedShortIds,
    /// Optional TLV extensions.
    pub tlvs: ReplyChannelRangeTlvs,
}

/// TLV extensions for `reply_channel_range`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplyChannelRangeTlvs {
    /// `channel_update` timestamps for each id.
    pub timestamps: Option<Vec<u8>>,
    /// `channel_update` checksums for each id.
    pub checksums: Option<Vec<u8>>,
}

impl ReplyChannelRange {
    /// The reply a node that knows no announced channels gives `query`: a
    /// single, final reply covering exactly the queried range.
    ///
    /// BOLT 7 requires the first reply to start at or before the queried
    /// `first_blocknum` and end after it, and the final one to end at or past
    /// the queried range with `sync_complete` set, which one reply spanning
    /// the same blocks satisfies. A query for zero blocks, which its sender
    /// must not send, is answered as if for one, since a zero-block reply
    /// could not end after the block it starts at.
    #[must_use]
    pub fn respond_to(query: &QueryChannelRange) -> Self {
        Self {
            chain_hash: query.chain_hash,
            first_blocknum: query.first_blocknum,
            number_of_blocks: query.number_of_blocks.max(1),
            sync_complete: 1,
            short_channel_ids: EncodedShortIds::uncompressed(Vec::new()),
            tlvs: ReplyChannelRangeTlvs::default(),
        }
    }

    /// Returns the block after the last one this reply covers, which a
    /// querier compares against its query's to tell when replies are done.
    #[must_use]
    pub fn end_blocknum(&self) -> u64 {
        u64::from(self.first_blocknum) + u64::from(self.number_of_blocks)
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.first_blocknum.write(&mut out);
        self.number_of_blocks.write(&mut out);
        self.sync_complete.write(&mut out);
        self.short_channel_ids.write_field(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(timestamps) = &self.tlvs.timestamps {
            tlv_stream.add(TLV_TIMESTAMPS, timestamps.clone());
        }
        if let Some(checksums) = &self.tlvs.checksums {
            tlv_stream.add(TLV_CHECKSUMS, checksums.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field or
    /// the encoded ids are malformed, or a TLV error if the TLV stream is
    /// malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let first_blocknum = u32::read(&mut cursor)?;
        let number_of_blocks = u32::read(&mut cursor)?;
        let sync_complete = u8::read(&mut cursor)?;
        let short_channel_ids = EncodedShortIds::read_field(&mut cursor)?;

        let tlv_stream = TlvStream::decode(cursor)?;
        Ok(Self {
            chain_hash,
            first_blocknum,
            number_of_blocks,
            sync_complete,
            short_channel_ids,
            tlvs: ReplyChannelRangeTlvs {
                timestamps: tlv_stream.get(TLV_TIMESTAMPS).map(<[u8]>::to_vec),
                checksums: tlv_stream.get(TLV_CHECKSUMS).map(<[u8]>::to_vec),
            },
        })
    }
}

/// BOLT 7 `query_short_channel_ids` message (type 261).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryShortChannelIds {
    /// Chain the query applies to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Channels whose announcements are being asked for.
    pub short_channel_ids: EncodedShortIds,
    /// Optional TLV extensions.
    pub tlvs: QueryShortChannelIdsTlvs,
}

/// TLV extensions for `query_short_channel_ids`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryShortChannelIdsTlvs {
    /// Per-id flags selecting which announcements to send.
    pub query_flags: Option<Vec<u8>>,
}

impl QueryShortChannelIds {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.short_channel_ids.write_field(&mut out);

        let mut tlv_stream = TlvStream::new();
        if let Some(flags) = &self.tlvs.query_flags {
            tlv_stream.add(TLV_QUERY_FLAGS, flags.clone());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short or the encoded ids are
    /// malformed, or a TLV error if the TLV stream is.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let short_channel_ids = EncodedShortIds::read_field(&mut cursor)?;

        let tlv_stream = TlvStream::decode(cursor)?;
        Ok(Self {
            chain_hash,
            short_channel_ids,
            tlvs: QueryShortChannelIdsTlvs {
                query_flags: tlv_stream.get(TLV_QUERY_FLAGS).map(<[u8]>::to_vec),
            },
        })
    }
}

/// BOLT 7 `reply_short_channel_ids_end` message (type 262).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyShortChannelIdsEnd {
    /// Chain the reply applies to.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Whether the peer knew any of the queried channels.
    pub full_information: u8,
}

impl ReplyShortChannelIdsEnd {
    /// The reply a node that keeps no gossip store gives `query`: no
    /// announcements, then the terminating `reply_short_channel_ids_end`.
    ///
    /// BOLT 7 requires `full_information` to be 0 from a node that does not
    /// maintain up-to-date channel information for the queried chain.
    #[must_use]
    pub fn respond_to(query: &QueryShortChannelIds) -> Self {
        Self {
            chain_hash: query.chain_hash,
            full_information: 0,
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.chain_hash.write(&mut out);
        self.full_information.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let chain_hash = WireFormat::read(&mut cursor)?;
        let full_information = u8::read(&mut cursor)?;
        Ok(Self {
            chain_hash,
            full_information,
        })
    }
}

#[cfg(test)]
mod tests;
