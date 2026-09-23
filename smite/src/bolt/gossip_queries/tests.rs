use super::*;

const CHAIN: [u8; CHAIN_HASH_SIZE] = [0x06; CHAIN_HASH_SIZE];

fn scids() -> Vec<ShortChannelId> {
    vec![
        ShortChannelId::new(700_000, 12, 1),
        ShortChannelId::new(700_001, 3, 0),
    ]
}

#[test]
fn query_channel_range_roundtrip() {
    let msg = QueryChannelRange {
        chain_hash: CHAIN,
        first_blocknum: 700_000,
        number_of_blocks: 144,
        tlvs: QueryChannelRangeTlvs {
            query_option: Some(vec![0x03]),
        },
    };
    assert_eq!(QueryChannelRange::decode(&msg.encode()).unwrap(), msg);
}

// BOLT 7 puts `query_option` at TLV type 1.
#[test]
fn query_channel_range_query_option_is_tlv_type_1() {
    let msg = QueryChannelRange {
        chain_hash: CHAIN,
        first_blocknum: 0,
        number_of_blocks: 1,
        tlvs: QueryChannelRangeTlvs {
            query_option: Some(vec![0x01]),
        },
    };
    let encoded = msg.encode();
    // chain_hash + first_blocknum + number_of_blocks, then type 1, length 1.
    assert_eq!(&encoded[CHAIN_HASH_SIZE + 8..], &[0x01, 0x01, 0x01]);
}

#[test]
fn reply_channel_range_roundtrip() {
    let msg = ReplyChannelRange {
        chain_hash: CHAIN,
        first_blocknum: 700_000,
        number_of_blocks: 144,
        sync_complete: 1,
        short_channel_ids: EncodedShortIds::uncompressed(scids()),
        tlvs: ReplyChannelRangeTlvs {
            timestamps: Some(vec![0x00, 0, 0, 0, 1, 0, 0, 0, 2]),
            checksums: Some(vec![0, 0, 0, 1, 0, 0, 0, 2]),
        },
    };
    assert_eq!(ReplyChannelRange::decode(&msg.encode()).unwrap(), msg);
}

#[test]
fn query_short_channel_ids_roundtrip() {
    let msg = QueryShortChannelIds {
        chain_hash: CHAIN,
        short_channel_ids: EncodedShortIds::uncompressed(scids()),
        tlvs: QueryShortChannelIdsTlvs {
            query_flags: Some(vec![0x00, 0x1f, 0x1f]),
        },
    };
    assert_eq!(QueryShortChannelIds::decode(&msg.encode()).unwrap(), msg);
}

// BOLT 7 puts `query_flags` at TLV type 1.
#[test]
fn query_short_channel_ids_query_flags_is_tlv_type_1() {
    let msg = QueryShortChannelIds {
        chain_hash: CHAIN,
        short_channel_ids: EncodedShortIds::uncompressed(Vec::new()),
        tlvs: QueryShortChannelIdsTlvs {
            query_flags: Some(vec![0x00]),
        },
    };
    let encoded = msg.encode();
    // chain_hash, len=1, encoding_type 0, then type 1, length 1, value 0.
    assert_eq!(
        &encoded[CHAIN_HASH_SIZE..],
        &[0x00, 0x01, 0x00, 0x01, 0x01, 0x00]
    );
}

#[test]
fn reply_short_channel_ids_end_roundtrip() {
    let msg = ReplyShortChannelIdsEnd {
        chain_hash: CHAIN,
        full_information: 1,
    };
    assert_eq!(ReplyShortChannelIdsEnd::decode(&msg.encode()).unwrap(), msg);
}

#[test]
fn encoded_short_ids_uncompressed_layout() {
    let mut out = Vec::new();
    EncodedShortIds::uncompressed(scids()).write_field(&mut out);
    // u16 length, encoding type 0, then 8 bytes per id.
    assert_eq!(&out[..3], &[0x00, 0x11, 0x00]);
    assert_eq!(out.len(), 2 + 1 + 2 * SHORT_CHANNEL_ID_SIZE);
}

// A zlib body is carried undecoded rather than rejected, so a peer's reply
// still decodes.
#[test]
fn encoded_short_ids_zlib_carried_raw() {
    let mut data: &[u8] = &[0x00, 0x03, 0x01, 0xaa, 0xbb];
    let field = EncodedShortIds::read_field(&mut data).unwrap();
    assert!(field.is_zlib());
    assert!(field.short_channel_ids.is_empty());
    assert!(data.is_empty());
}

#[test]
fn encoded_short_ids_rejects_partial_id() {
    let mut data: &[u8] = &[0x00, 0x04, 0x00, 1, 2, 3];
    assert!(EncodedShortIds::read_field(&mut data).is_err());
}

#[test]
fn encoded_short_ids_rejects_empty_field() {
    let mut data: &[u8] = &[0x00, 0x00];
    assert!(EncodedShortIds::read_field(&mut data).is_err());
}

#[test]
fn encoded_short_ids_rejects_truncated_body() {
    let mut data: &[u8] = &[0x00, 0x09, 0x00, 1, 2];
    assert!(EncodedShortIds::read_field(&mut data).is_err());
}

// One reply spanning the queried blocks is both the first and the final reply
// BOLT 7 requires.
#[test]
fn reply_channel_range_respond_to_covers_query() {
    let query = QueryChannelRange {
        chain_hash: CHAIN,
        first_blocknum: 700_000,
        number_of_blocks: 144,
        tlvs: QueryChannelRangeTlvs::default(),
    };
    let reply = ReplyChannelRange::respond_to(&query);

    assert_eq!(reply.chain_hash, query.chain_hash);
    // First reply: starts at or before, ends after, the queried first block.
    assert!(reply.first_blocknum <= query.first_blocknum);
    assert!(reply.end_blocknum() > u64::from(query.first_blocknum));
    // Final reply: ends at or past the queried range, sync_complete set.
    assert!(reply.end_blocknum() >= query.end_blocknum());
    assert_eq!(reply.sync_complete, 1);
}

// A zero-block query is answered as a one-block one, since a zero-block reply
// cannot end after the block it starts at.
#[test]
fn reply_channel_range_respond_to_zero_block_query() {
    let query = QueryChannelRange {
        chain_hash: CHAIN,
        first_blocknum: 10,
        number_of_blocks: 0,
        tlvs: QueryChannelRangeTlvs::default(),
    };
    let reply = ReplyChannelRange::respond_to(&query);
    assert!(reply.end_blocknum() > u64::from(query.first_blocknum));
}

// The range end is computed wide, so a query reaching past u32::MAX blocks
// does not wrap.
#[test]
fn channel_range_end_does_not_wrap() {
    let query = QueryChannelRange {
        chain_hash: CHAIN,
        first_blocknum: u32::MAX,
        number_of_blocks: u32::MAX,
        tlvs: QueryChannelRangeTlvs::default(),
    };
    assert_eq!(query.end_blocknum(), 2 * u64::from(u32::MAX));
}

#[test]
fn reply_short_channel_ids_end_respond_to_admits_no_information() {
    let query = QueryShortChannelIds {
        chain_hash: CHAIN,
        short_channel_ids: EncodedShortIds::uncompressed(scids()),
        tlvs: QueryShortChannelIdsTlvs::default(),
    };
    let reply = ReplyShortChannelIdsEnd::respond_to(&query);
    assert_eq!(reply.chain_hash, CHAIN);
    assert_eq!(reply.full_information, 0);
}

// A raw field goes out verbatim, so an empty one produces the zero length
// BOLT 7 forbids, and an unknown encoding type survives the round trip.
#[test]
fn encoded_short_ids_raw_written_verbatim() {
    let mut out = Vec::new();
    EncodedShortIds::raw(Vec::new()).write_field(&mut out);
    assert_eq!(out, [0x00, 0x00]);

    let mut out = Vec::new();
    EncodedShortIds::raw(vec![0x07, 0xaa]).write_field(&mut out);
    assert_eq!(out, [0x00, 0x02, 0x07, 0xaa]);
    let mut data: &[u8] = &out;
    assert_eq!(
        EncodedShortIds::read_field(&mut data).unwrap(),
        EncodedShortIds::raw(vec![0x07, 0xaa])
    );
}
