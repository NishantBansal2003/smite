//! Generator for the BOLT 7 gossip query flow.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// `query_option_flags` bits: timestamps (bit 0) and checksums (bit 1).
const QUERY_OPTION_FLAGS: std::ops::RangeInclusive<u8> = 0..=3;

/// `query_flags` asking for everything a node can send about a channel: its
/// `channel_announcement` (bit 0), both ends' `channel_update` (bits 1 and 2)
/// and both nodes' `node_announcement` (bits 3 and 4).
const QUERY_ALL_ANNOUNCEMENTS: u8 = 0x1f;

/// Encoding type of an uncompressed `encoded_short_ids` or
/// `encoded_query_flags`.
const ENCODING_UNCOMPRESSED: u8 = 0;

/// One in this many generated queries breaks a BOLT 7 rule on purpose, in
/// each of the ways it can: an unknown chain, a raw encoding, or not waiting
/// for an outstanding answer. The rest follow the rules, so the exchange
/// usually completes.
const INVALID_ONE_IN: u32 = 8;

/// Generates the gossip query flow: filter the gossip the target sends, ask
/// which channels it knows, and ask for the announcements of one.
///
/// The ranges span the whole chain so the target has to answer from
/// everything it holds, and the queried channel is picked from the program's
/// existing `short_channel_id`s, so after a funding flow it is usually the
/// channel that flow opened. Each query waits for its predecessor's answer, as
/// BOLT 7 requires, so a program carrying this flow twice completes the first
/// exchange before starting the second.
///
/// Occasionally a query breaks the rules instead, and it may follow with the
/// replies a queried node sends although the target asked for nothing. Every
/// raw input is seeded well-formed, so the byte mutator corrupts a near-valid
/// field rather than noise: an unknown encoding type, a partial or extra id,
/// a flag count that no longer matches, or a non-minimal flag.
#[derive(Clone, Copy)]
pub struct GossipQueryGenerator;

impl Generator for GossipQueryGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Usually our own chain; sometimes one the target cannot know.
        let chain_hash = if rng.random_ratio(1, INVALID_ONE_IN) {
            builder.append(Operation::LoadChainHash(rng.random()), &[])
        } else {
            builder.append(Operation::LoadChainHashFromContext, &[])
        };

        // Ask for all gossip, whenever it was timestamped.
        let first_timestamp = builder.append(Operation::LoadTimestamp(0), &[]);
        let timestamp_range = builder.append(Operation::LoadTimestamp(u32::MAX), &[]);
        builder.append(
            Operation::SendGossipTimestampFilter,
            &[chain_hash, first_timestamp, timestamp_range],
        );

        // Ask which channels the target knows anywhere in the chain.
        let first_blocknum = builder.append(Operation::LoadBlockHeight(0), &[]);
        let number_of_blocks = builder.append(Operation::LoadBlockHeight(u32::MAX), &[]);
        let option_flags = rng.random_range(QUERY_OPTION_FLAGS);
        let query_option_flags = builder.append(Operation::LoadU8(option_flags), &[]);
        // The minimal bigsize of the same flags.
        let raw_query_option = builder.append(Operation::LoadBytes(vec![option_flags]), &[]);
        builder.append(
            Operation::SendQueryChannelRange {
                include_query_option: rng.random(),
                raw_query_option: rng.random_ratio(1, INVALID_ONE_IN),
                await_answer: !rng.random_ratio(1, INVALID_ONE_IN),
            },
            &[
                chain_hash,
                first_blocknum,
                number_of_blocks,
                query_option_flags,
                raw_query_option,
            ],
        );

        // Ask for everything about one channel, preferring one the program
        // already names.
        let short_channel_id = builder.pick_variable(VariableType::ShortChannelId, rng);
        let query_flag = builder.append(Operation::LoadU8(QUERY_ALL_ANNOUNCEMENTS), &[]);
        // A well-formed list of one id, and the one flag that goes with it.
        let mut encoded_short_ids = vec![ENCODING_UNCOMPRESSED];
        encoded_short_ids.extend(rng.random::<u64>().to_be_bytes());
        let raw_encoded_short_ids = builder.append(Operation::LoadBytes(encoded_short_ids), &[]);
        let raw_encoded_query_flags = builder.append(
            Operation::LoadBytes(vec![ENCODING_UNCOMPRESSED, QUERY_ALL_ANNOUNCEMENTS]),
            &[],
        );
        builder.append(
            Operation::SendQueryShortChannelIds {
                include_query_flags: rng.random(),
                raw_encoding: rng.random_ratio(1, INVALID_ONE_IN),
                await_answer: !rng.random_ratio(1, INVALID_ONE_IN),
            },
            &[
                chain_hash,
                short_channel_id,
                query_flag,
                raw_encoded_short_ids,
                raw_encoded_query_flags,
            ],
        );

        // Unsolicited replies.
        if rng.random() {
            let sync_complete = builder.append(Operation::LoadU8(1), &[]);
            builder.append(
                Operation::SendReplyChannelRange,
                &[
                    chain_hash,
                    first_blocknum,
                    number_of_blocks,
                    sync_complete,
                    short_channel_id,
                ],
            );
        }
        if rng.random() {
            let full_information = builder.append(Operation::LoadU8(rng.random_range(0..=1)), &[]);
            builder.append(
                Operation::SendReplyShortChannelIdsEnd,
                &[chain_hash, full_information],
            );
        }
    }
}
