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
/// Sometimes it follows with the replies a queried node sends, although the
/// target asked for nothing: BOLT 7 gives a node receiving one no rule, which
/// is exactly what makes them worth sending.
#[derive(Clone, Copy)]
pub struct GossipQueryGenerator;

impl Generator for GossipQueryGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let chain_hash = builder.append(Operation::LoadChainHashFromContext, &[]);

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
        let query_option_flags =
            builder.append(Operation::LoadU8(rng.random_range(QUERY_OPTION_FLAGS)), &[]);
        builder.append(
            Operation::SendQueryChannelRange {
                include_query_option: rng.random(),
            },
            &[
                chain_hash,
                first_blocknum,
                number_of_blocks,
                query_option_flags,
            ],
        );

        // Ask for everything about one channel, preferring one the program
        // already names.
        let short_channel_id = builder.pick_variable(VariableType::ShortChannelId, rng);
        let query_flag = builder.append(Operation::LoadU8(QUERY_ALL_ANNOUNCEMENTS), &[]);
        builder.append(
            Operation::SendQueryShortChannelIds {
                include_query_flags: rng.random(),
            },
            &[chain_hash, short_channel_id, query_flag],
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
