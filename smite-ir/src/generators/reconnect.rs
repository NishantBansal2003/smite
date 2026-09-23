//! Generator for the reconnection flow of an established channel.

use rand::Rng;
use smite::bolt::PER_COMMITMENT_SECRET_SIZE;

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Commitment number of the next `commitment_signed` we expect after the
/// `channel_ready` exchange: neither side has signed a commitment beyond the
/// initial one, so the next is number 1.
const NEXT_COMMITMENT_NUMBER: u64 = 1;

/// Commitment number of the next `revoke_and_ack` we expect after the
/// `channel_ready` exchange: nothing has been revoked yet.
const NEXT_REVOCATION_NUMBER: u64 = 0;

/// Generates a complete reconnection flow: open a channel, drop the
/// connection and dial the target again, then reestablish the channel over the
/// new one.
///
/// The commitment numbers describe a channel that has just become ready, which
/// is the position `append_funding_flow` leaves it in, so the target has no
/// reason to fail the channel and the flow reaches the state where it
/// retransmits `channel_ready` and its own `channel_reestablish`.
#[derive(Clone, Copy)]
pub struct ReconnectGenerator;

impl Generator for ReconnectGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel = append_funding_flow(builder, rng);

        // Drop the connection and dial again, which re-exchanges `init`.
        builder.append(Operation::Reconnect, &[]);

        let next_commitment_number =
            builder.append(Operation::LoadCommitmentNumber(NEXT_COMMITMENT_NUMBER), &[]);
        let next_revocation_number =
            builder.append(Operation::LoadCommitmentNumber(NEXT_REVOCATION_NUMBER), &[]);

        // All zeroes, as BOLT 2 requires while no revocation was received.
        let your_last_per_commitment_secret = builder.append(
            Operation::LoadBytes(vec![0; PER_COMMITMENT_SECRET_SIZE]),
            &[],
        );
        let my_current_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        builder.append(
            Operation::SendChannelReestablish,
            &[
                channel.channel_id,
                next_commitment_number,
                next_revocation_number,
                your_last_per_commitment_secret,
                my_current_per_commitment_point,
            ],
        );
    }
}
