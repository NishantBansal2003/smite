//! Generator for a feerate change over a freshly opened channel.

use rand::{Rng, RngExt};

use super::Generator;
use super::OpenChannelGenerator;
use super::funding_flow::append_funding_flow;
use crate::Operation;
use crate::builder::ProgramBuilder;

/// Generates a complete feerate change: open a channel, send `update_fee` as
/// its funder, and commit the new feerate on both sides.
///
/// The feerate stays within the bounds `open_channel` is generated with, which
/// every target accepts and the funder's balance can afford.
#[derive(Clone, Copy)]
pub struct UpdateFeeGenerator;

impl Generator for UpdateFeeGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        type Bounds = OpenChannelGenerator;

        let channel = append_funding_flow(builder, rng);

        let feerate_per_kw = builder.append(
            Operation::LoadFeeratePerKw(
                rng.random_range(Bounds::MIN_FEERATE_PER_KW..=Bounds::MAX_FEERATE_PER_KW),
            ),
            &[],
        );
        builder.append(
            Operation::SendUpdateFee,
            &[channel.channel_id, feerate_per_kw],
        );

        // Sign the new feerate onto the counterparty's commitment, and trade
        // the revocations and signatures that carry it onto ours.
        builder.append(
            Operation::SettleChannel,
            &[channel.channel_id, channel.per_commitment_seed],
        );
    }
}
