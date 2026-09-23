//! Generator for the BOLT 2 `option_simple_close` mutual close flow.

use rand::{Rng, RngExt};

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::Operation;
use crate::builder::ProgramBuilder;
use crate::operation::ShutdownScriptVariant;

/// Satoshi range for the closing transaction fee, which the closer pays out of
/// its own output. Wide enough to cover the fee a target considers reasonable
/// for a close at the feerates `open_channel` is generated with, and far below
/// the closer's balance so its output survives the dust limit.
const CLOSING_FEE_SATOSHIS: std::ops::RangeInclusive<u64> = 200..=5_000;

/// Generates a complete mutual close: open a channel, exchange `shutdown`, and
/// negotiate the closing transaction with `closing_complete` and
/// `closing_sig`.
///
/// The channel carries no HTLCs, so the close follows the `shutdown` exchange
/// immediately, as BOLT 2 allows. The `closing_complete` is signed over the
/// closing transaction its scripts, fee and locktime describe, so a target
/// that verifies the signature accepts it and answers with its own
/// `closing_sig`.
///
/// Assumes `option_simple_close` was negotiated: the executor echoes the
/// target's own features in its `init`, so the flow reaches `closing_complete`
/// on any target that offers the bit and stops at the `shutdown` exchange on
/// one that does not.
#[derive(Clone, Copy)]
pub struct ChannelCloseGenerator;

impl Generator for ChannelCloseGenerator {
    // closer and closee are the BOLT 2 field names.
    #[allow(clippy::similar_names)]
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel = append_funding_flow(builder, rng);

        // Both sides name the script their close output is paid to. Ours goes
        // out in `shutdown` and comes back in `closing_complete`, so the same
        // variable is used twice.
        let closer_scriptpubkey = builder.append(
            Operation::LoadShutdownScript(ShutdownScriptVariant::random(rng)),
            &[],
        );
        let sent_shutdown = builder.append(
            Operation::SendShutdown,
            &[channel.channel_id, closer_scriptpubkey],
        );

        // The counterparty's `shutdown` names the script it wants paying, so
        // the closing transaction is built from what it actually asked for.
        let closee_scriptpubkey = builder.append(Operation::RecvShutdown, &[sent_shutdown]);

        let fee_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(CLOSING_FEE_SATOSHIS)),
            &[],
        );
        // An immediately spendable close, rather than one held back to a
        // height the target would reject.
        let locktime = builder.append(Operation::LoadBlockHeight(0), &[]);

        builder.append(
            Operation::SendClosingComplete,
            &[
                channel.channel_id,
                closer_scriptpubkey,
                closee_scriptpubkey,
                fee_satoshis,
                locktime,
            ],
        );
        builder.append(Operation::RecvClosingSig, &[]);
    }
}
