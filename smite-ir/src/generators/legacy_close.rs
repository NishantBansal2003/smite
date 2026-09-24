//! Generator for the BOLT 2 legacy `closing_signed` mutual close flow.

use rand::{Rng, RngExt};

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::Operation;
use crate::builder::ProgramBuilder;
use crate::operation::ShutdownScriptVariant;

/// Satoshi range for the fee we propose for the closing transaction, which the
/// funder pays out of its own output. Wide enough to cover the fee a target
/// considers reasonable for a close at the feerates `open_channel` is
/// generated with, and far below the funder's balance so its output survives
/// the dust limit.
const CLOSING_FEE_SATOSHIS: std::ops::RangeInclusive<u64> = 200..=5_000;

/// Highest `max_fee_satoshis` we offer, well above any fee a target wants for
/// the closing transaction and still far below the funder's balance, so the
/// ranges overlap and the target settles on a fee in one round trip.
const MAX_CLOSING_FEE_SATOSHIS: u64 = 20_000;

/// Blocks mined after the close, enough for any target to see the closing
/// transaction confirmed.
const CLOSE_CONFIRMATIONS: std::ops::RangeInclusive<u8> = 6..=16;

/// Longest `AnySegwit` program every target accepts: LND decodes no script
/// longer than 34 bytes, the version and push opcodes taking two of them.
const MAX_ACCEPTED_ANYSEGWIT_PROGRAM_LEN: usize = 32;

/// Generates a complete legacy mutual close: open a channel, exchange
/// `shutdown`, and negotiate the closing transaction's fee with
/// `closing_signed`, then mine it.
///
/// Targets that do not negotiate `option_simple_close` close this way, with
/// the funder, which is us, proposing the first fee. It offers a `fee_range`,
/// so a target settles on a fee inside it in one reply, which
/// `RecvClosingSigned` agrees to.
#[derive(Clone, Copy)]
pub struct LegacyCloseGenerator;

impl Generator for LegacyCloseGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel = append_funding_flow(builder, rng);

        // Both sides name the script their close output is paid to. Ours goes
        // out in `shutdown` and is what we sign the closing transaction over.
        let local_scriptpubkey = builder.append(
            Operation::LoadShutdownScript(accepted_shutdown_script(rng)),
            &[],
        );
        let sent_shutdown = builder.append(
            Operation::SendShutdown,
            &[channel.channel_id, local_scriptpubkey],
        );

        // The counterparty's `shutdown` names the script it wants paying.
        let remote_scriptpubkey = builder.append(Operation::RecvShutdown, &[sent_shutdown]);

        let fee = rng.random_range(CLOSING_FEE_SATOSHIS);
        let fee_satoshis = builder.append(Operation::LoadAmount(fee), &[]);
        let min_fee_satoshis =
            builder.append(Operation::LoadAmount(rng.random_range(0..=fee)), &[]);
        let max_fee_satoshis = builder.append(
            Operation::LoadAmount(rng.random_range(fee..=MAX_CLOSING_FEE_SATOSHIS)),
            &[],
        );

        builder.append(
            Operation::SendClosingSigned,
            &[
                channel.channel_id,
                local_scriptpubkey,
                remote_scriptpubkey,
                fee_satoshis,
                min_fee_satoshis,
                max_fee_satoshis,
            ],
        );
        builder.append(
            Operation::RecvClosingSigned,
            &[
                channel.channel_id,
                local_scriptpubkey,
                remote_scriptpubkey,
                fee_satoshis,
            ],
        );

        // Once the fee is agreed each side broadcasts the closing
        // transaction, so mining confirms the close on chain.
        builder.append(
            Operation::MineBlocks(rng.random_range(CLOSE_CONFIRMATIONS)),
            &[],
        );
    }
}

/// Picks a `shutdown` script every target accepts: an empty one is invalid
/// in `shutdown`, LND rejects P2PKH, P2SH and `OP_RETURN`, and CLN rejects
/// them on an anchor channel. `OperationParamMutator` still reaches them.
fn accepted_shutdown_script(rng: &mut impl Rng) -> ShutdownScriptVariant {
    match rng.random_range(0..3) {
        0 => ShutdownScriptVariant::P2wpkh(rng.random()),
        1 => ShutdownScriptVariant::P2wsh(rng.random()),
        _ => {
            let version = rng.random_range(
                ShutdownScriptVariant::ANYSEGWIT_MIN_VERSION
                    ..=ShutdownScriptVariant::ANYSEGWIT_MAX_VERSION,
            );
            let len = rng.random_range(
                ShutdownScriptVariant::ANYSEGWIT_MIN_PROGRAM_LEN
                    ..=MAX_ACCEPTED_ANYSEGWIT_PROGRAM_LEN,
            );
            let mut program = vec![0u8; len];
            rng.fill(&mut program[..]);
            ShutdownScriptVariant::AnySegwit { version, program }
        }
    }
}
