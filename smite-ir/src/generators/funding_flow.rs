//! Generator for the complete v1 outbound channel funding flow.

use rand::{Rng, RngExt};

use super::Generator;
use super::open_channel::append_open_channel;
use crate::builder::ProgramBuilder;
use crate::operation::AcceptChannelField;
use crate::{Operation, VariableType};

/// Generates the complete v1 outbound channel funding flow.
///
/// Emits instructions to:
/// 1. Build and send `open_channel`, then receive `accept_channel`
/// 2. Build and send `funding_created`, then receive `funding_signed`
/// 3. Broadcast and mine blocks to confirm the funding transaction
/// 4. Complete the `channel_ready` exchange
#[derive(Clone, Copy)]
pub struct FundingFlowGenerator;

/// Blocks mined to confirm the funding transaction, whose floor clears the
/// largest `minimum_depth` any target asks for in its `accept_channel`.
///
/// Below that depth `RecvChannelReady` correctly does nothing, the
/// counterparty never reveals its first per-commitment point, and any flow
/// continuing from the channel stalls until its read times out. Generators
/// that mean to exercise the shallow case mine their own blocks instead.
const FUNDING_CONFIRMATIONS: std::ops::RangeInclusive<u8> = 8..=16;

impl Generator for FundingFlowGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        append_funding_flow(builder, rng);
    }
}

/// Variables an opened channel leaves behind, for generators that continue
/// from it.
pub struct FundingFlowVars {
    /// The `channel_id` the funding outpoint produced.
    pub channel_id: usize,
    /// The funding transaction, for looking up the channel's
    /// `short_channel_id`.
    pub funding_transaction: usize,
}

/// Appends the complete funding flow and returns the variables a later flow
/// needs to keep using the channel.
pub fn append_funding_flow(builder: &mut ProgramBuilder, rng: &mut impl Rng) -> FundingFlowVars {
    // The funding key pair is generated fresh so the funding transaction
    // can later be signed with the key `open_channel` commits to.
    let funding_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
    let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);

    // Generate a fresh HTLC basepoint key pair for the commitment transaction.
    let htlc_basepoint_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
    let htlc_basepoint = builder.append(Operation::DerivePoint, &[htlc_basepoint_privkey]);

    // Build and send open_channel.
    let open_channel = append_open_channel(builder, rng, funding_pubkey, htlc_basepoint);

    // Receive accept_channel.
    let accept_channel = builder.append(
        Operation::RecvAcceptChannel,
        &[open_channel.sent_open_channel],
    );
    let acceptor_funding_pubkey = builder.append(
        Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
        &[accept_channel],
    );

    // Create the BOLT 3 funding transaction.
    let funding_transaction = builder.append(
        Operation::CreateFundingTransaction,
        &[
            funding_pubkey,
            acceptor_funding_pubkey,
            open_channel.funding_satoshis,
            open_channel.feerate_per_kw,
        ],
    );

    // Build and send funding_created.
    let sent_funding_created = builder.append(
        Operation::SendFundingCreated,
        &[
            funding_transaction,
            funding_privkey,
            htlc_basepoint_privkey,
            open_channel.temporary_channel_id,
        ],
    );

    // Receive funding_signed.
    let channel_id = builder.append(Operation::RecvFundingSigned, &[sent_funding_created]);

    // Broadcast the funding transaction.
    builder.append(Operation::BroadcastTransaction, &[funding_transaction]);

    // Mine blocks to confirm the funding transaction.
    builder.append(
        Operation::MineBlocks(rng.random_range(FUNDING_CONFIRMATIONS)),
        &[],
    );

    // Channel ready parameters.
    let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
    let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
    let include_alias = rng.random();

    // Build and send channel_ready.
    builder.append(
        Operation::SendChannelReady { include_alias },
        &[channel_id, second_per_commitment_point, short_channel_id],
    );

    // Receive channel_ready.
    builder.append(Operation::RecvChannelReady, &[]);

    FundingFlowVars {
        channel_id,
        funding_transaction,
    }
}
