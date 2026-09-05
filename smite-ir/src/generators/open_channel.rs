//! Generator for `open_channel` message flow.

use rand::Rng;
use rand::seq::IndexedRandom;
use smite::bolt::ChannelTypeVariant;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::ShutdownScriptVariant;
use crate::{Operation, VariableType};

/// Generates an `open_channel` -> `accept_channel` flow.
///
/// Emits instructions to:
/// 1. Generate channel parameters
/// 2. Build and send `open_channel`
/// 3. Receive and parse `accept_channel`
#[derive(Clone, Copy)]
pub struct OpenChannelGenerator;

/// Instruction indices produced by [`append_open_channel`], for later
/// instructions to reference as inputs.
pub struct OpenChannelVars {
    /// The `temporary_channel_id` the message was built with.
    pub temporary_channel_id: usize,
    /// The `funding_satoshis` the message was built with.
    pub funding_satoshis: usize,
    /// The `feerate_per_kw` the message was built with.
    pub feerate_per_kw: usize,
    /// The `SendOpenChannel` instruction, sequenced before receiving
    /// `accept_channel`.
    pub sent_open_channel: usize,
}

/// Appends the instructions that generate the channel parameters, then build
/// and send `open_channel` using `funding_pubkey`.
pub fn append_open_channel(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    funding_pubkey: usize,
) -> OpenChannelVars {
    // Public keys are generated fresh to ensure they're distinct.
    let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

    // Channel parameters.
    let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
    let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);
    let funding_satoshis = builder.pick_variable(VariableType::Amount, rng);
    let push_msat = builder.pick_variable(VariableType::Amount, rng);
    let dust_limit_satoshis = builder.pick_variable(VariableType::Amount, rng);
    let max_htlc_value_in_flight_msat = builder.pick_variable(VariableType::Amount, rng);
    let channel_reserve_satoshis = builder.pick_variable(VariableType::Amount, rng);
    let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
    let feerate_per_kw = builder.pick_variable(VariableType::FeeratePerKw, rng);
    let to_self_delay = builder.pick_variable(VariableType::U16, rng);
    let max_accepted_htlcs = builder.pick_variable(VariableType::U16, rng);
    let channel_flags = builder.pick_variable(VariableType::U8, rng);
    let shutdown_script_variant = ShutdownScriptVariant::random(rng);
    let upfront_shutdown_script =
        builder.append(Operation::LoadShutdownScript(shutdown_script_variant), &[]);
    let variant = *ChannelTypeVariant::ALL
        .choose(rng)
        .expect("ChannelTypeVariant::ALL is non-empty");
    let channel_type = builder.append(Operation::LoadChannelType(variant), &[]);

    // Build and send open_channel.
    let open_channel_msg = builder.append(
        Operation::BuildOpenChannel,
        &[
            chain_hash,
            temporary_channel_id,
            funding_satoshis,
            push_msat,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            feerate_per_kw,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            channel_flags,
            upfront_shutdown_script,
            channel_type,
        ],
    );
    let sent_open_channel = builder.append(Operation::SendOpenChannel, &[open_channel_msg]);

    OpenChannelVars {
        temporary_channel_id,
        funding_satoshis,
        feerate_per_kw,
        sent_open_channel,
    }
}

impl Generator for OpenChannelGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The funding public key is generated fresh to ensure it's distinct
        // from the basepoints.
        let funding_pubkey = builder.generate_fresh(VariableType::Point, rng);

        // Build and send open_channel.
        let open_channel = append_open_channel(builder, rng, funding_pubkey);

        // Receive accept_channel.
        builder.append(
            Operation::RecvAcceptChannel,
            &[open_channel.sent_open_channel],
        );
    }
}
