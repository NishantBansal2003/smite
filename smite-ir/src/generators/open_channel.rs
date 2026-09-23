//! Generator for `open_channel` message flow.

use rand::seq::IndexedRandom;
use rand::{Rng, RngExt};
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

impl OpenChannelGenerator {
    // Channel parameter bounds accepted by at least one target, so generators
    // are more likely to produce valid channels.

    /// The highest funding floor allowed by the targets: Eclair allows nothing
    /// below `100_000` sat, while LND stops at `20_000`, CLN at `10_000`, and
    /// LDK at `1_000` sat.
    pub const MIN_FUNDING_SATOSHIS: u64 = 100_000;
    /// Highest `funding_satoshis` amount allowed by the targets under BOLT 2
    /// without requiring wumbo support.
    pub const MAX_FUNDING_SATOSHIS: u64 = (1 << 24) - 1;
    /// Self-imposed bound: push at most half the funding so the opener retains
    /// enough balance for the channel reserve and commitment fee checked by
    /// targets.
    pub const FUNDING_TO_PUSH_MSAT_DIVISOR: u64 = 2;
    /// Self-imposed floor: push at least a quarter of the funding, so the
    /// acceptor holds a balance it can offer HTLCs from. Without it a flow
    /// that needs the target to send an `update_add_htlc` stalls whenever the
    /// push lands near zero. `OperationParamMutator` still walks the loaded
    /// value down, so the empty-acceptor case stays reachable.
    pub const FUNDING_TO_MIN_PUSH_MSAT_DIVISOR: u64 = 4;
    /// Self-imposed floor: allow at least half the funding in flight, so an
    /// HTLC sized against the channel is not rejected out of hand. The
    /// mutator still walks the loaded value down.
    pub const FUNDING_TO_MIN_HTLC_IN_FLIGHT_DIVISOR: u64 = 2;
    /// Self-imposed ceiling on `htlc_minimum_msat`, keeping the floor a target
    /// enforces well under any HTLC a flow sizes against the channel.
    pub const MAX_HTLC_MINIMUM_MSAT: u64 = 1_000_000;
    /// Minimum dust limit allowed by all targets and required by BOLT 2.
    pub const MIN_DUST_LIMIT_SATOSHIS: u64 = 354;
    /// Lowest dust limit ceiling allowed by the targets: LDK caps it at 546 sat
    /// LND at `1_062` sat, Eclair at `5_000` sat, and CLN has no fixed ceiling.
    pub const MAX_DUST_LIMIT_SATOSHIS: u64 = 546;
    /// Lowest reserve ceiling allowed by the targets: Eclair caps it at 5% of
    /// funding, LND at 20%, and LDK and CLN only require it to exceed the dust
    /// limit.
    pub const FUNDING_TO_RESERVE_DIVISOR: u64 = 20;
    /// Lowest `htlc_minimum_msat` ceiling allowed by the targets: LND caps it
    /// at a fifth of `max_htlc_value_in_flight_msat`, CLN at the effective
    /// capacity, LDK at the channel value, and Eclair has no fixed ceiling.
    pub const MAX_HTLC_IN_FLIGHT_TO_MINIMUM_DIVISOR: u64 = 5;
    /// Lowest feerate ceiling allowed by the targets: Eclair caps it at `25_000`
    /// sat/kW for anchor channels, while CLN caps it at ten times its highest
    /// bitcoind estimate. LND and LDK set no ceiling and only require the
    /// funder to cover the resulting commitment fee.
    pub const MAX_FEERATE_PER_KW: u32 = 25_000;
    /// Highest `to_self_delay` allowed by all targets: 2016 blocks (~2 weeks),
    /// beyond which they consider their funds locked for too long.
    pub const MAX_TO_SELF_DELAY: u16 = 2016;
    /// Lowest `max_accepted_htlcs` allowed by the targets: LND requires at least
    /// five HTLC slots, while LDK and CLN allow any value from one and Eclair
    /// has no minimum.
    pub const MIN_MAX_ACCEPTED_HTLCS: u16 = 5;
    /// Lowest `max_accepted_htlcs` ceiling allowed across targets: BOLT 2, LND,
    /// and CLN allow up to 483, while LDK and Eclair cap 0FC channels at 114
    /// due to the v3 package size limit.
    pub const MAX_MAX_ACCEPTED_HTLCS: u16 = 114;
    /// Keep channels unannounced: clearing `announce_channel` keeps
    /// `option_scid_alias` valid, while LDK and LND reject announced channels
    /// that negotiate it.
    pub const CHANNEL_FLAGS: u8 = 0;
}

/// Instruction indices produced by [`append_open_channel`], for later
/// instructions to reference as inputs.
pub struct OpenChannelVars {
    /// Millisatoshis pushed to the acceptor, which bounds the HTLCs it can
    /// offer back.
    pub push_msat_value: u64,
    /// The `max_htlc_value_in_flight_msat` the message was built with.
    pub max_htlc_in_flight_msat: u64,
    /// The `htlc_minimum_msat` the message was built with.
    pub htlc_minimum_msat_value: u64,
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

/// Appends the instructions that generate bounded channel parameters, then
/// build and send `open_channel` using `funding_pubkey`.
pub fn append_open_channel(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    funding_pubkey: usize,
    htlc_basepoint: usize,
    first_per_commitment_point: usize,
) -> OpenChannelVars {
    type Bounds = OpenChannelGenerator;

    // Public keys are generated fresh to ensure they're distinct.
    let revocation_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let payment_basepoint = builder.generate_fresh(VariableType::Point, rng);
    let delayed_payment_basepoint = builder.generate_fresh(VariableType::Point, rng);

    // Bounds for the channel parameters, so generators are more likely to
    // choose valid values.
    let funding_sats =
        rng.random_range(Bounds::MIN_FUNDING_SATOSHIS..=Bounds::MAX_FUNDING_SATOSHIS);
    let funding_msat = funding_sats * 1000;
    let dust_limit_sats =
        rng.random_range(Bounds::MIN_DUST_LIMIT_SATOSHIS..=Bounds::MAX_DUST_LIMIT_SATOSHIS);
    let max_htlc_in_flight_msat = rng
        .random_range(funding_msat / Bounds::FUNDING_TO_MIN_HTLC_IN_FLIGHT_DIVISOR..=funding_msat);
    let push_msat_value = rng.random_range(
        funding_msat / Bounds::FUNDING_TO_MIN_PUSH_MSAT_DIVISOR
            ..=funding_msat / Bounds::FUNDING_TO_PUSH_MSAT_DIVISOR,
    );
    let htlc_minimum_msat_value = rng.random_range(
        0..=(max_htlc_in_flight_msat / Bounds::MAX_HTLC_IN_FLIGHT_TO_MINIMUM_DIVISOR)
            .min(Bounds::MAX_HTLC_MINIMUM_MSAT),
    );

    // Channel parameters.
    let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
    // Fresh rather than picked, so a program carrying more than one flow opens
    // a distinct channel per flow instead of reusing the previous one's id,
    // which the target rejects and which would strand everything built on the
    // second channel. `InputSwapMutator` still points this at an existing
    // `ChannelId`, keeping the reuse `AcceptChannelOracle` checks for
    // reachable.
    let temporary_channel_id = builder.generate_fresh(VariableType::ChannelId, rng);
    let funding_satoshis = builder.append(Operation::LoadAmount(funding_sats), &[]);
    let push_msat = builder.append(Operation::LoadAmount(push_msat_value), &[]);
    let dust_limit_satoshis = builder.append(Operation::LoadAmount(dust_limit_sats), &[]);
    let max_htlc_value_in_flight_msat =
        builder.append(Operation::LoadAmount(max_htlc_in_flight_msat), &[]);
    let channel_reserve_satoshis = builder.append(
        Operation::LoadAmount(
            rng.random_range(dust_limit_sats..=funding_sats / Bounds::FUNDING_TO_RESERVE_DIVISOR),
        ),
        &[],
    );
    let htlc_minimum_msat = builder.append(Operation::LoadAmount(htlc_minimum_msat_value), &[]);
    let feerate_per_kw = builder.append(
        Operation::LoadFeeratePerKw(rng.random_range(0..=Bounds::MAX_FEERATE_PER_KW)),
        &[],
    );
    let to_self_delay = builder.append(
        Operation::LoadU16(rng.random_range(0..=Bounds::MAX_TO_SELF_DELAY)),
        &[],
    );
    let max_accepted_htlcs = builder.append(
        Operation::LoadU16(
            rng.random_range(Bounds::MIN_MAX_ACCEPTED_HTLCS..=Bounds::MAX_MAX_ACCEPTED_HTLCS),
        ),
        &[],
    );
    let channel_flags = builder.append(Operation::LoadU8(Bounds::CHANNEL_FLAGS), &[]);
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
        push_msat_value,
        max_htlc_in_flight_msat,
        htlc_minimum_msat_value,
        temporary_channel_id,
        funding_satoshis,
        feerate_per_kw,
        sent_open_channel,
    }
}

impl Generator for OpenChannelGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // The funding public key and HTLC basepoint are generated fresh to
        // ensure they are distinct from the other basepoints.
        let funding_pubkey = builder.generate_fresh(VariableType::Point, rng);
        let htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let first_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);

        // Build and send open_channel.
        let open_channel = append_open_channel(
            builder,
            rng,
            funding_pubkey,
            htlc_basepoint,
            first_per_commitment_point,
        );

        // Receive accept_channel.
        builder.append(
            Operation::RecvAcceptChannel,
            &[open_channel.sent_open_channel],
        );
    }
}
