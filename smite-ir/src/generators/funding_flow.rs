//! Generator for the full single-funded channel open flow, from
//! `open_channel` through `channel_ready`.

use rand::Rng;
use rand::seq::IndexedRandom;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::operation::{
    AcceptChannelField, ChannelTypeVariant, FundingSignedField, ShutdownScriptVariant,
};
use crate::{Operation, VariableType};

/// Number of blocks to mine after broadcasting the funding transaction. The
/// largest `minimum_depth` any target requires is 6; mining well past that
/// keeps the flow valid across targets and leaves headroom for any
/// per-implementation quirks.
const POST_FUNDING_CONFIRMATIONS: usize = 8;

/// Generates a single-funded channel open: `open_channel` -> `accept_channel`
/// -> `funding_created` -> `funding_signed` -> broadcast + confirm ->
/// `channel_ready` (both directions).
pub struct FundingFlowGenerator;

impl Generator for FundingFlowGenerator {
    #[allow(clippy::too_many_lines)] // one linear flow; splitting hurts readability
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Opener-side keys. We hold the private keys for funding_pubkey,
        // first_per_commitment_point, and second_per_commitment_point so we
        // can sign / produce them later. The other basepoints are public-only.
        let opener_funding_priv = builder.generate_fresh(VariableType::PrivateKey, rng);
        let opener_funding_pub = builder.append(Operation::DerivePoint, &[opener_funding_priv]);
        let opener_revocation_pub = builder.generate_fresh(VariableType::Point, rng);
        let opener_payment_pub = builder.generate_fresh(VariableType::Point, rng);
        let opener_delayed_payment_pub = builder.generate_fresh(VariableType::Point, rng);
        let opener_htlc_basepoint = builder.generate_fresh(VariableType::Point, rng);
        let opener_first_pc_priv = builder.generate_fresh(VariableType::PrivateKey, rng);
        let opener_first_pc_pub = builder.append(Operation::DerivePoint, &[opener_first_pc_priv]);
        let opener_second_pc_priv = builder.generate_fresh(VariableType::PrivateKey, rng);
        let opener_second_pc_pub = builder.append(Operation::DerivePoint, &[opener_second_pc_priv]);

        // Channel parameters.
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let temporary_channel_id = builder.pick_variable(VariableType::ChannelId, rng);
        let funding_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let push_msat = builder.pick_variable(VariableType::Amount, rng);
        let opener_dust_limit = builder.pick_variable(VariableType::Amount, rng);
        let max_htlc_value_in_flight_msat = builder.pick_variable(VariableType::Amount, rng);
        let channel_reserve_satoshis = builder.pick_variable(VariableType::Amount, rng);
        let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
        let feerate_per_kw = builder.pick_variable(VariableType::FeeratePerKw, rng);
        let opener_to_self_delay = builder.pick_variable(VariableType::U16, rng);
        let max_accepted_htlcs = builder.pick_variable(VariableType::U16, rng);
        let channel_flags = builder.pick_variable(VariableType::U8, rng);
        let shutdown_variant = ShutdownScriptVariant::random(rng);
        let upfront_shutdown_script =
            builder.append(Operation::LoadShutdownScript(shutdown_variant), &[]);
        let channel_type_variant = *ChannelTypeVariant::ALL
            .choose(rng)
            .expect("ChannelTypeVariant::ALL is non-empty");
        let channel_type = builder.append(Operation::LoadChannelType(channel_type_variant), &[]);

        // Build and send open_channel.
        let oc_msg = builder.append(
            Operation::BuildOpenChannel,
            &[
                chain_hash,
                temporary_channel_id,
                funding_satoshis,
                push_msat,
                opener_dust_limit,
                max_htlc_value_in_flight_msat,
                channel_reserve_satoshis,
                htlc_minimum_msat,
                feerate_per_kw,
                opener_to_self_delay,
                max_accepted_htlcs,
                opener_funding_pub,
                opener_revocation_pub,
                opener_payment_pub,
                opener_delayed_payment_pub,
                opener_htlc_basepoint,
                opener_first_pc_pub,
                channel_flags,
                upfront_shutdown_script,
                channel_type,
            ],
        );
        builder.append(Operation::SendMessage, &[oc_msg]);

        // Receive accept_channel and pull out the acceptor's keys/params.
        let ac = builder.append(Operation::RecvAcceptChannel, &[]);
        let acceptor_funding_pub = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
            &[ac],
        );
        let acceptor_revocation_pub = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::RevocationBasepoint),
            &[ac],
        );
        let acceptor_payment_pub = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::PaymentBasepoint),
            &[ac],
        );
        let acceptor_delayed_payment_pub = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::DelayedPaymentBasepoint),
            &[ac],
        );
        let acceptor_first_pc_pub = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::FirstPerCommitmentPoint),
            &[ac],
        );
        let acceptor_dust_limit = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::DustLimitSatoshis),
            &[ac],
        );
        let acceptor_to_self_delay = builder.append(
            Operation::ExtractAcceptChannel(AcceptChannelField::ToSelfDelay),
            &[ac],
        );

        // Construct the funding transaction via the wallet.
        let funding_tx = builder.append(
            Operation::BuildFundingTransaction,
            &[
                opener_funding_pub,
                acceptor_funding_pub,
                funding_satoshis,
                feerate_per_kw,
            ],
        );

        // Sign the acceptor's first commitment so we can carry the signature
        // in funding_created.
        let commitment_inputs = [
            funding_tx,
            funding_satoshis,
            push_msat,
            feerate_per_kw,
            channel_type,
            opener_funding_priv,
            opener_funding_pub,
            opener_revocation_pub,
            opener_payment_pub,
            opener_delayed_payment_pub,
            opener_dust_limit,
            opener_to_self_delay,
            opener_first_pc_pub,
            acceptor_funding_pub,
            acceptor_revocation_pub,
            acceptor_payment_pub,
            acceptor_delayed_payment_pub,
            acceptor_dust_limit,
            acceptor_to_self_delay,
            acceptor_first_pc_pub,
        ];
        let sig = builder.append(Operation::SignCounterpartyCommitment, &commitment_inputs);

        // Build and send funding_created.
        let fc_msg = builder.append(
            Operation::BuildFundingCreated,
            &[temporary_channel_id, funding_tx, sig],
        );
        builder.append(Operation::SendMessage, &[fc_msg]);

        // Receive funding_signed and verify the counterparty's signature
        // against our (opener's) commitment.
        let fs = builder.append(Operation::RecvFundingSigned, &[]);
        let channel_id = builder.append(
            Operation::ExtractFundingSigned(FundingSignedField::ChannelId),
            &[fs],
        );
        let _acceptor_sig = builder.append(
            Operation::ExtractFundingSigned(FundingSignedField::Signature),
            &[fs],
        );

        // Broadcast the funding tx and mine enough blocks to satisfy any
        // reasonable `minimum_depth`.
        builder.append(Operation::BroadcastFundingTransaction, &[funding_tx]);
        builder.append(
            Operation::MineBlocks(u8::try_from(POST_FUNDING_CONFIRMATIONS).expect("fits in u8")),
            &[],
        );

        // Wait for the target's channel_ready, then send ours.
        let _cr = builder.append(Operation::RecvChannelReady, &[]);
        let cr_msg = builder.append(
            Operation::BuildChannelReady,
            &[channel_id, opener_second_pc_pub],
        );
        builder.append(Operation::SendMessage, &[cr_msg]);
    }
}
