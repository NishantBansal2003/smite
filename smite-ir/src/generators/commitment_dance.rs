//! Generator for a complete commitment dance over a freshly opened channel.

use rand::{Rng, RngExt};

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Millisatoshi range for the offered HTLC. The floor keeps it clear of the
/// dust threshold at the feerates `open_channel` is generated with, so the
/// HTLC takes an output on both commitments and is signed with one.
const HTLC_AMOUNT_MSAT: std::ops::RangeInclusive<u64> = 50_000_000..=500_000_000;

/// Millisatoshis the target keeps for relaying, deducted from the amount it
/// forwards on. Comfortably above the default policies of every target, which
/// fail the HTLC back rather than forwarding it when underpaid.
const ROUTING_FEE_MSAT: u64 = 10_000_000;

/// Blocks between the incoming and outgoing expiries, which must be at least
/// the target's `cltv_expiry_delta` or it fails the HTLC back.
const CLTV_DELTA: u32 = 200;

/// Expiry of the HTLC we offer, far enough ahead to stay valid for the whole
/// dance.
const CLTV_EXPIRY: u32 = 1_000;

/// Generates a complete commitment dance: open a channel, offer an HTLC,
/// commit it on both sides, and resolve it.
///
/// With `route_to_self`, the onion carries a forwarding hop so the target
/// relays an `update_add_htlc` back to us, which the dance then fulfills with
/// the preimage it offered the HTLC against. Without it the target is the
/// payee and resolves the HTLC itself, so the dance only carries the rounds
/// needed to mirror that resolution onto both commitments.
#[derive(Clone, Copy)]
pub struct CommitmentDanceGenerator {
    /// Whether the onion routes back to us through the target.
    pub route_to_self: bool,
}

impl Generator for CommitmentDanceGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel = append_funding_flow(builder, rng);

        // The channel's own `short_channel_id`, which is what the target must
        // forward back over. The executor prefers the alias the counterparty
        // offered in `channel_ready` when it sent one.
        let short_channel_id = builder.append(
            Operation::LookupShortChannelId,
            &[channel.funding_transaction],
        );

        // Offer the HTLC against a preimage we hold, so the dance can redeem
        // it later with a preimage that matches by construction.
        let payment_preimage = builder.generate_fresh(VariableType::PaymentPreimage, rng);
        let payment_hash = builder.append(Operation::DerivePaymentHash, &[payment_preimage]);

        let amount_msat = rng.random_range(HTLC_AMOUNT_MSAT);
        let htlc_id = builder.append(Operation::LoadHtlcId(0), &[]);
        let amount = builder.append(Operation::LoadAmount(amount_msat), &[]);
        let cltv_expiry = builder.append(Operation::LoadBlockHeight(CLTV_EXPIRY), &[]);
        let session_key = builder.generate_fresh(VariableType::PrivateKey, rng);
        let payment_secret = builder.generate_fresh(VariableType::PaymentSecret, rng);

        // The onion's final hop is the target when it is the payee, and
        // ourselves when it is relaying back to us.
        let node_id = if self.route_to_self {
            builder.append(Operation::LoadOurPubkeyFromContext, &[])
        } else {
            builder.append(Operation::LoadTargetPubkeyFromContext, &[])
        };

        // What the target forwards on, the differences being its routing fee
        // and CLTV delta. Ignored unless routing back to ourselves.
        let forward_amount = builder.append(
            Operation::LoadAmount(amount_msat.saturating_sub(ROUTING_FEE_MSAT)),
            &[],
        );
        let forward_cltv = builder.append(
            Operation::LoadBlockHeight(CLTV_EXPIRY.saturating_sub(CLTV_DELTA)),
            &[],
        );

        builder.append(
            Operation::SendUpdateAddHtlc {
                route_to_self: self.route_to_self,
            },
            &[
                channel.channel_id,
                htlc_id,
                amount,
                payment_hash,
                cltv_expiry,
                session_key,
                node_id,
                payment_secret,
                short_channel_id,
                forward_amount,
                forward_cltv,
            ],
        );

        // Commit the HTLC onto the counterparty's commitment, then revoke ours
        // once they have mirrored it back onto it. The revocation blocks until
        // their `commitment_signed` arrives, so the HTLC is irrevocably
        // committed on both sides once this round completes.
        append_commit_and_revoke(builder, rng, channel.channel_id);

        // Redeem the HTLC the target relayed back to us. Its id is the
        // target's own numbering, which starts at zero for the first HTLC it
        // offers.
        if self.route_to_self {
            let relayed_htlc_id = builder.append(Operation::LoadHtlcId(0), &[]);
            builder.append(
                Operation::SendUpdateFulfillHtlc,
                &[channel.channel_id, relayed_htlc_id, payment_preimage],
            );
        }

        // A second round carries the resolution onto both commitments,
        // whether it was ours to send or the target's.
        append_commit_and_revoke(builder, rng, channel.channel_id);
    }
}

/// Appends one round of the dance: sign the counterparty's next commitment,
/// then revoke the commitment theirs replaced.
fn append_commit_and_revoke(builder: &mut ProgramBuilder, rng: &mut impl Rng, channel_id: usize) {
    builder.append(Operation::SendCommitmentSigned, &[channel_id]);

    let per_commitment_secret = builder.generate_fresh(VariableType::PrivateKey, rng);
    let next_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
    builder.append(
        Operation::SendRevokeAndAck,
        &[channel_id, per_commitment_secret, next_per_commitment_point],
    );
}
