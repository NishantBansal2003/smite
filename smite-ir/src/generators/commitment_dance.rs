//! Generator for a complete commitment dance over an already-open channel.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates one complete commitment dance: offer an HTLC, commit it, and
/// revoke the commitment it supersedes.
///
/// The channel is taken from the program context, so a meaningful exchange
/// requires a setup that opened one before the snapshot. Under `PostInitSetup`
/// the operations still send their messages, naming an all-zero channel the
/// target knows nothing about.
#[derive(Clone, Copy)]
pub struct CommitmentDanceGenerator;

impl CommitmentDanceGenerator {
    /// The first HTLC offered on a channel must have id 0, and ids increment
    /// from there. A mutator perturbing it is a case worth reaching, but not
    /// one worth emitting by default: every target rejects an out-of-order id.
    pub const FIRST_HTLC_ID: u64 = 0;

    /// Above the dust threshold of a channel at the low feerates these setups
    /// negotiate, so the HTLC takes a commitment output and a second-stage
    /// signature of its own instead of being trimmed away.
    pub const MIN_HTLC_AMOUNT_MSAT: u64 = 1_000_000;

    /// Well inside the capacity a setup opens its channel with, leaving the
    /// opener able to cover the channel reserve and the commitment fee.
    pub const MAX_HTLC_AMOUNT_MSAT: u64 = 100_000_000;

    /// Nearest expiry emitted, in blocks past the chain tip. Targets reject an
    /// HTLC expiring too near the tip.
    pub const MIN_CLTV_DELTA: u32 = 144;

    /// Furthest expiry emitted, in blocks past the chain tip. Targets reject an
    /// HTLC expiring more than roughly 2016 blocks beyond it.
    pub const MAX_CLTV_DELTA: u32 = 1_008;
}

impl Generator for CommitmentDanceGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        type Bounds = CommitmentDanceGenerator;

        // The channel the setup opened before the snapshot.
        let channel_id = builder.append(Operation::LoadChannelIdFromContext, &[]);

        // HTLC parameters, bounded so the target is likely to accept the HTLC
        // and carry the dance through rather than failing the channel.
        let htlc_id = builder.append(Operation::LoadHtlcId(Bounds::FIRST_HTLC_ID), &[]);
        let amount_msat = builder.append(
            Operation::LoadAmount(
                rng.random_range(Bounds::MIN_HTLC_AMOUNT_MSAT..=Bounds::MAX_HTLC_AMOUNT_MSAT),
            ),
            &[],
        );
        let payment_hash = builder.generate_fresh(VariableType::PaymentHash, rng);
        // Anchored to the height the setup snapshotted at, so the expiry lands
        // in the window targets accept instead of depending on where the chain
        // happens to be.
        let cltv_expiry = builder.append(
            Operation::LoadBlockHeightFromContext {
                offset: rng.random_range(Bounds::MIN_CLTV_DELTA..=Bounds::MAX_CLTV_DELTA),
            },
            &[],
        );

        // Onion parameters. Addressing the onion to the target is what lets it
        // peel the packet at all and reach its HTLC handling.
        let session_key = builder.generate_fresh(VariableType::PrivateKey, rng);
        let node_id = builder.append(Operation::LoadTargetPubkeyFromContext, &[]);
        let payment_secret = builder.generate_fresh(VariableType::PaymentHash, rng);

        // Offer the HTLC, then commit it onto the target's commitment.
        builder.append(
            Operation::SendUpdateAddHtlc,
            &[
                channel_id,
                htlc_id,
                amount_msat,
                payment_hash,
                cltv_expiry,
                session_key,
                node_id,
                payment_secret,
            ],
        );
        builder.append(Operation::SendCommitmentSigned, &[channel_id]);

        // Revoke the commitment the target has now superseded. The executor
        // first waits for the `commitment_signed` it is owed, so the
        // revocation follows the commitment it acknowledges.
        let next_per_commitment_privkey = builder.generate_fresh(VariableType::PrivateKey, rng);
        builder.append(
            Operation::SendRevokeAndAck,
            &[channel_id, next_per_commitment_privkey],
        );
    }
}
