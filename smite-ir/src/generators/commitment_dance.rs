//! Generator for a complete commitment dance over a freshly opened channel.

use rand::{Rng, RngExt};

use super::Generator;
use super::funding_flow::{append_funding_flow, append_per_commitment_point};
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Fraction of the acceptor's balance the offered HTLC is capped at, leaving
/// it room for its channel reserve and commitment fee when it offers the HTLC
/// back to us.
const PUSH_TO_HTLC_DIVISOR: u64 = 4;

/// Fraction of the HTLC the target keeps for relaying, deducted from the
/// amount it forwards on. Well above the default policies of every target,
/// which fail the HTLC back rather than forwarding it when underpaid.
const HTLC_TO_ROUTING_FEE_DIVISOR: u64 = 10;

/// Blocks between the incoming and outgoing expiries, which must be at least
/// the target's `cltv_expiry_delta` or it fails the HTLC back.
const CLTV_DELTA: u32 = 200;

/// Expiry of the HTLC we offer, far enough ahead to stay valid for the whole
/// dance.
const CLTV_EXPIRY: u32 = 1_000;

/// `failure_code`s a hop returns for an onion it cannot parse, BOLT 4's
/// `invalid_onion_version`, `invalid_onion_hmac` and `invalid_onion_key`, each
/// carrying the `BADONION` bit BOLT 2 requires of `update_fail_malformed_htlc`.
const MALFORMED_FAILURE_CODES: [u16; 3] = [0xC004, 0xC005, 0xC006];

/// Size of the `sha256_of_onion` an `update_fail_malformed_htlc` carries.
const SHA256_OF_ONION_SIZE: usize = 32;

/// Generates a complete commitment dance: open a channel, offer an HTLC,
/// commit it on both sides, and resolve it.
///
/// With `route_to_self`, the onion carries a forwarding hop so the target
/// relays an `update_add_htlc` back to us, which the dance then fulfills with
/// the preimage it offered the HTLC against, fails, or fails as malformed.
/// Without it the target is the payee and resolves the HTLC itself.
///
/// The first round always runs in the same order, so it is spelled out. What
/// follows depends on when the target forwards, resolves and batches, so
/// `SettleChannel` carries it.
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

        // Size the HTLC against the channel that was actually opened. The
        // ceiling keeps it within what the target will hold in flight and
        // within the balance it needs to offer the HTLC back to us, and the
        // floor respects the `htlc_minimum_msat` it will enforce. The bounds
        // `append_open_channel` uses keep the floor below the ceiling.
        let ceiling_msat = channel
            .max_htlc_in_flight_msat
            .min(channel.push_msat_value / PUSH_TO_HTLC_DIVISOR);
        let floor_msat = channel.htlc_minimum_msat_value.min(ceiling_msat);
        let amount_msat = rng.random_range(floor_msat..=ceiling_msat);
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
            Operation::LoadAmount(amount_msat - amount_msat / HTLC_TO_ROUTING_FEE_DIVISOR),
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
        // committed on both sides once this round completes. It revokes
        // commitment 0 and advertises the point of commitment 2.
        builder.append(Operation::SendCommitmentSigned, &[channel.channel_id]);
        let commitment_number = builder.append(Operation::LoadCommitmentNumber(0), &[]);
        let per_commitment_secret = builder.append(
            Operation::DerivePerCommitmentSecret,
            &[channel.per_commitment_seed, commitment_number],
        );
        let next_per_commitment_point =
            append_per_commitment_point(builder, channel.per_commitment_seed, 2);
        builder.append(
            Operation::SendRevokeAndAck,
            &[
                channel.channel_id,
                per_commitment_secret,
                next_per_commitment_point,
            ],
        );

        // Wait for the target to resolve our HTLC, or to relay it back to us
        // and irrevocably commit it.
        builder.append(
            Operation::SettleChannel,
            &[channel.channel_id, channel.per_commitment_seed],
        );

        // Resolve the HTLC the target relayed back to us, then commit our
        // resolution, and the target's of the HTLC we offered.
        if self.route_to_self {
            append_relayed_htlc_resolution(builder, rng, channel.channel_id, payment_preimage);
            builder.append(
                Operation::SettleChannel,
                &[channel.channel_id, channel.per_commitment_seed],
            );
        }
    }
}

/// Appends our resolution of the HTLC the target relayed back to us over
/// `channel_id`: redeeming it with `payment_preimage`, the preimage it was
/// offered against, failing it back, or failing it back as malformed. Its id
/// is the target's own numbering, which starts at zero for the first HTLC it
/// offers.
fn append_relayed_htlc_resolution(
    builder: &mut ProgramBuilder,
    rng: &mut impl Rng,
    channel_id: usize,
    payment_preimage: usize,
) {
    let relayed_htlc_id = builder.append(Operation::LoadHtlcId(0), &[]);
    match rng.random_range(0..3) {
        0 => {
            builder.append(
                Operation::SendUpdateFulfillHtlc,
                &[channel_id, relayed_htlc_id, payment_preimage],
            );
        }
        1 => {
            let reason = builder.generate_fresh(VariableType::Bytes, rng);
            builder.append(
                Operation::SendUpdateFailHtlc,
                &[channel_id, relayed_htlc_id, reason],
            );
        }
        _ => {
            let mut hash = vec![0u8; SHA256_OF_ONION_SIZE];
            rng.fill(&mut hash[..]);
            let sha256_of_onion = builder.append(Operation::LoadBytes(hash), &[]);
            let failure_code = builder.append(
                Operation::LoadU16(
                    MALFORMED_FAILURE_CODES[rng.random_range(0..MALFORMED_FAILURE_CODES.len())],
                ),
                &[],
            );
            builder.append(
                Operation::SendUpdateFailMalformedHtlc,
                &[channel_id, relayed_htlc_id, sha256_of_onion, failure_code],
            );
        }
    }
}
