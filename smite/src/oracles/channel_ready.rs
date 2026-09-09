//! BOLT 2 `channel_ready` oracle, for the v1 outbound channel funding flow.

use super::Oracle;
use crate::bolt::ChannelReady;
use crate::channel_tx::ChannelState;
use crate::violation::Violation;

/// Context for `ChannelReadyOracle`
pub struct ChannelReadyContext<'a> {
    /// The `channel_ready` received from the peer.
    pub channel_ready: &'a ChannelReady,
    /// The channel the `channel_ready` belongs to, identified by its
    /// `channel_id`, or `None` if no channel was funded for it.
    pub channel: Option<&'a ChannelState>,
}

/// Checks whether a received `channel_ready` satisfies the BOLT 2 v1 channel
/// establishment requirements.
pub struct ChannelReadyOracle;

impl Oracle<ChannelReadyContext<'_>> for ChannelReadyOracle {
    fn evaluate(&self, context: &ChannelReadyContext<'_>) -> Result<(), Violation> {
        // Check that the `channel_ready` answers a channel we funded.
        if context.channel.is_none() {
            return Err(Violation::InvalidChannelReady(
                context.channel_ready.channel_id,
                "unknown channel_id: no funding_created was sent for this channel".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{ChannelId, ChannelReadyTlvs, Features};
    use crate::channel_tx::{
        ChannelConfig, ChannelPartyConfig, CommitmentPartyState, CommitmentState, HolderIdentity,
        Side,
    };
    use bitcoin::OutPoint;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn secret_key(seed: u8) -> SecretKey {
        SecretKey::from_slice(&[seed; 32]).expect("valid secret key")
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &secret_key(seed))
    }

    /// Valid `channel_ready` message for testing.
    fn channel_ready() -> ChannelReady {
        ChannelReady {
            channel_id: ChannelId::new([1u8; 32]),
            second_per_commitment_point: pubkey(1),
            tlvs: ChannelReadyTlvs::default(),
        }
    }

    /// Funded channel state for testing.
    fn channel_state() -> ChannelState {
        let key = pubkey(2);
        let party = || ChannelPartyConfig {
            funding_pubkey: key,
            payment_basepoint: key,
            revocation_basepoint: key,
            delayed_payment_basepoint: key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        ChannelState::new(
            ChannelConfig {
                funding_outpoint: OutPoint::null(),
                funding_satoshis: 10_000_000,
                channel_type: Features::from_bits(&[Features::OPTION_STATIC_REMOTEKEY]),
                opener: party(),
                acceptor: party(),
                minimum_depth: 6,
            },
            HolderIdentity {
                side: Side::Opener,
                funding_privkey: secret_key(2),
            },
            CommitmentState {
                commitment_number: 0,
                feerate_per_kw: 15_000,
                opener: CommitmentPartyState {
                    per_commitment_point: key,
                    balance_msat: 7_000_000_000,
                },
                acceptor: CommitmentPartyState {
                    per_commitment_point: key,
                    balance_msat: 3_000_000_000,
                },
            },
            true,
            false,
        )
    }

    #[track_caller]
    fn assert_pass(channel_ready: &ChannelReady, channel: Option<&ChannelState>) {
        if let Err(err) = ChannelReadyOracle.evaluate(&ChannelReadyContext {
            channel_ready,
            channel,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(channel_ready: &ChannelReady, channel: Option<&ChannelState>, expected: &str) {
        match ChannelReadyOracle.evaluate(&ChannelReadyContext {
            channel_ready,
            channel,
        }) {
            Err(Violation::InvalidChannelReady(chan_id, reason)) => {
                assert_eq!(channel_ready.channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_channel_ready_passes() {
        assert_pass(&channel_ready(), Some(&channel_state()));
    }

    #[test]
    fn unknown_channel_id_fails() {
        assert_fail(
            &channel_ready(),
            None,
            "unknown channel_id: no funding_created was sent for this channel",
        );
    }
}
