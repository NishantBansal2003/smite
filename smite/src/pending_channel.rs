//! BOLT 2 channel negotiation state.
//!
//! Remembers the `open_channel`/`accept_channel` parameters of each channel
//! being established, so later steps can build commitments from them. It also
//! tracks the origin of each pubkey sent on the wire, so pubkey reuse can be
//! reported.

use crate::bolt::{AcceptChannel, ChannelId, OpenChannel, TemporaryChannelId};
use std::fmt;

/// Negotiation parameters for a channel being established.
///
/// Contains the initiating peer's `open_channel` message, the corresponding
/// `accept_channel` once received, and whether a `funding_created` has already
/// been built from this negotiation.
pub struct PendingChannel {
    pub open_channel: OpenChannel,
    pub accept_channel: Option<AcceptChannel>,
    pub funding_built: bool,
}

/// The origin of a pubkey sent on the wire.
///
/// A static pubkey may be reused across channels, but a per-commitment point's
/// secret is eventually revealed, so it must be unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// A pubkey we sent, identified by the first instruction that put it on the
    /// wire. We know its private key.
    Ours { instruction: usize },
    /// A static pubkey (funding key or basepoint) sent by the target. It may
    /// recur across channels, so this records the first channel it was sent on.
    TargetStatic {
        /// The channel's `temporary_channel_id`.
        channel: TemporaryChannelId,
        /// The message field containing the pubkey.
        field: &'static str,
    },
    /// A per-commitment point sent by the target.
    TargetPcp {
        /// The channel's `temporary_channel_id` before funding and `channel_id`
        /// after funding.
        channel: ChannelId,
        /// The commitment number for which the point is used.
        commitment_number: u64,
    },
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyOrigin::Ours { instruction } => {
                write!(f, "our key from instruction {instruction}")
            }
            KeyOrigin::TargetStatic { channel, field } => {
                write!(f, "target's {field} on channel {channel}")
            }
            KeyOrigin::TargetPcp {
                channel,
                commitment_number,
            } => write!(
                f,
                "target's per-commitment point on channel {channel} at commitment number {commitment_number}"
            ),
        }
    }
}
