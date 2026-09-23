//! Generator for BOLT 7 `announcement_signatures` over an opened channel.

use rand::Rng;

use super::Generator;
use super::funding_flow::append_funding_flow;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an `announcement_signatures` for a channel the program has just
/// opened.
///
/// The announcement it signs names that channel: its `channel_id`, its
/// `short_channel_id` looked up from the confirmed funding transaction, the
/// target as the other node, and both funding keys, so the bitcoin signature
/// is made with the key that actually funds the channel. The funding flow
/// confirms it past the six blocks BOLT 7 requires before the message is sent.
///
/// Our node signing key is fresh, since the node key the Noise handshake
/// presents is not available to a program, so the node signature does not
/// match our node id. That leaves no valid announcement to complete in any
/// case: every channel `append_open_channel` opens is unannounced, so it keeps
/// `option_scid_alias` valid, and BOLT 7 forbids `announcement_signatures`
/// for a channel that did not set `announce_channel`. What this exercises is
/// how the target treats one that arrives anyway, for a channel it holds.
#[derive(Clone, Copy)]
pub struct AnnouncementSignaturesGenerator;

impl Generator for AnnouncementSignaturesGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let channel = append_funding_flow(builder, rng);

        let short_channel_id = builder.append(
            Operation::LookupShortChannelId,
            &[channel.funding_transaction],
        );
        let features = builder.pick_variable(VariableType::Features, rng);
        let chain_hash = builder.append(Operation::LoadChainHashFromContext, &[]);
        let node_sk = builder.generate_fresh(VariableType::PrivateKey, rng);
        let target_node_id = builder.append(Operation::LoadTargetPubkeyFromContext, &[]);

        let msg = builder.append(
            Operation::BuildAnnouncementSignatures,
            &[
                channel.channel_id,
                features,
                chain_hash,
                short_channel_id,
                node_sk,
                target_node_id,
                channel.funding_privkey,
                channel.acceptor_funding_pubkey,
            ],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
