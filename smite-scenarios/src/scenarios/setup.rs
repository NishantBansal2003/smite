//! Snapshot setup: procedural pre-snapshot state preparation for IR fuzzing.

use std::time::Duration;

use smite::bolt::{FeatureBit, Features, Init, InitTlvs, Message, REGTEST_CHAIN_HASH};
use smite::noise::NoiseConnection;
use smite::scenarios::ScenarioError;

use super::{handshake_with_target, local_node_pubkey, ping_pong};
use crate::executor::ProgramContext;
use crate::targets::{INITIAL_BLOCKS, Target};

const TIMEOUT: Duration = Duration::from_secs(5);

/// Pre-snapshot setup that establishes a ready-to-use connection and produces
/// the [`ProgramContext`] an IR program will read at execution time. Called
/// once from `IrScenario::new()` before the Nyx snapshot is taken.
pub trait SnapshotSetup<T: Target> {
    /// Execute the setup and return the connection and context.
    ///
    /// # Errors
    ///
    /// Setup-specific; propagated to the scenario's `new()`.
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError>;
}

/// Features stripped from our echoed `init` so the target stays on the single
/// funded flow and doesn't emit unrelated noise:
/// - `option_dual_fund` (28/29): Eclair in particular will not allow
///   single-funded flows if either of these feature bits is set.
/// - `option_provide_storage` (42/43): When enabled, peers may send
///   `peer_storage` and `peer_storage_retrieval` messages at arbitrary times.
///
/// `gossip_queries` (6/7) and `gossip_queries_ex` (10/11) are echoed rather
/// than stripped: BOLT 7 has a node send gossip queries only to a peer
/// offering them, so a target only answers ours once they are negotiated. The
/// gossip it sends in return, and the queries it makes of us, are recorded or
/// answered wherever a message is received.
const STRIPPED_FEATURES: &[FeatureBit] =
    &[Features::OPTION_DUAL_FUND, Features::OPTION_PROVIDE_STORAGE];

/// Creates an `init` that echoes the received features with bits stripped that
/// would steer the target away from the single-funded `open_channel` flow.
fn init_for_single_funded(received: &Init) -> Init {
    let mut globalfeatures = Features::from(received.globalfeatures.clone());
    let mut features = Features::from(received.features.clone());
    for &bit in STRIPPED_FEATURES {
        globalfeatures.clear_feature(bit);
        features.clear_feature(bit);
    }
    Init {
        globalfeatures: globalfeatures.into_bytes(),
        features: features.into_bytes(),
        tlvs: InitTlvs::default(),
    }
}

/// Setup that snapshots just after the Noise handshake and init exchange are
/// complete.
pub struct PostInitSetup;

impl<T: Target> SnapshotSetup<T> for PostInitSetup {
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError> {
        let (mut conn, target_init) = handshake_with_target(target, TIMEOUT)?;

        // Echo features but strip the bits that would take us off the
        // single-funded `open_channel` path this setup is built for.
        let our_init = init_for_single_funded(&target_init);
        conn.send_message(&Message::Init(our_init.clone()).encode())?;

        // Drain any remaining post-init noise so the snapshot starts with a
        // clean connection.
        ping_pong(&mut conn)?;

        let context = ProgramContext {
            target_pubkey: *target.pubkey(),
            our_pubkey: local_node_pubkey(),
            chain_hash: REGTEST_CHAIN_HASH,
            // All targets gate startup on `INITIAL_BLOCKS` being mined, so
            // this is the floor. Dynamic per-target queries can replace it
            // later.
            block_height: u32::try_from(INITIAL_BLOCKS).expect("fits in u32"),
            // Since we echo the same features the target sent, but strip both
            // required and optional bits to exercise only the single funded
            // flow and avoid unrelated noise, negotiated features are just the
            // features we sent in our init.
            negotiated_features: Features::from(our_init.features),
        };

        Ok((conn, context))
    }
}
