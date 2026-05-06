//! Snapshot setup: procedural pre-snapshot state preparation for IR fuzzing.

use std::time::Duration;

use smite::bolt::{Init, InitTlvs, Message};
use smite::noise::NoiseConnection;
use smite::scenarios::ScenarioError;

use super::{handshake_with_target, ping_pong};
use crate::executor::ProgramContext;
use crate::targets::{INITIAL_BLOCKS, Target};

/// Bitcoin regtest genesis hash (in BOLT 2 network byte order).
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

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

/// Clears a feature bit from a feature vector.
///
/// Feature vectors are encoded as big-endian byte arrays where bit N lives in
/// byte `features[len - 1 - N/8]` at position `N % 8`.
fn clear_feature_bit(features: &mut [u8], bit: usize) {
    let byte_index = features.len().checked_sub(1 + bit / 8);
    if let Some(i) = byte_index {
        features[i] &= !(1 << (bit % 8));
    }
}

/// Gossip-related feature bits (BOLT 9): `gossip_queries` (6/7),
/// `gossip_queries_ex` (10/11). Stripped so the target doesn't send
/// `gossip_timestamp_filter` or other gossip noise during execution.
const GOSSIP_FEATURE_BITS: &[usize] = &[6, 7, 10, 11];

/// Feature bits that force a dual-funded flow when both peers support them:
/// `option_dual_fund` (28/29). Eclair in particular will not allow
/// single-funded flows if either of these feature bits is set, so we strip them
/// when fuzzing the single-funded flow.
const DUAL_FUNDING_FEATURE_BITS: &[usize] = &[28, 29];

/// Peer storage feature bits: `option_provide_storage` (42/43). When enabled,
/// peers may send `peer_storage` and `peer_storage_retrieval` messages at
/// arbitrary times. Disabling these bits eliminates peer storage noise.
const PEER_STORAGE_FEATURE_BITS: &[usize] = &[42, 43];

/// Creates an `init` that echoes the received features with bits stripped that
/// would steer the target away from the single-funded `open_channel` flow.
fn init_for_single_funded(received: &Init) -> Init {
    let mut globalfeatures = received.globalfeatures.clone();
    let mut features = received.features.clone();
    for &bit in GOSSIP_FEATURE_BITS
        .iter()
        .chain(DUAL_FUNDING_FEATURE_BITS)
        .chain(PEER_STORAGE_FEATURE_BITS)
    {
        clear_feature_bit(&mut globalfeatures, bit);
        clear_feature_bit(&mut features, bit);
    }
    Init {
        globalfeatures,
        features,
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
        conn.send_message(&Message::Init(our_init).encode())?;

        // Drain any remaining post-init noise so the snapshot starts with a
        // clean connection.
        ping_pong(&mut conn)?;

        let context = ProgramContext {
            target_pubkey: *target.pubkey(),
            chain_hash: REGTEST_CHAIN_HASH,
            // All targets gate startup on `INITIAL_BLOCKS` being mined, so
            // this is the floor. Dynamic per-target queries can replace it
            // later.
            block_height: u32::try_from(INITIAL_BLOCKS).expect("fits in u32"),
            target_features: target_init.features,
        };

        Ok((conn, context))
    }
}
