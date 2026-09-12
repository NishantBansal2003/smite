//! Snapshot setup: procedural pre-snapshot state preparation for IR fuzzing.

use std::time::{Duration, Instant};

use smite::bitcoin::BitcoinCli;
use smite::bolt::{ChannelTypeVariant, FeatureBit, Features, Init, InitTlvs, Message};
use smite::noise::NoiseConnection;
use smite::scenarios::ScenarioError;
use smite_ir::operation::{AcceptChannelField, ShutdownScriptVariant};
use smite_ir::{Operation, Program, ProgramBuilder};

use super::{handshake_with_target, ping_pong};
use crate::executor::{Executor, ProgramContext};
use crate::targets::{INITIAL_BLOCKS, Target};

/// Bitcoin regtest genesis hash (in BOLT 2 network byte order).
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

const TIMEOUT: Duration = Duration::from_secs(5);

/// Pre-snapshot setup that establishes a ready-to-use connection and produces
/// the [`Executor`] an IR program will run against. Called once from
/// `IrScenario::new()` before the Nyx snapshot is taken.
///
/// Returning the executor rather than its parts lets a setup leave state
/// behind in it, such as a channel it opened before the snapshot.
pub trait SnapshotSetup<T: Target> {
    /// Execute the setup and return the executor it prepared.
    ///
    /// # Errors
    ///
    /// Setup-specific; propagated to the scenario's `new()`.
    fn setup(target: &T) -> Result<Executor<NoiseConnection, BitcoinCli, T::Rpc>, ScenarioError>;
}

/// Features stripped from our echoed `init` so the target stays on the single
/// funded flow and doesn't emit unrelated noise:
/// - `gossip_queries` (6/7), `gossip_queries_ex` (10/11): Stripped so the
///   target doesn't send `gossip_timestamp_filter` or other gossip noise during
///   execution.
/// - `option_dual_fund` (28/29): Eclair in particular will not allow
///   single-funded flows if either of these feature bits is set.
/// - `option_provide_storage` (42/43): When enabled, peers may send
///   `peer_storage` and `peer_storage_retrieval` messages at arbitrary times.
const STRIPPED_FEATURES: &[FeatureBit] = &[
    Features::GOSSIP_QUERIES,
    Features::GOSSIP_QUERIES_EX,
    Features::OPTION_DUAL_FUND,
    Features::OPTION_PROVIDE_STORAGE,
];

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
    fn setup(target: &T) -> Result<Executor<NoiseConnection, BitcoinCli, T::Rpc>, ScenarioError> {
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
            channel_id: None,
        };

        Ok(Executor::new(
            conn,
            target.bitcoin_cli().clone(),
            target.rpc(),
            context,
        ))
    }
}

// Parameters of the channel `PostChannelOpenSetup` opens. Unlike a generated
// funding flow, a setup must succeed against every target on every run, so
// each value is fixed well inside the bounds all targets accept rather than
// drawn from an rng.
const SETUP_TEMPORARY_CHANNEL_ID: [u8; 32] = [0x20; 32];
const SETUP_FUNDING_SATOSHIS: u64 = 1_000_000;
const SETUP_DUST_LIMIT_SATOSHIS: u64 = 546;
const SETUP_CHANNEL_RESERVE_SATOSHIS: u64 = 10_000;
const SETUP_HTLC_MINIMUM_MSAT: u64 = 1_000;
const SETUP_FEERATE_PER_KW: u32 = 253;
const SETUP_TO_SELF_DELAY: u16 = 144;
const SETUP_MAX_ACCEPTED_HTLCS: u16 = 114;
/// Comfortably above every target's `minimum_depth`, so the funding
/// confirmation is always deep enough for the `channel_ready` exchange.
const SETUP_CONFIRMATION_BLOCKS: u8 = 16;

/// Setup that snapshots with a channel already open.
///
/// Runs the v1 funding flow as an IR program before the snapshot, so the
/// channel is established by the same executor path a fuzzed program uses. The
/// resulting channel id is recorded in the [`ProgramContext`], where
/// `LoadChannelIdFromContext` reads it.
pub struct PostChannelOpenSetup;

impl<T: Target> SnapshotSetup<T> for PostChannelOpenSetup {
    fn setup(target: &T) -> Result<Executor<NoiseConnection, BitcoinCli, T::Rpc>, ScenarioError> {
        let mut executor = PostInitSetup::setup(target)?;

        executor
            .execute(&funding_flow_program(), Instant::now())
            .map_err(|e| ScenarioError::Protocol(format!("funding flow: {e}")))?;

        // Programs built for this setup are meaningless without a channel, so
        // fail at init rather than snapshotting a state none of them can use.
        if executor.record_setup_channel().is_none() {
            return Err(ScenarioError::Protocol(
                "funding flow did not open a channel".into(),
            ));
        }

        // Drain the post-funding noise so the snapshot starts clean.
        ping_pong(executor.conn_mut())?;

        Ok(executor)
    }
}

/// Instruction indices produced by [`append_open_channel`], for the later
/// steps of the funding flow to reference as inputs.
struct SetupOpenChannel {
    /// The funding private key the commitment is signed with.
    funding_privkey: usize,
    /// The funding public key the message was built with.
    funding_pubkey: usize,
    /// The HTLC basepoint private key the commitment is signed with.
    htlc_basepoint_privkey: usize,
    /// The `temporary_channel_id` the message was built with.
    temporary_channel_id: usize,
    /// The `funding_satoshis` the message was built with.
    funding_satoshis: usize,
    /// The `feerate_per_kw` the message was built with.
    feerate_per_kw: usize,
    /// The secret behind the `first_per_commitment_point`, retained for the
    /// first `revoke_and_ack`.
    first_per_commitment_privkey: usize,
    /// The `SendOpenChannel` instruction, sequenced before receiving
    /// `accept_channel`.
    sent_open_channel: usize,
}

/// Appends the fixed channel keys and parameters, then builds and sends
/// `open_channel`.
fn append_open_channel(builder: &mut ProgramBuilder) -> SetupOpenChannel {
    // Distinct fixed keys, so no two basepoints collide. The funding key and
    // HTLC basepoint are loaded rather than derived in place because
    // `funding_created` signs the commitment with them.
    let funding_privkey = builder.append(Operation::LoadPrivateKey([0x21; 32]), &[]);
    let funding_pubkey = builder.append(Operation::DerivePoint, &[funding_privkey]);
    let htlc_basepoint_privkey = builder.append(Operation::LoadPrivateKey([0x22; 32]), &[]);
    let htlc_basepoint = builder.append(Operation::DerivePoint, &[htlc_basepoint_privkey]);
    let revocation_privkey = builder.append(Operation::LoadPrivateKey([0x23; 32]), &[]);
    let revocation_basepoint = builder.append(Operation::DerivePoint, &[revocation_privkey]);
    let payment_privkey = builder.append(Operation::LoadPrivateKey([0x24; 32]), &[]);
    let payment_basepoint = builder.append(Operation::DerivePoint, &[payment_privkey]);
    let delayed_payment_privkey = builder.append(Operation::LoadPrivateKey([0x25; 32]), &[]);
    let delayed_payment_basepoint =
        builder.append(Operation::DerivePoint, &[delayed_payment_privkey]);
    let first_per_commitment_privkey = builder.append(Operation::LoadPrivateKey([0x26; 32]), &[]);
    let first_per_commitment_point =
        builder.append(Operation::DerivePoint, &[first_per_commitment_privkey]);

    // Channel parameters.
    let chain_hash = builder.append(Operation::LoadChainHashFromContext, &[]);
    let temporary_channel_id =
        builder.append(Operation::LoadChannelId(SETUP_TEMPORARY_CHANNEL_ID), &[]);
    let funding_satoshis = builder.append(Operation::LoadAmount(SETUP_FUNDING_SATOSHIS), &[]);
    let push_msat = builder.append(Operation::LoadAmount(0), &[]);
    let dust_limit_satoshis = builder.append(Operation::LoadAmount(SETUP_DUST_LIMIT_SATOSHIS), &[]);
    let max_htlc_value_in_flight_msat =
        builder.append(Operation::LoadAmount(SETUP_FUNDING_SATOSHIS * 1000), &[]);
    let channel_reserve_satoshis =
        builder.append(Operation::LoadAmount(SETUP_CHANNEL_RESERVE_SATOSHIS), &[]);
    let htlc_minimum_msat = builder.append(Operation::LoadAmount(SETUP_HTLC_MINIMUM_MSAT), &[]);
    let feerate_per_kw = builder.append(Operation::LoadFeeratePerKw(SETUP_FEERATE_PER_KW), &[]);
    let to_self_delay = builder.append(Operation::LoadU16(SETUP_TO_SELF_DELAY), &[]);
    let max_accepted_htlcs = builder.append(Operation::LoadU16(SETUP_MAX_ACCEPTED_HTLCS), &[]);
    // Keep the channel unannounced, as `OpenChannelGenerator` does.
    let channel_flags = builder.append(Operation::LoadU8(0), &[]);
    let upfront_shutdown_script = builder.append(
        Operation::LoadShutdownScript(ShutdownScriptVariant::Empty),
        &[],
    );
    // `static_remotekey` alone is the one channel type every target accepts.
    let channel_type = builder.append(
        Operation::LoadChannelType(ChannelTypeVariant::StaticRemoteKey),
        &[],
    );

    // Build and send open_channel.
    let open_channel = builder.append(
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
    let sent_open_channel = builder.append(Operation::SendOpenChannel, &[open_channel]);

    SetupOpenChannel {
        funding_privkey,
        funding_pubkey,
        htlc_basepoint_privkey,
        temporary_channel_id,
        funding_satoshis,
        feerate_per_kw,
        first_per_commitment_privkey,
        sent_open_channel,
    }
}

/// Builds the fixed v1 funding flow program [`PostChannelOpenSetup`] runs:
/// `open_channel` / `accept_channel`, `funding_created` / `funding_signed`,
/// then the funding confirmation and `channel_ready` exchange.
fn funding_flow_program() -> Program {
    let mut builder = ProgramBuilder::new();

    // Build and send open_channel, then receive accept_channel.
    let open_channel = append_open_channel(&mut builder);
    let accept_channel = builder.append(
        Operation::RecvAcceptChannel,
        &[open_channel.sent_open_channel],
    );
    let acceptor_funding_pubkey = builder.append(
        Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
        &[accept_channel],
    );

    // Create the funding transaction, then exchange funding_created and
    // funding_signed.
    let funding_transaction = builder.append(
        Operation::CreateFundingTransaction,
        &[
            open_channel.funding_pubkey,
            acceptor_funding_pubkey,
            open_channel.funding_satoshis,
            open_channel.feerate_per_kw,
        ],
    );
    let sent_funding_created = builder.append(
        Operation::SendFundingCreated,
        &[
            funding_transaction,
            open_channel.funding_privkey,
            open_channel.htlc_basepoint_privkey,
            open_channel.temporary_channel_id,
            open_channel.first_per_commitment_privkey,
        ],
    );
    let channel_id = builder.append(Operation::RecvFundingSigned, &[sent_funding_created]);

    // Confirm the funding transaction.
    builder.append(Operation::BroadcastTransaction, &[funding_transaction]);
    builder.append(Operation::MineBlocks(SETUP_CONFIRMATION_BLOCKS), &[]);

    // Complete the channel_ready exchange.
    let second_per_commitment_privkey = builder.append(Operation::LoadPrivateKey([0x27; 32]), &[]);
    let short_channel_id = builder.append(Operation::LoadShortChannelId(0), &[]);
    builder.append(
        Operation::SendChannelReady {
            include_alias: false,
        },
        &[channel_id, second_per_commitment_privkey, short_channel_id],
    );
    builder.append(Operation::RecvChannelReady, &[]);

    builder.build()
}
