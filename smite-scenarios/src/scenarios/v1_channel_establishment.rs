//! V1 Channel establishment scenario — drives the BOLT 2 channel open flow.
//!
//! ```text
//! +-------+                              +-------+
//! |       |--(1)---  open_channel  ----->|       |
//! |       |<-(2)--  accept_channel  -----|       |
//! |       |                              |       |
//! |   A   |--(3)--  funding_created  --->|   B   |
//! |       |<-(4)--  funding_signed  -----|       |
//! |       |                              |       |
//! |       |--(5)---  channel_ready  ---->|       |
//! |       |<-(6)---  channel_ready  -----|       |
//! +-------+                              +-------+
//! ```
//!
//!   A = funder (us),  B = fundee (target)

use std::time::Duration;

use secp256k1::PublicKey;
use smite::bolt::{
    AcceptChannel, ChannelId, ChannelReady, FundingCreated, FundingCreatedParams, Message,
    OpenChannel, OpenChannelKeys, msg_type,
};
use smite::noise::NoiseConnection;
use smite::scenarios::{Scenario, ScenarioResult};

use super::{ScenarioError, connect_to_target, ping_pong};
use crate::targets::{Target, bitcoind};

/// A scenario that drives the BOLT 2 channel establishment handshake.
pub struct V1ChannelEstablishmentScenario<T: Target> {
    target: T,
    conn: NoiseConnection,
}

/// Fields extracted from the opener's `open_channel` that are needed after
/// the message has been encoded and consumed.
struct OpenerContext {
    keys: OpenChannelKeys,
    temporary_channel_id: ChannelId,
    funding_satoshis: u64,
    push_msat: u64,
    to_self_delay: u16,
    feerate_per_kw: u32,
    payment_basepoint: PublicKey,
    revocation_basepoint: PublicKey,
}

impl<T: Target> V1ChannelEstablishmentScenario<T> {
    /// Drive the V1 Channel establishment scenario.
    fn establish_channel(&mut self, input: &[u8]) -> Result<(), ScenarioError> {
        // Send open_channel.
        let ctx = self.send_open_channel(input)?;
        log::info!("Sent open_channel");

        // Receive accept_channel.
        let accept = self.recv_accept_channel()?;
        log::info!("Received accept_channel");

        // Send funding_created.
        let (funding_txid, funding_vout) = self.send_funding_created(&accept, &ctx)?;
        log::info!("Sent funding_created");

        // Receive funding_signed.
        self.recv_funding_signed()?;
        log::info!("Received funding_signed");

        // Mine blocks so the target sees the funding tx confirmed.
        bitcoind::mine_blocks(self.target.cli(), self.target.mining_addr(), 8);

        // Send channel_ready.
        self.send_channel_ready(&ctx, &funding_txid, funding_vout)?;
        log::info!("Sent channel_ready");

        // Receive channel_ready.
        self.recv_channel_ready()?;
        log::info!("Received channel_ready");

        // Brief pause so the target finishes processing channel_ready before shutting down.
        std::thread::sleep(Duration::from_millis(50));

        // Check if target is still alive.
        self.target.check_alive().map_err(ScenarioError::Target)
    }

    /// Build an `open_channel` from fuzz input and send it.
    fn send_open_channel(&mut self, input: &[u8]) -> Result<OpenerContext, ScenarioError> {
        let (open, open_keys) =
            OpenChannel::from_fuzz_input(input).map_err(ScenarioError::FuzzInput)?;

        let ctx = OpenerContext {
            payment_basepoint: open.payment_basepoint,
            temporary_channel_id: open.temporary_channel_id,
            funding_satoshis: open.funding_satoshis,
            push_msat: open.push_msat,
            to_self_delay: open.to_self_delay,
            feerate_per_kw: open.feerate_per_kw,
            revocation_basepoint: open.revocation_basepoint,
            keys: open_keys,
        };
        self.conn
            .send_message(&Message::OpenChannel(open).encode())?;
        Ok(ctx)
    }

    /// Build a `funding_created` from the accept and opener context, then send it.
    fn send_funding_created(
        &mut self,
        accept: &AcceptChannel,
        ctx: &OpenerContext,
    ) -> Result<([u8; 32], u16), ScenarioError> {
        let fc_params = FundingCreatedParams {
            temporary_channel_id: ctx.temporary_channel_id,
            opener_funding_privkey: ctx.keys.funding_secret,
            acceptor_funding_pubkey: accept.funding_pubkey,
            acceptor_per_commitment_point: accept.first_per_commitment_point,
            acceptor_payment_basepoint: accept.payment_basepoint,
            acceptor_delayed_payment_basepoint: accept.delayed_payment_basepoint,
            acceptor_dust_limit_satoshis: accept.dust_limit_satoshis,
            feerate_per_kw: ctx.feerate_per_kw,
            funding_satoshis: ctx.funding_satoshis,
            push_msat: ctx.push_msat,
            opener_revocation_basepoint: ctx.revocation_basepoint,
            opener_payment_basepoint: ctx.payment_basepoint,
            opener_to_self_delay: ctx.to_self_delay,
        };

        let secp = secp256k1::Secp256k1::new();
        let opener_funding_pubkey =
            PublicKey::from_secret_key(&secp, &fc_params.opener_funding_privkey);

        let (funding_txid, funding_vout) = bitcoind::create_funding_tx(
            self.target.cli(),
            &opener_funding_pubkey,
            &fc_params.acceptor_funding_pubkey,
            ctx.funding_satoshis,
        )
        .ok_or_else(|| ScenarioError::Protocol("create_funding_tx failed".into()))?;

        let funding_created = FundingCreated::with_outpoint(&fc_params, funding_txid, funding_vout);
        self.conn
            .send_message(&Message::FundingCreated(funding_created).encode())?;
        Ok((funding_txid, funding_vout))
    }

    /// Build and send `channel_ready`.
    fn send_channel_ready(
        &mut self,
        ctx: &OpenerContext,
        funding_txid: &[u8; 32],
        funding_vout: u16,
    ) -> Result<(), ScenarioError> {
        let secp = secp256k1::Secp256k1::new();
        let channel_id = ChannelId::from_funding_outpoint(funding_txid, funding_vout);
        let second_per_commitment_point =
            PublicKey::from_secret_key(&secp, &ctx.keys.per_commitment_secret);
        let channel_ready = ChannelReady::new(channel_id, second_per_commitment_point);
        self.conn
            .send_message(&Message::ChannelReady(channel_ready).encode())?;
        Ok(())
    }

    /// Wait for `accept_channel`, ignoring other messages.
    fn recv_accept_channel(&mut self) -> Result<AcceptChannel, ScenarioError> {
        loop {
            let msg = self.recv_and_decode()?;
            if let Message::AcceptChannel(a) = msg {
                return Ok(a);
            }
        }
    }

    /// Wait for `funding_signed`, ignoring other messages.
    fn recv_funding_signed(&mut self) -> Result<(), ScenarioError> {
        loop {
            let msg = self.recv_and_decode()?;
            if matches!(msg, Message::FundingSigned(_)) {
                return Ok(());
            }
        }
    }

    /// Wait for `channel_ready`, ignoring other messages.
    fn recv_channel_ready(&mut self) -> Result<(), ScenarioError> {
        loop {
            let msg = self.recv_and_decode()?;
            if matches!(msg, Message::ChannelReady(_)) {
                return Ok(());
            }
        }
    }

    /// Receive one message, decode it, and auto-pong any pings.
    fn recv_and_decode(&mut self) -> Result<Message, ScenarioError> {
        loop {
            let bytes = self.conn.recv_message()?;
            let msg = Message::decode(&bytes)?;

            if msg.msg_type() == msg_type::PING {
                let pong = Message::Pong(smite::bolt::Pong::new(0)).encode();
                let _ = self.conn.send_message(&pong);
                continue;
            }

            if msg.msg_type() == msg_type::WARNING || msg.msg_type() == msg_type::ERROR {
                return Err(ScenarioError::Protocol(format!(
                    "target sent warning/error: {msg:?}"
                )));
            }

            return Ok(msg);
        }
    }
}

impl<T: Target> Scenario for V1ChannelEstablishmentScenario<T> {
    fn new(_args: &[String]) -> Result<Self, String> {
        let config = T::Config::default();
        let target = T::start(config).map_err(|e| e.to_string())?;
        let mut conn =
            connect_to_target(&target, Duration::from_secs(5)).map_err(|e| e.to_string())?;

        // Warm up the target with a ping/pong exchange.
        ping_pong(&mut conn).map_err(|e| e.to_string())?;

        Ok(Self { target, conn })
    }

    fn run(&mut self, input: &[u8]) -> ScenarioResult {
        match self.establish_channel(input) {
            Ok(()) => ScenarioResult::Ok,
            Err(e) if e.is_timeout() => ScenarioResult::Fail("target hung".into()),
            Err(e) => {
                log::debug!("Scenario error: {e}");
                match self.target.check_alive() {
                    Ok(()) => ScenarioResult::Ok,
                    Err(_) => ScenarioResult::Fail("target crashed".into()),
                }
            }
        }
    }
}
