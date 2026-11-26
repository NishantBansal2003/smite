//! LND target implementation.

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use bitcoin::secp256k1;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use smite::bitcoin::BitcoinCli;
use smite::process::ManagedProcess;
use smite::rpc::http_request;

use super::bitcoind;
use super::{Target, TargetError, TargetRpc, check_crash_log};

/// Configuration for the LND target.
pub struct LndConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// LND P2P listen port (default: 9735).
    pub lnd_p2p_port: u16,
    /// LND RPC port (default: 10009).
    pub lnd_rpc_port: u16,
    /// LND REST port (default: 8080).
    pub lnd_rest_port: u16,
    /// ZMQ block notification port (default: 28332).
    pub zmq_block_port: u16,
    /// ZMQ transaction notification port (default: 28333).
    pub zmq_tx_port: u16,
}

impl Default for LndConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            lnd_p2p_port: 9735,
            lnd_rpc_port: 10009,
            lnd_rest_port: 8080,
            zmq_block_port: 28332,
            zmq_tx_port: 28333,
        }
    }
}

impl LndConfig {
    fn bitcoind_config(&self) -> bitcoind::BitcoindConfig {
        bitcoind::BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            zmq_block_port: Some(self.zmq_block_port),
            zmq_tx_port: Some(self.zmq_tx_port),
            ..bitcoind::BitcoindConfig::default()
        }
    }
}

/// RPC handle for interacting with LND node target.
#[derive(Debug, Clone)]
pub struct LndRpc {
    /// LND REST port, served over plain HTTP.
    rest_port: u16,
    /// Hex-encoded macaroon authorizing REST calls.
    macaroon: String,
}

impl LndRpc {
    /// Creates an RPC handle for the LND REST API on `rest_port`, authorized
    /// by the hex-encoded `macaroon`.
    fn new(rest_port: u16, macaroon: String) -> Self {
        Self {
            rest_port,
            macaroon,
        }
    }

    /// Calls an LND REST method with the given HTTP method and JSON body,
    /// authorized by the macaroon.
    fn run(&self, http_method: &str, method: &str, body: &str) -> io::Result<serde_json::Value> {
        let headers = [("Grpc-Metadata-macaroon", self.macaroon.as_str())];
        http_request(
            http_method,
            self.rest_port,
            &format!("/v1/{method}"),
            &headers,
            body,
        )
    }
}

impl TargetRpc for LndRpc {
    /// LND receives new blocks directly from bitcoind over ZMQ, so no manual
    /// chain synchronization is required.
    fn chain_sync(&mut self) {}

    /// RPC to register an any-amount invoice on LND.
    ///
    /// # Panics
    ///
    /// - If LND answers with an error, which means the call itself is at fault
    ///   rather than the target having crashed/hanged.
    fn create_invoice(&mut self) -> Option<String> {
        // LND accepts an empty request, and omitting value makes the invoice
        // any-amount.
        let result = self
            .run("POST", "invoices", "{}")
            .inspect_err(|e| log::warn!("invoices could not reach lnd: {e}"))
            .ok()?;
        Some(
            result["payment_request"]
                .as_str()
                .expect("valid bolt11 invoice")
                .to_owned(),
        )
    }
}

/// LND Lightning node target.
///
/// Field order matters: `lnd` is declared before `bitcoind` so it drops first,
/// which allows LND to exit cleanly.
pub struct LndTarget {
    lnd: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    bitcoin_cli: BitcoinCli,
    rest_port: u16,
    macaroon: String,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LndTarget {
    /// Starts LND and waits for it to be ready. Returns the process and LND's
    /// identity pubkey.
    fn start_lnd(
        config: &LndConfig,
        lnd_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting lnd...");

        fs::create_dir_all(lnd_dir)?;

        let mut cmd = Command::new("lnd");
        cmd.arg("--noseedbackup")
            .arg("--debuglevel=info")
            .arg("--bitcoin.active")
            .arg("--bitcoin.regtest")
            .arg("--bitcoin.node=bitcoind")
            .arg(format!(
                "--bitcoind.rpchost=127.0.0.1:{}",
                config.bitcoind_rpc_port
            ))
            .arg("--bitcoind.rpcuser=rpcuser")
            .arg("--bitcoind.rpcpass=rpcpass")
            .arg(format!(
                "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:{}",
                config.zmq_block_port
            ))
            .arg(format!(
                "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:{}",
                config.zmq_tx_port
            ))
            .arg(format!("--lnddir={}", lnd_dir.display()))
            .arg(format!("--listen=127.0.0.1:{}", config.lnd_p2p_port))
            .arg(format!("--rpclisten=127.0.0.1:{}", config.lnd_rpc_port))
            .arg(format!("--restlisten=127.0.0.1:{}", config.lnd_rest_port))
            // Serve REST over plain HTTP so the RPC handle needs no TLS client.
            .arg("--no-rest-tls")
            // LND only advertises `option_scid_alias` when asked to. Without
            // it LND ignores the aliases we send in `channel_ready`.
            .arg("--protocol.option-scid-alias")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // LD_PRELOAD the crash handler to report crashes immediately (before
        // process teardown closes TCP sockets). Go only raises a signal the
        // handler sees at GOTRACEBACK=crash; by default it exits with status 2.
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler).env("GOTRACEBACK", "crash");
        }

        let mut lnd = ManagedProcess::spawn(&mut cmd, "lnd")?;

        // Wait for LND to be ready and fully synced. We poll getinfo until
        // block_height matches the initial blocks we generated.
        log::info!("Waiting for lnd to be ready and synced...");
        for _ in 0..120 {
            if !lnd.is_running() {
                return Err(TargetError::StartFailed("lnd exited during startup".into()));
            }
            if let Ok((pubkey, blockheight, synced_to_chain)) = Self::query_info(config, lnd_dir) {
                if blockheight >= bitcoind::INITIAL_BLOCKS && synced_to_chain {
                    log::info!("lnd synced (blockheight={blockheight})");
                    return Ok((lnd, pubkey));
                }
                log::debug!(
                    "lnd not yet synced (blockheight={blockheight}, synced_to_chain={synced_to_chain})"
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed("lnd failed to sync chain".into()))
    }

    /// Queries LND's identity public key and blockheight via getinfo, failing
    /// until LND's RPC server is active.
    fn query_info(
        config: &LndConfig,
        lnd_dir: &Path,
    ) -> Result<(secp256k1::PublicKey, u64, bool), TargetError> {
        #[derive(Deserialize)]
        struct GetStateResponse {
            state: String,
        }

        #[derive(Deserialize)]
        struct GetInfoResponse {
            identity_pubkey: String,
            block_height: u64,
            synced_to_chain: bool,
        }

        // LND rejects getinfo until its RPC server is active, and http_request
        // panics on rejections, so check the state first. The state endpoint
        // needs no macaroon, and macaroons may not exist yet.
        let state_rpc = LndRpc::new(config.lnd_rest_port, String::new());
        let GetStateResponse { state } = Self::rpc_json(&state_rpc, "state")?;
        if !matches!(state.as_str(), "RPC_ACTIVE" | "SERVER_ACTIVE") {
            return Err(TargetError::StartFailed("lnd RPC not active yet".into()));
        }

        let rpc = LndRpc::new(
            config.lnd_rest_port,
            hex::encode(fs::read(
                lnd_dir.join("data/chain/bitcoin/regtest/readonly.macaroon"),
            )?),
        );
        // NOTE: getinfo is currently just under LND's 2048-byte chunked
        // encoding threshold, which http_request does not support. Revisit
        // this once it grows past that.
        let info: GetInfoResponse = Self::rpc_json(&rpc, "getinfo")?;

        log::info!(
            "LND identity pubkey: {}, blockheight: {}, synced_to_chain: {}",
            info.identity_pubkey,
            info.block_height,
            info.synced_to_chain
        );

        let pubkey_bytes = hex::decode(&info.identity_pubkey)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.block_height, info.synced_to_chain))
    }

    /// Funds LND's on-chain wallet and waits until LND sees the funds confirmed.
    fn fund_wallet(rpc: &LndRpc, bitcoin_cli: &BitcoinCli) -> Result<(), TargetError> {
        #[derive(Deserialize)]
        struct NewAddressResponse {
            address: String,
        }

        // LND's REST API encodes 64-bit integers as JSON strings.
        #[derive(Deserialize)]
        struct WalletBalanceResponse {
            confirmed_balance: String,
        }

        // The address type defaults to WITNESS_PUBKEY_HASH (p2wkh).
        let NewAddressResponse { address } = Self::rpc_json(rpc, "newaddress")?;
        bitcoind::fund_wallet(bitcoin_cli, &address)?;

        log::info!("Waiting for lnd to confirm its wallet funding...");
        for _ in 0..120 {
            let balance: WalletBalanceResponse = Self::rpc_json(rpc, "balance/blockchain")?;
            if balance.confirmed_balance != "0" {
                log::info!("lnd confirmed balance: {} sat", balance.confirmed_balance);
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "lnd did not confirm its wallet funding".into(),
        ))
    }

    /// Calls an LND REST GET method and parses its result.
    fn rpc_json<T: DeserializeOwned>(rpc: &LndRpc, method: &str) -> Result<T, TargetError> {
        let result = rpc
            .run("GET", method, "")
            .map_err(|e| TargetError::StartFailed(format!("lnd {method} failed: {e}")))?;
        serde_json::from_value(result).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse lnd {method} result: {e}"))
        })
    }
}

impl Target for LndTarget {
    type Config = LndConfig;
    type Rpc = LndRpc;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let (bitcoind, bitcoin_cli) = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let lnd_dir = data_path.join("lnd");
        let (lnd, pubkey) = Self::start_lnd(&config, &lnd_dir)?;
        let macaroon = hex::encode(fs::read(
            lnd_dir.join("data/chain/bitcoin/regtest/invoice.macaroon"),
        )?);
        Self::fund_wallet(
            &LndRpc::new(config.lnd_rest_port, macaroon.clone()),
            &bitcoin_cli,
        )?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.lnd_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            lnd,
            bitcoind,
            pubkey,
            addr,
            bitcoin_cli,
            rest_port: config.lnd_rest_port,
            macaroon,
            temp_dir,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn rpc(&self) -> Self::Rpc {
        LndRpc::new(self.rest_port, self.macaroon.clone())
    }

    fn bitcoin_cli(&self) -> &BitcoinCli {
        &self.bitcoin_cli
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        check_crash_log()?;
        if !self.lnd.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }

    /// Known violations suppressed until fixed upstream:
    ///
    /// - LND doesn't fail the channel when both initial commitment balances are
    ///   at or below `channel_reserve_satoshis`, as BOLT 2 requires.
    ///   See: <https://github.com/lightningnetwork/lnd/issues/11149>
    ///
    /// - LND accepts `push_msat` above the channel capacity, which BOLT 2
    ///   requires it to reject. Its only bound is a fundee balance computed on
    ///   a wrapping `uint64` and then tested as an `int64`, so any push above
    ///   roughly 2^63 wraps back into the non-negative range.
    ///   See: <https://github.com/lightningnetwork/lnd/pull/10765>
    ///
    /// - LND as fundee sends an `accept_channel` with a shallow `minimum_depth`
    ///   for fairly large channels, since it scales the depth based on its
    ///   stake in the channel. A fix is in progress upstream.
    fn known_violations() -> &'static [&'static [&'static str]] {
        &[
            &["accepted invalid open_channel: neither side exceeds channel reserve"],
            &["invalid accept_channel: neither side exceeds channel reserve"],
            &[
                "accepted invalid open_channel: push_msat",
                "exceeds funding amount",
            ],
            &[
                "invalid accept_channel: non-zeroconf channel with capacity",
                "requires minimum_depth of at least",
            ],
        ]
    }
}
