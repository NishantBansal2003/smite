//! CLN (Core Lightning) target implementation.
//!
//! CLN is written in C, so AFL instrumentation (via `afl-clang-fast`) writes
//! directly to shared memory. No coverage pipes are needed.
//!
//! CLN uses a subdaemon architecture: `lightningd` spawns separate binaries
//! (`lightning_connectd`, `lightning_gossipd`, etc.). Global subdaemons have
//! `must_not_exit = true`, so if any of them crash, lightningd itself exits.
//! This means checking lightningd's liveness is sufficient for crash detection.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use smite::process::ManagedProcess;

use super::{Target, TargetError};

/// Configuration for the CLN target.
pub struct ClnConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// CLN P2P listen port (default: 9735).
    pub cln_p2p_port: u16,
}

impl Default for ClnConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            cln_p2p_port: 9735,
        }
    }
}

/// CLN (Core Lightning) node target.
///
/// Field order matters: `cln` is declared before `bitcoind` so it drops first,
/// which allows CLN to exit cleanly before bitcoind shuts down.
pub struct ClnTarget {
    cln: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    cln_dir: PathBuf,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl ClnTarget {
    /// Starts bitcoind and waits for it to be ready.
    fn start_bitcoind(config: &ClnConfig, data_dir: &Path) -> Result<ManagedProcess, TargetError> {
        log::info!("Starting bitcoind...");

        let bitcoind_dir = data_dir.join("bitcoind");
        fs::create_dir_all(&bitcoind_dir)?;

        // CLN uses the bcli plugin which polls via bitcoin-cli RPC, no ZMQ needed
        let mut cmd = Command::new("bitcoind");
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-port={}", config.bitcoind_p2p_port))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("-fallbackfee=0.00001")
            .arg("-txindex=1")
            .arg("-server=1")
            .arg("-rest=1")
            .arg("-printtoconsole=0")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let bitcoind = ManagedProcess::spawn(&mut cmd, "bitcoind")?;

        // Wait for bitcoind to be ready
        log::info!("Waiting for bitcoind to be ready...");
        for _ in 0..30 {
            let status = Command::new("bitcoin-cli")
                .arg("-regtest")
                .arg(format!("-datadir={}", bitcoind_dir.display()))
                .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
                .arg("-rpcuser=rpcuser")
                .arg("-rpcpassword=rpcpass")
                .arg("getblockchaininfo")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if status.is_ok_and(|s| s.success()) {
                log::info!("bitcoind is ready");
                return Self::setup_wallet(config, &bitcoind_dir, bitcoind);
            }

            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "bitcoind failed to become ready".into(),
        ))
    }

    /// Creates wallet and generates initial blocks.
    fn setup_wallet(
        config: &ClnConfig,
        bitcoind_dir: &Path,
        bitcoind: ManagedProcess,
    ) -> Result<ManagedProcess, TargetError> {
        // Create wallet (ignore error if already exists)
        let _ = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("createwallet")
            .arg("default")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Generate 101 blocks for coinbase maturity
        let status = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("-generate")
            .arg("101")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            return Err(TargetError::StartFailed(
                "failed to generate initial blocks".into(),
            ));
        }

        Ok(bitcoind)
    }

    /// Starts lightningd and waits for it to be ready.
    /// Returns the process, CLN's identity pubkey, and the lightning-dir path.
    fn start_cln(
        config: &ClnConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey, PathBuf), TargetError> {
        log::info!("Starting lightningd...");

        let cln_dir = data_dir.join("cln");
        fs::create_dir_all(&cln_dir)?;

        // Run lightningd in foreground mode (no --daemon) so ManagedProcess
        // can track the PID for liveness checks and signal delivery.
        let mut cmd = Command::new("lightningd");

        // LD_PRELOAD the crash handler into lightningd and its subdaemons.
        // Set only on lightningd (not lightning-cli/bitcoin-cli) to avoid
        // interfering with helper processes.
        if let Ok(handler) = std::env::var("SMITE_CRASH_HANDLER") {
            cmd.env("LD_PRELOAD", handler);
        }

        cmd.arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg(format!(
                "--bitcoin-rpcconnect=127.0.0.1:{}",
                config.bitcoind_rpc_port
            ))
            .arg("--bitcoin-rpcuser=rpcuser")
            .arg("--bitcoin-rpcpassword=rpcpass")
            .arg(format!("--addr=0.0.0.0:{}", config.cln_p2p_port))
            .arg("--log-level=info")
            .arg(format!("--log-file={}/cln.log", cln_dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let cln = ManagedProcess::spawn(&mut cmd, "lightningd")?;

        // Wait for CLN to be ready by polling lightning-cli getinfo
        log::info!("Waiting for lightningd to be ready...");
        for _ in 0..60 {
            if let Ok(pubkey) = Self::query_pubkey(&cln_dir) {
                log::info!("lightningd is ready");
                return Ok((cln, pubkey, cln_dir));
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "lightningd failed to become ready".into(),
        ))
    }

    /// Queries CLN's identity public key via lightning-cli.
    fn query_pubkey(cln_dir: &Path) -> Result<secp256k1::PublicKey, TargetError> {
        #[derive(Deserialize)]
        struct GetInfoResponse {
            id: String,
        }

        let output = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", cln_dir.display()))
            .arg("--network=regtest")
            .arg("getinfo")
            .output()?;

        if !output.status.success() {
            return Err(TargetError::StartFailed(format!(
                "lightning-cli getinfo failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse lightning-cli output: {e}"))
        })?;

        log::info!("CLN identity pubkey: {}", info.id);

        let pubkey_bytes = hex::decode(&info.id)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))
    }
}

impl Drop for ClnTarget {
    fn drop(&mut self) {
        // Use `lightning-cli stop` for graceful shutdown instead of SIGTERM.
        // lightningd's SIGTERM handler calls _exit(), which skips atexit handlers
        // and prevents LLVM coverage profraw data from being written. The `stop`
        // RPC triggers a clean exit through the event loop, running atexit handlers.
        log::debug!("lightningd: requesting graceful shutdown via lightning-cli stop");
        let result = Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", self.cln_dir.display()))
            .arg("--network=regtest")
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if result.is_ok_and(|s| s.success()) {
            // Wait for lightningd to fully exit with a timeout. The RPC response
            // is sent just before `return` from main(), so there's a small window
            // where the CLI has returned but lightningd hasn't exited yet.
            log::debug!("lightningd: waiting for process to exit");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while self.cln.is_running() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            log::debug!("lightningd: lightning-cli stop failed, falling back to SIGTERM");
        }
        // ManagedProcess::drop handles cleanup. If lightningd already exited,
        // is_running() returns false and no signal is sent. If the timeout
        // expired, ManagedProcess sends SIGTERM as a fallback.
    }
}

impl Target for ClnTarget {
    type Config = ClnConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        // Check for SMITE_DATA_DIR to preserve data directory for debugging
        let (data_path, temp_dir) = if let Ok(dir) = std::env::var("SMITE_DATA_DIR") {
            let path = PathBuf::from(dir);
            fs::create_dir_all(&path)?;
            log::info!("Preserving data directory: {}", path.display());
            (path, None)
        } else {
            let temp = tempfile::tempdir()?;
            let path = temp.path().to_path_buf();
            (path, Some(temp))
        };

        let bitcoind = Self::start_bitcoind(&config, &data_path)?;
        let (cln, pubkey, cln_dir) = Self::start_cln(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.cln_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            cln,
            bitcoind,
            pubkey,
            addr,
            cln_dir,
            temp_dir,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        // Check if the crash handler was triggered. In Nyx mode, crashes are
        // reported directly via hypercall and we never get to this point. In
        // local mode, the crash handler writes crash data to this file.
        let crash_log = std::path::Path::new("/tmp/smite-crash.log");
        if crash_log.exists() {
            if let Ok(msg) = std::fs::read_to_string(crash_log) {
                log::error!("crash handler: {}", msg.trim());
            }
            let _ = std::fs::remove_file(crash_log);
            return Err(TargetError::Crashed);
        }

        // Check whether lightningd is running.
        if !self.cln.is_running() {
            return Err(TargetError::Crashed);
        }

        Ok(())
    }
}
