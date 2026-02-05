//! LDK target implementation.
//!
//! Unlike LND, LDK is written in Rust so AFL instrumentation writes directly
//! to shared memory. No coverage pipes are needed.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use smite::process::ManagedProcess;

use super::{Target, TargetError};

/// Configuration for the LDK target.
pub struct LdkConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// LDK P2P listen port (default: 9735).
    pub ldk_p2p_port: u16,
}

impl Default for LdkConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            ldk_p2p_port: 9735,
        }
    }
}

/// LDK Lightning node target.
///
/// Field order matters: `ldk` is declared before `bitcoind` so it drops first,
/// which allows LDK to exit cleanly.
pub struct LdkTarget {
    ldk: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LdkTarget {
    /// Starts bitcoind and waits for it to be ready.
    fn start_bitcoind(config: &LdkConfig, data_dir: &Path) -> Result<ManagedProcess, TargetError> {
        log::info!("Starting bitcoind...");

        let bitcoind_dir = data_dir.join("bitcoind");
        fs::create_dir_all(&bitcoind_dir)?;

        // LDK uses bitcoind RPC directly, no ZMQ needed
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
        config: &LdkConfig,
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

    /// Starts ldk-node-wrapper and waits for it to be ready.
    /// Returns the process and LDK's identity pubkey.
    fn start_ldk(
        config: &LdkConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting ldk-node-wrapper...");

        let ldk_dir = data_dir.join("ldk");
        fs::create_dir_all(&ldk_dir)?;

        let mut cmd = Command::new("ldk-node-wrapper");
        cmd.arg(ldk_dir.to_str().expect("valid UTF-8 path"))
            .arg(config.ldk_p2p_port.to_string())
            .arg(config.bitcoind_rpc_port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut ldk = ManagedProcess::spawn(&mut cmd, "ldk-node-wrapper")?;

        // Parse pubkey from stdout. The wrapper prints:
        //   PUBKEY:<hex>
        //   READY
        let stdout = ldk.inner().stdout.take().ok_or_else(|| {
            TargetError::StartFailed("ldk-node-wrapper stdout not captured".into())
        })?;

        let reader = BufReader::new(stdout);
        let mut pubkey = None;

        for line in reader.lines() {
            let line = line.map_err(|e| TargetError::StartFailed(format!("read error: {e}")))?;

            if let Some(hex) = line.strip_prefix("PUBKEY:") {
                let bytes = hex::decode(hex).map_err(|e| {
                    TargetError::StartFailed(format!("failed to decode pubkey hex: {e}"))
                })?;
                pubkey = Some(secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                    TargetError::StartFailed(format!("failed to parse pubkey: {e}"))
                })?);
                log::info!("LDK identity pubkey: {hex}");
            } else if line == "READY" {
                break;
            }
        }

        let pubkey =
            pubkey.ok_or_else(|| TargetError::StartFailed("no PUBKEY line received".into()))?;

        log::info!("ldk-node-wrapper is ready");
        Ok((ldk, pubkey))
    }
}

impl Target for LdkTarget {
    type Config = LdkConfig;

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
        let (ldk, pubkey) = Self::start_ldk(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.ldk_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            ldk,
            bitcoind,
            pubkey,
            addr,
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
        // No coverage sync needed - Rust writes directly to AFL shm.
        // Just check that the process is still running.
        if !self.ldk.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }
}
