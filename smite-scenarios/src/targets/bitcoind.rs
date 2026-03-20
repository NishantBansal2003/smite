//! Shared bitcoind management for all targets.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use bitcoin::{Amount, ScriptBuf};
use smite::bolt::make_funding_redeemscript;
use smite::process::ManagedProcess;

use super::TargetError;

/// Number of blocks to generate at startup for coinbase maturity.
pub const INITIAL_BLOCKS: u64 = 101;

/// Bitcoind configuration.
pub struct BitcoindConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub p2p_port: u16,
    /// Optional ZMQ raw block notification port (`zmqpubrawblock`).
    pub zmq_block_port: Option<u16>,
    /// Optional ZMQ hash block notification port (`zmqpubhashblock`).
    pub zmq_hashblock_port: Option<u16>,
    /// Optional ZMQ transaction notification port (`zmqpubrawtx`).
    pub zmq_tx_port: Option<u16>,
    /// Additional bitcoind arguments (e.g. `-addresstype=bech32`).
    pub extra_args: Vec<String>,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
            rpc_port: 18443,
            p2p_port: 18444,
            zmq_block_port: None,
            zmq_hashblock_port: None,
            zmq_tx_port: None,
            extra_args: Vec::new(),
        }
    }
}

/// Wrapper around `bitcoin-cli` with preconfigured common arguments.
pub struct BitcoinCli {
    args: Vec<String>,
}

impl BitcoinCli {
    fn new(bitcoind_dir: &Path, rpc_port: u16) -> Self {
        let args = vec![
            "-regtest".to_string(),
            format!("-datadir={}", bitcoind_dir.display()),
            format!("-rpcport={}", rpc_port),
            "-rpcuser=rpcuser".to_string(),
            "-rpcpassword=rpcpass".to_string(),
        ];
        Self { args }
    }

    /// Run a `bitcoin-cli` command, return trimmed stdout on success.
    fn run(&self, extra: &[&str]) -> Result<String, String> {
        let out = Command::new("bitcoin-cli")
            .args(&self.args)
            .args(extra)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into());
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Resolves the data directory: uses `SMITE_DATA_DIR` if set, otherwise creates a temp dir.
///
/// Returns `(path, temp_dir)` where `temp_dir` is `Some` if a temp directory was created
/// (it will be cleaned up when dropped).
pub fn resolve_data_dir() -> Result<(PathBuf, Option<tempfile::TempDir>), TargetError> {
    if let Ok(dir) = std::env::var("SMITE_DATA_DIR") {
        let path = PathBuf::from(dir);
        fs::create_dir_all(&path)?;
        log::info!("Preserving data directory: {}", path.display());
        Ok((path, None))
    } else {
        let temp = tempfile::tempdir()?;
        let path = temp.path().to_path_buf();
        Ok((path, Some(temp)))
    }
}

/// Starts bitcoind and waits for it to be ready.
///
/// Returns (process, cli, `mining_address`) where cli is a wallet-scoped
/// `BitcoinCli` handle for later RPC calls (funding, mining, etc.).
pub fn start(
    config: &BitcoindConfig,
    data_dir: &Path,
) -> Result<(ManagedProcess, BitcoinCli, bitcoin::Address), TargetError> {
    log::info!("Starting bitcoind...");

    let bitcoind_dir = data_dir.join("bitcoind");
    fs::create_dir_all(&bitcoind_dir)?;

    let mut cmd = Command::new("bitcoind");
    cmd.arg("-regtest")
        .arg(format!("-datadir={}", bitcoind_dir.display()))
        .arg(format!("-port={}", config.p2p_port))
        .arg(format!("-rpcport={}", config.rpc_port))
        .arg("-rpcuser=rpcuser")
        .arg("-rpcpassword=rpcpass")
        .arg("-fallbackfee=0.00001")
        .arg("-txindex=1")
        .arg("-server=1")
        .arg("-rest=1")
        .arg("-printtoconsole=0")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Add ZMQ args if configured
    if let Some(port) = config.zmq_block_port {
        cmd.arg(format!("-zmqpubrawblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_hashblock_port {
        cmd.arg(format!("-zmqpubhashblock=tcp://127.0.0.1:{port}"));
    }
    if let Some(port) = config.zmq_tx_port {
        cmd.arg(format!("-zmqpubrawtx=tcp://127.0.0.1:{port}"));
    }

    // Add any extra args
    for arg in &config.extra_args {
        cmd.arg(arg);
    }

    let bitcoind = ManagedProcess::spawn(&mut cmd, "bitcoind")?;

    // Wait for bitcoind to be ready
    let cli = BitcoinCli::new(&bitcoind_dir, config.rpc_port);
    log::info!("Waiting for bitcoind to be ready...");
    for _ in 0..30 {
        if cli.run(&["getblockchaininfo"]).is_ok() {
            log::info!("bitcoind is ready");
            return setup_wallet(config, &bitcoind_dir, bitcoind);
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    Err(TargetError::StartFailed(
        "bitcoind failed to become ready".into(),
    ))
}

/// Creates wallet, generates initial blocks, returns a wallet-scoped CLI handle.
fn setup_wallet(
    config: &BitcoindConfig,
    bitcoind_dir: &Path,
    bitcoind: ManagedProcess,
) -> Result<(ManagedProcess, BitcoinCli, bitcoin::Address), TargetError> {
    // Create wallet.
    let cli = BitcoinCli::new(bitcoind_dir, config.rpc_port);
    let _ = cli.run(&["createwallet", "default"]);

    // Get a mining address and generate initial blocks.
    let addr_str = cli
        .run(&["getnewaddress"])
        .map_err(|e| TargetError::StartFailed(format!("getnewaddress: {e}")))?;
    let addr: bitcoin::Address = addr_str
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| TargetError::StartFailed(format!("bad address: {e}")))?
        .assume_checked();

    cli.run(&["generatetoaddress", &INITIAL_BLOCKS.to_string(), &addr_str])
        .map_err(|e| TargetError::StartFailed(format!("generate blocks: {e}")))?;
    log::info!("Generated {INITIAL_BLOCKS} initial blocks");

    Ok((bitcoind, cli, addr))
}

/// Create a funding transaction paying to the 2-of-2 P2WSH address derived
/// from the opener and acceptor funding pubkeys.
pub fn create_funding_tx(
    cli: &BitcoinCli,
    opener_pk: &secp256k1::PublicKey,
    acceptor_pk: &secp256k1::PublicKey,
    amount_sat: u64,
) -> Option<([u8; 32], u16)> {
    let redeem = make_funding_redeemscript(opener_pk, acceptor_pk);
    let p2wsh = ScriptBuf::new_p2wsh(&redeem.wscript_hash());
    let addr = bitcoin::Address::from_script(&p2wsh, bitcoin::Network::Regtest).ok()?;
    let amount = Amount::from_sat(amount_sat);

    let txid_hex = cli
        .run(&[
            "sendtoaddress",
            &addr.to_string(),
            &format!("{:.8}", amount.to_btc()),
        ])
        .ok()?;
    log::debug!("Funding txid: {txid_hex}");

    // Parse the hex txid into bytes (internal byte order).
    let mut txid_bytes: [u8; 32] = hex::decode(&txid_hex).ok()?.try_into().ok()?;
    // bitcoin txid display is big-endian; internal byte order is reversed.
    txid_bytes.reverse();

    // Find the output index by inspecting the raw transaction.
    let raw_json = cli.run(&["getrawtransaction", &txid_hex, "true"]).ok()?;
    let tx: serde_json::Value = serde_json::from_str(&raw_json).ok()?;
    let addr_str = addr.to_string();
    let vout = tx["vout"].as_array()?.iter().find(|v| {
        v["scriptPubKey"]["address"]
            .as_str()
            .is_some_and(|a| a == addr_str)
    })?["n"]
        .as_u64()?;
    let vout = u16::try_from(vout).ok()?;

    Some((txid_bytes, vout))
}

/// Mine n blocks on the backing regtest chain.
pub fn mine_blocks(cli: &BitcoinCli, mining_addr: &bitcoin::Address, n: u32) {
    let _ = cli.run(&[
        "generatetoaddress",
        &n.to_string(),
        &mining_addr.to_string(),
    ]);
}
