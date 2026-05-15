//! This module implements utilities for interacting with regtest
//! `bitcoind` instances via `bitcoin-cli`.

use std::path::PathBuf;
use std::process::Command;

/// Connection info for invoking `bitcoin-cli` against the regtest `bitcoind`
/// started by a target.
#[derive(Debug, Clone)]
pub struct BitcoinCli {
    /// RPC port exposed by the regtest `bitcoind` instance.
    pub rpc_port: u16,
    /// Path passed to `bitcoin-cli -datadir`.
    pub bitcoind_dir: PathBuf,
}

impl BitcoinCli {
    /// Creates a `bitcoin-cli` command preconfigured with the connection
    /// arguments for this regtest node.
    #[must_use]
    pub fn run(&self) -> Command {
        let mut cmd = Command::new("bitcoin-cli");
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", self.bitcoind_dir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass");
        cmd
    }

    /// Mines the given number of blocks.
    ///
    /// # Panics
    ///
    /// If the `bitcoin-cli -generate` command fails to execute or returns
    /// a non-success exit status.
    pub fn mine_blocks(&self, num_blocks: u8) {
        let mine_out = self
            .run()
            .arg("-generate")
            .arg(num_blocks.to_string())
            .output()
            .expect("bitcoin-cli -generate should not fail");
        assert!(
            mine_out.status.success(),
            "bitcoin-cli -generate {} failed: {}",
            num_blocks,
            String::from_utf8_lossy(&mine_out.stderr)
        );
    }
}
