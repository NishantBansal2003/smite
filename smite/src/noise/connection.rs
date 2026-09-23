//! High-level encrypted connection for Lightning Network peers.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use bitcoin::secp256k1::{PublicKey, SecretKey};

use super::cipher::{ENCRYPTED_LENGTH_SIZE, MAC_SIZE, MAX_MESSAGE_SIZE, NoiseCipher};
use super::error::NoiseError;
use super::handshake::{ACT_TWO_SIZE, NoiseHandshake};

/// A Noise-encrypted connection to a Lightning Network peer.
///
/// Wraps a TCP stream and provides encrypted message sending and receiving
/// using the BOLT 8 Noise protocol.
pub struct NoiseConnection {
    stream: TcpStream,
    cipher: NoiseCipher,
    /// Parameters of the original [`connect`](Self::connect), kept so the
    /// connection can be dropped and dialled again by
    /// [`reconnect`](Self::reconnect).
    addr: SocketAddr,
    remote_pubkey: PublicKey,
    local_static: SecretKey,
    local_ephemeral: SecretKey,
    timeout: Duration,
}

impl NoiseConnection {
    /// Connects to a remote Lightning node and performs the Noise handshake.
    ///
    /// # Arguments
    /// - `addr` - The socket address of the remote node
    /// - `remote_pubkey` - The remote node's static public key (node ID)
    /// - `local_static` - Our static private key
    /// - `local_ephemeral` - Our ephemeral private key (must be random for security)
    /// - `timeout` - Timeout for connection and individual read/write operations
    ///
    /// # Errors
    ///
    /// Returns an error if TCP connection or Noise handshake fails.
    pub fn connect(
        addr: SocketAddr,
        remote_pubkey: PublicKey,
        local_static: SecretKey,
        local_ephemeral: SecretKey,
        timeout: Duration,
    ) -> Result<Self, ConnectionError> {
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let cipher =
            Self::perform_handshake(&mut stream, local_static, local_ephemeral, remote_pubkey)?;

        Ok(Self {
            stream,
            cipher,
            addr,
            remote_pubkey,
            local_static,
            local_ephemeral,
            timeout,
        })
    }

    /// Drops this connection and dials the same peer again, performing a fresh
    /// Noise handshake.
    ///
    /// The peer sees a disconnect followed by a new connection, so it resets
    /// its per-connection state and expects the BOLT 1 `init` exchange, and
    /// then the BOLT 2 `channel_reestablish` exchange for any channel it still
    /// holds. The caller is responsible for both.
    ///
    /// The ephemeral key is reused rather than redrawn, keeping a fuzz failure
    /// reproducible; it costs the handshake the forward secrecy a real node
    /// would want, which does not matter against a target we control.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection or Noise handshake fails. The
    /// old connection is dropped either way, so a failure leaves this
    /// connection unusable rather than silently still attached to the old
    /// session.
    pub fn reconnect(&mut self) -> Result<(), ConnectionError> {
        let mut stream = TcpStream::connect_timeout(&self.addr, self.timeout)?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let cipher = Self::perform_handshake(
            &mut stream,
            self.local_static,
            self.local_ephemeral,
            self.remote_pubkey,
        )?;

        self.stream = stream;
        self.cipher = cipher;

        Ok(())
    }

    /// Performs the Noise handshake as initiator.
    fn perform_handshake(
        stream: &mut TcpStream,
        local_static: SecretKey,
        local_ephemeral: SecretKey,
        remote_pubkey: PublicKey,
    ) -> Result<NoiseCipher, ConnectionError> {
        let mut handshake =
            NoiseHandshake::new_initiator(local_static, local_ephemeral, remote_pubkey);

        let act_one = handshake.get_act_one()?;
        stream.write_all(&act_one)?;

        let mut act_two = [0u8; ACT_TWO_SIZE];
        stream.read_exact(&mut act_two)?;

        let act_three = handshake.process_act_two(&act_two)?;
        stream.write_all(&act_three)?;

        Ok(handshake.into_cipher()?)
    }

    /// Sends an encrypted message to the peer.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::MessageTooLarge` if the message exceeds `MAX_MESSAGE_SIZE`
    /// or an IO error if writing fails.
    pub fn send_message(&mut self, msg: &[u8]) -> Result<(), ConnectionError> {
        if msg.len() > MAX_MESSAGE_SIZE {
            return Err(ConnectionError::MessageTooLarge(msg.len()));
        }
        let encrypted = self.cipher.encrypt(msg);
        self.stream.write_all(&encrypted)?;
        Ok(())
    }

    /// Sets the read timeout applied to subsequent `recv_message` calls. `None`
    /// makes reads block indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an IO error if the underlying socket option cannot be set.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), ConnectionError> {
        self.stream.set_read_timeout(timeout)?;
        Ok(())
    }

    /// Returns the current read timeout or `None` if reads block indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an IO error if the underlying socket option cannot be read.
    pub fn read_timeout(&self) -> Result<Option<Duration>, ConnectionError> {
        Ok(self.stream.read_timeout()?)
    }

    /// Receives and decrypts a message from the peer.
    ///
    /// # Errors
    ///
    /// Returns an IO error if reading fails, or a Noise error if decryption fails.
    pub fn recv_message(&mut self) -> Result<Vec<u8>, ConnectionError> {
        // Read and decrypt length prefix
        let mut encrypted_len = [0u8; ENCRYPTED_LENGTH_SIZE];
        self.stream.read_exact(&mut encrypted_len)?;
        let msg_len = self.cipher.decrypt_length(&encrypted_len)?;

        // Read and decrypt message body
        let encrypted_msg_len = usize::from(msg_len) + MAC_SIZE;
        let mut encrypted_msg = vec![0u8; encrypted_msg_len];
        self.stream.read_exact(&mut encrypted_msg)?;
        let msg = self.cipher.decrypt_message(&encrypted_msg)?;

        Ok(msg)
    }
}

/// Errors that can occur during connection operations.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// IO error (connection, read, write)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Noise protocol error (handshake, decryption)
    #[error("Noise error: {0}")]
    Noise(#[from] NoiseError),
    /// Message exceeds `MAX_MESSAGE_SIZE`
    #[error("message too large: {0} bytes (max {max})", max = MAX_MESSAGE_SIZE)]
    MessageTooLarge(usize),
}
