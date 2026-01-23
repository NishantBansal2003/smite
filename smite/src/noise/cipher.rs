use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;

use super::error::NoiseError;

/// Poly1305 MAC size in bytes.
pub const MAC_SIZE: usize = 16;

/// Maximum Lightning message size (limited by 2-byte length prefix).
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Encrypted length prefix size: 2 bytes length + MAC.
pub const ENCRYPTED_LENGTH_SIZE: usize = 2 + MAC_SIZE;

/// Key rotation threshold - rotate after 1000 encryptions/decryptions (every 500 messages).
const KEY_ROTATION_THRESHOLD: u64 = 1000;

/// Handles post-handshake message encryption and decryption.
///
/// After a successful Noise handshake, this cipher is used to encrypt/decrypt
/// Lightning messages. It manages separate send/receive keys and nonces, and
/// implements key rotation per BOLT 8.
#[derive(Clone)]
pub struct NoiseCipher {
    /// Key for encrypting outgoing messages
    send_key: [u8; 32],
    /// Key for decrypting incoming messages
    recv_key: [u8; 32],
    /// Nonce for sending (incremented after each encryption)
    send_nonce: u64,
    /// Nonce for receiving (incremented after each decryption)
    recv_nonce: u64,
    /// Chaining key for send key rotation
    send_ck: [u8; 32],
    /// Chaining key for receive key rotation
    recv_ck: [u8; 32],
}

impl NoiseCipher {
    /// Creates a new cipher from handshake-derived keys.
    ///
    /// # Arguments
    /// - `send_key` - Key for encrypting messages
    /// - `recv_key` - Key for decrypting messages
    /// - `chaining_key` - The final chaining key from handshake (used for key rotation)
    #[must_use]
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], chaining_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            send_nonce: 0,
            recv_nonce: 0,
            send_ck: chaining_key,
            recv_ck: chaining_key,
        }
    }

    /// Encrypts a Lightning message for sending.
    ///
    /// Returns the encrypted packet: `encrypted_length || encrypted_message`.
    /// The length is encrypted separately from the message body.
    ///
    /// # Panics
    ///
    /// Panics if `plaintext` exceeds `MAX_MESSAGE_SIZE` bytes.
    #[must_use]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Check for key rotation before encrypting
        self.maybe_rotate_send_key();

        // Encrypt the 2-byte length prefix
        let len_bytes = u16::try_from(plaintext.len())
            .expect("message within MAX_MESSAGE_SIZE bytes")
            .to_be_bytes();
        let encrypted_len = encrypt_with_ad(&self.send_key, self.send_nonce, &[], &len_bytes);
        self.send_nonce += 1;

        // Check again after length encryption
        self.maybe_rotate_send_key();

        // Encrypt the message body
        let encrypted_msg = encrypt_with_ad(&self.send_key, self.send_nonce, &[], plaintext);
        self.send_nonce += 1;

        // Concatenate: encrypted_length || encrypted_message
        let mut result = Vec::with_capacity(encrypted_len.len() + encrypted_msg.len());
        result.extend_from_slice(&encrypted_len);
        result.extend_from_slice(&encrypted_msg);
        result
    }

    /// Decrypts the length prefix from an incoming packet.
    ///
    /// # Arguments
    /// - `encrypted_len` - The first `ENCRYPTED_LENGTH_SIZE` bytes of the packet
    ///
    /// # Returns
    /// The message length on success.
    ///
    /// # Errors
    /// Returns `NoiseError::DecryptionFailed` if MAC verification fails.
    pub fn decrypt_length(
        &mut self,
        encrypted_len: &[u8; ENCRYPTED_LENGTH_SIZE],
    ) -> Result<u16, NoiseError> {
        self.maybe_rotate_recv_key();

        let len_bytes = decrypt_with_ad(&self.recv_key, self.recv_nonce, &[], encrypted_len)?;
        self.recv_nonce += 1;

        // decrypt_with_ad returns exactly 2 bytes (18 - 16 byte MAC)
        Ok(u16::from_be_bytes([len_bytes[0], len_bytes[1]]))
    }

    /// Decrypts the message body after the length has been decrypted.
    ///
    /// # Arguments
    /// - `encrypted_msg` - The encrypted message (length + `MAC_SIZE` bytes)
    ///
    /// # Returns
    /// The decrypted message on success.
    ///
    /// # Errors
    /// Returns `NoiseError::DecryptionFailed` if MAC verification fails.
    pub fn decrypt_message(&mut self, encrypted_msg: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.maybe_rotate_recv_key();

        let plaintext = decrypt_with_ad(&self.recv_key, self.recv_nonce, &[], encrypted_msg)?;
        self.recv_nonce += 1;

        Ok(plaintext)
    }

    /// Rotates the send key if nonce reaches threshold.
    fn maybe_rotate_send_key(&mut self) {
        if self.send_nonce >= KEY_ROTATION_THRESHOLD {
            let (new_ck, new_key) = hkdf_two_keys(&self.send_ck, &self.send_key);
            self.send_ck = new_ck;
            self.send_key = new_key;
            self.send_nonce = 0;
        }
    }

    /// Rotates the receive key if nonce reaches threshold.
    fn maybe_rotate_recv_key(&mut self) {
        if self.recv_nonce >= KEY_ROTATION_THRESHOLD {
            let (new_ck, new_key) = hkdf_two_keys(&self.recv_ck, &self.recv_key);
            self.recv_ck = new_ck;
            self.recv_key = new_key;
            self.recv_nonce = 0;
        }
    }
}

/// Encodes nonce as 96-bit little-endian: 32 zero bits || 64-bit LE value.
fn encode_nonce(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// `encryptWithAD(k, n, ad, plaintext)` from BOLT 8.
///
/// Encrypts plaintext using ChaCha20-Poly1305 with the given key, nonce, and associated data.
pub fn encrypt_with_ad(key: &[u8; 32], nonce: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = encode_nonce(nonce);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("encryption should not fail")
}

/// `decryptWithAD(k, n, ad, ciphertext)` from BOLT 8.
///
/// Decrypts ciphertext using ChaCha20-Poly1305 with the given key, nonce, and associated data.
///
/// # Errors
///
/// Returns `NoiseError::DecryptionFailed` if MAC verification fails.
pub fn decrypt_with_ad(
    key: &[u8; 32],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_bytes = encode_nonce(nonce);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| NoiseError::DecryptionFailed)
}

/// HKDF extract-and-expand to derive two 32-byte keys.
pub fn hkdf_two_keys(salt: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = [0u8; 64];
    hk.expand(&[], &mut output).expect("valid HKDF length");
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    key1.copy_from_slice(&output[..32]);
    key2.copy_from_slice(&output[32..]);
    (key1, key2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_encoding() {
        let nonce = encode_nonce(0);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let nonce = encode_nonce(1);
        assert_eq!(nonce, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);

        let nonce = encode_nonce(256);
        assert_eq!(nonce, [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_hkdf_two_keys() {
        // Test vector from BOLT 8: deriving final keys
        let ck = hex::decode("919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01")
            .unwrap();
        let ikm = [0u8; 0]; // zero-length ikm

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&ck);

        let (key1, key2) = hkdf_two_keys(&salt, &ikm);

        // Expected: sk, rk for initiator
        let expected_key1 =
            hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
                .unwrap();
        let expected_key2 =
            hex::decode("bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442")
                .unwrap();

        assert_eq!(key1[..], expected_key1[..]);
        assert_eq!(key2[..], expected_key2[..]);
    }

    #[test]
    fn test_encrypt_with_ad() {
        // BOLT 8 message encryption test vectors
        // sk=0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9
        let sk = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
            .unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&sk);

        // Test vector 1: encrypt length (0x0005) with nonce 0
        // cleartext=0x0005, AD=NULL, sn=0x000000000000000000000000
        // => 0xcf2b30ddf0cf3f80e7c35a6e6730b59fe802
        let plaintext = hex::decode("0005").unwrap();
        let ciphertext = encrypt_with_ad(&key, 0, &[], &plaintext);
        let expected = hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802").unwrap();
        assert_eq!(ciphertext, expected);

        // Test vector 2: encrypt message "hello" with nonce 1
        // cleartext=0x68656c6c6f, AD=NULL, sn=0x000000000100000000000000
        // => 0x473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95
        let plaintext = hex::decode("68656c6c6f").unwrap(); // "hello"
        let ciphertext = encrypt_with_ad(&key, 1, &[], &plaintext);
        let expected = hex::decode("473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap();
        assert_eq!(ciphertext, expected);

        // Test vector 3: encrypt length (0x0005) with nonce 2
        // cleartext=0x0005, AD=NULL, sn=0x000000000200000000000000
        // => 0x72887022101f0b6753e0c7de21657d35a4cb
        let plaintext = hex::decode("0005").unwrap();
        let ciphertext = encrypt_with_ad(&key, 2, &[], &plaintext);
        let expected = hex::decode("72887022101f0b6753e0c7de21657d35a4cb").unwrap();
        assert_eq!(ciphertext, expected);

        // Test vector 4: encrypt message "hello" with nonce 3
        // cleartext=0x68656c6c6f, AD=NULL, sn=0x000000000300000000000000
        // => 0x2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1
        let plaintext = hex::decode("68656c6c6f").unwrap(); // "hello"
        let ciphertext = encrypt_with_ad(&key, 3, &[], &plaintext);
        let expected = hex::decode("2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_decrypt_with_ad() {
        // BOLT 8 message encryption test vectors (decrypt is inverse of encrypt)
        let sk = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
            .unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&sk);

        // Test vector 1: decrypt length ciphertext with nonce 0
        let ciphertext = hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802").unwrap();
        let plaintext = decrypt_with_ad(&key, 0, &[], &ciphertext).unwrap();
        let expected = hex::decode("0005").unwrap();
        assert_eq!(plaintext, expected);

        // Test vector 2: decrypt "hello" ciphertext with nonce 1
        let ciphertext = hex::decode("473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95").unwrap();
        let plaintext = decrypt_with_ad(&key, 1, &[], &ciphertext).unwrap();
        let expected = hex::decode("68656c6c6f").unwrap(); // "hello"
        assert_eq!(plaintext, expected);

        // Test vector 3: decrypt length ciphertext with nonce 2
        let ciphertext = hex::decode("72887022101f0b6753e0c7de21657d35a4cb").unwrap();
        let plaintext = decrypt_with_ad(&key, 2, &[], &ciphertext).unwrap();
        let expected = hex::decode("0005").unwrap();
        assert_eq!(plaintext, expected);

        // Test vector 4: decrypt "hello" ciphertext with nonce 3
        let ciphertext = hex::decode("2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1").unwrap();
        let plaintext = decrypt_with_ad(&key, 3, &[], &ciphertext).unwrap();
        let expected = hex::decode("68656c6c6f").unwrap(); // "hello"
        assert_eq!(plaintext, expected);
    }

    #[test]
    fn test_decrypt_with_ad_bad_mac() {
        let sk = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
            .unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&sk);

        // Corrupt the ciphertext (flip a bit)
        let mut ciphertext = hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802").unwrap();
        ciphertext[0] ^= 0x01;

        let result = decrypt_with_ad(&key, 0, &[], &ciphertext);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_with_ad_wrong_nonce() {
        let sk = hex::decode("969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9")
            .unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&sk);

        // Encrypted with nonce 0, try to decrypt with nonce 1
        let ciphertext = hex::decode("cf2b30ddf0cf3f80e7c35a6e6730b59fe802").unwrap();
        let result = decrypt_with_ad(&key, 1, &[], &ciphertext);
        assert_eq!(result, Err(NoiseError::DecryptionFailed));
    }
}
