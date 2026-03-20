//! Shared macros for decoding BOLT messages.

/// Reads exactly `N` bytes from `cursor`, advancing it past those bytes.
/// Returns zeroes for any bytes beyond the end of the slice.
macro_rules! consume_bytes {
    ($cursor:expr, $N:expr) => {{
        let mut out = [0u8; $N];
        let len = $N.min($cursor.len());
        out[..len].copy_from_slice(&$cursor[..len]);
        *$cursor = &$cursor[len..];
        out
    }};
}

/// Reads `size_of::<T>()` bytes from `cursor` and decodes them as a
/// big-endian integer, advancing the cursor.
macro_rules! consume {
    ($cursor:expr, $T:ty) => {{
        const N: usize = std::mem::size_of::<$T>();
        <$T>::from_be_bytes(consume_bytes!($cursor, N))
    }};
}

/// Reads a 33-byte compressed secp256k1 public key from `cursor`,
/// advancing it past the key bytes.
macro_rules! consume_pubkey {
    ($cursor:expr) => {{
        const PUBKEY_SIZE: usize = 33;
        let bytes = consume_bytes!($cursor, PUBKEY_SIZE);
        secp256k1::PublicKey::from_slice(&bytes).map_err(|_| BoltError::Truncated {
            expected: PUBKEY_SIZE,
            actual: 0,
        })
    }};
}
