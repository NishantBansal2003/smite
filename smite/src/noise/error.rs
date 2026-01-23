/// Errors that can occur during Noise protocol handshake and message processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoiseError {
    /// Act One: Unrecognized handshake version
    ActOneBadVersion(u8),
    /// Act One: Invalid public key encoding
    ActOneBadPubkey,
    /// Act One: MAC verification failed
    ActOneBadTag,

    /// Act Two: Unrecognized handshake version
    ActTwoBadVersion(u8),
    /// Act Two: Invalid public key encoding
    ActTwoBadPubkey,
    /// Act Two: MAC verification failed
    ActTwoBadTag,

    /// Act Three: Unrecognized handshake version
    ActThreeBadVersion(u8),
    /// Act Three: MAC verification failed on encrypted static key
    ActThreeBadCiphertext,
    /// Act Three: Invalid static public key after decryption
    ActThreeBadPubkey,
    /// Act Three: Final MAC verification failed
    ActThreeBadTag,

    /// Message decryption failed (bad MAC)
    DecryptionFailed,

    /// Handshake not complete - cannot encrypt/decrypt messages yet
    HandshakeIncomplete,

    /// Invalid handshake state for this operation
    InvalidState,
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActOneBadVersion(v) => write!(f, "ACT1_BAD_VERSION {v}"),
            Self::ActOneBadPubkey => write!(f, "ACT1_BAD_PUBKEY"),
            Self::ActOneBadTag => write!(f, "ACT1_BAD_TAG"),
            Self::ActTwoBadVersion(v) => write!(f, "ACT2_BAD_VERSION {v}"),
            Self::ActTwoBadPubkey => write!(f, "ACT2_BAD_PUBKEY"),
            Self::ActTwoBadTag => write!(f, "ACT2_BAD_TAG"),
            Self::ActThreeBadVersion(v) => write!(f, "ACT3_BAD_VERSION {v}"),
            Self::ActThreeBadCiphertext => write!(f, "ACT3_BAD_CIPHERTEXT"),
            Self::ActThreeBadPubkey => write!(f, "ACT3_BAD_PUBKEY"),
            Self::ActThreeBadTag => write!(f, "ACT3_BAD_TAG"),
            Self::DecryptionFailed => write!(f, "DECRYPTION_FAILED"),
            Self::HandshakeIncomplete => write!(f, "HANDSHAKE_INCOMPLETE"),
            Self::InvalidState => write!(f, "INVALID_STATE"),
        }
    }
}

impl std::error::Error for NoiseError {}
