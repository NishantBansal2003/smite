//! BOLT 2 funding created message.

use secp256k1::{PublicKey, SecretKey};

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use crate::commitment::{CommitmentParams, build_commitment_sighash, sign_commitment};

/// Size of a transaction ID (`SHA256d`, 32 bytes).
const TXID_SIZE: usize = 32;

/// Size of a signature (64 bytes, compact encoding per BOLT).
const SIGNATURE_SIZE: usize = 64;

/// Minimum wire-encoded size of a `funding_created` message (excluding TLVs).
const FUNDING_CREATED_WIRE_SIZE: usize = 130;

/// BOLT 2 `funding_created` message (type 34).
///
/// Sent by the opener after creating the funding transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingCreated {
    /// Temporary channel ID (must match `open_channel`).
    pub temporary_channel_id: ChannelId,
    /// Txid of the funding transaction.
    pub funding_txid: [u8; TXID_SIZE],
    /// Output index within the funding transaction.
    pub funding_output_index: u16,
    /// Signature for the acceptor's initial commitment transaction.
    pub signature: [u8; SIGNATURE_SIZE],
    /// `funding_created_tlvs` — TLV stream (See BOLT 2).
    pub funding_created_tlvs: TlvStream,
}

/// Parameters from the `open_channel` / `accept_channel` exchange that are
/// needed to compute the correct commitment signature.
pub struct FundingCreatedParams {
    /// Temporary channel ID.
    pub temporary_channel_id: ChannelId,
    /// Opener's funding private key (used to sign the commitment tx;
    /// the public key is derived from this).
    pub opener_funding_privkey: SecretKey,
    /// Fee rate per kw for commitment transactions.
    pub feerate_per_kw: u32,
    /// Total channel funding amount (satoshis).
    pub funding_satoshis: u64,
    /// Amount initially pushed to the acceptor (millisatoshis).
    pub push_msat: u64,
    /// Opener's revocation basepoint.
    pub opener_revocation_basepoint: PublicKey,
    /// Opener's payment basepoint.
    pub opener_payment_basepoint: PublicKey,
    /// Opener's `to_self_delay` (applied to acceptor's outputs).
    pub opener_to_self_delay: u16,
    /// Acceptor's funding public key.
    pub acceptor_funding_pubkey: PublicKey,
    /// Acceptor's first per-commitment point.
    pub acceptor_per_commitment_point: PublicKey,
    /// Acceptor's payment basepoint.
    pub acceptor_payment_basepoint: PublicKey,
    /// Acceptor's delayed payment basepoint.
    pub acceptor_delayed_payment_basepoint: PublicKey,
    /// Acceptor's dust limit in satoshis.
    pub acceptor_dust_limit_satoshis: u64,
}

impl FundingCreated {
    /// Creates a `FundingCreated` from fuzz input.
    ///
    /// The `fuzz_input` supplies the funding txid (32 bytes) and output
    /// index (2 bytes).  The commitment signature is computed from the
    /// actual channel parameters exchanged in `open_channel` / `accept_channel`.
    #[must_use]
    pub fn from_fuzz_input(params: &FundingCreatedParams, fuzz_input: &[u8]) -> Self {
        let needed = TXID_SIZE + 2; // 34 bytes
        let mut buf = vec![0u8; needed.max(fuzz_input.len())];
        let copy_len = fuzz_input.len().min(needed);
        buf[..copy_len].copy_from_slice(&fuzz_input[..copy_len]);
        let mut cursor: &[u8] = &buf;

        let funding_txid = consume_bytes!(&mut cursor, TXID_SIZE);
        let funding_output_index = consume!(&mut cursor, u16);

        Self::with_outpoint(params, funding_txid, funding_output_index)
    }

    /// Creates a `FundingCreated` with an explicit funding outpoint.
    #[must_use]
    pub fn with_outpoint(
        params: &FundingCreatedParams,
        funding_txid: [u8; 32],
        funding_output_index: u16,
    ) -> Self {
        Self::build(params, funding_txid, funding_output_index)
    }

    /// Builds the commitment signature and assembles the message.
    fn build(
        params: &FundingCreatedParams,
        funding_txid: [u8; 32],
        funding_output_index: u16,
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();
        let opener_funding_pubkey =
            PublicKey::from_secret_key(&secp, &params.opener_funding_privkey);

        let commitment_params = CommitmentParams {
            funding_txid,
            funding_output_index,
            acceptor_per_commitment_point: params.acceptor_per_commitment_point,
            feerate_per_kw: params.feerate_per_kw,
            funding_satoshis: params.funding_satoshis,
            push_msat: params.push_msat,
            opener_funding_pubkey,
            acceptor_funding_pubkey: params.acceptor_funding_pubkey,
            opener_payment_basepoint: params.opener_payment_basepoint,
            acceptor_payment_basepoint: params.acceptor_payment_basepoint,
            opener_revocation_basepoint: params.opener_revocation_basepoint,
            acceptor_delayed_payment_basepoint: params.acceptor_delayed_payment_basepoint,
            opener_to_self_delay: params.opener_to_self_delay,
            acceptor_dust_limit_satoshis: params.acceptor_dust_limit_satoshis,
        };

        let sighash = build_commitment_sighash(&commitment_params);
        let signature = sign_commitment(&sighash, &params.opener_funding_privkey);

        Self {
            temporary_channel_id: params.temporary_channel_id,
            funding_txid,
            funding_output_index,
            signature,
            funding_created_tlvs: TlvStream::new(),
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FUNDING_CREATED_WIRE_SIZE);
        self.temporary_channel_id.encode(&mut out);
        out.extend_from_slice(&self.funding_txid);
        out.extend_from_slice(&self.funding_output_index.to_be_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.funding_created_tlvs.encode());
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns Truncated if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        if payload.len() < FUNDING_CREATED_WIRE_SIZE {
            return Err(BoltError::Truncated {
                expected: FUNDING_CREATED_WIRE_SIZE,
                actual: payload.len(),
            });
        }
        let mut cursor = payload;

        let temporary_channel_id = ChannelId::decode(&mut cursor)?;
        let funding_txid = consume_bytes!(&mut cursor, TXID_SIZE);
        let funding_output_index = consume!(&mut cursor, u16);
        let signature = consume_bytes!(&mut cursor, SIGNATURE_SIZE);
        let funding_created_tlvs = TlvStream::decode(cursor)?;

        Ok(Self {
            temporary_channel_id,
            funding_txid,
            funding_output_index,
            signature,
            funding_created_tlvs,
        })
    }
}
