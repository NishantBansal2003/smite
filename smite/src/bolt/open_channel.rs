//! BOLT 2 open channel message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::{ChannelId, write_u16_be};

/// Size of a chain hash (SHA256).
const CHAIN_HASH_SIZE: usize = 32;

/// Minimum wire-encoded size of an `open_channel` message (excluding TLVs).
const OPEN_CHANNEL_WIRE_SIZE: usize = 319;

/// Number of 32-byte secret key slots consumed from fuzz input.
/// Order: funding, revocation, payment, `delayed_payment`, htlc,
/// `first_per_commitment`.
const NUM_KEY_SLOTS: usize = 6;

/// Minimum fuzz input size.
const FUZZ_INPUT_MIN_SIZE: usize = 281;

/// Bitcoin regtest genesis block hash (internal byte order).
const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

/// BOLT 2 `open_channel` message (type 32).
///
/// Sent by the channel initiator to begin the channel establishment flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenChannel {
    /// Genesis block hash of the chain to open the channel on.
    pub chain_hash: [u8; CHAIN_HASH_SIZE],
    /// Temporary channel ID until funding tx is known.
    pub temporary_channel_id: ChannelId,
    /// Amount the opener is placing into the channel (satoshis).
    pub funding_satoshis: u64,
    /// Amount initially pushed to the counterparty (millisatoshis).
    pub push_msat: u64,
    /// Dust limit below which outputs should not be generated (satoshis).
    pub dust_limit_satoshis: u64,
    /// Maximum value of outstanding HTLCs the counterparty can offer (msat).
    pub max_htlc_value_in_flight_msat: u64,
    /// Minimum channel reserve the counterparty must maintain (satoshis).
    pub channel_reserve_satoshis: u64,
    /// Minimum HTLC value the opener will accept (millisatoshis).
    pub htlc_minimum_msat: u64,
    /// Fee rate per kw for commitment transactions.
    pub feerate_per_kw: u32,
    /// Number of blocks the counterparty's to-self outputs must be delayed.
    pub to_self_delay: u16,
    /// Maximum number of outstanding HTLCs the counterparty can offer.
    pub max_accepted_htlcs: u16,
    /// Opener's funding pubkey.
    pub funding_pubkey: secp256k1::PublicKey,
    /// Opener's revocation basepoint.
    pub revocation_basepoint: secp256k1::PublicKey,
    /// Opener's payment basepoint.
    pub payment_basepoint: secp256k1::PublicKey,
    /// Opener's delayed payment basepoint.
    pub delayed_payment_basepoint: secp256k1::PublicKey,
    /// Opener's HTLC basepoint.
    pub htlc_basepoint: secp256k1::PublicKey,
    /// Opener's first per-commitment point.
    pub first_per_commitment_point: secp256k1::PublicKey,
    /// Channel flags (bit 0 = `announce_channel`).
    pub channel_flags: u8,
    /// `open_channel_tlvs` — TLV stream (See BOLT 2).
    pub open_channel_tlvs: TlvStream,
}

/// Private keys corresponding to the public keys in an `OpenChannel`.
pub struct OpenChannelKeys {
    /// Secret key for `funding_pubkey`.
    pub funding_secret: secp256k1::SecretKey,
    /// Secret key for `revocation_basepoint`.
    pub revocation_secret: secp256k1::SecretKey,
    /// Secret key for `payment_basepoint`.
    pub payment_secret: secp256k1::SecretKey,
    /// Secret key for `delayed_payment_basepoint`.
    pub delayed_payment_secret: secp256k1::SecretKey,
    /// Secret key for `htlc_basepoint`.
    pub htlc_secret: secp256k1::SecretKey,
    /// Secret key for `first_per_commitment_point`.
    pub per_commitment_secret: secp256k1::SecretKey,
}

impl OpenChannel {
    /// Creates an `OpenChannel` message from fuzz input.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is too short or contains an invalid secret key.
    pub fn from_fuzz_input(input: &[u8]) -> Result<(Self, OpenChannelKeys), String> {
        if input.len() < FUZZ_INPUT_MIN_SIZE {
            return Err(format!(
                "fuzz input too short: need {FUZZ_INPUT_MIN_SIZE} bytes, got {}",
                input.len()
            ));
        }

        // Open Channel Keys
        let secp = secp256k1::Secp256k1::new();
        let mut cursor = input;
        let mut sks = Vec::with_capacity(NUM_KEY_SLOTS);
        let mut pks = Vec::with_capacity(NUM_KEY_SLOTS);
        for i in 0..NUM_KEY_SLOTS {
            let chunk = consume_bytes!(&mut cursor, 32);
            let sk = secp256k1::SecretKey::from_byte_array(chunk)
                .map_err(|e| format!("invalid secret key at slot {i}: {e}"))?;
            sks.push(sk);
            pks.push(secp256k1::PublicKey::from_secret_key(&secp, &sk));
        }

        // Open Channel fields
        let funding_satoshis = consume!(&mut cursor, u64);
        let feerate_per_kw = consume!(&mut cursor, u32);
        let to_self_delay = consume!(&mut cursor, u16);
        let push_msat = consume!(&mut cursor, u64);
        let dust_limit_satoshis = consume!(&mut cursor, u64);
        let max_htlc_value_in_flight_msat = consume!(&mut cursor, u64);
        let channel_reserve_satoshis = consume!(&mut cursor, u64);
        let htlc_minimum_msat = consume!(&mut cursor, u64);
        let max_accepted_htlcs = consume!(&mut cursor, u16);
        let temp_id = consume_bytes!(&mut cursor, 32);
        let channel_flags = consume!(&mut cursor, u8);

        // Hardcoded open_channel_tlvs for the channel type used during fuzzing:
        //   type 0 (upfront_shutdown_script): empty - no shutdown script
        //   type 1 (channel_type): bit 12 = option_static_remotekey
        let mut open_channel_tlvs = TlvStream::new();
        open_channel_tlvs.add(0, vec![]);
        open_channel_tlvs.add(1, vec![0x10, 0x00]);

        let msg = Self {
            chain_hash: REGTEST_CHAIN_HASH,
            temporary_channel_id: ChannelId::new(temp_id),
            funding_satoshis,
            push_msat,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            feerate_per_kw,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey: pks[0],
            revocation_basepoint: pks[1],
            payment_basepoint: pks[2],
            delayed_payment_basepoint: pks[3],
            htlc_basepoint: pks[4],
            first_per_commitment_point: pks[5],
            channel_flags,
            open_channel_tlvs,
        };

        let keys = OpenChannelKeys {
            funding_secret: sks[0],
            revocation_secret: sks[1],
            payment_secret: sks[2],
            delayed_payment_secret: sks[3],
            htlc_secret: sks[4],
            per_commitment_secret: sks[5],
        };

        Ok((msg, keys))
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OPEN_CHANNEL_WIRE_SIZE);
        out.extend_from_slice(&self.chain_hash);
        self.temporary_channel_id.encode(&mut out);
        out.extend_from_slice(&self.funding_satoshis.to_be_bytes());
        out.extend_from_slice(&self.push_msat.to_be_bytes());
        out.extend_from_slice(&self.dust_limit_satoshis.to_be_bytes());
        out.extend_from_slice(&self.max_htlc_value_in_flight_msat.to_be_bytes());
        out.extend_from_slice(&self.channel_reserve_satoshis.to_be_bytes());
        out.extend_from_slice(&self.htlc_minimum_msat.to_be_bytes());
        out.extend_from_slice(&self.feerate_per_kw.to_be_bytes());
        write_u16_be(self.to_self_delay, &mut out);
        write_u16_be(self.max_accepted_htlcs, &mut out);
        out.extend_from_slice(&self.funding_pubkey.serialize());
        out.extend_from_slice(&self.revocation_basepoint.serialize());
        out.extend_from_slice(&self.payment_basepoint.serialize());
        out.extend_from_slice(&self.delayed_payment_basepoint.serialize());
        out.extend_from_slice(&self.htlc_basepoint.serialize());
        out.extend_from_slice(&self.first_per_commitment_point.serialize());
        out.push(self.channel_flags);
        out.extend_from_slice(&self.open_channel_tlvs.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns Truncated if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        if payload.len() < OPEN_CHANNEL_WIRE_SIZE {
            return Err(BoltError::Truncated {
                expected: OPEN_CHANNEL_WIRE_SIZE,
                actual: payload.len(),
            });
        }
        let mut cursor = payload;

        let chain_hash = consume_bytes!(&mut cursor, CHAIN_HASH_SIZE);
        let temporary_channel_id = ChannelId::decode(&mut cursor)?;
        let funding_satoshis = consume!(&mut cursor, u64);
        let push_msat = consume!(&mut cursor, u64);
        let dust_limit_satoshis = consume!(&mut cursor, u64);
        let max_htlc_value_in_flight_msat = consume!(&mut cursor, u64);
        let channel_reserve_satoshis = consume!(&mut cursor, u64);
        let htlc_minimum_msat = consume!(&mut cursor, u64);
        let feerate_per_kw = consume!(&mut cursor, u32);
        let to_self_delay = consume!(&mut cursor, u16);
        let max_accepted_htlcs = consume!(&mut cursor, u16);
        let funding_pubkey = consume_pubkey!(&mut cursor)?;
        let revocation_basepoint = consume_pubkey!(&mut cursor)?;
        let payment_basepoint = consume_pubkey!(&mut cursor)?;
        let delayed_payment_basepoint = consume_pubkey!(&mut cursor)?;
        let htlc_basepoint = consume_pubkey!(&mut cursor)?;
        let first_per_commitment_point = consume_pubkey!(&mut cursor)?;
        let channel_flags = consume!(&mut cursor, u8);
        let open_channel_tlvs = TlvStream::decode_with_known(cursor, &[0])?;

        Ok(Self {
            chain_hash,
            temporary_channel_id,
            funding_satoshis,
            push_msat,
            dust_limit_satoshis,
            max_htlc_value_in_flight_msat,
            channel_reserve_satoshis,
            htlc_minimum_msat,
            feerate_per_kw,
            to_self_delay,
            max_accepted_htlcs,
            funding_pubkey,
            revocation_basepoint,
            payment_basepoint,
            delayed_payment_basepoint,
            htlc_basepoint,
            first_per_commitment_point,
            channel_flags,
            open_channel_tlvs,
        })
    }
}
