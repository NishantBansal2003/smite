//! BOLT 3 commitment transaction construction and signing.
//!
//! Builds the acceptor's initial commitment transaction and produces the
//! sighash that the opener signs in `funding_created`.

use bitcoin::WPubkeyHash;
use bitcoin::hashes::{Hash, HashEngine, hash160, sha256::Hash as Sha256};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use secp256k1::{Message as SecpMessage, PublicKey, Scalar, Secp256k1, SecretKey};

/// Parameters needed to build and sign the acceptor's initial commitment
/// transaction (commitment number 0).
pub struct CommitmentParams {
    /// Funding transaction ID (internal byte order).
    pub funding_txid: [u8; 32],
    /// Output index of the funding output within the funding transaction.
    pub funding_output_index: u16,
    /// Fee rate for the commitment transaction (satoshis per kilo-weight).
    pub feerate_per_kw: u32,
    /// Total channel funding amount in satoshis (`funding_satoshis` from `open_channel`).
    pub funding_satoshis: u64,
    /// Amount pushed to the acceptor at channel open in millisatoshis
    /// (`push_msat` from `open_channel`).
    pub push_msat: u64,
    /// Acceptor's `first_per_commitment_point` from `accept_channel`.
    pub acceptor_per_commitment_point: PublicKey,
    /// Opener's `funding_pubkey` from `open_channel`.
    pub opener_funding_pubkey: PublicKey,
    /// Acceptor's `funding_pubkey` from `accept_channel`.
    pub acceptor_funding_pubkey: PublicKey,
    /// Opener's `payment_basepoint` from `open_channel`.
    pub opener_payment_basepoint: PublicKey,
    /// Acceptor's `payment_basepoint` from `accept_channel`.
    pub acceptor_payment_basepoint: PublicKey,
    /// Opener's `revocation_basepoint` from `open_channel`.
    pub opener_revocation_basepoint: PublicKey,
    /// Acceptor's `delayed_payment_basepoint` from `accept_channel`.
    pub acceptor_delayed_payment_basepoint: PublicKey,
    /// Opener's `to_self_delay` from `open_channel` (applied to the
    /// acceptor's outputs on the acceptor's commitment transaction).
    pub opener_to_self_delay: u16,
    /// Acceptor's `dust_limit_satoshis` from `accept_channel`.
    pub acceptor_dust_limit_satoshis: u64,
}

/// Builds the sighash for the acceptor's initial commitment transaction
/// (commitment number 0).
///
/// Per BOLT 3, the commitment transaction spends the 2-of-2 funding output
/// and contains a `to_local` (CSV-encumbered, payable to the acceptor after
/// `to_self_delay`) and a `to_remote` (P2WPKH, immediately spendable by the
/// opener).  The opener pays the commitment fee from their balance.
///
/// Returns the 32-byte sighash digest that the opener must sign with their
/// funding private key to produce the `signature` in `funding_created`.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn build_commitment_sighash(params: &CommitmentParams) -> [u8; 32] {
    let commitment_number: u64 = 0;

    // BOLT 3: the 48-bit commitment number is obscured by XOR with the
    // lower 48 bits of SHA256(opener's payment_basepoint || acceptor's
    // payment_basepoint).
    let obscuring_factor = compute_obscuring_factor(
        &params.opener_payment_basepoint,
        &params.acceptor_payment_basepoint,
    );
    let obscured = commitment_number ^ obscuring_factor;

    // BOLT 3: upper 8 bits of sequence are 0x80; lower 24 bits are the
    // upper 24 bits of the obscured commitment number.
    #[allow(clippy::cast_possible_truncation)]
    let sequence = 0x8000_0000_u32 | ((obscured >> 24) as u32 & 0x00FF_FFFF);

    // BOLT 3: upper 8 bits of locktime are 0x20; lower 24 bits are the
    // lower 24 bits of the obscured commitment number.
    #[allow(clippy::cast_possible_truncation)]
    let locktime = 0x2000_0000_u32 | (obscured as u32 & 0x00FF_FFFF);

    // BOLT 3: funding output is P2WSH of `2 <pubkey1> <pubkey2> 2
    // OP_CHECKMULTISIG` where pubkeys are sorted lexicographically.
    let funding_redeemscript = make_funding_redeemscript(
        &params.opener_funding_pubkey,
        &params.acceptor_funding_pubkey,
    );

    let per_commitment_point = &params.acceptor_per_commitment_point;

    // BOLT 3 `to_remote` output: simple P2WPKH to the opener's
    // `payment_basepoint` (the `remotepubkey` from the acceptor's
    // perspective is just the opener's `payment_basepoint`).
    let to_remote_spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(
        hash160::Hash::hash(&params.opener_payment_basepoint.serialize()).to_byte_array(),
    ));

    // BOLT 3 key derivation:
    //   local_delayedpubkey = acceptor's delayed_payment_basepoint
    //                         + SHA256(per_commitment_point || basepoint) * G
    let local_delayedpubkey = derive_pubkey(
        &params.acceptor_delayed_payment_basepoint,
        per_commitment_point,
    );
    //   revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint ||
    //     per_commitment_point) + per_commitment_point * SHA256(per_commitment_point
    //     || revocation_basepoint)
    let revocationpubkey =
        derive_revocation_pubkey(&params.opener_revocation_basepoint, per_commitment_point);

    // BOLT 3 `to_local` output: P2WSH of the CSV-encumbered script:
    //   OP_IF <revocationpubkey> OP_ELSE <to_self_delay> OP_CSV OP_DROP
    //   <local_delayedpubkey> OP_ENDIF OP_CHECKSIG
    let to_local_redeem = build_to_local_script(
        &local_delayedpubkey,
        &revocationpubkey,
        params.opener_to_self_delay,
    );

    let to_local_spk = ScriptBuf::new_p2wsh(&to_local_redeem.wscript_hash());

    // BOLT 3: base commitment transaction weight = 724 (non-anchor, no HTLCs).
    // Fee = feerate_per_kw * weight / 1000.
    let commitment_weight: u32 = 724;
    let fee = params.feerate_per_kw.saturating_mul(commitment_weight) / 1000;

    // This is the *acceptor's* commitment transaction.  `push_msat` flows
    // from the opener to the acceptor at open:
    //   to_local  (acceptor, delayed) = push_msat / 1000
    //   to_remote (opener, P2WPKH)    = funding_satoshis - push_sat - fee
    // The opener (funder) pays the base commitment fee.
    let push_sat = params.push_msat / 1000;
    let to_local_value = push_sat;
    let to_remote_value = params
        .funding_satoshis
        .saturating_sub(push_sat)
        .saturating_sub(u64::from(fee));

    // BOLT 3: outputs below `dust_limit_satoshis` MUST NOT be produced.
    let mut outputs: Vec<TxOut> = Vec::new();

    if to_local_value >= params.acceptor_dust_limit_satoshis {
        outputs.push(TxOut {
            value: Amount::from_sat(to_local_value),
            script_pubkey: to_local_spk,
        });
    }
    if to_remote_value >= params.acceptor_dust_limit_satoshis {
        outputs.push(TxOut {
            value: Amount::from_sat(to_remote_value),
            script_pubkey: to_remote_spk,
        });
    }

    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array(params.funding_txid),
            vout: u32::from(params.funding_output_index),
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(sequence),
        witness: Witness::new(),
    };

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::from_consensus(locktime),
        input: vec![input],
        output: outputs,
    };

    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            &funding_redeemscript,
            Amount::from_sat(params.funding_satoshis),
            EcdsaSighashType::All,
        )
        .unwrap();

    sighash.to_byte_array()
}

/// Signs a commitment sighash with the opener's funding private key.
///
/// Returns the 64-byte compact ECDSA signature (without the sighash byte,
/// per BOLT spec: "clients MUST send the signature in compact encoding").
#[must_use]
pub fn sign_commitment(sighash: &[u8; 32], opener_funding_privkey: &SecretKey) -> [u8; 64] {
    let secp = Secp256k1::new();
    let msg = SecpMessage::from_digest(*sighash);
    let sig = secp.sign_ecdsa(msg, opener_funding_privkey);
    sig.serialize_compact()
}

/// Builds the funding output redeem script per BOLT 3:
///
///   `2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG`
///
/// where `pubkey1` is the lexicographically lesser of the two
/// `funding_pubkey`s in compressed format.
#[must_use]
pub fn make_funding_redeemscript(pk1: &PublicKey, pk2: &PublicKey) -> ScriptBuf {
    let b1 = pk1.serialize();
    let b2 = pk2.serialize();
    let (first, second) = if b1 < b2 { (&b1, &b2) } else { (&b2, &b1) };
    Builder::new()
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_slice(first)
        .push_slice(second)
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

/// Builds the `to_local` witness script per BOLT 3:
///
/// ```text
///   OP_IF
///     <revocationpubkey>
///   OP_ELSE
///     `to_self_delay` OP_CHECKSEQUENCEVERIFY OP_DROP
///     <local_delayedpubkey>
///   OP_ENDIF
///   OP_CHECKSIG
/// ```
fn build_to_local_script(
    local_delayedpubkey: &PublicKey,
    revocationpubkey: &PublicKey,
    to_self_delay: u16,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_IF)
        .push_slice(revocationpubkey.serialize())
        .push_opcode(opcodes::OP_ELSE)
        .push_int(i64::from(to_self_delay))
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_DROP)
        .push_slice(local_delayedpubkey.serialize())
        .push_opcode(opcodes::OP_ENDIF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

/// Computes the commitment number obscuring factor per BOLT 3.
///
/// The lower 48 bits of `SHA256(opener's payment_basepoint || acceptor's
/// payment_basepoint)` are used to XOR the 48-bit commitment number,
/// hiding it from chain observers.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let mut sha = Sha256::engine();

    sha.input(&opener_payment_basepoint.serialize());
    sha.input(&acceptor_payment_basepoint.serialize());
    let res = Sha256::from_engine(sha).to_byte_array();

    (u64::from(res[26]) << (5 * 8))
        | (u64::from(res[27]) << (4 * 8))
        | (u64::from(res[28]) << (3 * 8))
        | (u64::from(res[29]) << (2 * 8))
        | (u64::from(res[30]) << 8)
        | u64::from(res[31])
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3:
///
///   `pubkey = basepoint + SHA256(per_commitment_point || basepoint) * G`
///
/// Used for `localpubkey`, `local_htlcpubkey`, `remote_htlcpubkey`,
/// `local_delayedpubkey`, and `remote_delayedpubkey`.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let mut sha = Sha256::engine();
    sha.input(&per_commitment_point.serialize());
    sha.input(&basepoint.serialize());
    let tweak = Sha256::from_engine(sha).to_byte_array();

    basepoint
        .add_exp_tweak(&secp, &Scalar::from_be_bytes(tweak).unwrap())
        .unwrap()
}

/// Derives the `revocationpubkey` per BOLT 3:
///
///   `revocationpubkey = revocation_basepoint * SHA256(revocation_basepoint ||
///     per_commitment_point) + per_commitment_point *
///     SHA256(per_commitment_point || revocation_basepoint)`
///
/// This blinded construction ensures neither side can compute the revocation
/// private key without the other's secret.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let mut sha1 = Sha256::engine();
    sha1.input(&revocation_basepoint.serialize());
    sha1.input(&per_commitment_point.serialize());
    let tweak1 = Sha256::from_engine(sha1).to_byte_array();

    let mut sha2 = Sha256::engine();
    sha2.input(&per_commitment_point.serialize());
    sha2.input(&revocation_basepoint.serialize());
    let tweak2 = Sha256::from_engine(sha2).to_byte_array();

    let term1 = revocation_basepoint
        .mul_tweak(&secp, &Scalar::from_be_bytes(tweak1).unwrap())
        .unwrap();

    let term2 = per_commitment_point
        .mul_tweak(&secp, &Scalar::from_be_bytes(tweak2).unwrap())
        .unwrap();

    term1.combine(&term2).unwrap()
}
