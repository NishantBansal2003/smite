//! BOLT 3 initial commitment transaction construction and signing.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Base weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_WEIGHT_NON_ANCHOR: u64 = 724;

/// Base weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_WEIGHT_ANCHOR: u64 = 1124;

/// `option_anchors` feature bits (BOLT 9, bits 22/23).
const OPTION_ANCHORS_EVEN_BIT: usize = 22;
const OPTION_ANCHORS_ODD_BIT: usize = 23;

/// Parameters for building the initial commitment transaction.
pub struct CommitmentParams {
    /// Funding transaction ID.
    pub funding_txid: Txid,
    /// Output index of the funding output within the funding transaction.
    pub funding_output_index: u16,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Total channel funding amount in satoshis.
    pub funding_satoshis: u64,
    /// Amount pushed to the acceptor in millisatoshis.
    pub push_msat: u64,
    /// Opener's funding pubkey.
    pub opener_funding_pubkey: PublicKey,
    /// Acceptor's funding pubkey.
    pub acceptor_funding_pubkey: PublicKey,
    /// Opener's payment basepoint.
    pub opener_payment_basepoint: PublicKey,
    /// Acceptor's payment basepoint.
    pub acceptor_payment_basepoint: PublicKey,
    /// Opener's revocation basepoint.
    pub opener_revocation_basepoint: PublicKey,
    /// Acceptor's delayed payment basepoint.
    pub acceptor_delayed_payment_basepoint: PublicKey,
    /// Acceptor's first per-commitment point.
    pub acceptor_per_commitment_point: PublicKey,
    /// Opener's `to_self_delay`.
    pub opener_to_self_delay: u16,
    /// Acceptor's `dust_limit_satoshis`.
    pub acceptor_dust_limit_satoshis: u64,
    /// Channel type feature bits. The commitment format (anchor / legacy) is
    /// derived from the bits set here.
    pub channel_type: Vec<u8>,
}

/// Builds the sighash for the acceptor's initial commitment transaction.
///
/// The commitment format (legacy or anchor) is determined by the `channel_type`.
#[must_use]
#[allow(clippy::missing_panics_doc, clippy::cast_possible_truncation)]
pub fn build_commitment_sighash(params: &CommitmentParams) -> [u8; 32] {
    let commitment_number: u64 = 0;

    // Obscured commitment number.
    let obscuring_factor = compute_obscuring_factor(
        &params.opener_payment_basepoint,
        &params.acceptor_payment_basepoint,
    );
    let obscured_commitment_number = commitment_number ^ obscuring_factor;

    // Upper 8 bits of sequence are 0x80 and lower 24 bits are the upper 24 bits
    // of the obscured commitment number.
    let sequence = (0x80u32 << (8 * 3)) | ((obscured_commitment_number >> 24) as u32);

    // Upper 8 bits of locktime are 0x20 and lower 24 bits are the lower 24 bits
    // of the obscured commitment number.
    let locktime = (0x20u32 << (8 * 3)) | ((obscured_commitment_number & 0x00ff_ffff_u64) as u32);

    // Build the commitment transaction
    let outputs = build_commitment_outputs(params);

    let input = TxIn {
        previous_output: OutPoint {
            txid: params.funding_txid,
            vout: u32::from(params.funding_output_index),
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_consensus(sequence),
        witness: Witness::new(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(locktime),
        input: vec![input],
        output: outputs,
    };

    // Funding output redeem script.
    let funding_redeemscript = make_funding_redeemscript(
        &params.opener_funding_pubkey,
        &params.acceptor_funding_pubkey,
    );

    // Compute the BIP143 sighash
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

/// Computes the commitment number obscuring factor per BOLT 3.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let mut sha = sha256::Hash::engine();

    sha.input(&opener_payment_basepoint.serialize());
    sha.input(&acceptor_payment_basepoint.serialize());
    let hash = sha256::Hash::from_engine(sha).to_byte_array();

    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&hash[26..32]);
    u64::from_be_bytes(buf)
}

/// Builds the lexicographically sorted commitment outputs.
fn build_commitment_outputs(params: &CommitmentParams) -> Vec<TxOut> {
    let anchor = supports_option_anchors(&params.channel_type);

    // Fee and balances.
    let commitment_weight = if anchor {
        COMMITMENT_WEIGHT_ANCHOR
    } else {
        COMMITMENT_WEIGHT_NON_ANCHOR
    };
    let fee = u64::from(params.feerate_per_kw) * commitment_weight / 1000;

    // Acceptor's commitment: push_msat is the acceptor's balance.
    let push_sat = params.push_msat / 1000;
    let to_local_value = push_sat;
    let anchor_cost = if anchor { 2 * ANCHOR_OUTPUT_VALUE } else { 0 };
    let to_remote_value = params
        .funding_satoshis
        .saturating_sub(push_sat)
        .saturating_sub(fee)
        .saturating_sub(anchor_cost);

    // Outputs below `dust_limit_satoshis` MUST NOT be produced.
    let mut outputs: Vec<TxOut> = Vec::new();

    if to_local_value >= params.acceptor_dust_limit_satoshis {
        let local_delayedpubkey = derive_pubkey(
            &params.acceptor_delayed_payment_basepoint,
            &params.acceptor_per_commitment_point,
        );
        let revocationpubkey = derive_revocation_pubkey(
            &params.opener_revocation_basepoint,
            &params.acceptor_per_commitment_point,
        );

        let to_local_spk = build_to_local_redeemscript(
            &local_delayedpubkey,
            &revocationpubkey,
            params.opener_to_self_delay,
        );

        outputs.push(TxOut {
            value: Amount::from_sat(to_local_value),
            script_pubkey: to_local_spk,
        });

        if anchor {
            outputs.push(TxOut {
                value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                script_pubkey: build_anchor_redeemscript(&params.acceptor_funding_pubkey),
            });
        }
    }
    if to_remote_value >= params.acceptor_dust_limit_satoshis {
        let to_remote_spk = if anchor {
            build_to_remote_anchor_redeemscript(&params.opener_payment_basepoint)
        } else {
            ScriptBuf::new_p2wpkh(
                &CompressedPublicKey(params.opener_payment_basepoint).wpubkey_hash(),
            )
        };

        outputs.push(TxOut {
            value: Amount::from_sat(to_remote_value),
            script_pubkey: to_remote_spk,
        });

        if anchor {
            outputs.push(TxOut {
                value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                script_pubkey: build_anchor_redeemscript(&params.opener_funding_pubkey),
            });
        }
    }

    // BOLT 3 output ordering: sort by (value, script_pubkey).
    outputs.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then_with(|| a.script_pubkey.as_bytes().cmp(b.script_pubkey.as_bytes()))
    });

    outputs
}

/// Checks whether `option_anchors` (BOLT 9, bits 22/23) is set.
///
/// Per BOLT 9, even bit (22) = required, odd bit (23) = optional.
/// Either bit indicates anchor support.
fn supports_option_anchors(channel_type: &[u8]) -> bool {
    let byte_offset = OPTION_ANCHORS_EVEN_BIT / 8;
    let required_mask = 1 << (OPTION_ANCHORS_EVEN_BIT - 8 * byte_offset);
    let optional_mask = 1 << (OPTION_ANCHORS_ODD_BIT - 8 * byte_offset);
    channel_type
        .get(byte_offset)
        .is_some_and(|&b| b & (required_mask | optional_mask) != 0)
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let mut sha = sha256::Hash::engine();

    sha.input(&per_commitment_point.serialize());
    sha.input(&basepoint.serialize());
    let tweak = sha256::Hash::from_engine(sha).to_byte_array();
    let hashkey = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&tweak).unwrap());

    basepoint.combine(&hashkey).unwrap()
}

/// Derives the `revocationpubkey` per BOLT 3.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let rev_append_commit_hash_key = {
        let mut sha = sha256::Hash::engine();
        sha.input(&revocation_basepoint.serialize());
        sha.input(&per_commitment_point.serialize());

        sha256::Hash::from_engine(sha).to_byte_array()
    };

    let commit_append_rev_hash_key = {
        let mut sha = sha256::Hash::engine();
        sha.input(&per_commitment_point.serialize());
        sha.input(&revocation_basepoint.serialize());

        sha256::Hash::from_engine(sha).to_byte_array()
    };

    let revocation_contrib = revocation_basepoint
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(rev_append_commit_hash_key).unwrap(),
        )
        .unwrap();

    let commitment_contrib = per_commitment_point
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(commit_append_rev_hash_key).unwrap(),
        )
        .unwrap();

    revocation_contrib.combine(&commitment_contrib).unwrap()
}

/// Builds the `to_local` P2WSH `script_pubkey` per BOLT 3.
fn build_to_local_redeemscript(
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
        .to_p2wsh()
}

/// Builds the anchor `to_remote` P2WSH `script_pubkey` per BOLT 3.
fn build_to_remote_anchor_redeemscript(remote_pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(remote_pubkey.serialize())
        .push_opcode(opcodes::OP_CHECKSIGVERIFY)
        .push_opcode(opcodes::OP_PUSHNUM_1)
        .push_opcode(opcodes::OP_CSV)
        .into_script()
        .to_p2wsh()
}

/// Builds the anchor output P2WSH `script_pubkey` per BOLT 3.
fn build_anchor_redeemscript(funding_pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_slice(funding_pubkey.serialize())
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_IFDUP)
        .push_opcode(opcodes::OP_NOTIF)
        .push_opcode(opcodes::OP_PUSHNUM_16)
        .push_opcode(opcodes::OP_CSV)
        .push_opcode(opcodes::OP_ENDIF)
        .into_script()
        .to_p2wsh()
}

/// Builds the funding output redeem script per BOLT 3.
#[must_use]
fn make_funding_redeemscript(pubkey1: &PublicKey, pubkey2: &PublicKey) -> ScriptBuf {
    let key1_bytes = pubkey1.serialize();
    let key2_bytes = pubkey2.serialize();
    let (lesser, greater) = if key1_bytes < key2_bytes {
        (&key1_bytes, &key2_bytes)
    } else {
        (&key2_bytes, &key1_bytes)
    };
    Builder::new()
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_slice(lesser)
        .push_slice(greater)
        .push_opcode(opcodes::OP_PUSHNUM_2)
        .push_opcode(opcodes::OP_CHECKMULTISIG)
        .into_script()
}

/// Signs a commitment sighash with the opener's funding private key.
#[must_use]
pub fn sign_commitment(sighash: &[u8; 32], opener_funding_privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa_low_r(&msg, opener_funding_privkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(hex_str: &str) -> PublicKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        PublicKey::from_slice(&bytes).expect("valid pubkey")
    }

    fn secret(hex_str: &str) -> SecretKey {
        let bytes = hex::decode(hex_str).expect("valid hex");
        SecretKey::from_slice(&bytes).expect("valid secret key")
    }

    /// BOLT 3 Appendix C opener (local) funding private key.
    const OPENER_FUNDING_PRIVKEY: &str =
        "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749";

    #[test]
    fn obscuring_factor() {
        let opener_payment_basepoint =
            pubkey("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        let acceptor_payment_basepoint =
            pubkey("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
        let factor =
            compute_obscuring_factor(&opener_payment_basepoint, &acceptor_payment_basepoint);
        assert_eq!(factor, 0x2bb0_3852_1914);
    }

    #[test]
    fn supports_option_anchors_detection() {
        // Required (bit 22), optional (bit 23).
        assert!(supports_option_anchors(&[0x00, 0x00, 0x40]));
        assert!(supports_option_anchors(&[0x00, 0x00, 0x80]));
        // No support.
        assert!(!supports_option_anchors(&[]));
        assert!(!supports_option_anchors(&[0xff, 0xff]));
        assert!(!supports_option_anchors(&[0x00, 0x10]));
    }

    // BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors

    fn bolt3_commitment_params(
        feerate_per_kw: u32,
        push_msat: u64,
        channel_type: Vec<u8>,
    ) -> CommitmentParams {
        CommitmentParams {
            funding_txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                .parse()
                .unwrap(),
            funding_output_index: 0,
            feerate_per_kw,
            funding_satoshis: 10_000_000,
            push_msat,
            opener_funding_pubkey: pubkey(
                "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
            ),
            acceptor_funding_pubkey: pubkey(
                "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
            ),
            opener_payment_basepoint: pubkey(
                "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            ),
            acceptor_payment_basepoint: pubkey(
                "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
            ),
            opener_revocation_basepoint: pubkey(
                "0212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b19",
            ),
            acceptor_delayed_payment_basepoint: pubkey(
                "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
            ),
            acceptor_per_commitment_point: pubkey(
                "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
            ),
            opener_to_self_delay: 144,
            acceptor_dust_limit_satoshis: 546,
            channel_type,
        }
    }

    #[test]
    fn local_and_remote_above_dust_legacy() {
        let params = bolt3_commitment_params(15_000, 3_000_000_000, vec![]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "94e01e372ab38ee6e931dc20764c0bfe536f357b72c2cbccc190156fa213b56f",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "75daee7e777c395b5e3cc3c440170e630980bd68e0305becd7a4b83dc5376cb21d9ce018bad310907ac532b8a1329bbe08ea0848a6c33f9be76a31b7fa201770",
        );
    }

    #[test]
    fn local_below_dust_remote_above_dust_legacy() {
        let params = bolt3_commitment_params(15_000, 0, vec![]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "58fb0b0241890c863ae5485fd0c8c366839d11f3dab73dda0440b17699e2f055",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "0aa30672fad3f36ac6f95973e83143d4431ebc6c9873b86692502eea11ecf7b256f876c8927890e672fdfb0c2249221b4e49d8120ee7d1bcc0be8aad49e65e8f",
        );
    }

    #[test]
    fn local_above_dust_remote_below_dust_legacy() {
        let params = bolt3_commitment_params(9_667_817, 3_000_000_000, vec![]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "eea8bbc312d21915520b8d089ee84d5ad6d4ab20dea7e6fe03eb9c221d9cdbbd",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "7a14e47a22b4a8497dc2e68b856b986eca64291c0dbddca47224629ce8457f01042c045250bb13d9ac5515aab4fbc9f4b27cd79a71f8a77287a1666d561611eb",
        );
    }

    // BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors

    #[test]
    fn local_and_remote_above_dust_anchor() {
        let params = bolt3_commitment_params(15_000, 3_000_000_000, vec![0x00, 0x00, 0x40]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "e2ec4db903f5002263cf962c8a019ffa760f721a2112bbc7772a48a655aabf3a",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "4da81748c5fccc1c042b0ebf284cca5590c1f72fadcb8e34d077bca6c18d597c606ddfc7e7acc38e2994a9f28074ba229a59c21bc39dc5df9592c69c39766634",
        );
    }

    #[test]
    fn local_below_dust_remote_above_dust_anchor() {
        let params = bolt3_commitment_params(15_000, 0, vec![0x00, 0x00, 0x40]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "61ca1991232bb8e0db7ffe002bae1bdfc4c608489fcfeb891a264285cbbea596",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "45260dd24cf03a7c18fa9b7771a162a8eb9fdaf3770e2a1687921dc8e16ed30f76222d5e6875124d9258b72e64fdf0011f6c09c43dff4bc34315facb62d09f57",
        );
    }

    #[test]
    fn local_above_dust_remote_below_dust_anchor() {
        let params = bolt3_commitment_params(6_226_725, 3_000_000_000, vec![0x00, 0x00, 0x40]);
        let sighash = build_commitment_sighash(&params);
        assert_eq!(
            hex::encode(sighash),
            "d111260d0b6f848d1f8b29ee94ad85a1cad3d2a700be3ef6da4355fbc3a7d9aa",
        );

        let opener_sk = secret(OPENER_FUNDING_PRIVKEY);
        let sig = sign_commitment(&sighash, &opener_sk);
        assert_eq!(
            hex::encode(sig.serialize_compact()),
            "339848a17083b8a55493cbe80e6414eb4176ecbd581476446a381590b092a08c064c157c713e8fefc5e20e19bf3d6f050f4a0ac289902a33b411ce5dcc79c3b1",
        );
    }

    // BOLT 3 Appendix E: Key Derivation Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-e-key-derivation-test-vectors

    #[test]
    fn derive_pubkey_from_basepoint() {
        let basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let localpubkey = derive_pubkey(&basepoint, &per_commitment_point);
        assert_eq!(
            localpubkey,
            pubkey("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"),
        );
    }

    #[test]
    fn derive_revocation_pubkey_from_basepoint() {
        let revocation_basepoint =
            pubkey("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
        let per_commitment_point =
            pubkey("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
        let revocationpubkey =
            derive_revocation_pubkey(&revocation_basepoint, &per_commitment_point);
        assert_eq!(
            revocationpubkey,
            pubkey("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"),
        );
    }
}
