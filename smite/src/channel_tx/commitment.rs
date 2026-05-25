//! BOLT 3 commitment transaction construction and signing.

use super::funding::build_funding_witness_script;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::ripemd160::Hash as Ripemd160;
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all as opcodes;
use bitcoin::script::Builder;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, CompressedPublicKey, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
};

/// Anchor output value in satoshis.
const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Weight of a non-anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR: u64 = 724;

/// Weight of an anchor commitment transaction without HTLCs.
const COMMITMENT_TX_BASE_WEIGHT_ANCHOR: u64 = 1124;

/// Additional commitment weight per non-trimmed HTLC output.
const COMMITMENT_TX_WEIGHT_PER_HTLC: u64 = 172;

/// Weight of an HTLC-success transaction on a non-anchor channel.
const HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR: u64 = 703;

/// Weight of an HTLC-success transaction on a anchor channel.
const HTLC_SUCCESS_TX_WEIGHT_ANCHOR: u64 = 706;

/// Weight of an HTLC-timeout transaction on a non-anchor channel.
const HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR: u64 = 663;

/// Weight of an HTLC-timeout transaction on a anchor channel.
const HTLC_TIMEOUT_TX_WEIGHT_ANCHOR: u64 = 666;

/// `option_anchors` feature bits (BOLT 9, bits 22/23).
const OPTION_ANCHORS_FEATURE_BITS: &[usize] = &[22, 23];

/// Errors that can occur when constructing or validating commitment transactions.
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    /// Funding amount overflowed when converting to millisatoshis.
    #[error("funding_satoshis overflowed when converting to msat")]
    FundingMsatOverflow,

    /// Push amount exceeds the total funding amount.
    #[error("push_msat exceeds funding_msat")]
    PushExceedsFunding,

    /// Adding an HTLC would underflow the offerer's balance.
    #[error("htlc amount exceeds offerer's balance")]
    InsufficientBalance,

    /// The HTLC referenced by id was not found in the pending set.
    #[error("htlc with the given id was not found")]
    HtlcNotFound,
}

/// Identifies the channel participant relative to the funding flow.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Opener,
    Acceptor,
}

/// Holder's identity and funding secret for the commitment.
pub struct HolderIdentity {
    /// Whether the holder is the channel opener or acceptor.
    pub side: Side,
    /// Holder's funding private key.
    pub funding_privkey: SecretKey,
    /// Holder's HTLC basepoint private key.
    pub htlc_basepoint_privkey: SecretKey,
}

/// Static public keys and channel parameters for one side of a channel (opener or acceptor).
pub struct ChannelPartyConfig {
    /// Funding pubkey used in the funding output.
    pub funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    pub payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive keys that allow punishment of old states.
    pub revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the time-locked `to_local` output key.
    pub delayed_payment_basepoint: PublicKey,
    /// HTLC basepoint used to derive HTLC keys.
    pub htlc_basepoint: PublicKey,
    /// Minimum output value below which outputs are trimmed as dust.
    pub dust_limit_satoshis: u64,
    /// CSV delay this party imposes on the other's `to_local` output.
    pub to_self_delay: u16,
}

/// Channel configuration including funding details and both parties configuration.
pub struct ChannelConfig {
    /// Funding transaction outpoint.
    pub funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    pub funding_satoshis: u64,
    /// Channel type feature bits. The commitment format (anchor / legacy) is
    /// derived from the bits set here.
    pub channel_type: Vec<u8>,
    /// Opener's static keys and parameters.
    pub opener: ChannelPartyConfig,
    /// Acceptor's static keys and parameters.
    pub acceptor: ChannelPartyConfig,
}

/// An in-flight HTLC that appears (subject to dust trimming) as an output in
/// the commitment transaction.
#[derive(Clone, Copy)]
pub struct Htlc {
    /// HTLC ID.
    id: u64,
    /// The party that offered this HTLC.
    ///
    /// Combined with the commitment owner, this determines whether the HTLC
    /// is treated as an "offered" or "received" output.
    pub offerer: Side,
    /// HTLC amount in millisatoshis.
    pub amount_msat: u64,
    /// The expiry height of the HTLC
    pub cltv_expiry: u32,
    /// `SHA256` of the payment preimage.
    pub payment_hash: [u8; 32],
}

/// A single update to be applied to a [`CommitmentState`] during a commitment
/// round.
pub enum PendingUpdate {
    /// Add a new HTLC.
    AddHtlc(Htlc),
    /// Fulfill an existing HTLC by id.
    FulfillHtlc(u64),
    /// Fail an existing HTLC by id.
    FailHtlc(u64),
    /// Replace the commitment feerate.
    UpdateFee(u32),
    /// Replace a party's per-commitment point.
    UpdatePerCommitmentPoint(Side, PublicKey),
}

/// Per-party parameters used in a commitment transaction.
#[derive(Clone)]
pub struct CommitmentPartyState {
    /// Per-commitment point used to derive all commitment-specific keys.
    pub per_commitment_point: PublicKey,

    /// Amount allocated to this party in millisatoshis.
    /// Represents the balance before subtraction of fees, and anchors outputs.
    /// In-flight HTLCs are represented as separate outputs in the commitment
    /// transaction, so those values are already deducted from these balance values.
    pub balance_msat: u64,
}

/// Parameters for building a commitment transaction.
#[derive(Clone)]
pub struct CommitmentState {
    /// The commitment transaction number.
    pub commitment_number: u64,
    /// Fee rate for the commitment transaction.
    pub feerate_per_kw: u32,
    /// Parameters for the channel opener.
    pub opener: CommitmentPartyState,
    /// Parameters for the channel acceptor.
    pub acceptor: CommitmentPartyState,
    /// In-flight HTLCs offered in either direction.
    pub htlcs: Vec<Htlc>,
}

/// An HTLC output included in a commitment transaction after dust trimming and
/// output ordering have been finalized.
#[derive(Clone, Copy)]
struct HtlcOutputInCommitment {
    /// Whether this is an offered or received HTLC output from the commitment
    /// owner's perspective.
    offered: bool,
    /// The HTLC that this output corresponds to.
    htlc: Htlc,
    /// The output index of the HTLC in the commitment transaction.
    vout: u32,
}

/// Per-commitment keys used when constructing and signing a commitment
/// transaction from the local party's perspective.
struct CommitmentKeys {
    /// The per-commitment point used to derive the commitment-specific keys.
    per_commitment_point: PublicKey,
    /// Local delayed payment pubkey.
    local_delayedpubkey: PublicKey,
    /// Revocation pubkey for this commitment.
    revocationpubkey: PublicKey,
    /// Local per-commitment HTLC pubkey.
    local_htlcpubkey: PublicKey,
    /// Remote per-commitment HTLC pubkey.
    remote_htlcpubkey: PublicKey,
}

/// A fully built commitment transaction with the metadata needed to construct
/// and sign its second-stage HTLC transactions.
struct BuiltCommitment {
    /// Per-commitment keys for the local side.
    keys: CommitmentKeys,
    /// HTLC outputs with their post-sort indices into the commitment tx.
    htlc_outputs: Vec<HtlcOutputInCommitment>,
    /// The assembled commitment transaction.
    tx: Transaction,
}

/// A second-stage HTLC transaction spending an HTLC output from a commitment
/// transaction.
struct BuiltHtlcTx {
    /// The commitment transaction HTLC output being spent.
    htlc_output: HtlcOutputInCommitment,
    /// The HTLC-success or HTLC-timeout transaction.
    tx: Transaction,
}

impl Side {
    /// Returns the counterparty side.
    fn other(self) -> Self {
        match self {
            Self::Opener => Self::Acceptor,
            Self::Acceptor => Self::Opener,
        }
    }
}

impl HolderIdentity {
    /// Returns the counterparty side.
    #[must_use]
    fn counterparty_side(&self) -> Side {
        self.side.other()
    }
}

impl ChannelConfig {
    /// Returns the config for the given channel side.
    fn party(&self, side: Side) -> &ChannelPartyConfig {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Constructs the initial commitment state after channel funding.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`CommitmentError::FundingMsatOverflow`] if `funding_satoshis` overflows when
    ///   converting to millisatoshis.
    /// - [`CommitmentError::PushExceedsFunding`] if `push_msat` exceeds the total
    ///   funding amount in millisatoshis.
    pub fn new_initial_commitment(
        &self,
        push_msat: u64,
        feerate_per_kw: u32,
        opener_per_commitment_point: PublicKey,
        acceptor_per_commitment_point: PublicKey,
    ) -> Result<CommitmentState, CommitmentError> {
        let funding_msat = self
            .funding_satoshis
            .checked_mul(1000)
            .ok_or(CommitmentError::FundingMsatOverflow)?;
        let to_opener_balance_msat = funding_msat
            .checked_sub(push_msat)
            .ok_or(CommitmentError::PushExceedsFunding)?;
        let to_acceptor_balance_msat = push_msat;

        Ok(CommitmentState {
            commitment_number: 0,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: opener_per_commitment_point,
                balance_msat: to_opener_balance_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: acceptor_per_commitment_point,
                balance_msat: to_acceptor_balance_msat,
            },
            htlcs: Vec::new(),
        })
    }

    /// Checks whether the opener can afford the commitment fee at the given
    /// feerate, after accounting for the anchor outputs.
    #[must_use]
    pub fn can_opener_afford_feerate(&self, state: &CommitmentState, local_side: Side) -> bool {
        let nondust_htlc_count = state
            .htlcs
            .iter()
            .filter(|htlc| {
                !htlc.is_dust(
                    self.party(local_side).dust_limit_satoshis,
                    state.feerate_per_kw,
                    &self.channel_type,
                    local_side,
                )
            })
            .count();
        let fee = commit_tx_fee_sat(state.feerate_per_kw, nondust_htlc_count, &self.channel_type);
        let anchor_cost = total_anchors_sat(&self.channel_type);

        (state.opener.balance_msat / 1000)
            .checked_sub(fee)
            .and_then(|balance| balance.checked_sub(anchor_cost))
            .is_some()
    }

    /// Builds the signatures for the counterparty's commitment transaction:
    /// the funding-input signature plus one signature per non-dust HTLC
    /// output, in commitment-output order.
    #[must_use]
    pub fn sign_counterparty_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let commitment = self.build_commitment(state, holder.counterparty_side());
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.counterparty_side());
        let commit_sig = self.sign_commitment(&commitment, &holder.funding_privkey);
        let htlc_sigs = self.sign_htlc_txs(&commitment, &htlc_txs, &holder.htlc_basepoint_privkey);
        (commit_sig, htlc_sigs)
    }

    /// Verifies the counterparty's signatures on the holder's commitment
    /// transaction and all of its non-dust HTLC outputs.
    #[must_use]
    pub fn verify_counterparty_signature(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
        commit_sig: &Signature,
        htlc_sigs: &[Signature],
    ) -> bool {
        let commitment = self.build_commitment(state, holder.side);
        if !self.verify_commit_sig(&commitment, holder, commit_sig) {
            return false;
        }
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.side);
        self.verify_htlc_sigs(&commitment, &htlc_txs, htlc_sigs)
    }

    /// Builds the signatures for the holder's own commitment transaction and
    /// its HTLC outputs. Only used to exercise BOLT 3 test vectors.
    #[cfg(test)]
    fn sign_holder_commitment(
        &self,
        state: &CommitmentState,
        holder: &HolderIdentity,
    ) -> (Signature, Vec<Signature>) {
        let commitment = self.build_commitment(state, holder.side);
        let htlc_txs = self.build_htlc_txs(state, &commitment, holder.side);
        let commit_sig = self.sign_commitment(&commitment, &holder.funding_privkey);
        let htlc_sigs = self.sign_htlc_txs(&commitment, &htlc_txs, &holder.htlc_basepoint_privkey);
        (commit_sig, htlc_sigs)
    }

    /// Builds the commitment transaction. The commitment format (legacy or
    /// anchor) is determined by the `channel_type`.
    ///
    /// `local_side` selects whose commitment is built: the opener's or
    /// the acceptor's.
    fn build_commitment(&self, state: &CommitmentState, local_side: Side) -> BuiltCommitment {
        // Obscured commitment number.
        let obscuring_factor = compute_obscuring_factor(
            &self.opener.payment_basepoint,
            &self.acceptor.payment_basepoint,
        );
        let obscured_commitment_number = state.commitment_number ^ obscuring_factor;

        // Upper 8 bits of sequence are 0x80 and lower 24 bits are the upper 24 bits
        // of the obscured commitment number.
        let sequence = (0x80u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number >> 24)
                .expect("commitment_number cannot be more than 48 bits");

        // Upper 8 bits of locktime are 0x20 and lower 24 bits are the lower 24 bits
        // of the obscured commitment number.
        let locktime = (0x20u32 << (8 * 3))
            | u32::try_from(obscured_commitment_number & 0x00ff_ffff_u64)
                .expect("commitment_number cannot be more than 48 bits");

        // Build the commitment transaction
        let keys = self.derive_commitment_keys(state, local_side);
        let (outputs, htlc_outputs) = self.build_commitment_outputs(state, &keys, local_side);

        // Witness is not included in the BIP 143 sighash, so we leave it empty.
        let input = TxIn {
            previous_output: self.funding_outpoint,
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

        BuiltCommitment {
            keys,
            htlc_outputs,
            tx,
        }
    }

    /// Builds the sighash for the given commitment transaction.
    fn build_commitment_sighash(&self, tx: &Transaction) -> [u8; 32] {
        // Funding output witness script.
        let funding_witness_script = build_funding_witness_script(
            &self.opener.funding_pubkey,
            &self.acceptor.funding_pubkey,
        );

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(
                0,
                &funding_witness_script,
                Amount::from_sat(self.funding_satoshis),
                EcdsaSighashType::All,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Builds the lexicographically sorted commitment outputs together with
    /// the mapping from each non-dust HTLC to its output index.
    fn build_commitment_outputs(
        &self,
        state: &CommitmentState,
        keys: &CommitmentKeys,
        local_side: Side,
    ) -> (Vec<TxOut>, Vec<HtlcOutputInCommitment>) {
        // Tag each transaction output with its corresponding HTLC, if any
        // (non-HTLC outputs use `None`).
        //
        // This is done for two reasons:
        // - So we can recover the HTLC output index in the commitment transaction
        //   later when constructing second-stage HTLC transactions.
        // - So we can apply BOLT 3 output ordering by sorting outputs first by
        //   amount, then by `script_pubkey`, and finally by `cltv_expiry` for
        //   HTLC outputs.
        //
        // Since non-HTLC outputs have `None` as their HTLC, they sort before HTLC
        // outputs when amount and `script_pubkey` are identical.
        let mut outputs = self.build_htlc_outputs(state, keys, local_side);
        let nondust_htlc_count = outputs.len();
        outputs.extend(self.build_non_htlc_outputs(state, keys, nondust_htlc_count, local_side));

        // BOLT 3 output ordering: sort by (value, script_pubkey, cltv_expiry-if-htlc).
        outputs.sort_by(|a, b| {
            a.0.value
                .cmp(&b.0.value)
                .then_with(|| {
                    a.0.script_pubkey
                        .as_bytes()
                        .cmp(b.0.script_pubkey.as_bytes())
                })
                .then_with(|| a.1.map(|h| h.cltv_expiry).cmp(&b.1.map(|h| h.cltv_expiry)))
        });

        // Split the sorted tagged outputs into plain `TxOut`s and HTLC outputs,
        // recording the final `vout` index for each HTLC in the commitment
        // transaction.
        let mut txouts = Vec::with_capacity(outputs.len());
        let mut htlc_outputs = Vec::with_capacity(nondust_htlc_count);
        for (vout, (txout, htlc)) in outputs.into_iter().enumerate() {
            if let Some(htlc) = htlc {
                htlc_outputs.push(HtlcOutputInCommitment {
                    offered: htlc.offerer == local_side,
                    htlc,
                    vout: u32::try_from(vout)
                        .expect("commitment cannot have more than u32::MAX outputs"),
                });
            }
            txouts.push(txout);
        }

        (txouts, htlc_outputs)
    }

    /// Builds the non-dust HTLC outputs for the commitment transaction, tagging
    /// each output with its corresponding [`Htlc`].
    fn build_htlc_outputs(
        &self,
        state: &CommitmentState,
        keys: &CommitmentKeys,
        local_side: Side,
    ) -> Vec<(TxOut, Option<Htlc>)> {
        let anchor = supports_option_anchors(&self.channel_type);
        let dust_limit = self.party(local_side).dust_limit_satoshis;

        // Add non-dust HTLCs as commitment transaction outputs.
        let mut outputs = Vec::new();
        for htlc in &state.htlcs {
            if htlc.is_dust(
                dust_limit,
                state.feerate_per_kw,
                &self.channel_type,
                local_side,
            ) {
                continue;
            }

            let offered = htlc.offerer == local_side;
            let htlc_witness_script = build_witness_script(htlc, keys, offered, anchor);
            let output = TxOut {
                script_pubkey: htlc_witness_script.to_p2wsh(),
                value: htlc.amount(),
            };

            outputs.push((output, Some(*htlc)));
        }
        outputs
    }

    /// Builds the non-HTLC outputs for the commitment transaction (`to_local`,
    /// `to_remote`, and anchor outputs when applicable), tagging them with
    /// `None` for BOLT 3 output ordering.
    fn build_non_htlc_outputs(
        &self,
        state: &CommitmentState,
        keys: &CommitmentKeys,
        nondust_htlc_count: usize,
        local_side: Side,
    ) -> Vec<(TxOut, Option<Htlc>)> {
        let anchor = supports_option_anchors(&self.channel_type);

        // Fee and balances.
        let fee = commit_tx_fee_sat(state.feerate_per_kw, nondust_htlc_count, &self.channel_type);
        let anchor_cost = total_anchors_sat(&self.channel_type);

        let acceptor_balance = state.acceptor.balance_msat / 1000;
        let opener_balance = (state.opener.balance_msat / 1000)
            .saturating_sub(fee)
            .saturating_sub(anchor_cost);

        // Map opener/acceptor to local/remote for this commitment side.
        let (to_local_value, to_remote_value) = match local_side {
            Side::Opener => (opener_balance, acceptor_balance),
            Side::Acceptor => (acceptor_balance, opener_balance),
        };
        let local = self.party(local_side);
        let remote = self.party(local_side.other());

        let mut outputs: Vec<(TxOut, Option<Htlc>)> = Vec::new();

        if to_local_value >= local.dust_limit_satoshis {
            let to_local_spk = build_revocable_scriptpubkey(
                &keys.local_delayedpubkey,
                &keys.revocationpubkey,
                remote.to_self_delay,
            );

            outputs.push((
                TxOut {
                    value: Amount::from_sat(to_local_value),
                    script_pubkey: to_local_spk,
                },
                None,
            ));
        }
        if to_remote_value >= local.dust_limit_satoshis {
            let to_remote_spk = build_to_remote_scriptpubkey(&remote.payment_basepoint, anchor);

            outputs.push((
                TxOut {
                    value: Amount::from_sat(to_remote_value),
                    script_pubkey: to_remote_spk,
                },
                None,
            ));
        }

        if anchor {
            if to_local_value >= local.dust_limit_satoshis || nondust_htlc_count > 0 {
                outputs.push((
                    TxOut {
                        value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                        script_pubkey: build_anchor_scriptpubkey(&local.funding_pubkey),
                    },
                    None,
                ));
            }

            if to_remote_value >= local.dust_limit_satoshis || nondust_htlc_count > 0 {
                outputs.push((
                    TxOut {
                        value: Amount::from_sat(ANCHOR_OUTPUT_VALUE),
                        script_pubkey: build_anchor_scriptpubkey(&remote.funding_pubkey),
                    },
                    None,
                ));
            }
        }

        outputs
    }

    /// Signs the commitment transaction's funding-input sighash with the
    /// funding private key.
    fn sign_commitment(
        &self,
        commitment: &BuiltCommitment,
        funding_privkey: &SecretKey,
    ) -> Signature {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        sign(&sighash, funding_privkey)
    }

    /// Verifies the commitment signature against the counterparty's funding
    /// public key.
    fn verify_commit_sig(
        &self,
        commitment: &BuiltCommitment,
        holder: &HolderIdentity,
        commit_sig: &Signature,
    ) -> bool {
        let sighash = self.build_commitment_sighash(&commitment.tx);
        let counterparty = self.party(holder.counterparty_side());
        verify(&sighash, commit_sig, &counterparty.funding_pubkey)
    }

    /// Builds the second-stage HTLC transactions that spend the non-dust HTLC
    /// outputs of `commitment`, in commitment-output order.
    fn build_htlc_txs(
        &self,
        state: &CommitmentState,
        commitment: &BuiltCommitment,
        local_side: Side,
    ) -> Vec<BuiltHtlcTx> {
        let anchor = supports_option_anchors(&self.channel_type);
        let mut built_htlc_txs: Vec<BuiltHtlcTx> = Vec::new();

        for &htlc_output in &commitment.htlc_outputs {
            // Spend the HTLC output of the commitment transaction.
            let input = TxIn {
                previous_output: OutPoint {
                    txid: commitment.tx.compute_txid(),
                    vout: htlc_output.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(u32::from(anchor)),
                witness: Witness::new(),
            };

            let (success_fee_sat, timeout_fee_sat) =
                second_stage_tx_fees_sat(&self.channel_type, state.feerate_per_kw);
            let second_stage_fee_sat = if htlc_output.offered {
                timeout_fee_sat
            } else {
                success_fee_sat
            };

            let output = TxOut {
                script_pubkey: build_revocable_scriptpubkey(
                    &commitment.keys.local_delayedpubkey,
                    &commitment.keys.revocationpubkey,
                    self.party(local_side.other()).to_self_delay,
                ),

                value: htlc_output.htlc.amount() - Amount::from_sat(second_stage_fee_sat),
            };

            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::from_consensus(if htlc_output.offered {
                    htlc_output.htlc.cltv_expiry
                } else {
                    0
                }),
                input: vec![input],
                output: vec![output],
            };

            built_htlc_txs.push(BuiltHtlcTx { htlc_output, tx });
        }

        built_htlc_txs
    }

    /// Builds the sighash for the HTLC's second-stage transaction.
    fn build_htlc_sighash(&self, htlc_tx: &BuiltHtlcTx, keys: &CommitmentKeys) -> [u8; 32] {
        // HTLC output witness script.
        let anchor = supports_option_anchors(&self.channel_type);
        let htlc_witness_script = build_witness_script(
            &htlc_tx.htlc_output.htlc,
            keys,
            htlc_tx.htlc_output.offered,
            anchor,
        );

        let sighash_type = if supports_option_anchors(&self.channel_type) {
            EcdsaSighashType::SinglePlusAnyoneCanPay
        } else {
            EcdsaSighashType::All
        };

        // Compute the BIP143 sighash
        let sighash = SighashCache::new(&htlc_tx.tx)
            .p2wsh_signature_hash(
                0,
                &htlc_witness_script,
                htlc_tx.htlc_output.htlc.amount(),
                sighash_type,
            )
            .expect("input index 0 is always in bounds for a single input transaction");

        sighash.to_byte_array()
    }

    /// Signs each HTLC second-stage transaction using the local party's
    /// per-commitment HTLC private key.
    fn sign_htlc_txs(
        &self,
        commitment: &BuiltCommitment,
        htlc_txs: &[BuiltHtlcTx],
        htlc_basepoint_privkey: &SecretKey,
    ) -> Vec<Signature> {
        let htlc_privkey = derive_privkey(
            htlc_basepoint_privkey,
            &commitment.keys.per_commitment_point,
        );

        htlc_txs
            .iter()
            .map(|htlc_tx| {
                let sighash = self.build_htlc_sighash(htlc_tx, &commitment.keys);
                sign(&sighash, &htlc_privkey)
            })
            .collect()
    }

    /// Verifies the HTLC signatures against the counterparty's per-commitment
    /// HTLC public key.
    fn verify_htlc_sigs(
        &self,
        commitment: &BuiltCommitment,
        htlc_txs: &[BuiltHtlcTx],
        htlc_sigs: &[Signature],
    ) -> bool {
        if htlc_sigs.len() != htlc_txs.len() {
            return false;
        }

        htlc_txs.iter().zip(htlc_sigs.iter()).all(|(htlc_tx, sig)| {
            let sighash = self.build_htlc_sighash(htlc_tx, &commitment.keys);
            verify(&sighash, sig, &commitment.keys.remote_htlcpubkey)
        })
    }

    /// Derives the per-commitment keys for the `local_side`.
    fn derive_commitment_keys(&self, state: &CommitmentState, local_side: Side) -> CommitmentKeys {
        let local = self.party(local_side);
        let remote = self.party(local_side.other());
        let per_commitment_point = state.party(local_side).per_commitment_point;

        CommitmentKeys {
            per_commitment_point,
            local_delayedpubkey: derive_pubkey(
                &local.delayed_payment_basepoint,
                &per_commitment_point,
            ),
            revocationpubkey: derive_revocation_pubkey(
                &remote.revocation_basepoint,
                &per_commitment_point,
            ),
            local_htlcpubkey: derive_pubkey(&local.htlc_basepoint, &per_commitment_point),
            remote_htlcpubkey: derive_pubkey(&remote.htlc_basepoint, &per_commitment_point),
        }
    }
}

// TODO: Need to think about commiting the next commitnment state?
impl CommitmentState {
    /// Returns the parameters for the given commitment side.
    fn party(&self, side: Side) -> &CommitmentPartyState {
        match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        }
    }

    /// Returns a mutable reference to the parameters for the given commitment side.
    fn party_mut(&mut self, side: Side) -> &mut CommitmentPartyState {
        match side {
            Side::Opener => &mut self.opener,
            Side::Acceptor => &mut self.acceptor,
        }
    }

    /// Returns a new commitment state derived from the previous commitment
    /// state by applying `updates` in order and incrementing
    /// `commitment_number` by one.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`CommitmentError::InsufficientBalance`] if an `AddHtlc` update would
    ///   underflow the offerer's balance.
    /// - [`CommitmentError::HtlcNotFound`] if a `FulfillHtlc` or `FailHtlc`
    ///   update references an id not present in the in-flight set.
    pub fn advance(&self, updates: &[PendingUpdate]) -> Result<Self, CommitmentError> {
        let mut next = self.clone();
        next.commitment_number += 1;
        for update in updates {
            match *update {
                // Debit the offerer's balance and add the HTLC to the in-flight set.
                PendingUpdate::AddHtlc(htlc) => {
                    let offerer_balance = &mut next.party_mut(htlc.offerer).balance_msat;
                    *offerer_balance = offerer_balance
                        .checked_sub(htlc.amount_msat)
                        .ok_or(CommitmentError::InsufficientBalance)?;
                    next.htlcs.push(htlc);
                }
                // Remove the in-flight HTLC and credit its amount to the receiver.
                PendingUpdate::FulfillHtlc(id) => {
                    let pos = next
                        .htlcs
                        .iter()
                        .position(|h| h.id == id)
                        .ok_or(CommitmentError::HtlcNotFound)?;
                    let htlc = next.htlcs.remove(pos);
                    next.party_mut(htlc.offerer.other()).balance_msat += htlc.amount_msat;
                }
                // Remove the in-flight HTLC and refund its amount to the offerer.
                PendingUpdate::FailHtlc(id) => {
                    let pos = next
                        .htlcs
                        .iter()
                        .position(|h| h.id == id)
                        .ok_or(CommitmentError::HtlcNotFound)?;
                    let htlc = next.htlcs.remove(pos);
                    next.party_mut(htlc.offerer).balance_msat += htlc.amount_msat;
                }
                PendingUpdate::UpdateFee(feerate_per_kw) => {
                    next.feerate_per_kw = feerate_per_kw;
                }
                PendingUpdate::UpdatePerCommitmentPoint(side, per_commitment_point) => {
                    next.party_mut(side).per_commitment_point = per_commitment_point;
                }
            }
        }
        Ok(next)
    }
}

impl Htlc {
    /// Returns whether this HTLC would be trimmed from the commitment
    /// transaction due to dust limits.
    fn is_dust(
        &self,
        dust_limit_satoshis: u64,
        feerate_per_kw: u32,
        channel_type: &[u8],
        local_side: Side,
    ) -> bool {
        let offered = self.offerer == local_side;
        let (success_fee, timeout_fee) = second_stage_tx_fees_sat(channel_type, feerate_per_kw);
        let stage_fee = if offered { timeout_fee } else { success_fee };
        let amount_sat = self.amount_msat / 1000;
        amount_sat < dust_limit_satoshis.saturating_add(stage_fee)
    }

    /// Converts the HTLC amount from millisatoshis to satoshis.
    pub const fn amount(&self) -> Amount {
        Amount::from_sat(self.amount_msat / 1000)
    }
}

/// Get the fee cost of a commitment tx with a given number of HTLC outputs in
/// satoshis.
/// Note that `num_htlcs` should not include dust HTLCs.
fn commit_tx_fee_sat(feerate_per_kw: u32, num_htlcs: usize, channel_type: &[u8]) -> u64 {
    let commitment_base_weight = if supports_option_anchors(channel_type) {
        COMMITMENT_TX_BASE_WEIGHT_ANCHOR
    } else {
        COMMITMENT_TX_BASE_WEIGHT_NON_ANCHOR
    };

    let commitment_weight =
        commitment_base_weight + (num_htlcs as u64) * COMMITMENT_TX_WEIGHT_PER_HTLC;
    u64::from(feerate_per_kw) * commitment_weight / 1000
}

/// Get the anchor cost of a commitment tx in satoshis.
fn total_anchors_sat(channel_type: &[u8]) -> u64 {
    if supports_option_anchors(channel_type) {
        ANCHOR_OUTPUT_VALUE * 2
    } else {
        0
    }
}

/// Get the weight for an HTLC-Success transaction.
fn htlc_success_tx_weight(channel_type: &[u8]) -> u64 {
    if supports_option_anchors(channel_type) {
        HTLC_SUCCESS_TX_WEIGHT_ANCHOR
    } else {
        HTLC_SUCCESS_TX_WEIGHT_NON_ANCHOR
    }
}

/// Get the weight for an HTLC-Timeout transaction.
fn htlc_timeout_tx_weight(channel_type: &[u8]) -> u64 {
    if supports_option_anchors(channel_type) {
        HTLC_TIMEOUT_TX_WEIGHT_ANCHOR
    } else {
        HTLC_TIMEOUT_TX_WEIGHT_NON_ANCHOR
    }
}

/// Returns the fees for success and timeout second stage HTLC transactions.
fn second_stage_tx_fees_sat(channel_type: &[u8], feerate_per_kw: u32) -> (u64, u64) {
    if supports_option_anchors(channel_type) {
        return (0, 0);
    }

    (
        u64::from(feerate_per_kw) * htlc_success_tx_weight(channel_type) / 1000,
        u64::from(feerate_per_kw) * htlc_timeout_tx_weight(channel_type) / 1000,
    )
}

/// Returns `SHA256(pubkey1 || pubkey2)`.
///
/// Both public keys are serialized in compressed form before hashing.
fn hash_pubkeys(pubkey1: &PublicKey, pubkey2: &PublicKey) -> [u8; 32] {
    let mut sha = Sha256::engine();
    sha.input(&pubkey1.serialize());
    sha.input(&pubkey2.serialize());

    Sha256::from_engine(sha).to_byte_array()
}

/// Computes the commitment number obscuring factor per BOLT 3.
fn compute_obscuring_factor(
    opener_payment_basepoint: &PublicKey,
    acceptor_payment_basepoint: &PublicKey,
) -> u64 {
    let hash = hash_pubkeys(opener_payment_basepoint, acceptor_payment_basepoint);

    let mut buf = [0u8; 8];
    buf[2..].copy_from_slice(&hash[26..32]);
    u64::from_be_bytes(buf)
}

/// Checks whether `option_anchors` (BOLT 9, bits 22/23) is set in a
/// big-endian `channel_type` feature bitfield.
///
/// Per BOLT 9, even bit (22) = required, odd bit (23) = optional.
/// Either bit indicates anchor support.
fn supports_option_anchors(channel_type: &[u8]) -> bool {
    let byte_offset = OPTION_ANCHORS_FEATURE_BITS[0] / 8;
    let len = channel_type.len();
    if len <= byte_offset {
        return false;
    }

    let required_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[0] % 8);
    let optional_mask = 1 << (OPTION_ANCHORS_FEATURE_BITS[1] % 8);

    channel_type[len - 1 - byte_offset] & (required_mask | optional_mask) != 0
}

/// Derives a public key from a basepoint and per-commitment point per BOLT 3.
fn derive_pubkey(basepoint: &PublicKey, per_commitment_point: &PublicKey) -> PublicKey {
    let secp = Secp256k1::new();
    let tweak = hash_pubkeys(per_commitment_point, basepoint);
    let hashkey = PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&tweak).expect("SHA256 output is a valid secret key"),
    );

    basepoint
        .combine(&hashkey)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Derives a private key from a basepoint secret and a per-commitment point per
/// BOLT 3.
fn derive_privkey(basepoint_secret: &SecretKey, per_commitment_point: &PublicKey) -> SecretKey {
    let secp = Secp256k1::new();
    let basepoint = basepoint_secret.public_key(&secp);
    let tweak = hash_pubkeys(per_commitment_point, &basepoint);
    let scalar = Scalar::from_be_bytes(tweak).expect("SHA256 output is a valid scalar");
    basepoint_secret
        .add_tweak(&scalar)
        .expect("derived HTLC privkey tweak must be valid")
}

/// Derives the `revocationpubkey` per BOLT 3.
fn derive_revocation_pubkey(
    revocation_basepoint: &PublicKey,
    per_commitment_point: &PublicKey,
) -> PublicKey {
    let secp = Secp256k1::new();

    let rev_append_commit_hash_key = hash_pubkeys(revocation_basepoint, per_commitment_point);
    let commit_append_rev_hash_key = hash_pubkeys(per_commitment_point, revocation_basepoint);

    let revocation_contrib = revocation_basepoint
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(rev_append_commit_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    let commitment_contrib = per_commitment_point
        .mul_tweak(
            &secp,
            &Scalar::from_be_bytes(commit_append_rev_hash_key)
                .expect("SHA256 output is a valid scalar"),
        )
        .expect("scalar multiplication of a valid pubkey cannot fail");

    revocation_contrib
        .combine(&commitment_contrib)
        .expect("point addition of two valid pubkeys cannot produce infinity")
}

/// Builds the revocable P2WSH `script_pubkey` per BOLT 3.
/// Used by the `to_local` commitment output and by 2nd-stage HTLC outputs.
fn build_revocable_scriptpubkey(
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

/// Builds the `to_remote` output `script_pubkey` per BOLT 3.
///
/// With `option_anchors`, the output is P2WSH with a 1-block CSV lock.
/// Without anchors, it is a simple P2WPKH to the remote payment basepoint.
fn build_to_remote_scriptpubkey(payment_basepoint: &PublicKey, anchor: bool) -> ScriptBuf {
    if anchor {
        Builder::new()
            .push_slice(payment_basepoint.serialize())
            .push_opcode(opcodes::OP_CHECKSIGVERIFY)
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .into_script()
            .to_p2wsh()
    } else {
        ScriptBuf::new_p2wpkh(&CompressedPublicKey(*payment_basepoint).wpubkey_hash())
    }
}

/// Builds the anchor output P2WSH `script_pubkey` per BOLT 3.
fn build_anchor_scriptpubkey(funding_pubkey: &PublicKey) -> ScriptBuf {
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

/// Builds the offered and received HTLC output witness scripts as defined in BOLT 3.
///
/// From the `local_side` perspective, an HTLC is considered "offered" when
/// it was sent by `local_side`, and "received" otherwise.
fn build_witness_script(
    htlc: &Htlc,
    keys: &CommitmentKeys,
    offered: bool,
    anchor: bool,
) -> ScriptBuf {
    let payment_hash160 = Ripemd160::hash(&htlc.payment_hash[..]).to_byte_array();

    let mut bldr = Builder::new()
        .push_opcode(opcodes::OP_DUP)
        .push_opcode(opcodes::OP_HASH160)
        .push_slice(PubkeyHash::hash(&keys.revocationpubkey.serialize()))
        .push_opcode(opcodes::OP_EQUAL)
        .push_opcode(opcodes::OP_IF)
        .push_opcode(opcodes::OP_CHECKSIG)
        .push_opcode(opcodes::OP_ELSE)
        .push_slice(keys.remote_htlcpubkey.serialize())
        .push_opcode(opcodes::OP_SWAP)
        .push_opcode(opcodes::OP_SIZE)
        .push_int(32)
        .push_opcode(opcodes::OP_EQUAL);

    bldr = if offered {
        bldr.push_opcode(opcodes::OP_NOTIF)
            .push_opcode(opcodes::OP_DROP)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    } else {
        bldr.push_opcode(opcodes::OP_IF)
            .push_opcode(opcodes::OP_HASH160)
            .push_slice(payment_hash160)
            .push_opcode(opcodes::OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(opcodes::OP_SWAP)
            .push_slice(keys.local_htlcpubkey.serialize())
            .push_int(2)
            .push_opcode(opcodes::OP_CHECKMULTISIG)
            .push_opcode(opcodes::OP_ELSE)
            .push_opcode(opcodes::OP_DROP)
            .push_int(i64::from(htlc.cltv_expiry))
            .push_opcode(opcodes::OP_CLTV)
            .push_opcode(opcodes::OP_DROP)
            .push_opcode(opcodes::OP_CHECKSIG)
            .push_opcode(opcodes::OP_ENDIF)
    };

    if anchor {
        bldr = bldr
            .push_opcode(opcodes::OP_PUSHNUM_1)
            .push_opcode(opcodes::OP_CSV)
            .push_opcode(opcodes::OP_DROP);
    }
    bldr.push_opcode(opcodes::OP_ENDIF).into_script()
}

/// Signs a sighash with the given private key.
fn sign(sighash: &[u8; 32], privkey: &SecretKey) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.sign_ecdsa(&msg, privkey)
}

/// Verifies that `sig` is a valid signature for `sighash` under `pubkey`.
fn verify(sighash: &[u8; 32], sig: &Signature, pubkey: &PublicKey) -> bool {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(*sighash);
    secp.verify_ecdsa(&msg, sig, pubkey).is_ok()
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

    fn der_sig(hex_str: &str) -> Signature {
        let bytes = hex::decode(hex_str).expect("valid hex");
        Signature::from_der(&bytes).expect("valid DER signature")
    }

    /// BOLT 3 Appendix C opener (local) funding private key.
    const OPENER_FUNDING_PRIVKEY: &str =
        "30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749";

    /// BOLT 3 Appendix C acceptor (remote) funding private key.
    const ACCEPTOR_FUNDING_PRIVKEY: &str =
        "1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13";

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
        assert!(supports_option_anchors(&[0x40, 0x00, 0x00]));
        assert!(supports_option_anchors(&[0x80, 0x00, 0x00]));
        // No support.
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x40]));
        assert!(!supports_option_anchors(&[0x00, 0x00, 0x80]));
        assert!(!supports_option_anchors(&[]));
        assert!(!supports_option_anchors(&[0xff, 0xff]));
        assert!(!supports_option_anchors(&[0x00, 0x10]));
    }

    fn bolt3_commitment_params(
        feerate_per_kw: u32,
        to_opener_msat: u64,
        to_acceptor_msat: u64,
        dust_limit_satoshis: u64,
        channel_type: Vec<u8>,
    ) -> (
        ChannelConfig,
        CommitmentState,
        HolderIdentity,
        HolderIdentity,
    ) {
        let chan_config = ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid funding txid hex"),
                vout: 0,
            },
            funding_satoshis: 10_000_000,
            channel_type,
            opener: ChannelPartyConfig {
                funding_pubkey: pubkey(
                    "023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb",
                ),
                payment_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                revocation_basepoint: pubkey(
                    "02c6047f9441ed7d6d3045406e95c07cd85a0f5f0f3b9b3f3d5f9b1e5e4a7c4f09",
                ),
                delayed_payment_basepoint: pubkey(
                    "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
                ),
                htlc_basepoint: pubkey(
                    "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
            acceptor: ChannelPartyConfig {
                funding_pubkey: pubkey(
                    "030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1",
                ),
                payment_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                revocation_basepoint: pubkey(
                    "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
                ),
                delayed_payment_basepoint: pubkey(
                    "02a1633caf7bf0b7d9e5c4b8a1d6f2e3c4b5a6978877665544332211ffeeddccbb",
                ),
                htlc_basepoint: pubkey(
                    "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
                ),
                dust_limit_satoshis,
                to_self_delay: 144,
            },
        };

        let state = CommitmentState {
            commitment_number: 42,
            feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486",
                ),
                balance_msat: to_opener_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: pubkey(
                    "03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
                ),
                balance_msat: to_acceptor_msat,
            },
            htlcs: vec![],
        };

        let opener_holder = HolderIdentity {
            side: Side::Opener,
            funding_privkey: secret(OPENER_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
        };

        let acceptor_holder = HolderIdentity {
            side: Side::Acceptor,
            funding_privkey: secret(ACCEPTOR_FUNDING_PRIVKEY),
            htlc_basepoint_privkey: secret(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        };

        (chan_config, state, opener_holder, acceptor_holder)
    }

    // BOLT 3 Appendix C: Commitment and HTLC Transaction Test Vectors
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-c-commitment-and-htlc-transaction-test-vectors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix C)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 7_000_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30440220616210b2cc4d3afb601013c373bbd8aac54febd9f15400379a8cb65ce7deca60022034236c010991beb7ff770510561ae8dc885b8d38d1947248c38f2ae055647142",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100c3127b33dcc741dd6b05b1e63cbd1a9a7d816f37af9b6756fa2376b056f032370220408b96279808fe57eb7e463710804cdf4f108388bc5cf722d8c848d2c7f9f3b0",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(4_915, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221008a953551f4d67cb4df3037207fc082ddaf6be84d417b0bd14c80aab66f1b01a402207508796dc75034b2dee876fe01dc05a08b019f3e5d689ac8842ade2f1befccf5",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402203a286936e74870ca1459c700c71202af0381910a6bfab687ef494ef1bc3e02c902202506c362d0e3bee15e802aa729bf378e051644648253513f1c085b264cc2a720",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (maximum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_maximum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_180, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100e11b638c05c650c2f63a421d36ef8756c5ce82f2184278643520311cdf50aa200220259565fb9c8e4a87ccaf17f27a3b9ca4f20625754a0920d9c6c239d8156a11de",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402200a8544eba1d216f5c5e530597665fa9bec56943c0f66d98fc3d028df52d84f7002201e45fa5c6bc3a506cc2553e7d1c0043a9811313fc39c954692c0d47cfce2bbd3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum feerate) (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_feerate_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_181, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with fee greater than funder amount (BOLT 3 Appendix C)
    #[test]
    fn commitment_tx_with_fee_greater_than_funder_amount_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(9_651_936, 6_988_000_000, 3_000_000_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402207e8d51e0c570a5868a78414f4e0cbfaed1106b171b9581542c30718ee4eb95ba02203af84194c97adf98898c9afe2f2ed4a7f8dba05a2dfab28ac9d9c604aa49a379",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202ade0142008309eb376736575ad58d03e5b115499709c6db0b46e36ff394b492022037b63d78d66404d6504d4c4ac13be346f3d1802928a6d3ad95a6a944227161a2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 6_999_999_000, 3_000_000_123, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100a41609df3e71b939046d6dfface892aa6161ef8fb61898e142aeffc0ce1462df02201d1ca13eb145436593b0cb1a201c48bf2fdd6fc0c754784240d5f407c06ab4cf",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402202c85c0eb44ff3c5133e0a1e9f120a1af215b43d73da69b994e04c545b6cf7b600220331d81cacccfd7ae71eb3a1407bd767fc39a30776638e1048531441c95889bc2",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_legacy() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 5_005_430_000, 4_994_570_000, 546, vec![]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3045022100a51021a83202743cb336edad88ee08bd14f434779bff21351c8f39d78d035f9602200d889a4a98332aff37f02938157cd3d7cf336313e5663848ac18bcd09ad5ff13",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "304402206ad05e8243d8fa04953cf14fff140fbf00999c3b6ffe63670d8edbf2eccf82c502201ca99860981ee1df1d93a02129f5b54f5c18e2ff047e8d8864a017eca48f94c9",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // BOLT 3 Appendix F: Commitment and HTLC Transaction Test Vectors (anchors)
    //    https://github.com/lightning/bolts/blob/master/03-transactions.md#appendix-f-commitment-and-htlc-transaction-test-vectors-anchors

    // name: simple commitment tx with no HTLCs (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlcs_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                7_000_000_000,
                3_000_000_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f7",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: simple commitment tx with no HTLCs and single anchor (BOLT 3 Appendix F)
    #[test]
    fn simple_commitment_tx_with_no_htlc_and_single_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(15_000, 10_000_000_000, 0, 546, vec![0x40, 0x00, 0x00]);

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "3044022007cf6b405e9c9b4f527b0ecad9d8bb661fabb8b12abf7d1c0b3ad1855db3ed490220616d5c1eeadccc63bd775a131149455d62d95a42c2a1b01cc7821fc42dce7778",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30440220655bf909fb6fa81d086f1336ac72c97906dce29d1b166e305c99152d810e26e1022051f577faa46412c46707aaac46b65d50053550a66334e00a44af2706f27a8658",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with two outputs untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_two_outputs_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                4_894,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "3045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b95",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    // name: commitment tx with one output untrimmed (minimum dust limit) (BOLT 3 Appendix F)
    #[test]
    fn commitment_tx_with_one_output_untrimmed_minimum_dust_limit_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                6_216_010,
                6_988_000_000,
                3_000_000_000,
                4_001,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30450221009ad80792e3038fe6968d12ff23e6888a565c3ddd065037f357445f01675d63f3022018384915e5f1f4ae157e15debf4f49b61c8d9d2b073c7d6f97c4a68caa3ed4c1",
        );

        // Acceptor signs opener's commitment.
        let remote_signature = der_sig(
            "30450221008fd5dbff02e4b59020d4cd23a3c30d3e287065fda75a0a09b402980adf68ccda022001e0b8b620cd915ddff11f1de32addf23d81d51b90e6841b2cb8dcaf3faa5ecf",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Tests the edge case where `push_msat % 1000 != 0` to ensure there is
    /// no off-by-one error in opener balance calculation.
    #[test]
    fn commitment_tx_with_balance_msat_not_multiple_of_1000_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                6_999_999_000,
                3_000_000_123,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "304402202573a6da7fffc40fffb98d106dc4c83a5c94266118b3b0b44ea03100e20dab1e022038d9e65b3b84096ccebc91f9b56117d30c1cc249e21426d2d3dbf3e4617935fd",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022036e0e75ab8bd15f1232da3974db1a4cfca2491912b1fb06bfe2fbfca4f416e29022035c5a4f4b09f344a595ffdfb73aebf5982d41f1fcf5e90b141d8141c857e9aed",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
    }

    /// Not from BOLT 3 test vectors.
    /// Covers the case where commitment outputs have equal values,
    /// ensuring outputs are ordered by `script_pubkey`.
    #[test]
    fn commitment_tx_with_equal_output_values_orders_by_script_pubkey_anchor() {
        let (chan_config, commitment_params, opener_holder, acceptor_holder) =
            bolt3_commitment_params(
                15_000,
                5_008_760_000,
                4_991_240_000,
                546,
                vec![0x40, 0x00, 0x00],
            );

        // Opener signs own commitment.
        assert_eq!(
            hex::encode(
                chan_config
                    .sign_holder_commitment(&commitment_params, &opener_holder)
                    .0
                    .serialize_der()
            ),
            "30440220156f857fc1cfaa0e13dadc5a07553244971a91d99a3f53bf87305189864043a402200bd512ace372ac10c54a3745ae123e69d99305c564bd0420ade72ebcac994bd8",
        );

        // Acceptor signs opener's commitment.
        let remote_signature: Signature = der_sig(
            "3044022035fd44caf320fdca9f2a866fe88e27f186a4a93ecf390549c3ed9950a9042c2f0220237525890e37617749e1eae4c2cce10e19d1a796acea1937c29cb888ee992d19",
        );
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &opener_holder,
            &remote_signature,
            &[],
        ));

        // Opener signs the acceptor's commitment, then the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            chan_config.sign_counterparty_commitment(&commitment_params, &opener_holder);
        assert!(chan_config.verify_counterparty_signature(
            &commitment_params,
            &acceptor_holder,
            &acceptor_commit_sig,
            &acceptor_htlc_sigs,
        ));
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

    fn sample_chan_config(funding_satoshis: u64, channel_type: Vec<u8>) -> ChannelConfig {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let sample_party = || ChannelPartyConfig {
            funding_pubkey: sample_key,
            payment_basepoint: sample_key,
            revocation_basepoint: sample_key,
            delayed_payment_basepoint: sample_key,
            htlc_basepoint: sample_key,
            dust_limit_satoshis: 546,
            to_self_delay: 144,
        };

        ChannelConfig {
            funding_outpoint: OutPoint {
                txid: "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
                    .parse()
                    .expect("valid txid hex"),
                vout: 0,
            },
            funding_satoshis,
            channel_type,
            opener: sample_party(),
            acceptor: sample_party(),
        }
    }

    #[test]
    fn new_initial_from_funding_msat_overflow() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(u64::MAX, vec![]);
        let result = chan_config.new_initial_commitment(0, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::FundingMsatOverflow)));
    }

    #[test]
    fn new_initial_from_funding_push_exceeds_funding() {
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        let chan_config = sample_chan_config(1_000, vec![]);
        let result = chan_config.new_initial_commitment(2_000_000, 15_000, sample_key, sample_key);
        assert!(matches!(result, Err(CommitmentError::PushExceedsFunding)));
    }

    #[test]
    fn can_opener_afford_feerate_checks() {
        let feerate_per_kw: u32 = 15_000;
        let sample_key =
            pubkey("03b28f7c5a9d1e4f8c6a7b2d3e9f1048576a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e");
        // Legacy fee: 15000 * 724 / 1000 = 10_860 sat
        // Anchor fee: 15000 * 1124 / 1000 = 16_860 sat; anchor_cost = 660 sat

        // Comfortably affordable
        let chan_config = sample_chan_config(20_000, vec![]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Exact zero opener balance
        let chan_config = sample_chan_config(11_860, vec![]);
        let state = chan_config
            .new_initial_commitment(1_000_000, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Push fits but fee does not
        let chan_config = sample_chan_config(10_000, vec![]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));

        // Push + fee fit but anchor cost does not
        let chan_config = sample_chan_config(17_500, vec![0x40, 0x00, 0x00]);
        let state = chan_config
            .new_initial_commitment(0, feerate_per_kw, sample_key, sample_key)
            .expect("valid commitment");
        assert!(!chan_config.can_opener_afford_feerate(&state, Side::Opener));
    }
}
