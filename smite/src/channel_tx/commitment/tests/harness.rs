//! Test vector file format and the runner shared by the commitment tests.

use crate::bolt::ChannelTypeVariant;
use crate::channel_tx::commitment::*;

/// A file of commitment transaction test vectors.
///
/// Vector files may carry documentation-only keys (`reference` on the file,
/// `comment` on a vector); those are not deserialized.
#[derive(serde::Deserialize)]
struct TestVectorFile {
    /// What the file covers, used as context in assertion failures.
    description: String,
    /// Channel type shared by every vector in the file.
    channel_type: ChannelTypeVariant,
    /// Funding transaction outpoint.
    funding_outpoint: OutPoint,
    /// Total channel funding amount in satoshis.
    funding_amount_satoshis: u64,
    /// Commitment number every vector in the file is built at.
    commitment_number: u64,
    /// CSV delay each party imposes on the other's `to_local` output.
    to_self_delay: u16,
    /// Opener's static keys.
    opener: PartyKeys,
    /// Acceptor's static keys.
    acceptor: PartyKeys,
    /// The vectors themselves.
    tests: Vec<CommitmentVector>,
}

/// Static keys for one side of the channel, shared by every vector in a file.
#[derive(serde::Deserialize)]
struct PartyKeys {
    /// Funding private key, used to sign commitment transactions.
    funding_privkey: SecretKey,
    /// HTLC basepoint private key, used to sign HTLC transactions.
    htlc_basepoint_privkey: SecretKey,
    /// Funding public key used in the funding output.
    funding_pubkey: PublicKey,
    /// Payment basepoint used to derive the `to_remote` output key.
    payment_basepoint: PublicKey,
    /// Revocation basepoint used to derive the revocation key.
    revocation_basepoint: PublicKey,
    /// Delayed payment basepoint used to derive the `to_local` output key.
    delayed_payment_basepoint: PublicKey,
    /// HTLC basepoint used to derive HTLC keys.
    htlc_basepoint: PublicKey,
    /// Per-commitment point used to derive all commitment-specific keys.
    per_commitment_point: PublicKey,
}

/// A single commitment transaction test vector.
#[derive(serde::Deserialize)]
struct CommitmentVector {
    /// Vector name, as given by the BOLT 3 appendix where applicable.
    name: String,
    /// Fee rate for the commitment transaction.
    feerate_per_kw: u32,
    /// Default dust limit used by both parties unless overridden below.
    #[serde(default)]
    dust_limit_satoshis: Option<u64>,
    /// Dust limit used for the opener's commitment, overriding the default.
    #[serde(default)]
    opener_dust_limit_satoshis: Option<u64>,
    /// Dust limit used for the acceptor's commitment, overriding the default.
    #[serde(default)]
    acceptor_dust_limit_satoshis: Option<u64>,
    /// Opener's balance in millisatoshis, before fees and anchor outputs.
    to_opener_msat: u64,
    /// Acceptor's balance in millisatoshis.
    to_acceptor_msat: u64,
    /// HTLCs offered by the acceptor, deducted from its balance above.
    #[serde(default)]
    incoming_htlcs: Vec<HtlcVector>,
    /// HTLCs offered by the opener, deducted from its balance above.
    #[serde(default)]
    outgoing_htlcs: Vec<HtlcVector>,
    /// Opener's expected signature over its own commitment, DER encoded.
    local_signature: Signature,
    /// Opener's expected signatures over its own HTLC transactions, in
    /// commitment output order.
    #[serde(default)]
    local_htlc_signatures: Vec<Signature>,
    /// Acceptor's signature over the opener's commitment, DER encoded.
    remote_signature: Signature,
    /// Acceptor's signatures over the opener's HTLC transactions, in commitment
    /// output order.
    #[serde(default)]
    remote_htlc_signatures: Vec<Signature>,
    /// Number of untrimmed HTLC outputs on the acceptor's commitment, signed by
    /// the opener.
    acceptor_num_htlcs: usize,
}

/// A single in-flight HTLC used by a commitment vector.
///
/// The offering side comes from the key holding it: `incoming_htlcs` is offered
/// by the acceptor, `outgoing_htlcs` by the opener.
#[derive(serde::Deserialize)]
struct HtlcVector {
    /// HTLC ID.
    id: u64,
    /// HTLC amount in millisatoshis.
    amount_msat: u64,
    /// The expiry height of the HTLC.
    cltv_expiry: u32,
    /// Payment preimage, HTLC's payment hash is `SHA256` of this.
    #[serde(with = "hex")]
    payment_preimage: [u8; 32],
}

impl HtlcVector {
    /// Builds the HTLC as offered by `offerer`.
    fn to_htlc(&self, offerer: Side) -> Htlc {
        Htlc {
            id: self.id,
            offerer,
            amount_msat: self.amount_msat,
            cltv_expiry: self.cltv_expiry,
            payment_hash: Sha256::hash(&self.payment_preimage).to_byte_array(),
        }
    }
}

impl PartyKeys {
    /// Builds this party's channel config, taking the per-vector dust limit and
    /// the file-wide `to_self_delay`.
    fn to_party_config(&self, dust_limit_satoshis: u64, to_self_delay: u16) -> ChannelPartyConfig {
        ChannelPartyConfig {
            funding_pubkey: self.funding_pubkey,
            payment_basepoint: self.payment_basepoint,
            revocation_basepoint: self.revocation_basepoint,
            delayed_payment_basepoint: self.delayed_payment_basepoint,
            htlc_basepoint: self.htlc_basepoint,
            dust_limit_satoshis,
            to_self_delay,
        }
    }
}

impl TestVectorFile {
    /// Builds the channel config for a vector.
    fn build_channel_config(&self, vector: &CommitmentVector) -> ChannelConfig {
        let opener_dust_limit_satoshis = vector
            .opener_dust_limit_satoshis
            .or(vector.dust_limit_satoshis)
            .expect("opener dust limit must be set");
        let acceptor_dust_limit_satoshis = vector
            .acceptor_dust_limit_satoshis
            .or(vector.dust_limit_satoshis)
            .expect("acceptor dust limit must be set");

        ChannelConfig {
            funding_outpoint: self.funding_outpoint,
            funding_satoshis: self.funding_amount_satoshis,
            channel_type: self.channel_type.to_features(),
            opener: self
                .opener
                .to_party_config(opener_dust_limit_satoshis, self.to_self_delay),
            acceptor: self
                .acceptor
                .to_party_config(acceptor_dust_limit_satoshis, self.to_self_delay),
            minimum_depth: 8,
        }
    }

    /// Builds the commitment state for a vector, adding its HTLCs.
    fn build_commitment_state(&self, vector: &CommitmentVector) -> CommitmentState {
        let mut state = CommitmentState {
            commitment_number: self.commitment_number,
            feerate_per_kw: vector.feerate_per_kw,
            opener: CommitmentPartyState {
                per_commitment_point: self.opener.per_commitment_point,
                balance_msat: vector.to_opener_msat,
            },
            acceptor: CommitmentPartyState {
                per_commitment_point: self.acceptor.per_commitment_point,
                balance_msat: vector.to_acceptor_msat,
            },
            htlcs: vec![],
        };

        // Add incoming HTLCs.
        for htlc in &vector.incoming_htlcs {
            state
                .add_htlc(htlc.to_htlc(Side::Acceptor))
                .expect("balance covers HTLCs");
        }

        // Add outgoing HTLCs.
        for htlc in &vector.outgoing_htlcs {
            state
                .add_htlc(htlc.to_htlc(Side::Opener))
                .expect("balance covers HTLCs");
        }

        state
    }

    /// Builds the holder identity for the given side.
    fn build_holder_identity(&self, side: Side) -> HolderIdentity {
        let keys = match side {
            Side::Opener => &self.opener,
            Side::Acceptor => &self.acceptor,
        };

        HolderIdentity {
            side,
            funding_privkey: keys.funding_privkey,
            htlc_basepoint_privkey: keys.htlc_basepoint_privkey,
        }
    }
}

/// Runs every commitment vector in a test vector file.
///
/// Note: local is the opener.
pub fn run_commitment_vectors(json: &str) {
    let file: TestVectorFile = serde_json::from_str(json).expect("valid test vector file");
    assert!(
        !file.tests.is_empty(),
        "{}: no test vectors",
        file.description
    );

    let opener_holder = file.build_holder_identity(Side::Opener);
    let acceptor_holder = file.build_holder_identity(Side::Acceptor);

    for vector in &file.tests {
        let context = format!("{}: {}", file.description, vector.name);
        let channel_config = file.build_channel_config(vector);
        let commitment_state = file.build_commitment_state(vector);

        // Opener signs own commitment and its HTLC transactions.
        let (local_signature, local_htlc_signatures) =
            channel_config.sign_holder_commitment(&commitment_state, &opener_holder);
        assert_eq!(
            local_signature, vector.local_signature,
            "{context}: local signature mismatch",
        );
        assert_eq!(
            local_htlc_signatures, vector.local_htlc_signatures,
            "{context}: local HTLC signatures mismatch",
        );

        // Acceptor signs opener's commitment and HTLC transactions.
        assert!(
            channel_config.verify_counterparty_signature(
                &commitment_state,
                &opener_holder,
                &vector.remote_signature,
                &vector.remote_htlc_signatures,
            ),
            "{context}: remote signature does not verify",
        );

        // Opener signs the acceptor's commitment and HTLC transactions, then
        // the acceptor verifies it.
        let (acceptor_commit_sig, acceptor_htlc_sigs) =
            channel_config.sign_counterparty_commitment(&commitment_state, &opener_holder);
        assert_eq!(
            acceptor_htlc_sigs.len(),
            vector.acceptor_num_htlcs,
            "{context}: acceptor HTLC signature count mismatch",
        );
        assert!(
            channel_config.verify_counterparty_signature(
                &commitment_state,
                &acceptor_holder,
                &acceptor_commit_sig,
                &acceptor_htlc_sigs,
            ),
            "{context}: acceptor signature does not verify",
        );
    }
}
