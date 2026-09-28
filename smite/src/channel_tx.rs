//! BOLT 3 channel transaction construction.
//!
//! This module builds Lightning channel on-chain transactions: the funding
//! transaction and the commitment transaction.

mod commitment;
mod funding;

pub use commitment::{
    BroadcastableCommitment, ChannelCommitments, ChannelConfig, ChannelHtlcUpdates,
    ChannelPartyConfig, ChannelState, ClosingSignatures, CommitmentCost, CommitmentError,
    CommitmentState, HolderIdentity, Htlc, HtlcUpdateQueue, PendingHtlcUpdate, Side,
    per_commitment_secret,
};
pub use funding::{FundingTransaction, InsufficientFunds, build_funding_transaction};
