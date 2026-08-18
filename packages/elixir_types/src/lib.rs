#![no_std]

use soroban_sdk::{contracterror, contracttype, Address, Symbol, Val, Vec};

/// Bumped on any signer / threshold / policy / rule mutation.
/// Stamped onto every proposal at creation; `execute` rejects a mismatch.
/// Port of Squads' `stale_transaction_index`.
pub type ConfigEpoch = u32;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    pub target: Address,
    pub fn_name: Symbol,
    pub args: Vec<Val>,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Draft,
    Active,
    Approved,
    Rejected,
    Executed,
    Cancelled,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u64,
    pub creator: Address,
    /// None = the Elixir account itself (sub-account 0).
    pub subaccount: Option<Address>,
    pub invocations: Vec<Invocation>,
    pub config_epoch: ConfigEpoch,
    pub status: Status,
    pub approvals: Vec<Address>,
    pub rejections: Vec<Address>,
    pub approved_at: Option<u64>,
    /// Absolute ledger timestamp. Never derive expiry from TTL — anyone can extend TTL.
    pub expires_at: u64,
}

/// Role bitmask. A compromised proposer key must not be able to approve.
pub const ROLE_INITIATE: u32 = 1;
pub const ROLE_VOTE: u32 = 2;
pub const ROLE_EXECUTE: u32 = 4;
pub const ROLE_ALL: u32 = ROLE_INITIATE | ROLE_VOTE | ROLE_EXECUTE;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    /// Config changed after this proposal was created.
    StaleConfigEpoch = 4,
    InvalidStatus = 5,
    ThresholdNotMet = 6,
    TimelockNotElapsed = 7,
    ProposalExpired = 8,
    /// Threshold is zero or exceeds the signer count.
    UnsatisfiableThreshold = 9,
    QueueDisabled = 10,
    AlreadyVoted = 11,
    Frozen = 12,
    Reentrancy = 13,
}
