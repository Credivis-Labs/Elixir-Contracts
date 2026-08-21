#![no_std]

use soroban_sdk::{contracterror, contracttype, Address, Env, Symbol, Val, Vec};

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

/// elixir_account's configuration. Shared here so elixir_queue can read it over a
/// cross-contract call without depending on the account crate.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountConfig {
    pub config_epoch: ConfigEpoch,
    /// Seconds between approval settling and execution eligibility.
    pub time_lock: u32,
    /// elixir_queue address, if the queue module is enabled.
    pub queue: Option<Address>,
    /// Next sub-account index.
    pub subaccounts: u32,
    /// Ledger timestamp until which non-config execution is halted. 0 = not frozen.
    pub frozen_until: u64,
}

/// The slice of elixir_account that other Elixir contracts call.
#[soroban_sdk::contractclient(name = "AccountClient")]
pub trait AccountInterface {
    fn config(e: Env) -> AccountConfig;
    fn exec_queued(e: Env, target: Address, fn_name: Symbol, args: Vec<Val>) -> Val;
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
    EmptyProposal = 14,
    ProposalNotFound = 15,
    NotAMember = 16,
}
