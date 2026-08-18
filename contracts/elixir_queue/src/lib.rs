#![no_std]

//! elixir_queue — opt-in on-chain proposal queue (Squads-style async voting).
//!
//! Deliberately a SEPARATE contract from elixir_account: the audit surface of
//! "the thing that holds funds" should stay as small as possible.
//! See docs/ARCHITECTURE.md §4.1.
//!
//! execute() gate:
//!   status == Approved
//!   config_epoch == account.config_epoch     (no execution across a config change)
//!   now >= approved_at + time_lock
//!   now <  expires_at                        (absolute, not TTL-derived)
//!   caller has ROLE_EXECUTE
//!
//! Reentrancy: mark the proposal Executed BEFORE the external invocation.
//! docs/GAPS.md B3.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ElixirQueue;

#[contractimpl]
impl ElixirQueue {
    pub fn version(_e: Env) -> u32 {
        0
    }
}
