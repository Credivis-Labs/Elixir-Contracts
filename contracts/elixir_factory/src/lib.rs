#![no_std]

//! elixir_factory — deterministic deploy (salt = Squads' create_key analogue),
//! registry, and Wasm version management.
//!
//! Upgrade posture (docs/GAPS.md B5): upgradeable with a mandatory timelock and
//! opt-in adoption. The factory publishes versions; each account votes to adopt.
//! Accounts wanting immutability simply never adopt.
//!
//! Scaffold — see docs/GAPS.md §F3 spike 3 (per-instance deploy cost + TTL rent)
//! before committing to per-instance deployment.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct ElixirFactory;

#[contractimpl]
impl ElixirFactory {
    pub fn version(_e: Env) -> u32 {
        0
    }
}
