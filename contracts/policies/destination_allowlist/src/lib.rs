#![no_std]

//! destination_allowlist — policy OZ does not ship. Restricts transfer
//! destinations per context rule. Pairs with OZ spending_limit to make the
//! account usable as an operating account rather than a cold vault.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DestinationAllowlist;

#[contractimpl]
impl DestinationAllowlist {
    pub fn version(_e: Env) -> u32 {
        0
    }
}
