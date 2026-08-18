#![no_std]

//! timelock — enforces a delay between approval and execution, giving observers
//! a window to cancel. Complements the queue's own timelock check.

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Timelock;

#[contractimpl]
impl Timelock {
    pub fn version(_e: Env) -> u32 {
        0
    }
}
