#![no_std]

//! elixir_subaccount — a "vault". Squads gets 256 free addresses from PDA
//! derivation; Stellar has no PDAs, so sub-accounts are real deployed contracts.
//! One Wasm, N cheap instances, deployed from the factory with
//! salt = hash(elixir_address, index) so the address is knowable before deployment.
//!
//! Scaffold. __check_auth delegates to the parent via CAP-71
//! (parent.delegate_account_auth()) — confirm that host fn against soroban-sdk 27.x
//! before implementing. See docs/ARCHITECTURE.md §4.3.

use elixir_types::Error;
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Env, Symbol, Val, Vec,
};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Parent,
    Index,
}

#[contract]
pub struct ElixirSubaccount;

#[contractimpl]
impl ElixirSubaccount {
    pub fn __constructor(e: Env, parent: Address, index: u32) {
        if e.storage().instance().has(&DataKey::Parent) {
            panic_with_error!(&e, Error::AlreadyInitialized);
        }
        e.storage().instance().set(&DataKey::Parent, &parent);
        e.storage().instance().set(&DataKey::Index, &index);
    }

    pub fn parent(e: Env) -> Address {
        match e.storage().instance().get(&DataKey::Parent) {
            Some(p) => p,
            None => panic_with_error!(&e, Error::NotInitialized),
        }
    }

    /// Called by the parent to act as this address. Direct analogue of Squads'
    /// invoke_signed with vault seeds.
    pub fn exec(e: Env, target: Address, fn_name: Symbol, args: Vec<Val>) -> Val {
        let parent: Address = Self::parent(e.clone());
        parent.require_auth();
        // e.authorize_as_current_contract(tree);
        e.invoke_contract(&target, &fn_name, args)
    }
}
