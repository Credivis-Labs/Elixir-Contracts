#![no_std]

//! elixir_subaccount — a "vault". Squads gets 256 free addresses from PDA
//! derivation; Stellar has no PDAs, so sub-accounts are real deployed contracts.
//! One Wasm, N cheap instances, deployed from the factory with
//! salt = sha256(parent ‖ index) so the address is knowable before deployment.
//!
//! Two ways for the parent to act as this address:
//!
//!   * `exec` — the parent (or the queue via `exec_queued`) invokes it directly;
//!     invoker auth satisfies `parent.require_auth()`.
//!   * `__check_auth` — CAP-71 delegation. When something calls
//!     `require_auth()` on this address, the host runs `__check_auth` here, and
//!     we forward the whole authorization to the parent. The parent's own
//!     `__check_auth` (threshold, policies) then decides. No signature logic
//!     lives here. docs/ARCHITECTURE.md §4.3.
//!
//! Policies can be scoped per sub-account by making a context rule's scope this
//! address — that is the parent's concern, not this contract's.

use elixir_types::Error;
use soroban_sdk::{
    auth::Context, contract, contractimpl, contracttype, crypto::Hash, panic_with_error, Address,
    Env, Symbol, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const INSTANCE_LIFETIME_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const INSTANCE_BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;

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
        bump_instance(&e);
    }

    pub fn parent(e: Env) -> Address {
        load_parent(&e)
    }

    pub fn index(e: Env) -> u32 {
        match e.storage().instance().get(&DataKey::Index) {
            Some(i) => i,
            None => panic_with_error!(&e, Error::NotInitialized),
        }
    }

    /// Called by the parent to act as this address. Direct analogue of Squads'
    /// invoke_signed with vault seeds. Invoker auth covers direct calls; deeper
    /// sub-invocations that `require_auth` this address resolve through
    /// `__check_auth` below.
    pub fn exec(e: Env, target: Address, fn_name: Symbol, args: Vec<Val>) -> Val {
        load_parent(&e).require_auth();
        bump_instance(&e);
        e.invoke_contract(&target, &fn_name, args)
    }
}

#[contractimpl]
impl soroban_sdk::auth::CustomAccountInterface for ElixirSubaccount {
    type Signature = ();
    type Error = Error;

    /// Forward the authorization to the parent (CAP-71). The auth entry must
    /// name exactly the parent as its delegated signer; anything else is
    /// rejected here before the host asks the parent anything.
    fn __check_auth(
        e: Env,
        _signature_payload: Hash<32>,
        _signatures: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let parent = load_parent(&e);
        let delegates = e.custom_account().get_delegated_signers();
        if delegates.len() != 1 || delegates.get(0) != Some(parent.clone()) {
            return Err(Error::Unauthorized);
        }
        e.custom_account().delegate_auth(&parent);
        Ok(())
    }
}

fn load_parent(e: &Env) -> Address {
    match e.storage().instance().get(&DataKey::Parent) {
        Some(p) => p,
        None => panic_with_error!(e, Error::NotInitialized),
    }
}

fn bump_instance(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

mod test;
