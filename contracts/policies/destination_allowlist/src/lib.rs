#![no_std]

//! destination_allowlist — a policy OZ does not ship. Restricts where a
//! transfer under a given context rule may send funds. Pairs with a spending
//! limit to make the account usable as an operating account rather than a
//! cold vault.
//!
//! Evaluation: the context must be a contract call whose function is a
//! token transfer (`transfer` or `transfer_from`, SEP-41); the destination
//! argument must be on the list. Anything else — a different function, a
//! malformed argument — is denied. Fail closed.
//!
//! Storage: one persistent entry per (account, rule), holding the list. Lists
//! are capped at MAX_DESTINATIONS so TTL rent stays bounded and a lookup stays
//! cheap.

use elixir_types::{Error, PolicyInterface};
use soroban_sdk::{
    auth::Context, contract, contractevent, contractimpl, contracttype, panic_with_error,
    symbol_short, Address, Env, Val, Vec,
};

pub const MAX_DESTINATIONS: u32 = 64;

const DAY_IN_LEDGERS: u32 = 17280;
const LIFETIME_THRESHOLD: u32 = 90 * DAY_IN_LEDGERS;
const BUMP_AMOUNT: u32 = 365 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// (smart_account, rule_id) → allowed destinations.
    List(Address, u32),
}

#[contractevent]
pub struct AllowlistInstalled {
    pub smart_account: Address,
    pub rule_id: u32,
    pub count: u32,
}

#[contractevent]
pub struct AllowlistUninstalled {
    pub smart_account: Address,
    pub rule_id: u32,
}

#[contract]
pub struct DestinationAllowlist;

#[contractimpl]
impl DestinationAllowlist {
    pub fn version(_e: Env) -> u32 {
        1
    }

    pub fn destinations(e: Env, smart_account: Address, rule_id: u32) -> Vec<Address> {
        load(&e, &smart_account, rule_id)
    }

    pub fn is_allowed(e: Env, smart_account: Address, rule_id: u32, destination: Address) -> bool {
        load(&e, &smart_account, rule_id).contains(&destination)
    }
}

#[contractimpl]
impl PolicyInterface for DestinationAllowlist {
    fn enforce(
        e: Env,
        smart_account: Address,
        rule_id: u32,
        context: Context,
        _authenticated_signers: Vec<Address>,
    ) {
        smart_account.require_auth();
        let list = load(&e, &smart_account, rule_id);
        let destination = transfer_destination(&e, &context);
        if !list.contains(&destination) {
            panic_with_error!(&e, Error::PolicyViolation);
        }
        touch(&e, &smart_account, rule_id);
    }

    /// `params`: `Vec<Address>` of allowed destinations. Replaces any prior list.
    fn install(e: Env, smart_account: Address, rule_id: u32, params: Val) {
        smart_account.require_auth();
        let list: Vec<Address> = match Vec::<Address>::try_from_val(&e, &params) {
            Ok(v) => v,
            Err(_) => panic_with_error!(&e, Error::PolicyViolation),
        };
        if list.len() > MAX_DESTINATIONS {
            panic_with_error!(&e, Error::AllowlistTooLarge);
        }
        let key = DataKey::List(smart_account.clone(), rule_id);
        e.storage().persistent().set(&key, &list);
        e.storage()
            .persistent()
            .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
        AllowlistInstalled {
            smart_account,
            rule_id,
            count: list.len(),
        }
        .publish(&e);
    }

    fn uninstall(e: Env, smart_account: Address, rule_id: u32) {
        smart_account.require_auth();
        e.storage()
            .persistent()
            .remove(&DataKey::List(smart_account.clone(), rule_id));
        AllowlistUninstalled {
            smart_account,
            rule_id,
        }
        .publish(&e);
    }
}

use soroban_sdk::TryFromVal;

/// Destination of a SEP-41 transfer, or deny.
///   transfer(from, to, amount)                → args[1]
///   transfer_from(spender, from, to, amount)  → args[2]
fn transfer_destination(e: &Env, context: &Context) -> Address {
    let call = match context {
        Context::Contract(c) => c,
        _ => panic_with_error!(e, Error::PolicyViolation),
    };
    let idx = if call.fn_name == symbol_short!("transfer") {
        1
    } else if call.fn_name == soroban_sdk::Symbol::new(e, "transfer_from") {
        2
    } else {
        panic_with_error!(e, Error::PolicyViolation)
    };
    let raw = match call.args.get(idx) {
        Some(v) => v,
        None => panic_with_error!(e, Error::PolicyViolation),
    };
    match Address::try_from_val(e, &raw) {
        Ok(a) => a,
        Err(_) => panic_with_error!(e, Error::PolicyViolation),
    }
}

fn load(e: &Env, smart_account: &Address, rule_id: u32) -> Vec<Address> {
    match e
        .storage()
        .persistent()
        .get(&DataKey::List(smart_account.clone(), rule_id))
    {
        Some(l) => l,
        None => panic_with_error!(e, Error::PolicyNotInstalled),
    }
}

fn touch(e: &Env, smart_account: &Address, rule_id: u32) {
    e.storage().persistent().extend_ttl(
        &DataKey::List(smart_account.clone(), rule_id),
        LIFETIME_THRESHOLD,
        BUMP_AMOUNT,
    );
}

mod test;
