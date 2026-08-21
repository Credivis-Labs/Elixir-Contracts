#![no_std]

//! session_key — scoped, expiring authority for a bot or service.
//!
//! Hard-bounded on every axis: one key (the authenticated signer set must be
//! exactly `key`), one target contract, one method, a spend cap (for SEP-41
//! `transfer`, the amount argument is charged against `remaining` and
//! decremented BEFORE returning), and an absolute expiry (`now < expires_at`,
//! a timestamp, never a TTL).
//!
//! A session key attached to a context rule as its only signer, with this
//! policy, is how an automated payer gets "up to N of asset X to contract Y
//! until Friday" and nothing else.

use elixir_types::{Error, PolicyInterface};
use soroban_sdk::{
    auth::Context, contract, contractevent, contractimpl, contracttype, panic_with_error,
    symbol_short, Address, Env, Symbol, TryFromVal, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const LIFETIME_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionParams {
    /// The signer this session belongs to.
    pub key: Address,
    /// The only contract it may call.
    pub target: Address,
    /// The only function it may call.
    pub fn_name: Symbol,
    /// Total it may move through `transfer`, in the asset's smallest unit.
    /// Ignored (no cap) when `fn_name` is not `transfer`.
    pub spend_cap: i128,
    /// Ledger timestamp after which the session is dead.
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub params: SessionParams,
    pub remaining: i128,
    pub uses: u32,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Session(Address, u32),
}

#[contractevent]
pub struct SessionInstalled {
    pub smart_account: Address,
    pub rule_id: u32,
    pub key: Address,
    pub target: Address,
    pub expires_at: u64,
}

#[contractevent]
pub struct SessionUsed {
    pub smart_account: Address,
    pub rule_id: u32,
    pub spent: i128,
    pub remaining: i128,
}

#[contractevent]
pub struct SessionRevoked {
    pub smart_account: Address,
    pub rule_id: u32,
}

#[contract]
pub struct SessionKey;

#[contractimpl]
impl SessionKey {
    pub fn version(_e: Env) -> u32 {
        1
    }

    pub fn session(e: Env, smart_account: Address, rule_id: u32) -> Session {
        load(&e, &smart_account, rule_id)
    }
}

#[contractimpl]
impl PolicyInterface for SessionKey {
    fn enforce(
        e: Env,
        smart_account: Address,
        rule_id: u32,
        context: Context,
        authenticated_signers: Vec<Address>,
    ) {
        smart_account.require_auth();
        let mut s = load(&e, &smart_account, rule_id);

        if e.ledger().timestamp() >= s.params.expires_at {
            panic_with_error!(&e, Error::SessionExpired);
        }
        if authenticated_signers.len() != 1
            || authenticated_signers.get(0) != Some(s.params.key.clone())
        {
            panic_with_error!(&e, Error::Unauthorized);
        }
        let call = match &context {
            Context::Contract(c) => c,
            _ => panic_with_error!(&e, Error::PolicyViolation),
        };
        if call.contract != s.params.target || call.fn_name != s.params.fn_name {
            panic_with_error!(&e, Error::PolicyViolation);
        }

        let mut spent: i128 = 0;
        if call.fn_name == symbol_short!("transfer") {
            // transfer(from, to, amount)
            let raw = match call.args.get(2) {
                Some(v) => v,
                None => panic_with_error!(&e, Error::PolicyViolation),
            };
            let amount = match i128::try_from_val(&e, &raw) {
                Ok(a) => a,
                Err(_) => panic_with_error!(&e, Error::PolicyViolation),
            };
            if amount <= 0 || amount > s.remaining {
                panic_with_error!(&e, Error::SpendCapExceeded);
            }
            s.remaining -= amount;
            spent = amount;
        }
        s.uses += 1;

        // Charge before returning. docs/EXECUTION.md.
        store(&e, &smart_account, rule_id, &s);
        SessionUsed {
            smart_account,
            rule_id,
            spent,
            remaining: s.remaining,
        }
        .publish(&e);
    }

    /// `params`: `SessionParams`. Re-installing resets `remaining` to the cap.
    fn install(e: Env, smart_account: Address, rule_id: u32, params: Val) {
        smart_account.require_auth();
        let p = match SessionParams::try_from_val(&e, &params) {
            Ok(p) => p,
            Err(_) => panic_with_error!(&e, Error::PolicyViolation),
        };
        if p.spend_cap < 0 || p.expires_at <= e.ledger().timestamp() {
            panic_with_error!(&e, Error::PolicyViolation);
        }
        let s = Session {
            remaining: p.spend_cap,
            uses: 0,
            params: p.clone(),
        };
        store(&e, &smart_account, rule_id, &s);
        SessionInstalled {
            smart_account,
            rule_id,
            key: p.key,
            target: p.target,
            expires_at: p.expires_at,
        }
        .publish(&e);
    }

    fn uninstall(e: Env, smart_account: Address, rule_id: u32) {
        smart_account.require_auth();
        e.storage()
            .persistent()
            .remove(&DataKey::Session(smart_account.clone(), rule_id));
        SessionRevoked {
            smart_account,
            rule_id,
        }
        .publish(&e);
    }
}

fn load(e: &Env, smart_account: &Address, rule_id: u32) -> Session {
    match e
        .storage()
        .persistent()
        .get(&DataKey::Session(smart_account.clone(), rule_id))
    {
        Some(s) => s,
        None => panic_with_error!(e, Error::PolicyNotInstalled),
    }
}

fn store(e: &Env, smart_account: &Address, rule_id: u32, s: &Session) {
    let key = DataKey::Session(smart_account.clone(), rule_id);
    e.storage().persistent().set(&key, s);
    e.storage()
        .persistent()
        .extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
}

mod test;
