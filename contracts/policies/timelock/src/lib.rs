#![no_std]

//! timelock — a delay between "the signers agreed" and "it can run", giving
//! observers a window to cancel. The queue has its own timelock for queued
//! proposals; this one covers the fast path, where there is no proposal.
//!
//! Two steps, because a policy that panics cannot also remember anything:
//!
//!   1. `schedule(account, rule, payload)` — authorized by the account (so it
//!      needs the rule's normal threshold). Records `now`.
//!   2. `enforce(...)` — computes the same payload from the context, requires
//!      `scheduled_at + delay <= now < scheduled_at + delay + window`, and
//!      consumes the entry before returning. One schedule, one execution.
//!
//! `cancel(account, rule, payload)` removes a pending entry. Any signer the
//! account lets call `cancel` can use the window — that is the point.
//!
//! The payload is sha256 of the context's XDR: same contract, same function,
//! same arguments. Changing any argument after scheduling means starting over.

use elixir_types::{Error, PolicyInterface};
use soroban_sdk::{
    auth::Context, contract, contractevent, contractimpl, contracttype, panic_with_error,
    xdr::ToXdr, Address, Bytes, BytesN, Env, TryFromVal, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const CONFIG_LIFETIME_THRESHOLD: u32 = 90 * DAY_IN_LEDGERS;
const CONFIG_BUMP_AMOUNT: u32 = 365 * DAY_IN_LEDGERS;
const SCHEDULE_LIFETIME_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const SCHEDULE_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelockParams {
    /// Seconds that must pass after scheduling.
    pub delay: u64,
    /// Seconds after the delay during which execution is allowed. 0 = forever.
    pub window: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config(Address, u32),
    /// (account, rule, payload) → scheduled_at.
    Scheduled(Address, u32, BytesN<32>),
}

#[contractevent]
pub struct TimelockInstalled {
    pub smart_account: Address,
    pub rule_id: u32,
    pub delay: u64,
    pub window: u64,
}

#[contractevent]
pub struct Scheduled {
    pub smart_account: Address,
    pub rule_id: u32,
    pub payload: BytesN<32>,
    pub executable_at: u64,
}

#[contractevent]
pub struct ScheduleCancelled {
    pub smart_account: Address,
    pub rule_id: u32,
    pub payload: BytesN<32>,
}

#[contract]
pub struct Timelock;

#[contractimpl]
impl Timelock {
    pub fn version(_e: Env) -> u32 {
        1
    }

    pub fn params(e: Env, smart_account: Address, rule_id: u32) -> TimelockParams {
        load_params(&e, &smart_account, rule_id)
    }

    /// sha256 of the context XDR — what `schedule` expects for a given call.
    pub fn payload_of(e: Env, context: Context) -> BytesN<32> {
        payload(&e, &context)
    }

    pub fn scheduled_at(
        e: Env,
        smart_account: Address,
        rule_id: u32,
        payload: BytesN<32>,
    ) -> Option<u64> {
        e.storage()
            .persistent()
            .get(&DataKey::Scheduled(smart_account, rule_id, payload))
    }

    /// Start the clock for one future execution of `payload`.
    pub fn schedule(e: Env, smart_account: Address, rule_id: u32, payload: BytesN<32>) {
        smart_account.require_auth();
        let p = load_params(&e, &smart_account, rule_id);
        let now = e.ledger().timestamp();
        let key = DataKey::Scheduled(smart_account.clone(), rule_id, payload.clone());
        e.storage().persistent().set(&key, &now);
        e.storage().persistent().extend_ttl(
            &key,
            SCHEDULE_LIFETIME_THRESHOLD,
            SCHEDULE_BUMP_AMOUNT,
        );
        Scheduled {
            smart_account,
            rule_id,
            payload,
            executable_at: now + p.delay,
        }
        .publish(&e);
    }

    pub fn cancel(e: Env, smart_account: Address, rule_id: u32, payload: BytesN<32>) {
        smart_account.require_auth();
        let key = DataKey::Scheduled(smart_account.clone(), rule_id, payload.clone());
        if !e.storage().persistent().has(&key) {
            panic_with_error!(&e, Error::NotScheduled);
        }
        e.storage().persistent().remove(&key);
        ScheduleCancelled {
            smart_account,
            rule_id,
            payload,
        }
        .publish(&e);
    }
}

#[contractimpl]
impl PolicyInterface for Timelock {
    fn enforce(
        e: Env,
        smart_account: Address,
        rule_id: u32,
        context: Context,
        _authenticated_signers: Vec<Address>,
    ) {
        smart_account.require_auth();
        let p = load_params(&e, &smart_account, rule_id);
        let key = DataKey::Scheduled(smart_account, rule_id, payload(&e, &context));
        let scheduled_at: u64 = match e.storage().persistent().get(&key) {
            Some(t) => t,
            None => panic_with_error!(&e, Error::NotScheduled),
        };
        let now = e.ledger().timestamp();
        let executable_at = scheduled_at.saturating_add(p.delay);
        if now < executable_at {
            panic_with_error!(&e, Error::TimelockNotElapsed);
        }
        if p.window > 0 && now >= executable_at.saturating_add(p.window) {
            panic_with_error!(&e, Error::ProposalExpired);
        }
        // Consume before returning: one schedule, one execution.
        e.storage().persistent().remove(&key);
    }

    /// `params`: `TimelockParams`.
    fn install(e: Env, smart_account: Address, rule_id: u32, params: Val) {
        smart_account.require_auth();
        let p = match TimelockParams::try_from_val(&e, &params) {
            Ok(p) => p,
            Err(_) => panic_with_error!(&e, Error::PolicyViolation),
        };
        let key = DataKey::Config(smart_account.clone(), rule_id);
        e.storage().persistent().set(&key, &p);
        e.storage()
            .persistent()
            .extend_ttl(&key, CONFIG_LIFETIME_THRESHOLD, CONFIG_BUMP_AMOUNT);
        TimelockInstalled {
            smart_account,
            rule_id,
            delay: p.delay,
            window: p.window,
        }
        .publish(&e);
    }

    fn uninstall(e: Env, smart_account: Address, rule_id: u32) {
        smart_account.require_auth();
        e.storage()
            .persistent()
            .remove(&DataKey::Config(smart_account, rule_id));
    }
}

fn payload(e: &Env, context: &Context) -> BytesN<32> {
    let bytes: Bytes = context.clone().to_xdr(e);
    e.crypto().sha256(&bytes).into()
}

fn load_params(e: &Env, smart_account: &Address, rule_id: u32) -> TimelockParams {
    match e
        .storage()
        .persistent()
        .get(&DataKey::Config(smart_account.clone(), rule_id))
    {
        Some(p) => p,
        None => panic_with_error!(e, Error::PolicyNotInstalled),
    }
}

mod test;
