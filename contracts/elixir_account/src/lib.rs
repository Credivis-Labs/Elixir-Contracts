#![no_std]

//! elixir_account — the Elixir smart account.
//!
//! Scaffold. `__check_auth` is intentionally NOT implemented here: the plan
//! (docs/ARCHITECTURE.md §3) is to extend OpenZeppelin `stellar-contracts/accounts`
//! rather than reimplement threshold and spending-limit policies. This crate holds
//! the Elixir-specific state that OZ does not provide:
//!
//!   - config_epoch          proposal invalidation on config change
//!   - reconfigure()         atomic signer+threshold update (never expose raw add_signer)
//!   - freeze                emergency halt  (docs/GAPS.md A2)
//!   - last_activity         dead-man switch input  (docs/GAPS.md A1)
//!
//! Before implementing: resolve the week-one spikes in docs/GAPS.md §F3.

use elixir_types::{ConfigEpoch, Error};
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, panic_with_error, Address, Env, Symbol,
    Val, Vec,
};

/// Soroban RPC retains events for days, not forever — the audit trail must come
/// from your own ingest (Galexie/Hubble). Emit richly. docs/ARCHITECTURE.md §6.7.
#[contractevent]
pub struct Reconfigured {
    pub rule_id: u32,
    pub signer_count: u32,
    pub threshold: u32,
    pub config_epoch: ConfigEpoch,
}

#[contractevent]
pub struct Frozen {
    pub frozen_until: u64,
}

#[contractevent]
pub struct Unfrozen {
    pub at: u64,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    /// Ledger timestamp of the last successful auth. Input to the dead-man switch.
    LastActivity,
    /// Set while an external invocation is in flight. Reentrancy guard.
    ExecLock,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Config {
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

const DAY_IN_LEDGERS: u32 = 17280;
const INSTANCE_LIFETIME_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const INSTANCE_BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;

/// Bound the freeze so a single signer cannot halt the account indefinitely.
pub const MAX_FREEZE_SECONDS: u64 = 72 * 60 * 60;

#[contract]
pub struct ElixirAccount;

#[contractimpl]
impl ElixirAccount {
    pub fn __constructor(e: Env, time_lock: u32, queue: Option<Address>) {
        if e.storage().instance().has(&DataKey::Config) {
            panic_with_error!(&e, Error::AlreadyInitialized);
        }
        e.storage().instance().set(
            &DataKey::Config,
            &Config {
                config_epoch: 0,
                time_lock,
                queue,
                subaccounts: 0,
                frozen_until: 0,
            },
        );
        bump_instance(&e);
    }

    pub fn config(e: Env) -> Config {
        load_config(&e)
    }

    /// Queue path. Called by elixir_queue after threshold + timelock are satisfied.
    ///
    /// Reentrancy: the caller (elixir_queue) MUST mark the proposal Executed before
    /// invoking this. The lock here is defense in depth against a hostile target
    /// calling back in. See docs/GAPS.md B3.
    pub fn exec_queued(
        e: Env,
        target: Address,
        fn_name: Symbol,
        args: Vec<Val>,
        // tree: Vec<InvokerContractAuthEntry> — pre-authorize deeper sub-invocations
        // that will require_auth(self). Direct calls are covered by invoker auth.
        // Wire this up once the SDK surface is confirmed against 27.x.
    ) -> Val {
        let cfg = load_config(&e);
        let queue = match cfg.queue {
            Some(ref q) => q.clone(),
            None => panic_with_error!(&e, Error::QueueDisabled),
        };
        queue.require_auth();

        if is_frozen(&e, &cfg) {
            panic_with_error!(&e, Error::Frozen);
        }
        if e.storage().temporary().has(&DataKey::ExecLock) {
            panic_with_error!(&e, Error::Reentrancy);
        }
        e.storage().temporary().set(&DataKey::ExecLock, &true);

        // e.authorize_as_current_contract(tree);
        let result: Val = e.invoke_contract(&target, &fn_name, args);

        e.storage().temporary().remove(&DataKey::ExecLock);
        touch_activity(&e);
        result
    }

    /// Atomic reconfiguration. Never expose raw add_signer / set_threshold —
    /// a signer-set change that leaves the threshold stale can render the account
    /// permanently unsatisfiable. See docs/ARCHITECTURE.md §6.5.
    ///
    /// Requires self-auth, so it routes through __check_auth under the
    /// config-scoped context rule.
    pub fn reconfigure(e: Env, rule_id: u32, signer_count: u32, threshold: u32) {
        e.current_contract_address().require_auth();

        if threshold == 0 || threshold > signer_count {
            panic_with_error!(&e, Error::UnsatisfiableThreshold);
        }

        // apply_signers(&e, rule_id, &signers);
        // apply_threshold(&e, rule_id, threshold);

        bump_config_epoch(&e);
        touch_activity(&e);
        Reconfigured {
            rule_id,
            signer_count,
            threshold,
            config_epoch: load_config(&e).config_epoch,
        }
        .publish(&e);
    }

    /// Emergency halt. Deliberately low threshold (1-of-N) via its own context rule:
    /// raising the alarm must be cheaper than moving money. Bounded so it expires on
    /// its own; unfreezing takes normal threshold. See docs/GAPS.md A2.
    pub fn freeze(e: Env, duration_seconds: u64) {
        e.current_contract_address().require_auth();

        let d = if duration_seconds > MAX_FREEZE_SECONDS {
            MAX_FREEZE_SECONDS
        } else {
            duration_seconds
        };
        let mut cfg = load_config(&e);
        cfg.frozen_until = e.ledger().timestamp() + d;
        e.storage().instance().set(&DataKey::Config, &cfg);

        Frozen {
            frozen_until: cfg.frozen_until,
        }
        .publish(&e);
    }

    pub fn unfreeze(e: Env) {
        e.current_contract_address().require_auth();
        let mut cfg = load_config(&e);
        cfg.frozen_until = 0;
        e.storage().instance().set(&DataKey::Config, &cfg);
        Unfrozen {
            at: e.ledger().timestamp(),
        }
        .publish(&e);
    }

    pub fn is_frozen(e: Env) -> bool {
        let cfg = load_config(&e);
        is_frozen(&e, &cfg)
    }

    /// Ledger timestamp of the last successful auth. Dead-man switch input.
    pub fn last_activity(e: Env) -> u64 {
        e.storage()
            .instance()
            .get(&DataKey::LastActivity)
            .unwrap_or(0)
    }
}

fn load_config(e: &Env) -> Config {
    match e.storage().instance().get(&DataKey::Config) {
        Some(c) => c,
        None => panic_with_error!(e, Error::NotInitialized),
    }
}

fn is_frozen(e: &Env, cfg: &Config) -> bool {
    cfg.frozen_until > e.ledger().timestamp()
}

fn bump_config_epoch(e: &Env) {
    let mut cfg = load_config(e);
    cfg.config_epoch += 1;
    e.storage().instance().set(&DataKey::Config, &cfg);
}

fn touch_activity(e: &Env) {
    e.storage()
        .instance()
        .set(&DataKey::LastActivity, &e.ledger().timestamp());
    bump_instance(e);
}

fn bump_instance(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

mod test;
