#![no_std]

//! elixir_account — the Elixir smart account.
//!
//! Signer storage extends OpenZeppelin `stellar-contracts/accounts` rather than
//! reimplementing threshold and spending-limit policies (docs/ARCHITECTURE.md §3).
//! This crate holds the Elixir-specific state that OZ does not provide:
//!
//!   - config_epoch          proposal invalidation on config change
//!   - reconfigure()         atomic signer+threshold update (never expose raw add_signer)
//!   - freeze                emergency halt  (docs/GAPS.md A2)
//!   - last_activity         dead-man switch input  (docs/GAPS.md A1)
//!
//! `__check_auth` is still NOT implemented. Signers are stored and the threshold is
//! recorded, but nothing verifies signatures against them yet — that is #7, blocked
//! on the C-account simulation spike (#1). Storing a signer set is deliberately
//! separable from verifying it, which is why the first half could land early.
//!
//! Until `__check_auth` exists this account cannot authorize anything on its own:
//! `reconfigure`, `freeze`, and `unfreeze` all self-auth and so are unreachable
//! on-network. They are exercised in tests via `mock_all_auths`.
//!
//! Also outstanding before this is safe to deploy: the context-rule downgrade guard
//! (#8). OZ lets the *client* choose which rule to evaluate, so a permissive rule
//! must never be satisfiable for a context a stricter rule was meant to govern.

use elixir_types::{AccountConfig, ConfigEpoch, Error};
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, panic_with_error, Address, Env, Map,
    String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    add_context_rule, batch_add_signer, get_context_rule, get_context_rules_count, remove_signer,
    ContextRule, ContextRuleType, Signer,
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
    /// Approval threshold per context rule.
    ///
    /// Held here rather than in OZ's `simple_threshold` policy contract because
    /// that policy requires a cross-contract install against a deployed policy
    /// address. Keeping it local lets `reconfigure` validate signers and threshold
    /// in one atomic step. When `__check_auth` lands (#7) this either moves behind
    /// the policy or stays as the source of truth the policy reads.
    Threshold(u32),
}

/// Re-exported from elixir_types so the queue and account agree on one shape.
pub type Config = AccountConfig;

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
    /// Reentrancy: the Soroban host already refuses to invoke a contract that is
    /// on the call stack, and the queue marks the proposal Executed before calling
    /// this. The lock here is a third layer; it costs one temporary entry and
    /// would hold on its own if the host rule were ever relaxed. On a failure path
    /// it needs no clearing — the transaction reverts and takes it along.
    /// See docs/EXECUTION.md.
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
    /// This is the whole reason the method takes both halves at once. OZ's
    /// `simple_threshold` explicitly does NOT update the threshold when a signer
    /// set changes — its own docs warn that an administrator must call
    /// `set_threshold` manually "to avoid DoS or security degradation". Splitting
    /// that across two calls is the bug; validating both together is the fix.
    ///
    /// Requires self-auth, so it routes through __check_auth under the
    /// config-scoped context rule.
    ///
    /// The threshold is validated and recorded here, but not yet *enforced* —
    /// enforcement is `__check_auth`, which is #7 and blocked on the C-account
    /// simulation spike (#1). Storing signers is deliberately separable from
    /// verifying their signatures.
    pub fn reconfigure(e: Env, rule_id: u32, signers: Vec<Signer>, threshold: u32) {
        e.current_contract_address().require_auth();

        let signer_count = signers.len();
        if threshold == 0 || threshold > signer_count {
            panic_with_error!(&e, Error::UnsatisfiableThreshold);
        }

        apply_signers(&e, rule_id, &signers);
        set_threshold(&e, rule_id, threshold);

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

    /// Signers currently attached to a context rule.
    pub fn signers(e: Env, rule_id: u32) -> Vec<Signer> {
        get_context_rule(&e, rule_id).signers
    }

    /// Threshold recorded for a context rule. 0 = unset.
    pub fn threshold(e: Env, rule_id: u32) -> u32 {
        e.storage()
            .instance()
            .get(&DataKey::Threshold(rule_id))
            .unwrap_or(0)
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

/// Replace the signer set on `rule_id`, creating the rule on first use.
///
/// Replace, not append. `reconfigure` states the new signer set in full, and the
/// threshold is validated against `signers.len()` — appending would let the stored
/// count drift above the number the threshold was checked against, and would hit
/// OZ's MAX_SIGNERS (15) after a few calls.
///
/// Insertion happens before removal: OZ rejects a rule that is momentarily empty
/// (NoSignersAndPolicies), so the old set cannot be cleared first. The cost is that
/// the two sets coexist briefly, so a rotation is bounded by MAX_SIGNERS across
/// *both* sets — old + new must not exceed 15. Rotating a full 15-signer set in one
/// call is therefore not possible; that is an OZ constraint, not an Elixir one.
///
/// OZ registers signers per context rule and rejects canonical duplicates, so a
/// repeated key panics rather than silently inflating the signer count against
/// the threshold.
fn apply_signers(e: &Env, rule_id: u32, signers: &Vec<Signer>) {
    if rule_id < get_context_rules_count(e) {
        let previous = get_context_rule(e, rule_id).signer_ids;
        batch_add_signer(e, rule_id, signers);
        for signer_id in previous.iter() {
            remove_signer(e, rule_id, signer_id);
        }
    } else {
        let rule: ContextRule = add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "elixir"),
            None,
            signers,
            &Map::new(e),
        );
        if rule.id != rule_id {
            panic_with_error!(e, Error::Unauthorized);
        }
    }
}

fn set_threshold(e: &Env, rule_id: u32, threshold: u32) {
    e.storage()
        .instance()
        .set(&DataKey::Threshold(rule_id), &threshold);
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
