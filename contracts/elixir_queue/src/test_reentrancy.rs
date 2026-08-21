#![cfg(test)]

//! Reentrancy: a hostile target that calls back into the queue or the account
//! during execution. docs/GAPS.md B3, issue #9.
//!
//! Three layers, outermost first. The Soroban host refuses to invoke a contract
//! that is already on the call stack (`Context / InvalidAction`); this is what
//! actually fires. The queue writes `Executed` before the external call, so if
//! the host rule were ever relaxed a re-entrant `execute` would hit
//! `InvalidStatus`. `ExecLock` on the account covers a re-entrant `exec_queued`.
//!
//! The tests assert the host layer and prove the transaction reverts cleanly.
//! See docs/EXECUTION.md.

use crate::{ElixirQueue, ElixirQueueClient};
use elixir_account::ElixirAccount;
use elixir_types::{AccountClient, Invocation, Status, ROLE_ALL};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec,
    xdr::{ScErrorCode, ScErrorType},
    Address, Env, IntoVal, Symbol, Val, Vec,
};

/// A target that, when invoked, tries to re-enter. Which re-entry it attempts
/// is chosen per test so each path is covered in isolation.
#[contract]
pub struct Hostile;

#[contracttype]
#[derive(Clone)]
pub enum HostileKey {
    Queue,
    Account,
    Member,
    ProposalId,
    Mode,
    Hits,
}

#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Call queue.execute(member, id) again from inside the invocation.
    ReenterQueue,
    /// Call account.exec_queued(...) directly from inside the invocation.
    ReenterAccount,
    /// Do nothing hostile; just count.
    Benign,
}

#[contractimpl]
impl Hostile {
    pub fn arm(e: Env, queue: Address, account: Address, member: Address, id: u64, mode: Mode) {
        e.storage().instance().set(&HostileKey::Queue, &queue);
        e.storage().instance().set(&HostileKey::Account, &account);
        e.storage().instance().set(&HostileKey::Member, &member);
        e.storage().instance().set(&HostileKey::ProposalId, &id);
        e.storage().instance().set(&HostileKey::Mode, &mode);
    }

    pub fn hits(e: Env) -> u32 {
        e.storage().instance().get(&HostileKey::Hits).unwrap_or(0)
    }

    /// The invocation the proposal targets.
    pub fn poke(e: Env) {
        let hits: u32 = e.storage().instance().get(&HostileKey::Hits).unwrap_or(0) + 1;
        e.storage().instance().set(&HostileKey::Hits, &hits);

        let mode: Mode = e.storage().instance().get(&HostileKey::Mode).unwrap();
        match mode {
            Mode::Benign => {}
            Mode::ReenterQueue => {
                let queue: Address = e.storage().instance().get(&HostileKey::Queue).unwrap();
                let member: Address = e.storage().instance().get(&HostileKey::Member).unwrap();
                let id: u64 = e.storage().instance().get(&HostileKey::ProposalId).unwrap();
                ElixirQueueClient::new(&e, &queue).execute(&member, &id);
            }
            Mode::ReenterAccount => {
                let account: Address = e.storage().instance().get(&HostileKey::Account).unwrap();
                let me = e.current_contract_address();
                AccountClient::new(&e, &account).exec_queued(
                    &me,
                    &symbol_short!("poke"),
                    &Vec::<Val>::new(&e),
                );
            }
        }
    }
}

struct Fx<'a> {
    e: &'a Env,
    queue: ElixirQueueClient<'a>,
    queue_addr: Address,
    account: Address,
    hostile: Address,
    alice: Address,
}

fn fx(e: &Env) -> Fx<'_> {
    e.mock_all_auths_allowing_non_root_auth();
    let alice = Address::generate(e);
    let queue_addr = Address::generate(e);
    let account = e.register(ElixirAccount, (0u32, Some(queue_addr.clone())));
    let members: Vec<(Address, u32)> = vec![e, (alice.clone(), ROLE_ALL)];
    e.register_at(
        &queue_addr,
        ElixirQueue,
        (account.clone(), members, 1u32, 0u64),
    );
    let hostile = e.register(Hostile, ());
    Fx {
        e,
        queue: ElixirQueueClient::new(e, &queue_addr),
        queue_addr,
        account,
        hostile,
        alice,
    }
}

fn poke_invocation(f: &Fx) -> Vec<Invocation> {
    vec![
        f.e,
        Invocation {
            target: f.hostile.clone(),
            fn_name: symbol_short!("poke"),
            args: Vec::new(f.e),
        },
    ]
}

fn propose_armed(f: &Fx, mode: Mode) -> u64 {
    let id = f.queue.propose(&f.alice, &None, &poke_invocation(f));
    HostileClient::new(f.e, &f.hostile).arm(&f.queue_addr, &f.account, &f.alice, &id, &mode);
    id
}

/// The host rejects re-entry before any contract code runs.
#[track_caller]
fn assert_host_reentry<T: core::fmt::Debug, C: core::fmt::Debug>(
    r: Result<Result<T, C>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
) {
    let expected =
        soroban_sdk::Error::from_type_and_code(ScErrorType::Context, ScErrorCode::InvalidAction);
    match r {
        Err(Ok(got)) => assert_eq!(got, expected, "expected host reentrancy rejection"),
        other => panic!("expected host reentrancy rejection, got {other:?}"),
    }
}

#[test]
fn benign_target_runs_once() {
    let e = Env::default();
    let f = fx(&e);
    let id = propose_armed(&f, Mode::Benign);
    f.queue.execute(&f.alice, &id);
    assert_eq!(HostileClient::new(&e, &f.hostile).hits(), 1);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Executed);
}

/// A target that re-enters `execute` for the same id is refused by the host.
/// The whole tx then reverts (Soroban is atomic), so the first run is undone
/// too — nothing executes twice, and nothing executes once, either.
#[test]
fn reentering_execute_fails_and_reverts_everything() {
    let e = Env::default();
    let f = fx(&e);
    let id = propose_armed(&f, Mode::ReenterQueue);

    assert_host_reentry(f.queue.try_execute(&f.alice, &id));

    // Revert means the outer run never happened from the ledger's point of view.
    assert_eq!(HostileClient::new(&e, &f.hostile).hits(), 0);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Approved);
}

/// A target that bypasses the queue and calls the account directly is also
/// refused by the host — the account is on the stack via exec_queued.
#[test]
fn reentering_account_is_blocked() {
    let e = Env::default();
    let f = fx(&e);
    let id = propose_armed(&f, Mode::ReenterAccount);

    assert_host_reentry(f.queue.try_execute(&f.alice, &id));
    assert_eq!(HostileClient::new(&e, &f.hostile).hits(), 0);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Approved);
}

/// Nothing set during a failed execution may outlive it — ExecLock included.
/// A failed execution rolls everything back, so the next attempt is not
/// spuriously rejected.
#[test]
fn exec_lock_does_not_leak_across_transactions() {
    let e = Env::default();
    let f = fx(&e);
    let id = propose_armed(&f, Mode::ReenterAccount);
    assert_host_reentry(f.queue.try_execute(&f.alice, &id));

    // Disarm and retry: must succeed, proving no stale lock remains.
    HostileClient::new(&e, &f.hostile).arm(&f.queue_addr, &f.account, &f.alice, &id, &Mode::Benign);
    f.queue.execute(&f.alice, &id);
    assert_eq!(HostileClient::new(&e, &f.hostile).hits(), 1);
}

/// Direct calls to exec_queued from anything but the queue are rejected,
/// regardless of reentrancy. Guards the "bypass the queue" path outright.
#[test]
fn exec_queued_rejects_callers_other_than_the_queue() {
    let e = Env::default();
    let f = fx(&e);
    let mallory = Address::generate(&e);
    let acct = AccountClient::new(&e, &f.account);

    // Authorize as mallory only; the account requires the queue's auth.
    e.mock_auths(&[MockAuth {
        address: &mallory,
        invoke: &MockAuthInvoke {
            contract: &f.account,
            fn_name: "exec_queued",
            args: (
                f.hostile.clone(),
                Symbol::new(&e, "poke"),
                Vec::<Val>::new(&e),
            )
                .into_val(&e),
            sub_invokes: &[],
        },
    }]);
    let r = acct.try_exec_queued(&f.hostile, &symbol_short!("poke"), &Vec::<Val>::new(&e));
    assert!(r.is_err(), "only the queue may call exec_queued");
    assert_eq!(HostileClient::new(&e, &f.hostile).hits(), 0);
}
