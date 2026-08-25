#![cfg(test)]

use crate::{ElixirQueue, ElixirQueueClient};
use elixir_account::ElixirAccount;
use elixir_types::{Error, Invocation, Status, ROLE_ALL, ROLE_EXECUTE, ROLE_INITIATE, ROLE_VOTE};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, Env, Vec,
};

/// Bump the account's config_epoch. These tests care only that a reconfigure
/// happened, not about the signer set, so any valid set will do.
fn reconfigure_account(e: &Env, account: &Address) {
    let mut s = Vec::new(e);
    for _ in 0..3 {
        s.push_back(stellar_accounts::smart_account::Signer::Delegated(
            Address::generate(e),
        ));
    }
    elixir_account::ElixirAccountClient::new(e, account).reconfigure(&0, &s, &2);
}

// A target with observable state, so tests can prove an invocation ran (or did not).
#[contract]
pub struct Counter;

#[contracttype]
#[derive(Clone)]
pub enum CounterKey {
    Count,
}

#[contractimpl]
impl Counter {
    pub fn bump(e: Env) -> u32 {
        let n: u32 = e.storage().instance().get(&CounterKey::Count).unwrap_or(0) + 1;
        e.storage().instance().set(&CounterKey::Count, &n);
        n
    }
    pub fn count(e: Env) -> u32 {
        e.storage().instance().get(&CounterKey::Count).unwrap_or(0)
    }
}

struct Fixture<'a> {
    e: &'a Env,
    queue: ElixirQueueClient<'a>,
    account: Address,
    counter: Address,
    alice: Address, // ROLE_ALL
    bob: Address,   // ROLE_ALL
    carol: Address, // ROLE_VOTE | ROLE_EXECUTE
    dave: Address,  // ROLE_INITIATE only
}

fn fixture(e: &Env, threshold: u32, time_lock: u32) -> Fixture<'_> {
    e.mock_all_auths();
    let alice = Address::generate(e);
    let bob = Address::generate(e);
    let carol = Address::generate(e);
    let dave = Address::generate(e);

    // Account and queue reference each other; pin the queue address first.
    let queue_addr = Address::generate(e);
    let account = e.register(ElixirAccount, (time_lock, Some(queue_addr.clone())));
    let members: Vec<(Address, u32)> = vec![
        e,
        (alice.clone(), ROLE_ALL),
        (bob.clone(), ROLE_ALL),
        (carol.clone(), ROLE_VOTE | ROLE_EXECUTE),
        (dave.clone(), ROLE_INITIATE),
    ];
    e.register_at(
        &queue_addr,
        ElixirQueue,
        (account.clone(), members, threshold, 0u64),
    );
    let counter = e.register(Counter, ());

    Fixture {
        e,
        queue: ElixirQueueClient::new(e, &queue_addr),
        account,
        counter,
        alice,
        bob,
        carol,
        dave,
    }
}

fn bump_invocation(f: &Fixture) -> Vec<Invocation> {
    vec![
        f.e,
        Invocation {
            target: f.counter.clone(),
            fn_name: symbol_short!("bump"),
            args: Vec::new(f.e),
        },
    ]
}

fn count(f: &Fixture) -> u32 {
    CounterClient::new(f.e, &f.counter).count()
}

fn advance(e: &Env, secs: u64) {
    e.ledger().with_mut(|l| l.timestamp += secs);
}

/// Contract fns panic with a typed error; `try_*` surfaces it as a host error code.
#[track_caller]
fn assert_err<T: core::fmt::Debug, C: core::fmt::Debug>(
    r: Result<Result<T, C>, Result<soroban_sdk::Error, soroban_sdk::InvokeError>>,
    expected: Error,
) {
    match r {
        Err(Ok(got)) => assert_eq!(
            got,
            soroban_sdk::Error::from_contract_error(expected as u32)
        ),
        other => panic!("expected contract error {expected:?}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Happy path

#[test]
fn propose_approve_execute_runs_the_invocation() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);

    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_eq!(f.queue.get_proposal(&id).status, Status::Active);
    assert_eq!(
        f.queue.get_proposal(&id).approvals.len(),
        1,
        "creator auto-approves"
    );

    f.queue.approve(&f.bob, &id);
    let p = f.queue.get_proposal(&id);
    assert_eq!(p.status, Status::Approved);
    assert!(p.approved_at.is_some());

    assert_eq!(count(&f), 0);
    f.queue.execute(&f.carol, &id);
    assert_eq!(count(&f), 1);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Executed);
}

#[test]
fn one_of_n_settles_on_creation() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_eq!(f.queue.get_proposal(&id).status, Status::Approved);
}

#[test]
fn batch_runs_every_invocation() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let inv = Invocation {
        target: f.counter.clone(),
        fn_name: symbol_short!("bump"),
        args: Vec::new(&e),
    };
    let id = f
        .queue
        .propose(&f.alice, &None, &vec![&e, inv.clone(), inv.clone(), inv]);
    f.queue.execute(&f.alice, &id);
    assert_eq!(count(&f), 3);
}

// ---------------------------------------------------------------------------
// Invariant: no path from creation to Executed skips the threshold

#[test]
fn execute_before_threshold_is_rejected() {
    let e = Env::default();
    let f = fixture(&e, 3, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    f.queue.approve(&f.bob, &id); // 2 of 3
    assert_err(f.queue.try_execute(&f.carol, &id), Error::InvalidStatus);
    assert_eq!(count(&f), 0);
}

#[test]
fn threshold_counts_only_distinct_voters() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_err(f.queue.try_approve(&f.alice, &id), Error::AlreadyVoted);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Active);
}

// ---------------------------------------------------------------------------
// Invariant: no execution across a config epoch boundary

#[test]
fn stale_epoch_cannot_execute() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    f.queue.approve(&f.bob, &id);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Approved);

    // The account reconfigures; its epoch bumps; the proposal is now stale.
    reconfigure_account(&e, &f.account);

    assert_err(f.queue.try_execute(&f.carol, &id), Error::StaleConfigEpoch);
    assert_eq!(count(&f), 0);
}

#[test]
fn proposal_created_after_reconfigure_carries_new_epoch() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    reconfigure_account(&e, &f.account);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_eq!(f.queue.get_proposal(&id).config_epoch, 1);
    f.queue.execute(&f.alice, &id);
    assert_eq!(count(&f), 1);
}

// ---------------------------------------------------------------------------
// Timelock and expiry

#[test]
fn timelock_blocks_until_elapsed() {
    let e = Env::default();
    let f = fixture(&e, 1, 3600);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_err(
        f.queue.try_execute(&f.alice, &id),
        Error::TimelockNotElapsed,
    );
    advance(&e, 3599);
    assert_err(
        f.queue.try_execute(&f.alice, &id),
        Error::TimelockNotElapsed,
    );
    advance(&e, 1);
    f.queue.execute(&f.alice, &id);
    assert_eq!(count(&f), 1);
}

#[test]
fn expired_proposal_cannot_execute() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    advance(&e, crate::DEFAULT_PROPOSAL_LIFETIME);
    assert_err(f.queue.try_execute(&f.alice, &id), Error::ProposalExpired);
}

// ---------------------------------------------------------------------------
// Cancel works post-approval

#[test]
fn cancel_after_approval_blocks_execution() {
    let e = Env::default();
    let f = fixture(&e, 2, 3600);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    f.queue.approve(&f.bob, &id);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Approved);

    f.queue.cancel(&f.carol, &id);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Cancelled);

    advance(&e, 3600);
    assert_err(f.queue.try_execute(&f.carol, &id), Error::InvalidStatus);
    assert_eq!(count(&f), 0);
}

#[test]
fn cancelled_proposal_cannot_be_voted_on() {
    let e = Env::default();
    let f = fixture(&e, 3, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    f.queue.cancel(&f.bob, &id);
    assert_err(f.queue.try_approve(&f.carol, &id), Error::InvalidStatus);
}

#[test]
fn executed_proposal_cannot_be_cancelled() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    f.queue.execute(&f.alice, &id);
    assert_err(f.queue.try_cancel(&f.alice, &id), Error::InvalidStatus);
}

// ---------------------------------------------------------------------------
// Roles are enforced separately

#[test]
fn initiate_only_key_can_propose_but_never_approve() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);
    let id = f.queue.propose(&f.dave, &None, &bump_invocation(&f));
    let p = f.queue.get_proposal(&id);
    assert_eq!(
        p.approvals.len(),
        0,
        "a non-voter's creation is not an approval"
    );

    assert_err(f.queue.try_approve(&f.dave, &id), Error::Unauthorized);
    assert_err(f.queue.try_reject(&f.dave, &id), Error::Unauthorized);
    assert_err(f.queue.try_cancel(&f.dave, &id), Error::Unauthorized);
}

#[test]
fn vote_only_key_cannot_propose() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);
    assert_err(
        f.queue.try_propose(&f.carol, &None, &bump_invocation(&f)),
        Error::Unauthorized,
    );
}

#[test]
fn execute_requires_execute_role() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_err(f.queue.try_execute(&f.dave, &id), Error::Unauthorized);
    assert_eq!(count(&f), 0);
    // The gate checks status/epoch/timelock/expiry before the role, so a
    // non-executor still sees the real reason when the proposal is not ready.
}

#[test]
fn non_member_is_rejected_everywhere() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let mallory = Address::generate(&e);
    let id = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_err(
        f.queue.try_propose(&mallory, &None, &bump_invocation(&f)),
        Error::NotAMember,
    );
    assert_err(f.queue.try_approve(&mallory, &id), Error::NotAMember);
    assert_err(f.queue.try_execute(&mallory, &id), Error::NotAMember);
}

// ---------------------------------------------------------------------------
// Rejection settles when the threshold can no longer be met

#[test]
fn enough_rejections_close_the_proposal() {
    let e = Env::default();
    // 3 voters (alice, bob, carol), threshold 2 → one rejection leaves 2 possible, still open;
    // two rejections leave 1 possible, closed.
    let f = fixture(&e, 2, 0);
    let id = f.queue.propose(&f.dave, &None, &bump_invocation(&f));
    f.queue.reject(&f.alice, &id);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Active);
    f.queue.reject(&f.bob, &id);
    assert_eq!(f.queue.get_proposal(&id).status, Status::Rejected);
    assert_err(f.queue.try_approve(&f.carol, &id), Error::InvalidStatus);
}

// ---------------------------------------------------------------------------
// Configuration

#[test]
fn empty_proposal_is_rejected() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    assert_err(
        f.queue.try_propose(&f.alice, &None, &Vec::new(&e)),
        Error::EmptyProposal,
    );
}

#[test]
#[should_panic]
fn threshold_above_voter_count_is_rejected_at_construction() {
    let e = Env::default();
    let account = Address::generate(&e);
    let a = Address::generate(&e);
    let members: Vec<(Address, u32)> = vec![&e, (a, ROLE_ALL)];
    // 2-of-1 must be unsatisfiable.
    e.register(ElixirQueue, (account, members, 2u32, 0u64));
}

#[test]
fn set_members_is_account_only_and_atomic() {
    let e = Env::default();
    let f = fixture(&e, 2, 0);
    let erin = Address::generate(&e);
    let members: Vec<(Address, u32)> =
        vec![&e, (f.alice.clone(), ROLE_ALL), (erin.clone(), ROLE_ALL)];
    // Atomic: a bad threshold leaves the old set in place.
    assert_err(
        f.queue.try_set_members(&members, &3),
        Error::UnsatisfiableThreshold,
    );
    assert_eq!(f.queue.config().members.len(), 4);

    f.queue.set_members(&members, &2);
    let cfg = f.queue.config();
    assert_eq!(cfg.members.len(), 2);
    assert!(cfg.members.contains_key(erin));
    assert!(!cfg.members.contains_key(f.bob.clone()));
}

#[test]
fn ids_are_sequential_and_unique() {
    let e = Env::default();
    let f = fixture(&e, 1, 0);
    let a = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    let b = f.queue.propose(&f.alice, &None, &bump_invocation(&f));
    assert_eq!(b, a + 1);
    assert_err(f.queue.try_get_proposal(&(b + 1)), Error::ProposalNotFound);
}
