#![cfg(test)]

use crate::{Timelock, TimelockClient, TimelockParams};
use elixir_types::Error;
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, BytesN, Env, IntoVal, Val, Vec,
};

fn ctx(e: &Env, target: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: target.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![e, amount.into_val(e)],
    })
}

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
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

struct Fx<'a> {
    c: TimelockClient<'a>,
    account: Address,
    target: Address,
    none: Vec<Address>,
}

fn fx(e: &Env, delay: u64, window: u64) -> Fx<'_> {
    e.mock_all_auths();
    let id = e.register(Timelock, ());
    let c = TimelockClient::new(e, &id);
    let account = Address::generate(e);
    let params: Val = TimelockParams { delay, window }.into_val(e);
    c.install(&account, &0, &params);
    Fx {
        c,
        account,
        target: Address::generate(e),
        none: Vec::new(e),
    }
}

fn advance(e: &Env, secs: u64) {
    e.ledger().with_mut(|l| l.timestamp += secs);
}

#[test]
fn unscheduled_call_is_denied() {
    let e = Env::default();
    let f = fx(&e, 3600, 0);
    assert_err(
        f.c.try_enforce(&f.account, &0, &ctx(&e, &f.target, 1), &f.none),
        Error::NotScheduled,
    );
}

#[test]
fn schedule_then_wait_then_execute_once() {
    let e = Env::default();
    let f = fx(&e, 3600, 0);
    let c = ctx(&e, &f.target, 1);
    let payload = f.c.payload_of(&c);
    f.c.schedule(&f.account, &0, &payload);
    assert_eq!(
        f.c.scheduled_at(&f.account, &0, &payload),
        Some(e.ledger().timestamp())
    );

    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &f.none),
        Error::TimelockNotElapsed,
    );
    advance(&e, 3599);
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &f.none),
        Error::TimelockNotElapsed,
    );
    advance(&e, 1);
    f.c.enforce(&f.account, &0, &c, &f.none);

    // Consumed: a second execution needs a new schedule.
    assert_eq!(f.c.scheduled_at(&f.account, &0, &payload), None);
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &f.none),
        Error::NotScheduled,
    );
}

/// The payload binds the exact call. Change one argument and it is a
/// different, unscheduled call.
#[test]
fn different_arguments_are_a_different_payload() {
    let e = Env::default();
    let f = fx(&e, 10, 0);
    let scheduled = ctx(&e, &f.target, 100);
    let tampered = ctx(&e, &f.target, 101);
    assert_ne!(f.c.payload_of(&scheduled), f.c.payload_of(&tampered));

    f.c.schedule(&f.account, &0, &f.c.payload_of(&scheduled));
    advance(&e, 10);
    assert_err(
        f.c.try_enforce(&f.account, &0, &tampered, &f.none),
        Error::NotScheduled,
    );
    f.c.enforce(&f.account, &0, &scheduled, &f.none);
}

#[test]
fn window_closes_after_delay_plus_window() {
    let e = Env::default();
    let f = fx(&e, 100, 50);
    let c = ctx(&e, &f.target, 1);
    f.c.schedule(&f.account, &0, &f.c.payload_of(&c));
    advance(&e, 150);
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &f.none),
        Error::ProposalExpired,
    );
}

#[test]
fn window_zero_means_no_expiry() {
    let e = Env::default();
    let f = fx(&e, 100, 0);
    let c = ctx(&e, &f.target, 1);
    f.c.schedule(&f.account, &0, &f.c.payload_of(&c));
    advance(&e, 1_000_000);
    f.c.enforce(&f.account, &0, &c, &f.none);
}

#[test]
fn cancel_removes_a_pending_schedule() {
    let e = Env::default();
    let f = fx(&e, 100, 0);
    let c = ctx(&e, &f.target, 1);
    let payload = f.c.payload_of(&c);
    f.c.schedule(&f.account, &0, &payload);
    f.c.cancel(&f.account, &0, &payload);
    advance(&e, 100);
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &f.none),
        Error::NotScheduled,
    );
    assert_err(
        f.c.try_cancel(&f.account, &0, &payload),
        Error::NotScheduled,
    );
}

#[test]
fn zero_delay_executes_immediately_after_schedule() {
    let e = Env::default();
    let f = fx(&e, 0, 0);
    let c = ctx(&e, &f.target, 1);
    f.c.schedule(&f.account, &0, &f.c.payload_of(&c));
    f.c.enforce(&f.account, &0, &c, &f.none);
}

#[test]
fn not_installed_is_rejected() {
    let e = Env::default();
    let f = fx(&e, 10, 0);
    let payload = BytesN::from_array(&e, &[0u8; 32]);
    assert_err(
        f.c.try_schedule(&f.account, &9, &payload),
        Error::PolicyNotInstalled,
    );
    f.c.uninstall(&f.account, &0);
    assert_err(
        f.c.try_schedule(&f.account, &0, &payload),
        Error::PolicyNotInstalled,
    );
}

#[test]
fn everything_requires_account_auth() {
    let e = Env::default();
    let f = fx(&e, 10, 0);
    let c = ctx(&e, &f.target, 1);
    let payload = f.c.payload_of(&c);
    e.set_auths(&[]);
    assert!(f.c.try_schedule(&f.account, &0, &payload).is_err());
    assert!(f.c.try_enforce(&f.account, &0, &c, &f.none).is_err());
    assert!(f.c.try_cancel(&f.account, &0, &payload).is_err());
}
