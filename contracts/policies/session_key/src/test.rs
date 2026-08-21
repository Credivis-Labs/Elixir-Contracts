#![cfg(test)]

use crate::{SessionKey, SessionKeyClient, SessionParams};
use elixir_types::Error;
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, Env, IntoVal, Symbol, Val, Vec,
};

fn transfer(e: &Env, token: &Address, from: &Address, to: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![e, from.into_val(e), to.into_val(e), amount.into_val(e)],
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
    c: SessionKeyClient<'a>,
    account: Address,
    key: Address,
    token: Address,
    payee: Address,
    signers: Vec<Address>,
}

const CAP: i128 = 1_000;
const TTL: u64 = 86_400;

fn fx(e: &Env) -> Fx<'_> {
    e.mock_all_auths();
    let id = e.register(SessionKey, ());
    let c = SessionKeyClient::new(e, &id);
    let account = Address::generate(e);
    let key = Address::generate(e);
    let token = Address::generate(e);
    let params: Val = SessionParams {
        key: key.clone(),
        target: token.clone(),
        fn_name: symbol_short!("transfer"),
        spend_cap: CAP,
        expires_at: e.ledger().timestamp() + TTL,
    }
    .into_val(e);
    c.install(&account, &0, &params);
    Fx {
        c,
        account,
        key: key.clone(),
        token,
        payee: Address::generate(e),
        signers: vec![e, key],
    }
}

#[test]
fn session_key_can_spend_within_cap() {
    let e = Env::default();
    let f = fx(&e);
    f.c.enforce(
        &f.account,
        &0,
        &transfer(&e, &f.token, &f.account, &f.payee, 400),
        &f.signers,
    );
    let s = f.c.session(&f.account, &0);
    assert_eq!(s.remaining, 600);
    assert_eq!(s.uses, 1);
}

#[test]
fn cap_is_cumulative_and_charged_before_returning() {
    let e = Env::default();
    let f = fx(&e);
    f.c.enforce(
        &f.account,
        &0,
        &transfer(&e, &f.token, &f.account, &f.payee, 600),
        &f.signers,
    );
    f.c.enforce(
        &f.account,
        &0,
        &transfer(&e, &f.token, &f.account, &f.payee, 400),
        &f.signers,
    );
    assert_eq!(f.c.session(&f.account, &0).remaining, 0);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, 1),
            &f.signers,
        ),
        Error::SpendCapExceeded,
    );
}

#[test]
fn a_single_transfer_over_the_cap_is_denied_and_nothing_is_charged() {
    let e = Env::default();
    let f = fx(&e);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, CAP + 1),
            &f.signers,
        ),
        Error::SpendCapExceeded,
    );
    assert_eq!(f.c.session(&f.account, &0).remaining, CAP);
    assert_eq!(f.c.session(&f.account, &0).uses, 0);
}

#[test]
fn non_positive_amounts_are_denied() {
    let e = Env::default();
    let f = fx(&e);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, 0),
            &f.signers,
        ),
        Error::SpendCapExceeded,
    );
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, -5),
            &f.signers,
        ),
        Error::SpendCapExceeded,
    );
}

#[test]
fn only_the_session_key_may_use_it() {
    let e = Env::default();
    let f = fx(&e);
    let other = Address::generate(&e);
    let c = transfer(&e, &f.token, &f.account, &f.payee, 1);
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &vec![&e, other.clone()]),
        Error::Unauthorized,
    );
    // Even alongside the real key: the signer set must be exactly the key.
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &vec![&e, f.key.clone(), other]),
        Error::Unauthorized,
    );
    assert_err(
        f.c.try_enforce(&f.account, &0, &c, &Vec::new(&e)),
        Error::Unauthorized,
    );
}

#[test]
fn wrong_target_or_method_is_denied() {
    let e = Env::default();
    let f = fx(&e);
    let other_token = Address::generate(&e);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &other_token, &f.account, &f.payee, 1),
            &f.signers,
        ),
        Error::PolicyViolation,
    );
    let approve = Context::Contract(ContractContext {
        contract: f.token.clone(),
        fn_name: symbol_short!("approve"),
        args: vec![
            &e,
            f.account.clone().into_val(&e),
            f.payee.clone().into_val(&e),
            1i128.into_val(&e),
        ],
    });
    assert_err(
        f.c.try_enforce(&f.account, &0, &approve, &f.signers),
        Error::PolicyViolation,
    );
}

#[test]
fn expires_at_is_absolute() {
    let e = Env::default();
    let f = fx(&e);
    e.ledger().with_mut(|l| l.timestamp += TTL - 1);
    f.c.enforce(
        &f.account,
        &0,
        &transfer(&e, &f.token, &f.account, &f.payee, 1),
        &f.signers,
    );
    e.ledger().with_mut(|l| l.timestamp += 1);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, 1),
            &f.signers,
        ),
        Error::SessionExpired,
    );
}

#[test]
fn non_transfer_session_has_no_spend_accounting() {
    let e = Env::default();
    e.mock_all_auths();
    let id = e.register(SessionKey, ());
    let c = SessionKeyClient::new(&e, &id);
    let account = Address::generate(&e);
    let key = Address::generate(&e);
    let pool = Address::generate(&e);
    let params: Val = SessionParams {
        key: key.clone(),
        target: pool.clone(),
        fn_name: Symbol::new(&e, "claim_rewards"),
        spend_cap: 0,
        expires_at: e.ledger().timestamp() + 10,
    }
    .into_val(&e);
    c.install(&account, &0, &params);
    let ctx = Context::Contract(ContractContext {
        contract: pool,
        fn_name: Symbol::new(&e, "claim_rewards"),
        args: vec![&e, account.clone().into_val(&e)],
    });
    c.enforce(&account, &0, &ctx, &vec![&e, key.clone()]);
    c.enforce(&account, &0, &ctx, &vec![&e, key]);
    assert_eq!(c.session(&account, &0).uses, 2);
}

#[test]
fn install_rejects_already_expired_or_negative_cap() {
    let e = Env::default();
    let f = fx(&e);
    let expired: Val = SessionParams {
        key: f.key.clone(),
        target: f.token.clone(),
        fn_name: symbol_short!("transfer"),
        spend_cap: 1,
        expires_at: e.ledger().timestamp(),
    }
    .into_val(&e);
    assert_err(
        f.c.try_install(&f.account, &1, &expired),
        Error::PolicyViolation,
    );
    let negative: Val = SessionParams {
        key: f.key.clone(),
        target: f.token.clone(),
        fn_name: symbol_short!("transfer"),
        spend_cap: -1,
        expires_at: e.ledger().timestamp() + 10,
    }
    .into_val(&e);
    assert_err(
        f.c.try_install(&f.account, &1, &negative),
        Error::PolicyViolation,
    );
}

#[test]
fn uninstall_revokes_immediately() {
    let e = Env::default();
    let f = fx(&e);
    f.c.uninstall(&f.account, &0);
    assert_err(
        f.c.try_enforce(
            &f.account,
            &0,
            &transfer(&e, &f.token, &f.account, &f.payee, 1),
            &f.signers,
        ),
        Error::PolicyNotInstalled,
    );
}

#[test]
fn reinstall_resets_the_cap() {
    let e = Env::default();
    let f = fx(&e);
    f.c.enforce(
        &f.account,
        &0,
        &transfer(&e, &f.token, &f.account, &f.payee, 900),
        &f.signers,
    );
    let params: Val = SessionParams {
        key: f.key.clone(),
        target: f.token.clone(),
        fn_name: symbol_short!("transfer"),
        spend_cap: CAP,
        expires_at: e.ledger().timestamp() + TTL,
    }
    .into_val(&e);
    f.c.install(&f.account, &0, &params);
    assert_eq!(f.c.session(&f.account, &0).remaining, CAP);
    assert_eq!(f.c.session(&f.account, &0).uses, 0);
}
