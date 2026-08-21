#![cfg(test)]

use crate::{DestinationAllowlist, DestinationAllowlistClient, MAX_DESTINATIONS};
use elixir_types::Error;
use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short,
    testutils::Address as _,
    vec, Address, Env, IntoVal, Symbol, Val, Vec,
};

fn transfer_ctx(e: &Env, token: &Address, from: &Address, to: &Address, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![e, from.into_val(e), to.into_val(e), amount.into_val(e)],
    })
}

fn transfer_from_ctx(
    e: &Env,
    token: &Address,
    spender: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> Context {
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: Symbol::new(e, "transfer_from"),
        args: vec![
            e,
            spender.into_val(e),
            from.into_val(e),
            to.into_val(e),
            amount.into_val(e),
        ],
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
    c: DestinationAllowlistClient<'a>,
    account: Address,
    token: Address,
    ok_dest: Address,
    bad_dest: Address,
    none: Vec<Address>,
}

fn fx(e: &Env) -> Fx<'_> {
    e.mock_all_auths();
    let id = e.register(DestinationAllowlist, ());
    let c = DestinationAllowlistClient::new(e, &id);
    let account = Address::generate(e);
    let ok_dest = Address::generate(e);
    let list: Vec<Address> = vec![e, ok_dest.clone(), Address::generate(e)];
    let params: Val = list.into_val(e);
    c.install(&account, &0, &params);
    Fx {
        c,
        account,
        token: Address::generate(e),
        ok_dest,
        bad_dest: Address::generate(e),
        none: Vec::new(e),
    }
}

#[test]
fn allows_transfer_to_listed_destination() {
    let e = Env::default();
    let f = fx(&e);
    let ctx = transfer_ctx(&e, &f.token, &f.account, &f.ok_dest, 100);
    f.c.enforce(&f.account, &0, &ctx, &f.none);
    assert!(f.c.is_allowed(&f.account, &0, &f.ok_dest));
}

#[test]
fn denies_transfer_to_unlisted_destination() {
    let e = Env::default();
    let f = fx(&e);
    let ctx = transfer_ctx(&e, &f.token, &f.account, &f.bad_dest, 100);
    assert_err(
        f.c.try_enforce(&f.account, &0, &ctx, &f.none),
        Error::PolicyViolation,
    );
    assert!(!f.c.is_allowed(&f.account, &0, &f.bad_dest));
}

#[test]
fn transfer_from_uses_the_third_argument() {
    let e = Env::default();
    let f = fx(&e);
    let spender = Address::generate(&e);
    let ok = transfer_from_ctx(&e, &f.token, &spender, &f.account, &f.ok_dest, 5);
    f.c.enforce(&f.account, &0, &ok, &f.none);
    let bad = transfer_from_ctx(&e, &f.token, &spender, &f.account, &f.bad_dest, 5);
    assert_err(
        f.c.try_enforce(&f.account, &0, &bad, &f.none),
        Error::PolicyViolation,
    );
}

/// Fail closed: a call this policy cannot evaluate is denied, not waved through.
#[test]
fn denies_non_transfer_calls() {
    let e = Env::default();
    let f = fx(&e);
    let ctx = Context::Contract(ContractContext {
        contract: f.token.clone(),
        fn_name: symbol_short!("approve"),
        args: vec![
            &e,
            f.account.clone().into_val(&e),
            f.ok_dest.clone().into_val(&e),
            100i128.into_val(&e),
        ],
    });
    assert_err(
        f.c.try_enforce(&f.account, &0, &ctx, &f.none),
        Error::PolicyViolation,
    );
}

#[test]
fn denies_malformed_destination_argument() {
    let e = Env::default();
    let f = fx(&e);
    let ctx = Context::Contract(ContractContext {
        contract: f.token.clone(),
        fn_name: symbol_short!("transfer"),
        args: vec![
            &e,
            f.account.clone().into_val(&e),
            42u32.into_val(&e),
            100i128.into_val(&e),
        ],
    });
    assert_err(
        f.c.try_enforce(&f.account, &0, &ctx, &f.none),
        Error::PolicyViolation,
    );
}

#[test]
fn rules_are_isolated_per_account_and_rule() {
    let e = Env::default();
    let f = fx(&e);
    let ctx = transfer_ctx(&e, &f.token, &f.account, &f.ok_dest, 1);
    assert_err(
        f.c.try_enforce(&f.account, &1, &ctx, &f.none),
        Error::PolicyNotInstalled,
    );
    let other = Address::generate(&e);
    assert_err(
        f.c.try_enforce(&other, &0, &ctx, &f.none),
        Error::PolicyNotInstalled,
    );
}

#[test]
fn reinstall_replaces_the_list() {
    let e = Env::default();
    let f = fx(&e);
    let fresh: Vec<Address> = vec![&e, f.bad_dest.clone()];
    let params: Val = fresh.into_val(&e);
    f.c.install(&f.account, &0, &params);
    assert!(f.c.is_allowed(&f.account, &0, &f.bad_dest));
    assert!(!f.c.is_allowed(&f.account, &0, &f.ok_dest));
    assert_eq!(f.c.destinations(&f.account, &0).len(), 1);
}

#[test]
fn uninstall_removes_the_rule() {
    let e = Env::default();
    let f = fx(&e);
    f.c.uninstall(&f.account, &0);
    let ctx = transfer_ctx(&e, &f.token, &f.account, &f.ok_dest, 1);
    assert_err(
        f.c.try_enforce(&f.account, &0, &ctx, &f.none),
        Error::PolicyNotInstalled,
    );
}

#[test]
fn list_size_is_bounded() {
    let e = Env::default();
    let f = fx(&e);
    let mut big: Vec<Address> = Vec::new(&e);
    for _ in 0..=MAX_DESTINATIONS {
        big.push_back(Address::generate(&e));
    }
    let params: Val = big.into_val(&e);
    assert_err(
        f.c.try_install(&f.account, &1, &params),
        Error::AllowlistTooLarge,
    );
}

#[test]
fn install_and_enforce_require_account_auth() {
    let e = Env::default();
    let f = fx(&e);
    e.set_auths(&[]);
    let ctx = transfer_ctx(&e, &f.token, &f.account, &f.ok_dest, 1);
    assert!(f.c.try_enforce(&f.account, &0, &ctx, &f.none).is_err());
    let params: Val = Vec::<Address>::new(&e).into_val(&e);
    assert!(f.c.try_install(&f.account, &2, &params).is_err());
}
