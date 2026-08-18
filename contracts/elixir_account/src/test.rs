#![cfg(test)]

use crate::{ElixirAccount, ElixirAccountClient, MAX_FREEZE_SECONDS};
use soroban_sdk::{testutils::Ledger, Env};

fn setup(e: &Env) -> ElixirAccountClient<'_> {
    let id = e.register(ElixirAccount, (0u32, None::<soroban_sdk::Address>));
    ElixirAccountClient::new(e, &id)
}

#[test]
fn constructor_sets_epoch_zero() {
    let e = Env::default();
    let c = setup(&e);
    assert_eq!(c.config().config_epoch, 0);
    assert!(!c.is_frozen());
}

#[test]
fn reconfigure_bumps_config_epoch() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &3, &2);
    assert_eq!(c.config().config_epoch, 1);

    c.reconfigure(&0, &5, &3);
    assert_eq!(c.config().config_epoch, 2);
}

/// Invariant: config_epoch is monotonic. Any pending proposal stamped with an
/// older epoch must fail to execute. docs/ARCHITECTURE.md §4.4.
#[test]
fn config_epoch_is_monotonic() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    let mut last = c.config().config_epoch;
    for n in 1..=5u32 {
        c.reconfigure(&0, &5, &n.min(5));
        let now = c.config().config_epoch;
        assert!(now > last, "epoch must strictly increase");
        last = now;
    }
}

/// A signer-set change that leaves the threshold unsatisfiable must be rejected
/// atomically. docs/ARCHITECTURE.md §6.5.
#[test]
#[should_panic]
fn reconfigure_rejects_threshold_above_signer_count() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);
    c.reconfigure(&0, &3, &4);
}

#[test]
#[should_panic]
fn reconfigure_rejects_zero_threshold() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);
    c.reconfigure(&0, &3, &0);
}

/// A failed reconfigure must not bump the epoch — otherwise a griefing signer
/// could invalidate every pending proposal with calls that always revert.
#[test]
fn failed_reconfigure_does_not_bump_epoch() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &3, &2);
    let before = c.config().config_epoch;

    assert!(c.try_reconfigure(&0, &3, &9).is_err());
    assert_eq!(c.config().config_epoch, before);
}

#[test]
fn freeze_expires_on_its_own() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.freeze(&3600);
    assert!(c.is_frozen());

    e.ledger().with_mut(|l| l.timestamp += 3601);
    assert!(!c.is_frozen(), "freeze must expire without intervention");
}

/// Griefing bound: a single signer must not be able to halt the account forever.
/// docs/GAPS.md A2.
#[test]
fn freeze_duration_is_capped() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.freeze(&(MAX_FREEZE_SECONDS * 100));
    e.ledger()
        .with_mut(|l| l.timestamp += MAX_FREEZE_SECONDS + 1);
    assert!(
        !c.is_frozen(),
        "freeze must be bounded by MAX_FREEZE_SECONDS"
    );
}

#[test]
fn unfreeze_clears_immediately() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.freeze(&MAX_FREEZE_SECONDS);
    assert!(c.is_frozen());
    c.unfreeze();
    assert!(!c.is_frozen());
}
