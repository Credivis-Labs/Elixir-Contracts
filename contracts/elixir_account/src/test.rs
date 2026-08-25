#![cfg(test)]

use crate::{ElixirAccount, ElixirAccountClient, MAX_FREEZE_SECONDS};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, Vec,
};
use stellar_accounts::smart_account::Signer;
extern crate std;

fn setup(e: &Env) -> ElixirAccountClient<'_> {
    let id = e.register(ElixirAccount, (0u32, None::<soroban_sdk::Address>));
    ElixirAccountClient::new(e, &id)
}

/// `n` distinct delegated signers. Delegated covers the G-account case: OZ's
/// `authenticate` resolves it to `require_auth_for_args` on the address, so the
/// host verifies a classic signature.
fn signers(e: &Env, n: u32) -> Vec<Signer> {
    let mut v = Vec::new(e);
    for _ in 0..n {
        v.push_back(Signer::Delegated(Address::generate(e)));
    }
    v
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

    c.reconfigure(&0, &signers(&e, 3), &2);
    assert_eq!(c.config().config_epoch, 1);

    c.reconfigure(&0, &signers(&e, 5), &3);
    assert_eq!(c.config().config_epoch, 2);
}

/// Signers must actually be stored, not just counted.
#[test]
fn reconfigure_persists_signers_and_threshold() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 3), &2);

    assert_eq!(c.signers(&0).len(), 3);
    assert_eq!(c.threshold(&0), 2);
}

/// Reconfigure REPLACES the signer set; it does not append. Appending would let
/// the stored count drift above the number the threshold was validated against,
/// and would hit OZ's MAX_SIGNERS (15) after a few rotations.
#[test]
fn reconfigure_replaces_signer_set() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 2), &2);
    let first = c.signers(&0);
    assert_eq!(first.len(), 2);

    let second_set = signers(&e, 3);
    c.reconfigure(&0, &second_set, &3);

    let now = c.signers(&0);
    assert_eq!(now.len(), 3, "old signers must be gone, not appended to");
    assert_eq!(now, second_set);
    for old in first.iter() {
        assert!(!now.contains(&old), "a rotated-out signer must not remain");
    }
    assert_eq!(c.threshold(&0), 3);
}

/// Rotation is bounded by MAX_SIGNERS across BOTH sets, because OZ forbids a
/// momentarily-empty rule and so the new signers must be added before the old ones
/// are removed. old + new <= 15 succeeds.
#[test]
fn reconfigure_rotates_within_the_signer_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 7), &4);
    c.reconfigure(&0, &signers(&e, 8), &5);

    assert_eq!(c.signers(&0).len(), 8);
    assert_eq!(c.threshold(&0), 5);
}

/// The other side of that constraint, asserted so the limit is documented by a
/// test rather than discovered in production. Signers are applied as a delta, so
/// the transient peak is the UNION of the old and new sets. Two disjoint 15-signer
/// sets union to 30 and exceed MAX_SIGNERS; rotate in two steps instead.
#[test]
#[should_panic(expected = "Error(Contract, #3010)")]
fn reconfigure_cannot_rotate_a_full_set_in_one_call() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 15), &8);
    c.reconfigure(&0, &signers(&e, 15), &8);
}

/// Reconfigure is self-auth'd. Without auth it must not mutate the signer set.
#[test]
#[should_panic]
fn reconfigure_requires_self_auth() {
    let e = Env::default();
    let c = setup(&e);
    c.reconfigure(&0, &signers(&e, 3), &2);
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
        c.reconfigure(&0, &signers(&e, 5), &n.min(5));
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
    c.reconfigure(&0, &signers(&e, 3), &4);
}

#[test]
#[should_panic]
fn reconfigure_rejects_zero_threshold() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);
    c.reconfigure(&0, &signers(&e, 3), &0);
}

/// A failed reconfigure must not bump the epoch — otherwise a griefing signer
/// could invalidate every pending proposal with calls that always revert.
#[test]
fn failed_reconfigure_does_not_bump_epoch() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 3), &2);
    let before = c.config().config_epoch;

    assert!(c.try_reconfigure(&0, &signers(&e, 3), &9).is_err());
    assert_eq!(c.config().config_epoch, before);
    assert_eq!(c.threshold(&0), 2, "threshold must survive a failed call");
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

/// Boundary probe for the rotation cap, at the union boundary.
#[test]
fn rotation_cap_boundary_is_the_union_of_both_sets() {
    let e = Env::default();
    e.mock_all_auths();

    // 7 + 8 disjoint = 15 union, exactly at MAX_SIGNERS. Must succeed.
    let c = setup(&e);
    c.reconfigure(&0, &signers(&e, 7), &4);
    c.reconfigure(&0, &signers(&e, 8), &5);
    assert_eq!(c.signers(&0).len(), 8);

    // 8 + 8 disjoint = 16 union, one over. Must fail.
    let d = setup(&e);
    d.reconfigure(&0, &signers(&e, 8), &5);
    assert!(d.try_reconfigure(&0, &signers(&e, 8), &5).is_err());
}

/// Overlap is the common case: a real rotation keeps most signers and changes a
/// few. Applying the set wholesale would re-add the retained signers and trip
/// OZ's DuplicateSigner check, so this must go through the delta path.
#[test]
fn reconfigure_keeps_overlapping_signers() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    let a = Signer::Delegated(Address::generate(&e));
    let b = Signer::Delegated(Address::generate(&e));
    let d = Signer::Delegated(Address::generate(&e));

    let mut first = Vec::new(&e);
    first.push_back(a.clone());
    first.push_back(b.clone());
    first.push_back(d.clone());
    c.reconfigure(&0, &first, &2);

    // Drop `d`, keep `a` and `b`.
    let mut second = Vec::new(&e);
    second.push_back(a.clone());
    second.push_back(b.clone());
    c.reconfigure(&0, &second, &2);

    let now = c.signers(&0);
    assert_eq!(
        now.len(),
        2,
        "retained signers must survive, dropped one must go"
    );
    assert!(now.contains(&a));
    assert!(now.contains(&b));
    assert!(!now.contains(&d), "the dropped signer must be gone");
    assert_eq!(c.threshold(&0), 2);
}

/// A no-op reconfigure — same set, same threshold — must be accepted. The delta
/// is empty on both sides, so nothing is added and nothing removed.
#[test]
fn reconfigure_with_an_unchanged_set_is_a_no_op() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    let set = signers(&e, 3);
    c.reconfigure(&0, &set, &2);
    c.reconfigure(&0, &set, &2);

    assert_eq!(c.signers(&0), set);
    assert_eq!(c.threshold(&0), 2);
}

/// A full 15-signer rule cannot swap a signer in one call, even though only one
/// changes. `batch_add_signer` validates the rule AFTER appending and BEFORE the
/// caller removes anything, so the transient peak is 15 + 1 = 16 and trips
/// MAX_SIGNERS. Remove first, then add — two calls. Asserted so the limit is
/// documented rather than discovered in production.
#[test]
#[should_panic(expected = "Error(Contract, #3010)")]
fn full_set_cannot_swap_a_signer_in_one_call() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    let mut set = signers(&e, 15);
    c.reconfigure(&0, &set, &8);

    set.pop_back();
    set.push_back(Signer::Delegated(Address::generate(&e)));
    c.reconfigure(&0, &set, &8);
}

/// The two-step form of the above: shrink, then grow. This is the documented way
/// to rotate a signer out of a full rule.
#[test]
fn full_set_swaps_a_signer_in_two_calls() {
    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    let mut set = signers(&e, 15);
    c.reconfigure(&0, &set, &8);

    // Step one: drop to 14. Union is 15, within the cap.
    set.pop_back();
    c.reconfigure(&0, &set, &8);
    assert_eq!(c.signers(&0).len(), 14);

    // Step two: add the replacement. Union is 15 again.
    let replacement = Signer::Delegated(Address::generate(&e));
    set.push_back(replacement.clone());
    c.reconfigure(&0, &set, &8);

    let now = c.signers(&0);
    assert_eq!(now.len(), 15);
    assert!(now.contains(&replacement));
}

/// The indexer reconciles `account_signers` from OZ own signer events, which
/// carry the full Signer value. Assert they actually fire from reconfigure, so a
/// backend that depends on them is not depending on an accident.
#[test]
fn reconfigure_emits_oz_signer_events() {
    use soroban_sdk::testutils::Events as _;

    let e = Env::default();
    e.mock_all_auths();
    let c = setup(&e);

    c.reconfigure(&0, &signers(&e, 2), &2);
    c.reconfigure(&0, &signers(&e, 2), &2);

    let dump = std::format!("{:?}", e.events().all());
    for expected in ["signer_registered", "signer_added", "signer_removed"] {
        assert!(
            dump.contains(expected),
            "expected event {expected} in {dump}"
        );
    }
}
