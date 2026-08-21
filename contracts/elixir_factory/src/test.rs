#![cfg(test)]

use crate::{ElixirFactory, ElixirFactoryClient};
use elixir_subaccount::ElixirSubaccountClient as SubaccountClient;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

// The factory deploys by Wasm hash, so tests need the real sub-account Wasm.
// CI builds the wasm target before running tests.
const SUBACCOUNT_WASM: &[u8] =
    include_bytes!("../../../target/wasm32v1-none/release/elixir_subaccount.wasm");

struct Fx<'a> {
    factory: ElixirFactoryClient<'a>,
    admin: Address,
    parent: Address,
    wasm: BytesN<32>,
}

fn fx(e: &Env) -> Fx<'_> {
    e.mock_all_auths();
    let admin = Address::generate(e);
    let parent = Address::generate(e);
    let wasm = e
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(e, SUBACCOUNT_WASM));
    let id = e.register(ElixirFactory, (admin.clone(), wasm.clone()));
    Fx {
        factory: ElixirFactoryClient::new(e, &id),
        admin,
        parent,
        wasm,
    }
}

#[test]
fn predicted_address_matches_deployed_address() {
    let e = Env::default();
    let f = fx(&e);
    let predicted = f.factory.predict_address(&f.parent, &0);
    let deployed = f.factory.deploy_subaccount(&f.parent, &0);
    assert_eq!(predicted, deployed);
}

#[test]
fn addresses_are_distinct_per_index_and_per_parent() {
    let e = Env::default();
    let f = fx(&e);
    let other = Address::generate(&e);
    let a0 = f.factory.predict_address(&f.parent, &0);
    let a1 = f.factory.predict_address(&f.parent, &1);
    let b0 = f.factory.predict_address(&other, &0);
    assert_ne!(a0, a1);
    assert_ne!(a0, b0);
}

#[test]
fn deployed_subaccount_knows_its_parent_and_index() {
    let e = Env::default();
    let f = fx(&e);
    f.factory.deploy_subaccount(&f.parent, &0);
    let addr = f.factory.deploy_subaccount(&f.parent, &1);
    let sub = SubaccountClient::new(&e, &addr);
    assert_eq!(sub.parent(), f.parent);
    assert_eq!(sub.index(), 1);
}

#[test]
fn registry_and_count_track_deployments() {
    let e = Env::default();
    let f = fx(&e);
    assert_eq!(f.factory.count(&f.parent), 0);
    assert_eq!(f.factory.subaccount(&f.parent, &0), None);

    let a0 = f.factory.deploy_subaccount(&f.parent, &0);
    let a1 = f.factory.deploy_subaccount(&f.parent, &1);
    assert_eq!(f.factory.count(&f.parent), 2);
    assert_eq!(f.factory.subaccount(&f.parent, &0), Some(a0));
    assert_eq!(f.factory.subaccount(&f.parent, &1), Some(a1));
    assert_eq!(f.factory.subaccount(&f.parent, &2), None);
}

#[test]
fn indices_must_be_allocated_in_order() {
    let e = Env::default();
    let f = fx(&e);
    assert!(
        f.factory.try_deploy_subaccount(&f.parent, &1).is_err(),
        "index 1 before 0"
    );
    f.factory.deploy_subaccount(&f.parent, &0);
    assert!(
        f.factory.try_deploy_subaccount(&f.parent, &0).is_err(),
        "index 0 twice"
    );
    assert!(
        f.factory.try_deploy_subaccount(&f.parent, &2).is_err(),
        "skipping 1"
    );
    f.factory.deploy_subaccount(&f.parent, &1);
}

#[test]
fn wasm_update_bumps_version_and_applies_to_new_deployments_only() {
    let e = Env::default();
    let f = fx(&e);
    assert_eq!(f.factory.version(), 1);
    let before = f.factory.deploy_subaccount(&f.parent, &0);

    // Re-upload the same bytes under a different hash is not possible; use a
    // distinct hash to prove the pointer moved, then restore it to deploy again.
    let fake = BytesN::from_array(&e, &[7u8; 32]);
    f.factory.set_subaccount_wasm(&fake);
    assert_eq!(f.factory.version(), 2);
    assert_eq!(f.factory.subaccount_wasm(), fake);
    assert!(
        f.factory.try_deploy_subaccount(&f.parent, &1).is_err(),
        "unknown wasm hash"
    );

    f.factory.set_subaccount_wasm(&f.wasm);
    assert_eq!(f.factory.version(), 3);
    let after = f.factory.deploy_subaccount(&f.parent, &1);
    assert_ne!(before, after);
    assert_eq!(
        SubaccountClient::new(&e, &before).index(),
        0,
        "existing instance untouched"
    );
}

#[test]
fn only_admin_can_update_wasm() {
    let e = Env::default();
    let f = fx(&e);
    let _ = f.admin;
    e.set_auths(&[]);
    assert!(f
        .factory
        .try_set_subaccount_wasm(&BytesN::from_array(&e, &[1u8; 32]))
        .is_err());
}

#[test]
fn deploy_requires_parent_auth() {
    let e = Env::default();
    let f = fx(&e);
    e.set_auths(&[]);
    assert!(f.factory.try_deploy_subaccount(&f.parent, &0).is_err());
}
