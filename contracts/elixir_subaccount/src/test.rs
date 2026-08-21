#![cfg(test)]

extern crate std;

use crate::{ElixirSubaccount, ElixirSubaccountClient};
use elixir_types::Error;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    symbol_short,
    testutils::Address as _,
    xdr::{
        InvokeContractArgs, ScAddress, ScVal, SorobanAddressCredentials,
        SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
        SorobanDelegateSignature, StringM, VecM,
    },
    Address, Env, IntoVal, Val, Vec,
};

// A parent that approves every delegated auth and records that it was asked.
// Stands in for elixir_account's __check_auth, which is #7.
#[contract]
pub struct ApprovingParent;

#[contracttype]
#[derive(Clone)]
pub enum ParentKey {
    Asked,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ParentError {
    Never = 1,
}

#[contractimpl]
impl CustomAccountInterface for ApprovingParent {
    type Signature = ();
    type Error = ParentError;
    fn __check_auth(e: Env, _p: Hash<32>, _s: (), _c: Vec<Context>) -> Result<(), ParentError> {
        e.storage().instance().set(&ParentKey::Asked, &true);
        Ok(())
    }
}

#[contractimpl]
impl ApprovingParent {
    pub fn asked(e: Env) -> bool {
        e.storage()
            .instance()
            .get(&ParentKey::Asked)
            .unwrap_or(false)
    }
}

// A target that requires the sub-account's own authorization.
#[contract]
pub struct Protected;

#[contractimpl]
impl Protected {
    pub fn guarded(e: Env, who: Address) -> u32 {
        who.require_auth();
        let n: u32 = e.storage().instance().get(&symbol_short!("n")).unwrap_or(0) + 1;
        e.storage().instance().set(&symbol_short!("n"), &n);
        n
    }
    pub fn n(e: Env) -> u32 {
        e.storage().instance().get(&symbol_short!("n")).unwrap_or(0)
    }
}

#[test]
fn constructor_records_parent_and_index() {
    let e = Env::default();
    let parent = Address::generate(&e);
    let id = e.register(ElixirSubaccount, (parent.clone(), 3u32));
    let c = ElixirSubaccountClient::new(&e, &id);
    assert_eq!(c.parent(), parent);
    assert_eq!(c.index(), 3);
}

#[test]
fn exec_runs_target_as_the_subaccount() {
    let e = Env::default();
    e.mock_all_auths_allowing_non_root_auth();
    let parent = Address::generate(&e);
    let sub = e.register(ElixirSubaccount, (parent.clone(), 0u32));
    let target = e.register(Protected, ());

    let args: Vec<Val> = soroban_sdk::vec![&e, sub.clone().into_val(&e)];
    ElixirSubaccountClient::new(&e, &sub).exec(&target, &symbol_short!("guarded"), &args);
    assert_eq!(ProtectedClient::new(&e, &target).n(), 1);
}

#[test]
fn exec_requires_parent_auth() {
    let e = Env::default();
    let parent = Address::generate(&e);
    let sub = e.register(ElixirSubaccount, (parent, 0u32));
    let target = e.register(Protected, ());
    e.set_auths(&[]);
    let args: Vec<Val> = soroban_sdk::vec![&e, sub.clone().into_val(&e)];
    let r =
        ElixirSubaccountClient::new(&e, &sub).try_exec(&target, &symbol_short!("guarded"), &args);
    assert!(r.is_err());
    assert_eq!(ProtectedClient::new(&e, &target).n(), 0);
}

/// CAP-71: something calls require_auth(sub). The host runs the sub-account's
/// __check_auth, which forwards to the parent. The parent approves. No
/// signature logic ran in the sub-account.
#[test]
fn check_auth_delegates_to_parent() {
    let e = Env::default();
    let parent = e.register(ApprovingParent, ());
    let sub = e.register(ElixirSubaccount, (parent.clone(), 0u32));
    let target = e.register(Protected, ());

    e.set_auths(&[delegated_entry(&e, &sub, &parent, &target)]);
    ProtectedClient::new(&e, &target).guarded(&sub);

    assert!(
        ApprovingParentClient::new(&e, &parent).asked(),
        "parent's __check_auth must run"
    );
    assert_eq!(ProtectedClient::new(&e, &target).n(), 1);
}

/// An auth entry naming anyone but the parent as the delegate is rejected by
/// the sub-account itself, before the host consults that address.
#[test]
fn check_auth_rejects_a_delegate_that_is_not_the_parent() {
    let e = Env::default();
    let parent = e.register(ApprovingParent, ());
    let impostor = e.register(ApprovingParent, ());
    let sub = e.register(ElixirSubaccount, (parent.clone(), 0u32));
    let target = e.register(Protected, ());

    e.set_auths(&[delegated_entry(&e, &sub, &impostor, &target)]);
    let r = ProtectedClient::new(&e, &target).try_guarded(&sub);
    assert!(r.is_err());
    assert!(
        !ApprovingParentClient::new(&e, &impostor).asked(),
        "impostor must never be consulted"
    );
    assert!(!ApprovingParentClient::new(&e, &parent).asked());
    assert_eq!(ProtectedClient::new(&e, &target).n(), 0);
    let _ = Error::Unauthorized;
}

/// An auth entry with no delegate at all is rejected: the sub-account has no
/// signers of its own.
#[test]
fn check_auth_rejects_entry_without_delegate() {
    let e = Env::default();
    let parent = e.register(ApprovingParent, ());
    let sub = e.register(ElixirSubaccount, (parent, 0u32));
    let target = e.register(Protected, ());

    let sub_addr: ScAddress = sub.clone().into();
    e.set_auths(&[SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: sub_addr.clone(),
            nonce: 1,
            signature_expiration_ledger: 100,
            signature: ScVal::Void,
        }),
        root_invocation: invocation(&target, &sub_addr),
    }]);
    assert!(ProtectedClient::new(&e, &target).try_guarded(&sub).is_err());
    assert_eq!(ProtectedClient::new(&e, &target).n(), 0);
}

fn invocation(target: &Address, sub_addr: &ScAddress) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: target.clone().into(),
            function_name: StringM::try_from("guarded").unwrap().into(),
            args: std::vec![ScVal::Address(sub_addr.clone())]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

fn delegated_entry(
    e: &Env,
    sub: &Address,
    delegate: &Address,
    target: &Address,
) -> SorobanAuthorizationEntry {
    let _ = e;
    let sub_addr: ScAddress = sub.clone().into();
    let delegate_addr: ScAddress = delegate.clone().into();
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: sub_addr.clone(),
                    nonce: 1,
                    signature_expiration_ledger: 100,
                    signature: ScVal::Void,
                },
                delegates: std::vec![SorobanDelegateSignature {
                    address: delegate_addr,
                    signature: ScVal::Void,
                    nested_delegates: VecM::default(),
                }]
                .try_into()
                .unwrap(),
            },
        ),
        root_invocation: invocation(target, &sub_addr),
    }
}
