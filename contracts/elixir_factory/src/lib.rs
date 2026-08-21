#![no_std]

//! elixir_factory — deterministic sub-account deployment, registry, and Wasm
//! version management.
//!
//! Address derivation: the factory deploys with `salt = sha256(parent ‖ index)`
//! under its own address, so `predict_address(parent, index)` is exact before
//! anything is deployed. Whether funds can safely land on a not-yet-deployed
//! address is the SAC spike (#2); the contract is the same either way.
//!
//! Upgrade posture (docs/GAPS.md B5): the factory publishes sub-account Wasm
//! versions. Already-deployed sub-accounts are not touched; adoption is per
//! instance and opt-in.
//!
//! Bookkeeping lives here, not on the account. The account cannot be called
//! back while it is on the stack (the host forbids re-entry), so the factory
//! keeps `count(parent)` and the (parent, index) → address registry itself.

use elixir_types::Error;
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, panic_with_error, xdr::ToXdr, Address,
    Bytes, BytesN, Env,
};

const DAY_IN_LEDGERS: u32 = 17280;
const INSTANCE_LIFETIME_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const INSTANCE_BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;
const REGISTRY_LIFETIME_THRESHOLD: u32 = 90 * DAY_IN_LEDGERS;
const REGISTRY_BUMP_AMOUNT: u32 = 365 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    SubaccountWasm,
    Version,
    /// (parent, index) → deployed sub-account address.
    Subaccount(Address, u32),
    /// parent → number of sub-accounts deployed.
    Count(Address),
}

#[contractevent]
pub struct SubaccountDeployed {
    pub parent: Address,
    pub index: u32,
    pub address: Address,
    pub version: u32,
}

#[contractevent]
pub struct WasmUpdated {
    pub version: u32,
    pub wasm_hash: BytesN<32>,
}

#[contract]
pub struct ElixirFactory;

#[contractimpl]
impl ElixirFactory {
    pub fn __constructor(e: Env, admin: Address, subaccount_wasm: BytesN<32>) {
        if e.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&e, Error::AlreadyInitialized);
        }
        e.storage().instance().set(&DataKey::Admin, &admin);
        e.storage()
            .instance()
            .set(&DataKey::SubaccountWasm, &subaccount_wasm);
        e.storage().instance().set(&DataKey::Version, &1u32);
        bump_instance(&e);
    }

    pub fn version(e: Env) -> u32 {
        e.storage().instance().get(&DataKey::Version).unwrap_or(0)
    }

    pub fn subaccount_wasm(e: Env) -> BytesN<32> {
        match e.storage().instance().get(&DataKey::SubaccountWasm) {
            Some(h) => h,
            None => panic_with_error!(&e, Error::NotInitialized),
        }
    }

    /// Publish a new sub-account Wasm. Affects future deployments only.
    pub fn set_subaccount_wasm(e: Env, wasm_hash: BytesN<32>) {
        let admin: Address = match e.storage().instance().get(&DataKey::Admin) {
            Some(a) => a,
            None => panic_with_error!(&e, Error::NotInitialized),
        };
        admin.require_auth();
        let version = Self::version(e.clone()) + 1;
        e.storage()
            .instance()
            .set(&DataKey::SubaccountWasm, &wasm_hash);
        e.storage().instance().set(&DataKey::Version, &version);
        bump_instance(&e);
        WasmUpdated { version, wasm_hash }.publish(&e);
    }

    /// The address `deploy_subaccount(parent, index)` will produce. Exact, and
    /// independent of whether it has been deployed yet.
    pub fn predict_address(e: Env, parent: Address, index: u32) -> Address {
        e.deployer()
            .with_current_contract(salt(&e, &parent, index))
            .deployed_address()
    }

    /// Deploy sub-account `index` for `parent`. Requires the parent's
    /// authorization — when the call arrives through `exec_queued`, the account
    /// is the invoker and that satisfies it. Indices must be allocated in order.
    pub fn deploy_subaccount(e: Env, parent: Address, index: u32) -> Address {
        parent.require_auth();

        let expected = Self::count(e.clone(), parent.clone());
        if index != expected {
            panic_with_error!(&e, Error::InvalidStatus);
        }
        let key = DataKey::Subaccount(parent.clone(), index);
        if e.storage().persistent().has(&key) {
            panic_with_error!(&e, Error::AlreadyInitialized);
        }

        let wasm = Self::subaccount_wasm(e.clone());
        let address = e
            .deployer()
            .with_current_contract(salt(&e, &parent, index))
            .deploy_v2(wasm, (parent.clone(), index));

        e.storage().persistent().set(&key, &address);
        e.storage().persistent().extend_ttl(
            &key,
            REGISTRY_LIFETIME_THRESHOLD,
            REGISTRY_BUMP_AMOUNT,
        );
        let count_key = DataKey::Count(parent.clone());
        e.storage().persistent().set(&count_key, &(index + 1));
        e.storage().persistent().extend_ttl(
            &count_key,
            REGISTRY_LIFETIME_THRESHOLD,
            REGISTRY_BUMP_AMOUNT,
        );
        bump_instance(&e);

        SubaccountDeployed {
            parent,
            index,
            address: address.clone(),
            version: Self::version(e.clone()),
        }
        .publish(&e);
        address
    }

    /// Deployed address for (parent, index), if any.
    pub fn subaccount(e: Env, parent: Address, index: u32) -> Option<Address> {
        e.storage()
            .persistent()
            .get(&DataKey::Subaccount(parent, index))
    }

    /// How many sub-accounts `parent` has deployed; also the next index.
    pub fn count(e: Env, parent: Address) -> u32 {
        e.storage()
            .persistent()
            .get(&DataKey::Count(parent))
            .unwrap_or(0)
    }
}

fn salt(e: &Env, parent: &Address, index: u32) -> BytesN<32> {
    let mut b: Bytes = parent.clone().to_xdr(e);
    b.extend_from_array(&index.to_be_bytes());
    e.crypto().sha256(&b).into()
}

fn bump_instance(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

mod test;
