#![no_std]

//! elixir_queue — opt-in on-chain proposal queue (Squads-style async voting).
//!
//! Deliberately a SEPARATE contract from elixir_account: the audit surface of
//! "the thing that holds funds" should stay as small as possible.
//! See docs/ARCHITECTURE.md §4.1.
//!
//! Lifecycle: Active → Approved → Executed
//!                   ↘ Rejected
//!            Active | Approved → Cancelled
//!
//! execute() gate — all five must hold, checked in this order:
//!   status == Approved
//!   config_epoch == account.config_epoch     (no execution across a config change)
//!   now >= approved_at + time_lock
//!   now <  expires_at                        (absolute, not TTL-derived)
//!   caller has ROLE_EXECUTE
//!
//! Reentrancy: the proposal is marked Executed and written to storage BEFORE the
//! external invocation. A hostile target that re-enters `execute` for the same id
//! hits InvalidStatus. docs/GAPS.md B3.
//!
//! Auth model: every entrypoint takes the acting member as an argument and calls
//! `require_auth` on it. Roles are held here, per member, as a bitmask — a key
//! with only ROLE_INITIATE can never approve.

use elixir_types::{
    AccountClient, Error, Invocation, Proposal, Status, ROLE_EXECUTE, ROLE_INITIATE, ROLE_VOTE,
};
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Env, IntoVal, Map, Val, Vec,
};

const DAY_IN_LEDGERS: u32 = 17280;
const INSTANCE_LIFETIME_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const INSTANCE_BUMP_AMOUNT: u32 = 90 * DAY_IN_LEDGERS;
/// Proposals live in persistent storage. The TTL is a storage concern only;
/// `expires_at` is the time-based invariant.
const PROPOSAL_LIFETIME_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const PROPOSAL_BUMP_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;

/// Default absolute lifetime of a proposal from creation, in seconds.
pub const DEFAULT_PROPOSAL_LIFETIME: u64 = 7 * 24 * 60 * 60;

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Proposal(u64),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueConfig {
    /// The elixir_account this queue executes on behalf of.
    pub account: Address,
    /// Member → role bitmask.
    pub members: Map<Address, u32>,
    /// Approvals needed for a proposal to become Approved.
    pub threshold: u32,
    /// Seconds from creation until a proposal expires.
    pub proposal_lifetime: u64,
    pub next_id: u64,
}

#[contractevent]
pub struct Proposed {
    pub id: u64,
    pub creator: Address,
    pub config_epoch: u32,
    pub expires_at: u64,
}

#[contractevent]
pub struct Voted {
    pub id: u64,
    pub member: Address,
    pub approve: bool,
    pub status: Status,
}

#[contractevent]
pub struct Cancelled {
    pub id: u64,
    pub by: Address,
}

#[contractevent]
pub struct Executed {
    pub id: u64,
    pub by: Address,
}

#[contractevent]
pub struct MembersSet {
    pub member_count: u32,
    pub threshold: u32,
}

#[contract]
pub struct ElixirQueue;

#[contractimpl]
impl ElixirQueue {
    /// `members` is a list of (address, role bitmask). Threshold counts approvals
    /// from members holding ROLE_VOTE, so it must not exceed that count.
    pub fn __constructor(
        e: Env,
        account: Address,
        members: Vec<(Address, u32)>,
        threshold: u32,
        proposal_lifetime: u64,
    ) {
        if e.storage().instance().has(&DataKey::Config) {
            panic_with_error!(&e, Error::AlreadyInitialized);
        }
        let map = build_members(&e, &members, threshold);
        e.storage().instance().set(
            &DataKey::Config,
            &QueueConfig {
                account,
                members: map,
                threshold,
                proposal_lifetime: if proposal_lifetime == 0 {
                    DEFAULT_PROPOSAL_LIFETIME
                } else {
                    proposal_lifetime
                },
                next_id: 1,
            },
        );
        bump_instance(&e);
    }

    pub fn config(e: Env) -> QueueConfig {
        load_config(&e)
    }

    pub fn get_proposal(e: Env, id: u64) -> Proposal {
        load_proposal(&e, id)
    }

    pub fn version(_e: Env) -> u32 {
        1
    }

    /// Replace the member set and threshold atomically. Only the account may call
    /// this — it is the on-chain mirror of `elixir_account::reconfigure`, and the
    /// account's epoch bump is what invalidates pending proposals.
    pub fn set_members(e: Env, members: Vec<(Address, u32)>, threshold: u32) {
        let mut cfg = load_config(&e);
        cfg.account.require_auth();
        cfg.members = build_members(&e, &members, threshold);
        cfg.threshold = threshold;
        e.storage().instance().set(&DataKey::Config, &cfg);
        bump_instance(&e);
        MembersSet {
            member_count: members.len(),
            threshold,
        }
        .publish(&e);
    }

    /// Create a proposal. The creator's approval is recorded immediately, so a
    /// 1-of-N queue settles to Approved on creation.
    pub fn propose(
        e: Env,
        creator: Address,
        subaccount: Option<Address>,
        invocations: Vec<Invocation>,
    ) -> u64 {
        creator.require_auth();
        let mut cfg = load_config(&e);
        require_role(&e, &cfg, &creator, ROLE_INITIATE);
        if invocations.is_empty() {
            panic_with_error!(&e, Error::EmptyProposal);
        }

        let account = AccountClient::new(&e, &cfg.account);
        let epoch = account.config().config_epoch;
        let now = e.ledger().timestamp();
        let id = cfg.next_id;
        cfg.next_id += 1;
        e.storage().instance().set(&DataKey::Config, &cfg);

        let mut p = Proposal {
            id,
            creator: creator.clone(),
            subaccount,
            invocations,
            config_epoch: epoch,
            status: Status::Active,
            approvals: Vec::new(&e),
            rejections: Vec::new(&e),
            approved_at: None,
            expires_at: now + cfg.proposal_lifetime,
        };
        if has_role(&cfg, &creator, ROLE_VOTE) {
            p.approvals.push_back(creator.clone());
            settle(&e, &cfg, &mut p, now);
        }
        store_proposal(&e, &p);
        bump_instance(&e);

        Proposed {
            id,
            creator,
            config_epoch: epoch,
            expires_at: p.expires_at,
        }
        .publish(&e);
        id
    }

    pub fn approve(e: Env, member: Address, id: u64) {
        vote(&e, member, id, true);
    }

    pub fn reject(e: Env, member: Address, id: u64) {
        vote(&e, member, id, false);
    }

    /// Post-approval escape hatch. Any voting member can cancel an Active or
    /// Approved proposal — this is what makes the timelock window useful.
    pub fn cancel(e: Env, member: Address, id: u64) {
        member.require_auth();
        let cfg = load_config(&e);
        require_role(&e, &cfg, &member, ROLE_VOTE);
        let mut p = load_proposal(&e, id);
        if p.status != Status::Active && p.status != Status::Approved {
            panic_with_error!(&e, Error::InvalidStatus);
        }
        p.status = Status::Cancelled;
        store_proposal(&e, &p);
        Cancelled { id, by: member }.publish(&e);
    }

    /// Run every invocation through the account. Atomic: if any invocation
    /// fails, the whole transaction reverts, including the status write below.
    pub fn execute(e: Env, member: Address, id: u64) {
        member.require_auth();
        let cfg = load_config(&e);
        let mut p = load_proposal(&e, id);
        let account = AccountClient::new(&e, &cfg.account);
        let acct_cfg = account.config();
        let now = e.ledger().timestamp();

        // The gate, in the order the architecture doc specifies.
        if p.status != Status::Approved {
            panic_with_error!(&e, Error::InvalidStatus);
        }
        if p.config_epoch != acct_cfg.config_epoch {
            panic_with_error!(&e, Error::StaleConfigEpoch);
        }
        let approved_at = p.approved_at.unwrap_or(u64::MAX);
        if now < approved_at.saturating_add(acct_cfg.time_lock as u64) {
            panic_with_error!(&e, Error::TimelockNotElapsed);
        }
        if now >= p.expires_at {
            panic_with_error!(&e, Error::ProposalExpired);
        }
        require_role(&e, &cfg, &member, ROLE_EXECUTE);

        // Mark Executed BEFORE any external call. docs/GAPS.md B3.
        p.status = Status::Executed;
        store_proposal(&e, &p);

        for inv in p.invocations.iter() {
            match &p.subaccount {
                // Route through the sub-account: the account authorizes as invoker,
                // and the sub-account's `exec` requires exactly that.
                Some(sub) => {
                    let args: Vec<Val> =
                        (inv.target.clone(), inv.fn_name.clone(), inv.args.clone()).into_val(&e);
                    account.exec_queued(sub, &symbol_short!("exec"), &args);
                }
                None => {
                    account.exec_queued(&inv.target, &inv.fn_name, &inv.args);
                }
            }
        }

        Executed { id, by: member }.publish(&e);
    }
}

fn vote(e: &Env, member: Address, id: u64, approve: bool) {
    member.require_auth();
    let cfg = load_config(e);
    require_role(e, &cfg, &member, ROLE_VOTE);
    let mut p = load_proposal(e, id);
    if p.status != Status::Active {
        panic_with_error!(e, Error::InvalidStatus);
    }
    if p.approvals.contains(&member) || p.rejections.contains(&member) {
        panic_with_error!(e, Error::AlreadyVoted);
    }
    if approve {
        p.approvals.push_back(member.clone());
    } else {
        p.rejections.push_back(member.clone());
    }
    settle(e, &cfg, &mut p, e.ledger().timestamp());
    store_proposal(e, &p);
    Voted {
        id,
        member,
        approve,
        status: p.status,
    }
    .publish(e);
}

/// Resolve Active → Approved when the threshold is met, or → Rejected when it
/// can no longer be met.
fn settle(e: &Env, cfg: &QueueConfig, p: &mut Proposal, now: u64) {
    if p.status != Status::Active {
        return;
    }
    if p.approvals.len() >= cfg.threshold {
        p.status = Status::Approved;
        p.approved_at = Some(now);
        return;
    }
    let voters = voter_count(e, cfg);
    let remaining = voters.saturating_sub(p.rejections.len());
    if remaining < cfg.threshold {
        p.status = Status::Rejected;
    }
}

fn voter_count(_e: &Env, cfg: &QueueConfig) -> u32 {
    let mut n = 0u32;
    for (_, roles) in cfg.members.iter() {
        if roles & ROLE_VOTE != 0 {
            n += 1;
        }
    }
    n
}

fn build_members(e: &Env, members: &Vec<(Address, u32)>, threshold: u32) -> Map<Address, u32> {
    let mut map: Map<Address, u32> = Map::new(e);
    let mut voters = 0u32;
    for (addr, roles) in members.iter() {
        if roles & ROLE_VOTE != 0 {
            voters += 1;
        }
        map.set(addr, roles);
    }
    if threshold == 0 || threshold > voters {
        panic_with_error!(e, Error::UnsatisfiableThreshold);
    }
    map
}

fn has_role(cfg: &QueueConfig, member: &Address, role: u32) -> bool {
    match cfg.members.get(member.clone()) {
        Some(r) => r & role != 0,
        None => false,
    }
}

fn require_role(e: &Env, cfg: &QueueConfig, member: &Address, role: u32) {
    match cfg.members.get(member.clone()) {
        None => panic_with_error!(e, Error::NotAMember),
        Some(r) if r & role == 0 => panic_with_error!(e, Error::Unauthorized),
        Some(_) => {}
    }
}

fn load_config(e: &Env) -> QueueConfig {
    match e.storage().instance().get(&DataKey::Config) {
        Some(c) => c,
        None => panic_with_error!(e, Error::NotInitialized),
    }
}

fn load_proposal(e: &Env, id: u64) -> Proposal {
    let key = DataKey::Proposal(id);
    match e.storage().persistent().get(&key) {
        Some(p) => {
            e.storage().persistent().extend_ttl(
                &key,
                PROPOSAL_LIFETIME_THRESHOLD,
                PROPOSAL_BUMP_AMOUNT,
            );
            p
        }
        None => panic_with_error!(e, Error::ProposalNotFound),
    }
}

fn store_proposal(e: &Env, p: &Proposal) {
    let key = DataKey::Proposal(p.id);
    e.storage().persistent().set(&key, p);
    e.storage()
        .persistent()
        .extend_ttl(&key, PROPOSAL_LIFETIME_THRESHOLD, PROPOSAL_BUMP_AMOUNT);
}

fn bump_instance(e: &Env) {
    e.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

mod test;
mod test_reentrancy;
