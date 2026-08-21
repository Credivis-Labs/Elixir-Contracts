# Execution semantics

What happens when `elixir_queue::execute` runs, what can interrupt it, and what
the caller sees when it fails. Issue #9.

## Ordering

```
execute(member, id)
  1. load proposal, load account config
  2. gate: Approved → epoch matches → timelock elapsed → not expired → ROLE_EXECUTE
  3. write proposal.status = Executed            ← before any external call
  4. for each invocation, in order:
       account.exec_queued(target, fn, args)
         4a. queue.require_auth()  (satisfied by invoker auth)
         4b. frozen? → Frozen
         4c. ExecLock set? → Reentrancy;  set ExecLock
         4d. invoke_contract(target, fn, args)
         4e. clear ExecLock; touch last_activity
  5. emit Executed
```

Step 3 precedes step 4 deliberately. If a target could re-enter `execute` for
the same id, it would find `Executed` and fail with `InvalidStatus`.

## Reentrancy

Three layers, outermost first.

| Layer | Where | What it does |
|---|---|---|
| Host | Soroban | Refuses to invoke any contract already on the call stack. Fails with `Context / InvalidAction`. |
| Ordering | `elixir_queue::execute` | `Executed` is written before the external call. |
| `ExecLock` | `elixir_account::exec_queued` | Temporary-storage flag set around the invocation. |

The host layer is what actually fires today: `test_reentrancy.rs` proves that a
target re-entering either the queue or the account is rejected before any
contract code runs, and that the whole transaction reverts. Layers two and
three are kept because they cost almost nothing and would hold on their own if
the host ever relaxed its rule.

`ExecLock` lives in temporary storage and is cleared on the success path. On
the failure path it does not need clearing: the transaction reverts, taking the
flag with it. `exec_lock_does_not_leak_across_transactions` covers this.

## Batches

A proposal carries `Vec<Invocation>`. `execute` runs them in order through
`exec_queued`, one host call each.

**All or nothing.** A Soroban transaction is atomic. If invocation 3 of 5 panics,
invocations 1 and 2 are rolled back along with the `Executed` status write, and
the proposal is still `Approved` afterwards. There is no partial execution and
no retry-from-step-3; the next `execute` starts from invocation 1 again.

**What the caller sees.** The error surfaced is whatever the failing target
raised, wrapped by the host. The queue does not add a "failed at index N"
marker, because there is no state left behind to attach it to. Diagnostics
come from simulation: the SDK simulates the full batch before submission and
reports which invocation fails and why. The dapp shows that before anyone
signs. docs/GAPS.md B1.

**Ordering within a batch matters.** Invocation 2 sees the effects of
invocation 1. A batch that funds a sub-account and then spends from it is
valid; the reverse is not.

**Sub-account batches.** When `proposal.subaccount` is set, every invocation is
wrapped as `exec_queued(sub, "exec", [target, fn, args])`. The account
authorizes as invoker, and the sub-account's `exec` requires exactly that. The
atomicity rule is unchanged.

## Spending limits

`exec_queued` does not yet decrement a spending limit, because the policy
machinery lives in OpenZeppelin `stellar-accounts` and that crate currently
pins soroban-sdk 26.x against this workspace's 27.0.6 (#7). When it lands, the
decrement goes **before** `invoke_contract` in `exec_queued`, for the same
reason `Executed` goes before the call: a hostile token must see the limit
already spent.

## Frozen accounts

`exec_queued` refuses while `frozen_until` is in the future, so a queued
proposal cannot execute during a freeze even if its gate is open. Settings
operations are not exempt here today; that exemption is part of the freeze
decision in #5 and will be added alongside it.
