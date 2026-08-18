# Elixir-Contracts

Soroban contracts for **Elixir** — a treasury multisig for Stellar.

> **Status: scaffold.** Structure, shared types, and safety invariants are in place.
> The auth layer is deliberately unimplemented — see [Before you implement](#before-you-implement).

## The design in one paragraph

Squads v4 exists on Solana because a program can sign for a PDA it derives, so the whole
proposal/vote/execute machine is needed to forge a vault's signature. Stellar doesn't need
that: a contract address *is* an account, and `__check_auth` lets the address define what a
signature means. So Elixir is a **smart account by default** (signatures collected off-chain
into one auth entry, ~1 tx per action) **plus an opt-in on-chain queue** for teams that need
async voting or an on-chain audit trail. Squads only has the second thing.

## Layout

```
contracts/
  elixir_account/       smart account: config_epoch, reconfigure, freeze, activity
  elixir_subaccount/    a "vault" — thin delegating account (CAP-71)
  elixir_factory/       deterministic deploy, registry, versioning
  elixir_queue/         opt-in proposals, votes, timelock
  policies/
    destination_allowlist/
    timelock/
packages/
  elixir_types/         shared types: Proposal, Status, roles, errors
```

The queue is a **separate contract** on purpose: the audit surface of the thing that holds
funds should stay as small as possible.

## Build

```bash
rustup target add wasm32v1-none
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo build --target wasm32v1-none --release
```

Pinned to `soroban-sdk` 27.0.6 (Protocol 27 "Zipper").

## Safety invariants (encoded as tests)

| Invariant | Why |
|---|---|
| `config_epoch` is monotonic | Port of Squads' `stale_transaction_index`. Stops "get 2 approvals, quietly add a member, execute against changed policy." |
| A failed `reconfigure` does not bump the epoch | Otherwise a griefing signer invalidates every pending proposal with calls that always revert. |
| `reconfigure` rejects `threshold == 0` or `threshold > signers` | Signer/threshold divergence can render an account permanently unsatisfiable. Never expose raw `add_signer`. |
| Freeze expires on its own, bounded by `MAX_FREEZE_SECONDS` | A 1-of-N alarm must not become a permanent halt. |

## Before you implement

Three things must happen before this scaffold becomes real code:

1. **Resolve the week-one spikes** (`GAPS.md` §F3). Chiefly: *can we simulate a
   2-of-3 C-account invocation with CAP-71 delegation end-to-end on the current SDK?*
   Auth entry assembly depends on it, and Stellar's docs still list contract-account
   simulation support as in development. If that answer is no, the schedule moves.
2. **Decide recovery and emergency-freeze models.** Both touch storage layout, and
   retrofitting either into an audited contract is expensive. The `freeze` /
   `last_activity` hooks here are placeholders for that decision, not the decision.
3. **Extend OpenZeppelin `stellar-contracts/accounts`** rather than reimplementing
   threshold and spending-limit policies. They're audited; those are exactly the
   primitives most likely to hide a subtle bug. Elixir's differentiation is the queue,
   sub-accounts, the policies OZ lacks, and the off-chain stack.

`__check_auth` is intentionally absent for reason 3.

## Known hazards

Read the architecture and gaps docs before writing auth code. The short list:

- **Contract accounts can't be transaction source accounts.** A relayer is mandatory, not
  optional, and it's a centralization point to document honestly.
- **Contract accounts can't do classic ops** — no SDEX offers, ChangeTrust, or path payments.
- **Context-rule selection is client-chosen**, and specificity does not imply precedence. A
  broad fallback rule must be your *strictest* rule. A downgrade bug of this exact shape has
  been found in a Stellar smart account in the wild.
- **Never derive expiry from TTL.** Anyone can extend TTL; store absolute timestamps.
- **Reentrancy**: mark proposals `Executed` before the external invocation; decrement
  spending limits before transfers.

## License

AGPL-3.0-or-later, matching Squads v4.
