# settle-report

Commit, verify, settle. With guards that actually guard.

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

On-chain settlement follows a pattern: commit to a result hash, submit the computation, verify the hash matches, mark it settled, never settle it again. This template implements that exact pattern with three guards that mirror what production NockApps like Vesl use:

1. **Commitment guard** — can't settle without a prior commitment
2. **Replay guard** — can't settle the same ID twice
3. **Hash guard** — submitted data must hash to the committed value

The full Vesl kernel adds Merkle proofs and STARK proving on top of this skeleton. But the settlement bones are identical.

## The Kernel

**State:**
- `commitments=(map @ @)` — id-to-hash mapping
- `settlements=(set @)` — IDs that have been settled

**Pokes:**
| Cause | Effect | What Happens |
|-------|--------|-------------|
| `[%commit id dat]` | `[%committed id hash]` | Stores `shax(dat)` as commitment for `id` |
| `[%settle id dat]` | `[%settled id hash]` or `[%rejected id reason]` | Three-guard verification, then settlement |

**Rejection reasons:**
- `'no commitment'` — no commitment exists for this ID
- `'already settled'` — ID was already settled (replay)
- `'hash mismatch'` — `shax(dat)` doesn't match committed hash

**Peeks:**
| Path | Returns |
|------|---------|
| `/committed/<id>` | `%.y` if commitment exists |
| `/settled/<id>` | `%.y` if already settled |

## Build & Run

```bash
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon
cargo build
cargo run
```

The demo walks through five scenarios:

1. Commit data for ID 1 -> `%committed`
2. Settle ID 1 with correct data -> `%settled`
3. Replay settle ID 1 -> `%rejected` (already settled)
4. Settle ID 999 (never committed) -> `%rejected` (no commitment)
5. Commit ID 2, settle with wrong data -> `%rejected` (hash mismatch)

## The Guard Pattern

The `%settle` poke handler is the interesting part. Read it from top to bottom — it's a guard chain:

```
?.  (has commitment)   -> reject 'no commitment'
?:  (has settlement)   -> reject 'already settled'
?.  (hashes match)     -> reject 'hash mismatch'
::  all clear
settle
```

Each guard early-returns a `%rejected` effect with a reason. Only if all three pass does the kernel update state and emit `%settled`. This pattern scales: add more guards (signature check, timestamp window, balance check) by adding more `?.`/`?:` branches before the settlement logic.

~
