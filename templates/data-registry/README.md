# data-registry

A name-to-hash registry. Register data commitments, verify them later.

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

The pattern: "I committed to this data at time T, and I can prove it hasn't changed." This comes up everywhere — document hashes, configuration digests, model weights, audit logs. The kernel hashes your data with SHA-256 on registration, then verifies against the stored hash on demand.

This is the generalized version of Vesl's root registration, stripped down to the essential pattern.

## The Kernel

**State:**
- `registry=(map @t @)` — name-to-hash mapping
- `entries=@ud` — number of registered entries

**Pokes:**
| Cause | Effect | What Happens |
|-------|--------|-------------|
| `[%register name dat]` | `[%registered name hash]` | Stores `shax(dat)` under `name` |
| `[%verify name dat]` | `[%verified name valid]` or `[%not-found name]` | Checks `shax(dat)` against stored hash |
| `[%lookup name]` | `[%found name hash]` or `[%not-found name]` | Returns the stored hash |

**Peeks:**
| Path | Returns |
|------|---------|
| `/entries` | Number of registered entries |
| `/hash/<name>` | Hash for a specific name (unit) |

## Build & Run

```bash
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon
cargo build
cargo run
```

Expected output:
```
--- registering 'doc-v1' ---
  effect: %registered
--- verifying 'doc-v1' with correct data ---
  effect: %verified
--- verifying 'doc-v1' with wrong data ---
  effect: %verified
--- looking up 'doc-v1' ---
  effect: %found
--- looking up 'ghost' (not registered) ---
  effect: %not-found
```

The second verify returns `%verified` with `valid=%.n` (loobean false) — the effect tag is the same, but the payload contains the boolean result.

## What to Read

`hoon/app/app.hoon` — focus on the `%register` and `%verify` poke handlers. The register stores `(shax dat)`, the verify computes `(shax dat)` again and compares. Same hash function, same deterministic result, different time. That's a commitment scheme.

~
