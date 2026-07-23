# graft-settle

A NockApp with Vesl's full settlement tier grafted in.

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

`graft-mint` grafts commitment and verification. This template goes further: it grafts **Settle** — full settlement lifecycle with replay protection. Notes transition from `%pending` to `%settled` and can never be settled twice.

Drop the hook — settle state on-chain.

## What's Grafted

**Domain logic:**
- `%submit title body` — submit a report (assigns incrementing ID)
- `/report/<id>` — peek at a report
- `/count` — how many reports

**Grafted verification (full settlement):**
- `%settle-register hull root` — register Merkle root
- `%settle-verify payload` — verify manifest (read-only)
- `%settle-note payload` — verify + settle note (state transition + replay guard)
- `/settle-registered/<hull>`, `/settle-root/<hull>`, `/settle-noted/<note-id>`

The kernel's `%settle-note` handler:
1. Cues the jammed settlement-payload
2. Checks the root is registered (guard 1)
3. Checks the note isn't already settled (guard 2 — replay)
4. Verifies the full manifest against the root (guard 3)
5. Transitions the note to `%settled`

All five steps are handled by `settle-poke` from `settle-graft.hoon`. Your kernel just delegates.

## The Settlement Pattern

```
submit reports → commit to Merkle tree → register root
                                              ↓
              verify proofs ← Guard   settle notes ← Settle
                                              ↓
                                    permanent record
                                    (replay-protected)
```

## Build & Run

```bash
# Compile Hoon kernel (requires $NOCK_HOME for tip5 primitives)
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon

# Or use the pre-compiled out.jam (already included)

# Build Rust binary
cargo build

# Run
cargo run
```

## Upgrading from graft-mint

If you started with `graft-mint` and need settlement:

1. Add `%settle-note` to your cause type (it's already in `settle-cause`)
2. Add the settle delegation in your poke arm (3 lines, same pattern)
3. Done. The Graft handles replay protection and state transitions.

~
