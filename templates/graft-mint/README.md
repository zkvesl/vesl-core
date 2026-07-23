# graft-mint

A NockApp with Vesl's Mint + Guard tiers grafted in.

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

You have a NockApp. You want to add Merkle commitment and verification to it. You don't want to write any verification logic. The Graft pattern lets you compose Vesl's verification state and poke handlers into your kernel alongside your domain logic.

This template is the reference implementation of a 10-minute Graft.

## What's Grafted

The kernel has two layers:

**Domain logic** (yours):
- `%put key val` — store a note
- `%del key` — delete a note
- `/note/<key>` — peek at a note
- `/count` — how many notes

**Grafted verification** (Vesl's):
- `%settle-register hull root` — register a Merkle root
- `%settle-verify payload` — verify a manifest against a registered root
- `%settle-note payload` — verify + settle a note
- `/settle-registered/<hull>` — is this hull registered?
- `/settle-root/<hull>` — what root did this hull register?

Zero verification code in the kernel. The `++poke` arm delegates `%settle-*` causes to `settle-poke` from `settle-graft.hoon`. Three lines per cause.

## The Pattern

In your kernel's state, compose `settle-state`:

```hoon
+$  versioned-state
  $:  %v1
      settle=settle-state       :: grafted
      notes=(map @t @t)         :: yours
  ==
```

In your poke arm, delegate:

```hoon
  %settle-register
=/  lc=settle-cause  [%settle-register hull.u.act root.u.act]
=/  rag-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =/  mani  ;;(manifest data)
  (verify-manifest mani expected-root)
=/  [efx=(list settle-effect) new-settle=settle-state]
  (settle-poke settle.state lc rag-gate)
:_  state(settle new-settle)
^-  (list effect)  efx
```

In your peek arm, fall through:

```hoon
?+  path  (settle-peek settle.state path)
  [%note key=@t ~]  ...your peeks...
==
```

That's the Graft. Your domain logic stays clean. Vesl verification is composable infrastructure.

## Rust Side

The Rust driver demonstrates the Mint + Guard workflow:

1. **Mint** builds a Merkle tree from your data and gives you a root + proofs
2. You poke `%settle-register` to tell the kernel about the root
3. **Guard** verifies individual proofs against the root (local, no kernel needed)

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

## Files

```
hoon/
  app/app.hoon          — the kernel (domain + graft)
  lib/settle-graft.hoon — composable state and poke dispatcher
  lib/rag-logic.hoon   — RAG verification gates
  lib/vesl-merkle.hoon  — Merkle primitives (tip5)
  sur/vesl.hoon          — type definitions
  common/wrapper.hoon  — NockApp protocol
src/main.rs            — Rust driver with Mint + Guard demo
```

## What to Read

Start with `hoon/app/app.hoon`. The Graft delegation is at the bottom of the `++poke` arm — look for the "grafted verification" comment. Then compare the Rust side (`src/main.rs`) to see how `Mint::commit()` and `Guard::check()` mirror the kernel's registration and verification.

~
