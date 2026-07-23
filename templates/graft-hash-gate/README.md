# graft-hash-gate

A NockApp with a custom (non-RAG) verification gate grafted in. Hashes data, compares it to a committed root — that's the whole gate.

## This is not an intent primitive

It used to be named `graft-intent`, which was misleading. This template does not implement intent coordination (declare / match / cancel). It demonstrates that the settle graft's verification gate is a parameter — you can swap RAG's manifest logic for any other predicate. For the reserved intent-family graft see `templates/graft-intent/` and `protocol/lib/intent-graft.hoon` (placeholder pending canonical upstream).

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

`graft-mint` and `graft-settle` use RAG verification — manifests, Merkle proofs, prompt reconstruction. That's one gate. The Graft doesn't care what your gate does. This template proves it.

The verification gate here is one line:

```hoon
=((hash-leaf ;;(@ data)) expected-root)
```

Hash the data, compare to root. No manifest types, no `sur/vesl.hoon`, no `rag-logic.hoon`. The Graft is domain-agnostic — the gate is yours.

## What's Grafted

**Domain logic (the kernel's own arms — unrelated to the reserved intent-graft primitive):**
- `%declare intent` — register a string under the kernel's local `intent` keyspace
- `/intent/<id>` — peek at a registered string
- `/count` — how many strings

**Grafted verification (custom hash gate):**
- `%settle-register hull root` — register a Merkle root
- `%settle-verify payload` — verify data against root via hash gate
- `%settle-note payload` — verify + settle (state transition + replay guard)
- `/settle-registered/<hull>`, `/settle-root/<hull>`, `/settle-noted/<note-id>`

## The Custom Gate Pattern

Define your gate inline where you delegate pokes:

```hoon
=/  hash-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  =((hash-leaf ;;(@ data)) expected-root)
=/  [efx=(list settle-effect) new-settle=settle-state]
  (settle-poke settle.state lc hash-gate)
```

The gate signature is `$-([note-id=@ data=* expected-root=@] ?)`. Cast `data` to your domain type, verify however you want, return a loobean. Bind `note-id` into the data if you want pre-commit protection (see `.dev/AUDIT_REPORT.md` H-03).

## Build & Run

```bash
# Compile Hoon kernel (requires $NOCK_HOME for tip5 primitives)
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon

# Build Rust binary
cargo build

# Run
cargo run
```

## Files

```
hoon/
  app/app.hoon          — the kernel (hash gate demo + local string registry)
  lib/settle-graft.hoon — composable state and poke dispatcher
  lib/vesl-merkle.hoon  — Merkle primitives (tip5)
  common/wrapper.hoon   — NockApp protocol
src/main.rs             — Rust driver with Mint commitment demo
```

## Writing Your Own Gate

The gate type is `verify-gate`:

```hoon
+$  verify-gate  $-([note-id=@ data=* expected-root=@] ?)
```

`data` is opaque `*`. Cast it to whatever your domain needs:

```hoon
::  hash comparison (this template)
=((hash-leaf ;;(@ data)) expected-root)

::  RAG manifest verification (graft-mint, graft-settle)
(verify-manifest ;;(manifest data) expected-root)

::  signature check (your domain)
(verify-signature ;;(signed-payload data) expected-root)

::  always true (testing)
%.y
```
