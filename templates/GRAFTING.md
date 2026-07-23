# How to Graft Mint onto Your NockApp

> **nockup users:** Install via `nockup package add zkvesl/vesl-graft` (bundles the Hoon libs), then run `graft-inject hoon/app/app.hoon` to auto-wire the kernel. Rust crates go into your `Cargo.toml` manually — nockup doesn't manage Rust deps. The manual steps below are for developers using Docker or integrating by hand. See [vesl-nockup](https://github.com/zkVesl/vesl-nockup).

> **Quick start:** Copy [`graft-scaffold/`](./graft-scaffold/) and customize. All Hoon deps are bundled, the graft wiring is done, and `src/main.rs` demonstrates the full lifecycle (domain poke, Mint, Guard, register, verify, settle). No `$NOCK_HOME` needed for compilation.

You have a NockApp. It does something useful. Now you want tamper-evident data commitment — Merkle roots, inclusion proofs, the works. You don't want to write hash functions or proof verification logic.

The Graft pattern attaches Vesl's verification infrastructure to your kernel as a composable library. Three lines of poke delegation. No verification code written.

## Prerequisites

- **Pinned nightly Rust** — nockvm requires nightly features, and `core::hint::cold_path()` pins the date: `rustup toolchain install nightly-2026-04-03`, then `cargo +nightly-2026-04-03 build`
- **honk** in your PATH — `cargo install --locked --force --path $NOCK_HOME/crates/honk --bin honk`
- **`$NOCK_HOME`** set to your nockchain monorepo root (only needed if not using bundled deps)

## What You Get

| Tier | Capability |
|------|-----------|
| **Mint** (Rust) | Build Merkle trees, generate proofs, get roots |
| **Guard** (Rust) | Verify proofs against roots locally |
| **Graft** (Hoon) | Register roots, verify manifests, settle notes — in-kernel |

Mint and Guard are pure math. No kernel boot required. The Graft adds state tracking and guard logic to your Hoon kernel.

## Step 1: Add the Hoon Files

Copy these into your template's `hoon/` directory:

```
hoon/
  lib/settle-graft.hoon    # state + poke dispatcher (gate-agnostic)
  lib/vesl-merkle.hoon   # Merkle primitives (tip5)
```

For RAG verification, also copy:

```
hoon/
  sur/vesl.hoon          # RAG type definitions (manifest, chunk, etc.)
  lib/rag-logic.hoon    # RAG verification gates (verify-manifest)
```

These live in `protocol/sur/` and `protocol/lib/` in the Vesl repo. For non-RAG gates, only `settle-graft.hoon` and `vesl-merkle.hoon` are required — see [Custom Gates](#custom-gates--beyond-rag) below.

For self-contained compilation (no `$NOCK_HOME`), also copy the tip5 primitives:

```
hoon/
  common/zeke.hoon        # tip5 hash chain entry point
  common/ztd/             # tip5 math tables (all 8 files)
```

These live in `proof-log/hoon/common/` in the Vesl repo. The [`graft-scaffold`](./graft-scaffold/) template bundles all of these.

## Step 2: Import the Graft

At the top of your kernel (`hoon/app/app.hoon`):

```hoon
/-  *vesl             :: RAG types (only needed for RAG gates)
/+  *settle-graft       :: state + poke dispatcher
/+  *rag-logic       :: RAG verification gates (only for RAG)
/=  *  /common/wrapper
```

## Step 3: Compose State

Add `settle-state` to your `versioned-state`. It tracks which roots are registered and which notes are settled:

```hoon
+$  versioned-state
  $:  %v1
      settle=settle-state          ::  [epoch registered settled settle-count prior-settled]
      ::  ...your state fields below...
      items=(map @t @)
  ==
```

## Step 4: Include Graft Causes

Add `settle-cause` to your cause union. It brings `%settle-register`, `%settle-verify`, and `%settle-note`:

```hoon
+$  cause
  $%  [%add-item key=@t val=@]    ::  your domain poke
      settle-cause                   ::  brings all %settle-* pokes
  ==
```

## Step 5: Delegate Pokes

In your `++poke` arm, delegate Vesl causes to `settle-poke`. Define your verification gate and pass it as the third argument:

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

Same pattern for `%settle-verify` and `%settle-note`. Copy-paste, change the cause tag. The gate can be any function matching `$-([note-id=@ data=* expected-root=@] ?)` — see [Custom Gates](#custom-gates--beyond-rag).

## Step 6: Delegate Peeks

In your `++peek` arm, fall through to `settle-peek` for unrecognized paths:

```hoon
++  peek
  |=  =path
  ^-  (unit (unit *))
  ?+  path  (settle-peek settle.state path)    ::  fallthrough
    [%item key=@t ~]  ...your peeks...
  ==
```

This gives you `/vesl-registered/<hull>`, `/vesl-settled/<note-id>`, and `/vesl-root/<hull>` for free.

## Step 7: Rust Side — Add Dependencies

In your `Cargo.toml`:

```toml
vesl-core = { path = "../../crates/vesl-core" }
nock-noun-rs = { path = "../../crates/nock-noun-rs" }
```

## Step 8: Commit Data with Mint

```rust
use vesl_core::Mint;

let mut mint = Mint::new();
let leaves: Vec<&[u8]> = documents.iter()
    .map(|d| d.as_bytes())
    .collect();
mint.commit(&leaves);

let root = mint.root().expect("committed");
```

## Step 9: Register the Root

Build a `%settle-register` poke and send it to the kernel:

```rust
use vesl_core::tip5_to_atom_le_bytes;
use nock_noun_rs::{make_atom_in, make_tag_in};
use nockapp::noun::slab::NounSlab;
use nockvm::noun::{D, T};

let mut slab = NounSlab::new();
let tag = make_tag_in(&mut slab, "vesl-register");
// tip5_to_atom_le_bytes encodes the [u64; 5] hash as the base-p atom
// that matches Hoon's digest-to-atom encoding. Do NOT use flat LE
// byte concatenation — it produces a different atom.
let root_bytes = tip5_to_atom_le_bytes(&root);
let root_atom = make_atom_in(&mut slab, &root_bytes);
let poke = T(&mut slab, &[tag, D(hull_id), root_atom]);
slab.set_root(poke);

app.poke(SystemWire.to_wire(), slab).await?;
```

Note: `make_tag_in` handles tags longer than 8 bytes (like `vesl-register`) that don't fit in a u64 direct atom. Use it instead of `D(tas!(b"..."))` for long tags.

## Step 10: Verify Proofs with Guard

```rust
use vesl_core::Guard;

let mut guard = Guard::new();
guard.register_root(root).unwrap();

for (i, doc) in documents.iter().enumerate() {
    let proof = mint.proof(i).unwrap();
    let valid = guard.check(doc.as_bytes(), &proof, &root);
    // valid is true if the document is bound to the Merkle root
}
```

Guard verification is local — no kernel, no network, no async. Pure math.

## Step 11: Build and Send a Settlement Payload

To settle a note, build a `graft-payload` noun, jam it, and poke `%settle-note`:

```rust
use vesl_core::tip5_to_atom_le_bytes;
use nock_noun_rs::{jam_to_bytes, make_atom_in, make_tag_in, new_stack};
use nockvm::noun::{D, T};

let mut slab = NounSlab::new();
let rb = tip5_to_atom_le_bytes(&root);

// Build the graft-payload noun:
//   [note=[id=@ hull=@ root=@ state=[%pending ~]] data=* expected-root=@]
let note_root = make_atom_in(&mut slab, &rb);
let pending_tag = make_tag_in(&mut slab, "pending");
let state = T(&mut slab, &[pending_tag, D(0)]);
let note = T(&mut slab, &[D(note_id), D(hull_id), note_root, state]);

let data = make_atom_in(&mut slab, leaf_bytes);
let exp_root = make_atom_in(&mut slab, &rb);
let payload_noun = T(&mut slab, &[note, data, exp_root]);

// Jam the payload and send as [%settle-note jammed]
let payload_bytes = {
    let mut stack = new_stack();
    jam_to_bytes(&mut stack, payload_noun)
};
let jammed = make_atom_in(&mut slab, &payload_bytes);
let tag = make_tag_in(&mut slab, "vesl-settle");
let poke = T(&mut slab, &[tag, jammed]);
slab.set_root(poke);

app.poke(SystemWire.to_wire(), slab).await?;
```

The same pattern works for `%settle-verify` (soft verification, no state change). See [`graft-scaffold/src/main.rs`](./graft-scaffold/src/main.rs) for a complete working example.

## Compile

honk takes the stdlib prelude as a flag and the library root as its last positional argument:

```bash
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon
```

The library root is your own `hoon/` either way. Templates that bundle zeke.hoon + ztd/ locally (like `graft-scaffold`) resolve those from it; the rest pull them from the nockchain tree. The `--prelude` path comes from the nockchain monorepo in both cases.

## The Primitives

If you only need commitment: use Mint (Rust-only, no kernel).

If you need commitment + verification: add Guard (still Rust-only).

If you need in-kernel state tracking: add the Graft (Hoon library).

If you need settlement with replay protection: delegate `%settle-note` (Settle pattern).

| Need | Use | Kernel? |
|------|-----|---------|
| Hash data, get roots | Mint | No |
| Verify proofs | Mint + Guard | No |
| Register roots in kernel | Mint + Graft | Yes |
| Verify in kernel | Graft (%settle-verify) | Yes |
| Settle notes | Graft (%settle-note) | Yes |
| STARK proofs | Full vesl-kernel + prover | Yes (18MB) |

## Custom Gates — Beyond RAG

The Graft is domain-agnostic. The examples above use a RAG verification gate (cast data to a manifest, verify Merkle proofs, check prompt reconstruction). That's one gate. The `verify-gate` type is:

```hoon
+$  verify-gate  $-([note-id=@ data=* expected-root=@] ?)
```

`data` is opaque `*`. Cast it to your domain type and return a loobean. Some examples:

```hoon
::  RAG manifest verification (graft-mint, graft-settle)
|=  [note-id=@ data=* expected-root=@]
=/  mani  ;;(manifest data)
(verify-manifest mani expected-root)

::  Simple hash comparison (graft-hash-gate)
|=  [note-id=@ data=* expected-root=@]
=((hash-leaf ;;(@ data)) expected-root)

::  Signature verification (your domain)
|=  [note-id=@ data=* expected-root=@]
=/  payload  ;;([sig=@ msg=@] data)
(verify-sig sig.payload msg.payload expected-root)

::  Always-true gate (testing)
|=  [note-id=@ data=* expected-root=@]
%.y
```

### How to Use a Custom Gate

1. **Import what you need.** For hash-based gates: `/+  *vesl-merkle`. For RAG: `/+  *rag-logic` and `/-  *vesl`. For your own logic: import your own library.

2. **Define the gate inline** in your poke delegation:

```hoon
  %settle-note
=/  lc=settle-cause  [%settle-note payload.u.act]
=/  my-gate=verify-gate
  |=  [note-id=@ data=* expected-root=@]
  ^-  ?
  :: ...your verification logic...
  %.y
=/  [efx=(list settle-effect) new-settle=settle-state]
  (settle-poke settle.state lc my-gate)
:_  state(settle new-settle)
^-  (list effect)  efx
```

3. **Build the payload from Rust.** The Graft expects a jammed `graft-payload`:

```hoon
+$  graft-payload
  $:  note=[id=@ hull=@ root=@ state=[%pending ~]]
      data=*
      expected-root=@
  ==
```

`data` is whatever your gate expects. JAM the whole payload, pass it as the `payload` field in `%settle-note` or `%settle-verify`.

### The graft-hash-gate Template

[`graft-hash-gate`](./graft-hash-gate/) is a working example of a non-RAG gate. No `sur/vesl.hoon`, no `rag-logic.hoon`. The gate is one line: hash the data, compare to root. Read it to see the pattern stripped to the minimum.

(This template was formerly called `graft-intent`; the name was misleading. The real intent-family primitive lives at `protocol/lib/intent-graft.hoon` — still a placeholder pending canonical upstream.)

## Reference Templates

- [`graft-scaffold`](./graft-scaffold/) — **Start here.** Full lifecycle with bundled deps and CUSTOMIZE markers
- [`graft-mint`](./graft-mint/) — Mint + Guard with RAG verification gate
- [`graft-settle`](./graft-settle/) — Full settlement lifecycle with settlement poke
- [`graft-hash-gate`](./graft-hash-gate/) — Custom hash gate, no RAG types

## Operator Notes

Things the graft does not do for you — documented so nobody ships a
broken deploy.

### Untrusted callers can crash your poke (AUDIT M-02)

`%settle-note` and `%settle-verify` both run `cue` on the attacker-supplied
`payload` atom before any guard. A malformed JAM crashes the kernel —
you get a restart, no settlement, no state change, but every bad poke
burns a Nock trace. If your graft sits behind a public HTTP endpoint,
**rate-limit the poke path upstream**. The hull/HTTP layer is the right
place for shape pre-validation. Do not rely on the graft to filter
malformed pokes.

### The gate owns `data` shape validation (AUDIT M-03)

`graft-payload`'s `data` field is typed `*` (any noun). The strict-mold
cast inside `settle-poke` validates `note` and `expected-root` but lets
`data` pass through untyped — that's intentional so the graft can stay
domain-agnostic. Your gate is the only line of defense on `data` shape.

A gate that panics on unexpected `data` shapes will crash the whole
settle path. Options:

- **Hard cast (crash on mismatch)**: `=/  mani  ;;(manifest data)`
  then operate on `mani`. Any shape mismatch crashes the gate, which
  crashes the settle — same behavior as verification failure in the
  `%settle-note` path (unprovable STARK), but noisier for
  `%settle-verify` which usually returns a soft `%.n`.
- **Safe cast (soft reject)**: wrap the cast in `mule`:
  ```hoon
  =/  attempt  (mule |.(;;(manifest data)))
  ?.  -.attempt  %.n
  (verify-manifest p.attempt expected-root)
  ```
  Gate returns `%.n` for malformed `data`, keeping `%settle-verify`
  honest and letting `%settle-note` reject without a kernel crash.

### Peek paths are unauthenticated (AUDIT M-04)

`settle-peek` exposes these paths with no auth:

| Path | Returns |
|------|---------|
| `[%settle-registered hull=@ ~]` | `%.y` / `%.n` — is this hull registered? |
| `[%settle-noted note-id=@ ~]`  | `%.y` / `%.n` — is this note-id in current OR prior epoch? |
| `[%settle-root hull=@ ~]`        | The Merkle root bound to this hull |
| `[%settle-epoch ~]`            | Current epoch number |
| `[%settle-count ~]`            | Notes settled in current epoch |

Any caller that can peek your state can see which hulls are registered,
which notes settled, and the Merkle root bound to each hull. Public by
design for verifiable graft deployments — a third party can independently
audit what your graft has committed to.

If you need private-graft semantics, the kernel that wraps `settle-peek`
owns gating. Don't re-export these paths without thinking about who
sees them. The typical pattern is to fall through to `settle-peek` at
the top of your kernel's `++peek`; if that's too permissive for your
deployment, inline only the peek paths you want to expose.

