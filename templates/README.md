# NockApp Templates

You shouldn't need to reverse-engineer 57K lines of wallet code to figure out how a NockApp works.

These three templates cover the space between `nockup`'s "hello world" and a production NockApp. Each one teaches a different pattern. Read them in order or jump to what you need.

## The Templates

### 1. [counter](./counter/) — State Management

The absolute minimum viable stateful NockApp. A counter. You increment it, you decrement it, you peek at it. If you understand this kernel, you understand `versioned-state`, `poke`, `peek`, `load`, and effect emission. Everything else is just more of this.

**What you learn:** The NockApp lifecycle. How state flows through pokes. How peeks read without mutating. How effects propagate to the Rust runtime.

### 2. [data-registry](./data-registry/) — Data Commitments

A name-to-hash registry. Register data (stores its SHA-256 hash), then verify later that data matches the registered commitment. This is the generalized pattern behind any system that needs to prove "I committed to this before you asked."

**What you learn:** Map-based state, cryptographic hashing in Hoon (`shax`), the register/verify commitment pattern.

### 3. [settle-report](./settle-report/) — Settlement Pattern

The commit-verify-settle lifecycle with three guards: commitment must exist, no duplicate settlements, hash must match. This is the simplified version of what Vesl does for verifiable RAG — minus the Merkle proofs and STARK proving, but the same bones.

**What you learn:** Multi-guard verification, replay protection, rejection effects with reason codes, the settlement pattern that Vesl and other on-chain NockApps use.

---

### 4. [graft-mint](./graft-mint/) — Graft: Commitment + Verification

Your NockApp with Vesl's settle tier grafted in. A note store with Merkle commitment — zero verification code in the kernel. The `settle-graft.hoon` library provides the state fragment and poke dispatcher; your kernel just delegates `%settle-*` pokes.

**What you learn:** The Graft pattern — composing `settle-state` into your kernel state, delegating to `settle-poke`, falling through to `settle-peek`. How `Mint::commit()` and `Guard::check()` work on the Rust side.

### 5. [graft-settle](./graft-settle/) — Graft: Full Settlement

Extends graft-mint with Settle: full settlement lifecycle with replay protection. Notes transition from `%pending` to `%settled`. A report submission system that commits to Merkle roots and creates permanent verifiable records.

**What you learn:** The settlement tier — `%settle-note` with three guards (registered root, no replay, valid manifest). How to upgrade from graft-mint to graft-settle in three lines.

## Quick Start

Each template is `nockup`-compatible (handlebars variables for scaffolding) and also works standalone.

### With nockup

Copy a template to `~/.nockup/templates/`, create your `nockapp.toml`, and scaffold:

```bash
nockup project init
```

> **Grafting onto a new nockup project?** See [vesl-nockup](https://github.com/zkVesl/vesl-nockup) — packages that integrate with `nockup package add`, plus a `graft-inject` tool that auto-wires the graft into your `hoon/app/app.hoon`.

### Standalone

```bash
cd templates/counter

# Compile the Hoon kernel
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon

# Build the Rust binary (replace handlebars vars in Cargo.toml first)
cargo build

# Run
./target/debug/counter
```

## Template Structure

All templates follow the same layout:

```
template/
+-- Cargo.toml          # Rust project config (handlebars-templated)
+-- build.rs            # Cargo build script (hoonc invocation)
+-- src/
|   +-- main.rs         # Rust runtime (poke/peek/effect handling)
+-- hoon/
    +-- app/
    |   +-- app.hoon    # Kernel (the actual NockApp logic)
    +-- lib/
    |   +-- lib.hoon    # Shared library (placeholder or helpers)
    +-- common/
        +-- wrapper.hoon  # NockApp wrapper (standard, don't modify)
```

## The Pattern

Every NockApp kernel has three arms:

- **`++load`** — State migration. Called on kernel upgrade. Returns old state (identity) until you need version branching.
- **`++peek`** — Read-only query. Maps paths to state values. Returns `(unit (unit *))`.
- **`++poke`** — State mutation. Accepts a cause, returns `[(list effect) new-state]`.

The wrapper (`common/wrapper.hoon`) handles the NockApp protocol handshake. You write the inner core. The wrapper calls your arms.

## Two Things That Will Trip You Up

1. **The Two-Space Law.** Every Hoon rune takes exactly two spaces after it. `|=  a=@` not `|= a=@`. Your code will compile fine with one space and then behave in ways that make you question reality.

2. **Loobeans.** `%.y` is yes/true, `%.n` is no/false. `0` is true, `1` is false. Yes, this is backwards from everything you know. The convention is called a "loobean" and it's one of those things you accept and move on.

~
