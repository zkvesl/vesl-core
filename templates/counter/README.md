# counter

A counter. The simplest stateful NockApp that does anything useful.

## About this template

Finished scaffold. Copy it, rename in `Cargo.toml` if you want a different crate name, and build. No renderer, no `graft-inject` step required — the template is already a complete example. For graft-inject composition against a marker-bearing reference kernel, start from `templates/app.hoon` instead.

## Why This Exists

Every NockApp tutorial starts with "here's how to print hello world" and then jumps to "here's a 4000-line wallet." This template is the missing middle: state that persists, mutations that produce effects, queries that don't mutate.

## The Kernel

**State:** A single `@ud` (unsigned integer).

**Pokes:**
| Cause | Effect | State Change |
|-------|--------|-------------|
| `[%inc ~]` | `[%count n]` | count + 1 |
| `[%dec ~]` | `[%count n]` | count - 1 (floors at 0) |
| `[%set n=@ud]` | `[%count n]` | count = n |
| `[%reset ~]` | `[%count 0]` | count = 0 |

**Peeks:**
| Path | Returns |
|------|---------|
| `/count` | Current counter value |

## Build & Run

```bash
# Compile Hoon kernel to JAM
honk --new --output out.jam --prelude $NOCK_HOME/hoon/common/hoon.hoon hoon/app/app.hoon hoon

# Build Rust binary
cargo build

# Run
cargo run
```

Expected output:
```
[inc #1] count = 1
[inc #2] count = 2
[inc #3] count = 3
[dec] count = 2
[reset] count = 0
```

## What to Read

Start with `hoon/app/app.hoon`. It's ~80 lines. The interesting parts:

- **Lines 1-10:** Imports. `/+  lib` pulls in the library, `/=  *  /common/wrapper` loads the NockApp wrapper.
- **`+$  versioned-state`:** The state type. Tagged `%v1` for future upgrades.
- **`++  poke`:** The mutation arm. Soft-casts the input, switches on the cause tag, returns effects + new state.
- **`++  peek`:** The query arm. Pattern-matches the path, returns double-wrapped value.
- **Last line `((moat |) inner)`:** Wires the inner core into the NockApp protocol.

Then read `src/main.rs` to see how Rust sends pokes and reads effects.

~
