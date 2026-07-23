# vesl-core

A verification SDK for Nockchain. Four primitives — **mint** (commit), **guard** (verify), **settle** (on-chain), **forge** (STARK-prove) — each shipping as a Hoon kernel with a Rust facade. Plus graft templates and supporting math libraries for composing them into a NockApp.

If you're building a NockApp, you probably want [vesl-nockup](https://github.com/zkvesl/vesl-nockup) — it bundles vesl-core, adds a `graft-inject` CLI for auto-wiring grafts into your kernel, ships a test harness, and works with the upstream `nockup` scaffolder. Clone this repo if you're working on the protocol itself.

## Crates

| Crate | Purpose |
|---|---|
| [`vesl-core`](crates/vesl-core) | The SDK. Rust facades for the four kernels, cause/effect builders, peek decoders. |
| [`nock-noun-rs`](crates/nock-noun-rs) | Pure-Rust Nock noun types — no nockvm dep. Used by hardware-wallet vendors. |
| [`nockchain-tip5-rs`](crates/nockchain-tip5-rs) | The Tip5 hash primitive, vendored from nockchain. |
| [`nockchain-client-rs`](crates/nockchain-client-rs) | Async client for the nockchain gRPC interface. |
| [`vesl-checkpoint`](crates/vesl-checkpoint) | NockApp state snapshot + resume helpers. |

## Quick start

```toml
[dependencies]
vesl-core = { git = "https://github.com/zkvesl/vesl-core", tag = "v0.5.0" }
```

```rust
use vesl_core::{build_settle_register_poke, build_settle_note_poke};

let poke = build_settle_register_poke(hull, &root);
// hand to your NockApp ...
```

Each primitive facade exposes `build_<name>_*_poke` builders for every primary cause and `decode_<name>_outcome` helpers for the typed effects. The full per-graft table lives in vesl-nockup's [cause-builder reference](https://github.com/zkvesl/vesl-nockup#cause-builder-reference).

## What's in this repo

- `protocol/lib/` — Hoon source for kernels and grafts
- `protocol/tests/` — Hoon-side compile-time assertions
- `kernels/` — Rust crates that embed each kernel JAM via `include_bytes!`
- `assets/` — the four compiled kernel JAMs (`mint.jam`, `guard.jam`, `settle.jam`, `forge.jam`)
- `hull/` — example HTTP server harness
- `templates/` — graft scaffolds that get bundled into vesl-nockup
- `crates/` — the Rust SDK plus the math libraries

## Manual setup

vesl-core path-deps a sibling [nockchain](https://github.com/nockchain/nockchain) clone for `nockapp`, `nockvm`, and the math crates, and a sibling [vesl-wallet](https://github.com/zkvesl/vesl-wallet) for `vesl-signing`. Layout assumed by the workspace:

```
<parent>/
  vesl-core/         (this repo)
  nockchain/         (sibling clone, checked out at NOCK_PIN)
  vesl-wallet/       (sibling clone)
```

If your layout differs, edit `crates/*/Cargo.toml` path-deps.

### Toolchain

| Piece | What it tracks | Where the pin lives |
|---|---|---|
| Rust | `nightly-2026-04-03` — the same nightly nockchain pins | `rust-toolchain.toml` |
| nockchain | upstream `master` | `NOCK_PIN` in `.github/workflows/ci.yml` |
| honk | `master` plus a few compiler fixes staged on `sobchek/nockchain` pending upstream review | `HONK_REV` in `.github/workflows/jam-determinism.yml` |

The nightly is pinned to a date, not floating. `nockvm` uses the unstable `core::hint::cold_path()`, so a bare `nightly` is a build waiting to break on a toolchain you didn't choose. When nockchain moves its nightly, this repo moves with it.

`scripts/check-pins.sh` asserts every pin site agrees and that each SHA actually exists upstream. Bump with `scripts/bump-pin.sh <type> <sha>` rather than editing the sites by hand — it rewrites them in lockstep.

### Compiling kernels

Kernel JAMs are built with **honk**, the native Hoon compiler:

```bash
cargo install --locked --force --path ../nockchain/crates/honk --bin honk
honk --new --output out.jam --prelude hoon/common/hoon.hoon protocol/lib/<name>-kernel.hoon hoon
```

honk is the primary compiler here because its output bytes are reproducible from any checkout location. `hoonc` still works for cross-checks, but it bakes absolute build paths into the JAM, so its bytes are machine-dependent — never regenerate a committed JAM with it.

The four JAMs in `assets/` are what actually ship: each `kernels/*` crate embeds one via `include_bytes!` and panics at boot if the hash drifts. After editing any `protocol/lib/*-kernel.hoon`, regenerate and run `scripts/check-jam.sh`, which verifies each JAM against `scripts/CHECKSUMS.sha256`. CI gates the same assertion on every PR.

## Documentation

| Where | What |
|---|---|
| [zkvesl.org](https://zkvesl.org) | project home |
| [docs.zkvesl.org](https://docs.zkvesl.org) | full walkthrough |
| [ARCHITECTURE.md](ARCHITECTURE.md) | how kernels, grafts, and the hull fit together |
| [CONTRIBUTING.md](CONTRIBUTING.md) | local dev setup, the kernel JAM regen flow, sister-repo sync |

## Maintainer

sobchek · <sobchek@zkvesl.org>

## License

Apache-2.0 OR MIT.
