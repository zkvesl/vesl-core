# Contributing to vesl-core

vesl-core is the protocol source-of-truth: Hoon kernels (mint/guard/
settle/forge), graft templates, the Rust SDK that wraps them, and
the pre-built JAM artifacts every hull boots. External contributions
are welcome — this doc names what to read first, how the test suite
hangs together, and where to look if you want a small win on your
way in.

PRs land against the `dev` branch — `main` is squash-merged from
`dev` on release days. Branch off `origin/dev`, push to your fork,
open the PR against `zkvesl/vesl-core:dev`.

vesl-core ships in two flavors that need to stay in sync:

- **Hoon source** under `protocol/lib/` and `hoon/` — the canonical
  protocol logic.
- **Rust crates** under `crates/` — `vesl-core` SDK, `nock-noun-rs`,
  `nockchain-tip5-rs`, `nockchain-client-rs`, `vesl-checkpoint`.
- **Compiled JAMs** under `assets/` (`mint.jam`, `guard.jam`,
  `settle.jam`, `forge.jam`) — byte-shipped artifacts loaded via
  `include_bytes!` in the `kernels/*` crates. The maintainer's
  reference hashes live at `scripts/CHECKSUMS.sha256` and are
  checked locally by the pre-push preflight (`scripts/check-jam.sh`).

A change that touches a kernel's Hoon must regenerate + recommit
its JAM in the same PR. The local preflight gate will fail
otherwise. See the "Modifying a Hoon kernel" section below.

## Good first PRs

Three contribution shapes that don't require deep familiarity with
the whole stack:

| Add a... | Open this directory | Pattern |
|---|---|---|
| **Graft manifest** | `protocol/lib/<name>-graft.{hoon,toml}` | A graft is a `.hoon` body plus a `.toml` manifest naming its blocks, types, and gates. `kv-graft.{hoon,toml}` is ~150 lines total and a good template. The manifest schema is documented in `docs/graft-manifest.md`. |
| **Rust SDK rustdoc** | `crates/vesl-core/src/*.rs` | Run `cargo doc --no-deps -p vesl-core` and look for `pub` items without a `///` line. Each Mint/Guard/Settle facade exposes builders that downstream Rust consumers read via `cargo doc --open`. |
| **Test vector** | `crates/vesl-core/src/graft_pokes/<graft>.rs` (tests block) | Each graft has a Rust poke builder. Adding a `#[test]` that asserts a known-good `(input, expected noun)` pair guards the builder against silent drift from the Hoon side. |

For larger work — new kernel families, gate scheme changes, graft
priority refactors — open a draft PR or an issue first so we can
coordinate the impact on downstream consumers (vesl-nockup, hull-llm).

## The Two-Space Law

Every Hoon rune must be followed by exactly **TWO SPACES**. This is
non-negotiable; `hoonc` will accept many other shapes, but the
repo's existing source is uniform and reviewers will ask you to
match.

```hoon
|=  a=@        :: correct
|= [a=@]       :: incorrect (single space)
```

## Adding a new Hoon library

Dropping a new `.hoon` file into `protocol/lib/` is **not enough**.
`hoonc` resolves `/+ *foo` against the library root passed on the
command line (`hoon/`), and `hoon/lib/` holds symlinks into
`protocol/lib/` — not the files themselves. If you skip the
symlink, `hoonc` silently exits 2 with no `out.jam` and the trace
blames hoonc internals rather than your new file.

Checklist for any new `protocol/lib/<name>.hoon`:

1. `ln -s ../../protocol/lib/<name>.hoon hoon/lib/<name>.hoon`
   (relative symlink — match the neighbours).
2. If shipping a graft, drop the sibling `<name>-graft.toml`
   manifest alongside, and add both files to `vesl-nockup/sync.sh`'s
   library copy list in a follow-up PR.
3. Recompile with `hoonc --ephemeral` — hoonc caches aggressively
   and will happily serve you a stale "it compiled" if you forget.

**Failure signature** when the symlink is missing: `hoonc` exits 2,
emits `[DIAG soft] DETERMINISTIC error mote=Exit`, and writes no
`out.jam`. Don't chase type errors — check `hoon/lib/` first.

## Modifying a Hoon kernel

Changing `protocol/lib/<name>-kernel.hoon` (or any library it
imports transitively) invalidates `assets/<name>.jam`. The
compiled JAM is what ships — `kernels/<name>/src/lib.rs` embeds it
via `include_bytes!`, its sha256 is baked in at build time, and
runtime `verify_kernel()` panics on a mismatch. A stale `.jam`
ships a kernel whose Hoon source has drifted from what runs in
production.

Regen + commit flow:

```bash
honk --new --output out.jam --prelude hoon/common/hoon.hoon hoon/lib/<name>-kernel.hoon hoon
mv out.jam assets/<name>.jam
cd assets && sha256sum guard.jam mint.jam settle.jam forge.jam > ../scripts/CHECKSUMS.sha256
scripts/check-jam.sh    # must return all-green before committing
```

Compile through `hoon/lib/`, not `protocol/lib/`. The symlink reaches
the same source, but only an entry inside the dependency directory gets
a dep-relative `%spot` path — the spelling honk and hoonc agree on
byte-for-byte. Outside it, hoonc bakes an absolute build path and the
two can never match.

Commit the JAM regen as a dedicated `sync kernel JAM artifacts with
source` commit, separate from the Hoon edit. The reviewer needs the
byte change in isolation, and CI's `jam-determinism` job gates the
same assertion on every PR.

`scripts/check-jam.sh` is the local equivalent of that CI gate.
Run it after any `protocol/lib/*-kernel.hoon` edit, before you push.

## Running tests

```bash
# Rust workspace tests. Requires a sibling nockchain checkout at
# ../nockchain (the workspace's nockchain crate path-deps resolve
# against it). Incremental ~10s warm; cold (first clone) ~5-8 min.
cargo test -p vesl-core

# Lint gates that CI enforces.
cargo clippy -p vesl-core -- -D warnings

# Cargo-audit: advisory check on transitive deps. CI runs this as
# a hard gate.
cargo audit

# Pin validation: confirms NOCK_PIN agrees across sync.sh, ci.yml,
# Dockerfile, and that the SHA exists upstream. Runs in <1s. Wired
# into CI as a pre-flight gate.
scripts/check-pins.sh

# JAM determinism: recompiles guard / mint / settle / forge and
# asserts sha256 matches scripts/CHECKSUMS.sha256 (the maintainer's
# reference hashes). Run after any kernel Hoon edit. The pre-push
# preflight runs this; the CI-side gate is disabled (hoonc output
# isn't byte-portable across environments).
scripts/check-jam.sh
```

## CI and getting reviewed

PRs run four workflows (visible at the bottom of the PR
conversation):

- **ci.yml** (`check-pins`, `test`, `audit`, `clippy`) — the
  workspace test + lint gate. `audit` is `cargo audit` on the
  transitive dep set; `clippy` is `-D warnings`.
- **jam-determinism.yml** — currently disabled (`if: false`).
  Re-enable when we land a reproducible-build setup for hoonc.
  Local verification lives in `scripts/check-jam.sh` (run via
  the pre-push preflight).
- **vesl-core-sync.yml** — fails on non-empty `diff -rq
  --exclude=target vesl-core/crates vesl-nockup/crates`. Triggered
  on PRs touching `crates/*`. Catches the "fixed in vesl-core,
  forgot to run sync.sh in vesl-nockup" drift before merge.
- **release.yml** — runs on tag push; not gated on PRs.

A clean run shows green checks across every job in <10 min. A red
job's "Details" link goes straight to the failing step's logs.
Re-run a flaky job from the PR page if needed.

**Reviewer routing.** Tag `@zkvesl` on the PR or in your
description if it sits open more than a day; we triage from there.

For PRs touching `protocol/lib/*-kernel.hoon` (the four
commitment-family kernels) or `crates/vesl-core/src/` (the SDK
facade), expect a closer review — these surfaces are what every
downstream NockApp depends on.

## Sister-repo coordination

- **vesl-nockup** (the user-facing toolchain) consumes vesl-core's
  `crates/` and selected Hoon libs via `./sync.sh`. If your PR
  touches `crates/*` or any file listed in vesl-nockup's
  `sync.sh`, a follow-up PR in vesl-nockup will be needed after
  merge. The maintainer running the release bumps
  `VESL_CORE_PIN` there.
- **hull-llm** (the RAG reference impl) consumes vesl-core via a
  pinned git-rev. Bumps happen independently on the hull-llm side
  after a vesl-core release.

## Conventions

- **License**: dual MIT / Apache-2.0. New files get the standard
  SPDX header on contribution.
- **Commits**: imperative-mood subject lines, ≤72 chars, body
  wrapped at 72 chars. Don't bundle a kernel Hoon edit and its
  JAM regen in one commit — separate them so the byte change is
  reviewable in isolation.
- **PRs**: rebased on `dev`, CI green, no force-pushes after
  review starts.

## Reporting issues

Use the GitHub issue tracker. For security-sensitive reports
(signing primitives, verify-gate behavior, settle-graft commitment
surface), contact the maintainers directly rather than opening a
public issue.
