# {{project_name}}

A grafted NockApp scaffolded from the `vesl` template.

## Three-command path to a running kernel

```bash
nockup graft inject --apply hoon/app/app.hoon   # composes graft bodies into the kernel
honk --new --output out.jam --prelude hoon/common/hoon.hoon hoon/app/app.hoon hoon
cargo +nightly-2026-04-03 run                   # boots the kernel and exercises the lifecycle
```

Expected stdout end:

```
  effect: %settle-registered
  effect: %settle-noted
```

## Layout

- `Cargo.toml` — vesl-graft's `[[patches]]` rewrites the deps to git-deps pinned at the synced rev and adds both `[patch]` blocks during `nockup package install`. The pre-patch template ships path-deps as a fallback for sibling-clone workflows or eject mode (`nockup patches eject zkvesl/vesl-graft`).
- `build.rs` — no-op; `out.jam` is built explicitly via `honk`.
- `src/main.rs` — 30-line hull that registers a Merkle root and settles a note against it.
- `hoon/app/app.hoon` — markered kernel template; `nockup graft inject` composes graft bodies into the `::  nockup:*` anchors.
- `hoon/lib/lib.hoon` — stub `/+ lib` import for your domain library.

## Testing

`vesl-test` ships in `[dev-dependencies]`. Add a `#[tokio::test]` against `vesl_test::GraftTestHarness` to exercise the register / settle / replay lifecycle, or call `vesl-test inspect peek out.jam --path-tag <tag>` for one-shot kernel peeks. See the zkvesl-docs Testing page for the canonical lifecycle test.

## Where to go next

- `vesl-nockup/README.md` — the canonical 6-step tour, including the Customizing section (multi-leaf gates, signed gates, STARK gates) and the state-graft catalog.
- `zkvesl-docs/` — published reference covering the graft manifest schema, peek paths, and the typed effect-union codegen.
