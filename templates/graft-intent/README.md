# graft-intent (placeholder)

**This is a placeholder, not a working primitive.** It exists to reserve the family-5 (intent coordination) slot in vesl's 5-family graft catalog. Every `%intent-*` poke the kernel receives crashes with `%intent-graft-placeholder`. That crash is the point.

## Why reserve the slot instead of building the real thing?

The Nockchain monorepo has not yet published a canonical intent structure. Any shape vesl picks today will probably be wrong by the time upstream lands. Rather than commit to semantics that get thrown away, the placeholder locks down:

- the family-5 priority band (200–299) so other grafts don't scribble on it,
- the `intent-graft` name so the cause-tag namespace (`%intent-declare`, `%intent-match`, `%intent-cancel`, `%intent-expire`) stays available,
- the manifest shape (`stability = "placeholder"`, priority 200) so `graft-inject` tooling knows how to list it.

When upstream publishes, `intent-graft.hoon` and this template get swapped for the real primitive in a single PR. Nothing structural around it has to change.

## What lives here

```
hoon/
  app/app.hoon          — minimal kernel composing intent-graft
  lib/intent-graft.hoon — the crashing placeholder library
  common/wrapper.hoon   — NockApp protocol wrapper
src/main.rs             — driver that pokes %intent-declare and reports the crash
MOVED.md                — redirect stub: the old `graft-intent` hash-gate demo now lives at `templates/graft-hash-gate/`
```

## Running it

```bash
# Compile (from the vesl repo root — resolves hoon/lib/ via the vesl tree):
honk --new --output out.jam --prelude hoon/common/hoon.hoon templates/graft-intent/hoon/app/app.hoon hoon
cp out.jam templates/graft-intent/out.jam

# Build the Rust driver:
cd templates/graft-intent && cargo build

# Run — expect a crash:
./target/debug/graft-intent
```

Running the binary pokes `%intent-declare` at the placeholder kernel and reports the `%intent-graft-placeholder` crash trace. If the poke returns without crashing, the placeholder has been tampered with — check that `hoon/lib/intent-graft.hoon` still has its bang arms.

## What the real `graft-intent` will do

The intended shape (see `.dev/BIFURCATE_INTENT.md` for the full design sketch) is multi-party coordination over state transitions:

- `%intent-declare` — register an open intent under a hull, with optional expiry
- `%intent-match` — flip an open intent to matched, after the domain verified satisfaction
- `%intent-cancel` — declarer-initiated close of an open intent
- `%intent-expire` — time-driven close once `expires-at` passes

None of these are wired up today. The types are declared, the cause tags are reserved, and the arms crash. That is the entire contract.

## Other families

The other four families in vesl's graft catalog:

| # | Family | Status | Where |
|---|---|---|---|
| 1 | Commitment | Shipped | `protocol/lib/{settle,mint,guard,forge}-graft.hoon` |
| 2 | Verification gates | Scaffolded | `.dev/01_GATE_CATALOG.md` |
| 3 | State | Planned | `.dev/02_STATE_GRAFTS.md` |
| 4 | Behavior | Planned | `.dev/03_BEHAVIOR_GRAFTS.md` |
| 5 | Intent | **Placeholder** | you are here |

The authoritative lattice is in [`docs/graft-manifest.md`](../../docs/graft-manifest.md).
