# `graft.toml` schema

A graft manifest describes how `graft-inject` composes a Hoon library
into a host kernel's `app.hoon`. One manifest per graft, sibling to the
graft's `.hoon` file under `protocol/lib/` (or `hoon/lib/` after `sync.sh`
in vesl-nockup).

This document is the source of truth for the manifest format. The Rust
loader in `vesl-nockup/tools/graft-inject` implements it; graft authors
read this to write a manifest without reading the loader.

## Trust model

A manifest's `body` field is Hoon text pasted **verbatim** into the
developer's `app.hoon`. `graft-inject` does not sanitize, sandbox, check
signatures on, or verify the provenance of the manifest. Whatever Hoon
a `.toml` declares becomes kernel source on the next invocation.

Consequences:

- Manifests are code. Treat them like any other dependency: review
  incoming changes the way you would a PR that touches `protocol/lib/`.
- `graft-inject` is a composition step, not a trust boundary. Trust is
  managed at the distribution layer — checkout provenance, directory
  hygiene, what lands in `hoon/lib/` via `sync.sh` or manual edits.
- As the AUDIT 2026-04-19 H-10 write-up spells out, `graft-inject`
  defaults to **preview-only** — the composed diff and a sha256 per
  manifest print to stderr, and `--apply` is required to write. This
  keeps silent supply-chain drift impossible without explicit consent.

## Layout

```
protocol/lib/
  settle-graft.hoon       host library
  settle-graft.toml       manifest (this file's schema)
  mint-graft.hoon
  mint-graft.toml
  ...
```

Flat — no per-graft directory. The manifest's `name` field, not its
filename, is the canonical identifier the loader uses.

**Symlink requirement.** `honk` resolves `/+ *foo` against the library
root passed as its last positional argument — in vesl, that's `hoon/`,
which holds symlinks pointing at `protocol/lib/`. Dropping a new `.hoon`
under `protocol/lib/` is not enough; add a matching symlink with
`ln -s ../../protocol/lib/<name>.hoon hoon/lib/<name>.hoon` before the
first compile. If the symlink is missing, honk exits 1 and names the
import it couldn't resolve:
`native hoon compile failed: parse error: native import not found: `/+ foo``.
Check the symlink tree before you go looking for a type error.
Downstream (`vesl-nockup`) skips this by copying both files into
`hoon/lib/` via `sync.sh`; the symlink dance only matters inside the
vesl repo.

## `[graft]` — top-level metadata

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Canonical name. Matches the `--grafts <CSV>` argument. Must be unique across all manifests under the discovery root. |
| `version` | string | yes | Semver. Bumped when blocks change in a backwards-incompatible way. |
| `priority` | int | yes | Injection order. Lower = injected earlier. See **The 5-family lattice** below for the band assignments. |
| `stability` | string | no | One of `stable`, `beta`, `placeholder`. Defaults to `stable` if omitted. `placeholder` marks a reserved family slot whose body crashes on invocation (see `intent-graft.hoon`) — consumers building on it are explicitly building against an unfinished primitive. `beta` is for grafts that compile and run but whose interface may change. |
| `after` | string list | no | Soft ordering hints. Each entry names another graft that must inject earlier. If an entry names a graft not present in the discovered set, the hint is silently ignored; a one-line `note` prints to stderr and priority-based ordering applies. This lets selective composition (e.g., dropping `queue-graft` from the cp set while keeping `rbac-graft`) work without manifest edits. Resolved after `priority` ties. |

Example:

```toml
[graft]
name      = "settle-graft"
version   = "0.1.0"
priority  = 10
stability = "stable"
after     = []
```

## The 5-family lattice

Grafts fall into five families. The priority number both orders injection and labels the family a graft belongs to — reviewers reading a manifest can tell at a glance which part of the catalog a graft lives in.

| # | Family | Role | Priority band | Status | Example grafts |
|---|---|---|---|---|---|
| 1 | Commitment | STARK-bearing primitives that commit data to hull-keyed roots | 10–40 | Shipped | `settle-graft` (10), `mint-graft` (20), `guard-graft` (30), `forge-graft` (40) |
| 2 | Verification gates | Parameterized decision functions consumed by commitment grafts. Delivered as a library, not a priority-claimed graft | n/a (library) | Scaffolded | `vesl-gates.hoon` (planned — see `.dev/01_GATE_CATALOG.md`) |
| 3 | State | Domain-keyed app-state primitives (kv, counter, queue, rbac, registry) | 50–99 | Shipped | `kv-graft` (50), `counter-graft` (60), `queue-graft` (70), `rbac-graft` (80), `registry-graft` (90) |
| 4 | Behavior | Runtime wrappers that enforce or observe rules around other grafts | 100–149 | Planned | per `.dev/03_BEHAVIOR_GRAFTS.md` |
| 5 | Intent | Multi-party coordination primitives (declare / match / cancel / expire) | 200–299 | Placeholder | `intent-graft` (200, `stability = "placeholder"`) |

**Why these bands, and not something simpler:**

- Bands 10–40 and 50–99 are already populated; expanding them would force renumbering shipped grafts.
- Band 100–149 is a *new* dedicated slot for behavior grafts — resolves an overlap where the old lattice pushed behavior and state into the same 50–99 range.
- Band 200–299 for intents is deliberately far from state (50–99) and behavior (100–149). Intents compose *above* state and behavior — they coordinate over state transitions rather than implementing state. A numbering gap makes that architectural distance visible when a reviewer skims a `graft-inject` list.
- Bands 150–199 and 300+ stay reserved for future families or user domain grafts.

**Verification gates do not claim a priority band.** They are library arms imported by commitment grafts via the reserved `[graft.gates]` extension (`gate = "name"` or `gate-chain = ["a", "b"]`). A gate is a parameter, not a stage. See the `[graft.gates]` section below.

**The intent family is a placeholder.** `intent-graft.hoon` reserves the shape and band but crashes loudly on invocation. The Nockchain monorepo has not published a canonical intent structure; Vesl's placeholder will be swapped for the real primitive when upstream lands. Do not build production logic against it. See `.dev/BIFURCATE_INTENT.md` and `.dev/GRAFT_REFACTOR.md` for the reasoning.

## `[graft.blocks.*]` — injection blocks

A graft contributes one block per marker it claims. Nine markers exist:
seven content markers — `imports`, `state`, `cause`, `poke-prelude`,
`poke`, `poke-postlude`, `peek` — plus two codegen markers
(`domain-effect`, `effect-union`) introduced in Phase 03f Lever 1.
Codegen markers are anchors for the typed effect-union pass: grafts do
not contribute per-graft blocks at them. A content block omitted from
the manifest is not injected for that marker — the marker is left
untouched (or, for `peek`, joins the chain only if other grafts contribute).

Each present block is a TOML sub-table with two fields:

| Field | Type | Required | Notes |
|---|---|---|---|
| `sentinel` | string | yes | Documentation-only after AUDIT 2026-04-19. The loader used to scan for this substring to detect already-injected wiring; idempotence now runs off `::  graft-inject:<name>:<marker>:begin` banner comments the composer emits. `sentinel` still names the field's canonical marker — useful for authors and reviewers reading the manifest — but carries no behavior. |
| `body` | string | yes | The Hoon to paste at the marker. Stored unindented; the loader re-applies indentation from the marker line's leading whitespace. Leading and trailing newlines on the string are trimmed before injection. |

### Sentinel rules

The sentinel is documentation; the loader does not read it for
idempotence. Authors should still pick a short, unambiguous marker so
reviewers reading the manifest can map a graft to its canonical
injected line.

Conventional sentinels:
- `imports`: `*<graft-name>` (e.g., `*mint-graft`) — the import directive.
- `state`: `<field>=<type-name>` (e.g., `mint=mint-state`).
- `cause`: `<graft>-cause` (e.g., `mint-cause`) — the embedded cause union.
- `poke`: `%<graft>-<verb>` of the first arm (e.g., `%mint-commit`).
- `peek`: `<graft>-peek` (e.g., `mint-peek`) — the helper arm name.

### Body rules

- **Indentation**: each line in `body` is stored at the indentation it
  needs *relative to the marker*. The loader prepends the marker line's
  leading whitespace to every non-empty line. Empty lines stay empty.
- **Trim**: leading and trailing newlines on the `body` string are
  removed before composition. Use TOML's triple-quoted form for
  multi-line bodies; a leading newline after `"""` is convenient.
- **Two-space law**: every Hoon rune in the body must be followed by
  exactly two spaces (or end-of-line). The loader does not enforce this,
  but `honk` will fail downstream if violated.
- **Per-marker conventions**:
  - `imports`: one or more `/+` directives. No leading `::`.
  - `state`: a single `field=type` pair to splice into the kernel's
    `versioned-state $:` block.
  - `cause`: a single bare type name to splice into the `cause $%` union.
  - `poke`: arm bodies for the kernel's `?-` switch, with internal `::`
    separators between arms. Bodies start with `::` to separate from
    any pre-existing arm in the user's switch.
  - `peek`: a single Hoon expression that returns `(unit (unit *))`.
    Returns `~` for non-matching paths. The composer wraps each peek
    body into a chain — see Composition below.

## `[graft.types]` — typed effect-union codegen

A graft that exports a tagged effect type can opt in to the typed
effect-union codegen by declaring it in a `[graft.types]` table:

```toml
[graft.types]
effect = "settle-effect"
cause  = "settle-cause"
```

Both fields are optional. `effect` names the bare Hoon type the graft
exports for its effect variant — graft-inject splats it into the
kernel's `+$ effect $%(...)` union under the `nockup:effect-union`
marker. `cause` is parsed forward-compat for Phase 03f Lever 3 (cause
destructuring); current codegen reads only `effect`.

Names must be kebab-case (`^[a-z][a-z0-9-]*$`) — they're spliced
literally into Hoon source, so a malformed name surfaces as a honk
`find . X` failure with no manifest attribution.

Two grafts cannot declare the same `effect` (or `cause`) name —
graft-inject hard-errors at discovery with both manifest paths. Hoon's
`$%` would otherwise reject the synthesized union as `not a fork` with
no manifest attribution.

### Codegen markers

Two `nockup:` markers anchor the codegen pass:

| Marker | Purpose |
|---|---|
| `nockup:domain-effect` | Anchor for the developer's `+$ domain-effect $%(...)` declaration. graft-inject does not own the body here — only the marker presence. When present, codegen splices `domain-effect` into the union after the graft effects. |
| `nockup:effect-union` | REPLACE-IF-PRESENT codegen target. graft-inject owns the banner-bounded block beneath this marker; rerunning with a different graft set rewrites the block to match. |

The synthesized block looks like:

```hoon
::  nockup:effect-union
::  graft-inject:effect-union:begin
+$  effect
  $%  settle-effect
      counter-effect
      domain-effect
  ==
::  graft-inject:effect-union:end
```

Variant order matches the composer's input order (priority-sorted by
default). An empty union falls back to `[%effect-placeholder ~]` so
Hoon's `$%` stays non-empty.

### Drop semantics

graft-inject is symmetric: dropping a graft from `--grafts` (or
`--exclude`-ing it) on a re-run with `--apply` auto-prunes every
banner-pair-bounded block that graft owned. The pruned markers surface
in the per-graft summary as `<name>-graft  no-manifest    pruned N/M
(orphan blocks from previous injection)`. The codegen union shrinks
in the same pass — its variant collection reads only from the active
graft set, so a graft that's no longer present contributes no variant.

Lib files (`hoon/lib/<name>-graft.hoon`, `hoon/lib/<name>-graft.toml`)
are not touched by the prune; remove them manually if you want them
gone for good. Re-adding the graft to `--grafts` later round-trips
byte-identically: the inject pass restores the banner pairs at the
priority-sorted position they originally held.

### Auto-migration

Kernels that pre-date Phase 03f (carrying a bare `+$  effect  *` line
and no codegen markers) auto-migrate on the next `graft-inject` run.
The bare line is replaced with a placeholder `+$ domain-effect` block
and the two codegen markers; the codegen pass then takes over the
typed-union slot in the same `--apply` invocation. Pass `--no-migrate`
to opt out — the kernel keeps its bare `+$ effect *` and codegen is
skipped (the cast/weld friction at multi-graft `weld` sites remains).

A custom `+$ effect (list @t)` (or any non-bare shape) is left alone
even with auto-migration on. Surface a stderr note; don't rewrite
bespoke domain types.

### `--list --json` output

Each graft summary gains a `types` field when the manifest declares one:

```json
{
  "name": "settle-graft",
  ...
  "types": { "effect": "settle-effect", "cause": "settle-cause" }
}
```

Grafts without `[graft.types]` omit the field (additive per the
schema's "append never reshape" contract).

## Composition

When multiple grafts contribute blocks for the same marker, `graft-inject`
composes them in `priority` order (lower first), `after`-hint order for
ties, then by `name`.

Each injected block — regardless of marker — is wrapped in a per-graft
begin/end banner pair:

```hoon
::  graft-inject:<graft-name>:<marker>:begin
<composed body lines>
::  graft-inject:<graft-name>:<marker>:end
```

The banners are the idempotence signal (see below). They also read as
useful provenance when a reviewer is scanning a composed `app.hoon` —
every injected block is attributable to its manifest at a glance.

### Non-peek markers

Each graft's `body` is wrapped in banners and concatenated in priority
order.

### `peek` marker

A peek chain. Each graft contributes a banner-wrapped pair:

```hoon
::  graft-inject:<name>:peek:begin
=/  <stub>-res  <peek.body>
?.  =(~ <stub>-res)  <stub>-res
::  graft-inject:<name>:peek:end
```

The terminal `~` from the bare scaffold remains as the chain's final
fallback. A graft's peek body must return `~` (not `[~ ~]`) for paths
it doesn't handle, so the chain falls through to the next graft.

### Idempotence

- **Per-graft-per-marker**: re-running `graft-inject` scans the file
  for exact trimmed-line matches against `::  graft-inject:<name>:<marker>:begin`.
  If found, the graft is considered already wired at that marker and
  skipped; other grafts and other markers are evaluated independently.
- **Peek-chain**: new grafts' banner-wrapped pairs land immediately
  before the last bare `~` between the peek marker and its block's
  closing `==`. The window is unbounded within the block (AUDIT
  2026-04-19 H-13 fix), so chains grow safely past any size.
- **No overwrite**: removing a graft from `--grafts` does NOT remove
  its existing banner block. The tool is additive by design; cleanup
  is a manual operation.

## Discovery and selection

`graft-inject` discovers manifests by scanning `--lib-dir` (default
`./hoon/lib/`) for files matching `*.toml` with a `[graft]` table. Files
without `[graft]` are ignored — TOML used for unrelated config can live
beside graft manifests without conflict.

CLI:

```
graft-inject [OPTIONS] [PATH]
  --grafts <CSV>    explicit grafts in injection order; bypasses auto-discover
  --exclude <CSV>   subtract these from the discovered set
  --lib-dir <DIR>   discovery root (default: ./hoon/lib/)
  --list            print discovered grafts and exit
  --json            machine-readable output (pairs with --list)
  --apply           write the composed output to PATH (default: preview-only)
  --dry-run         deprecated alias of the default preview-only behavior
```

Default behavior (no `--apply`): `graft-inject` prints the composed
output to stdout and a per-manifest sha256 summary + "add --apply to
write" hint to stderr. `--apply` is required to write to disk. See the
Trust model section above for the reasoning.

`--grafts <name>` with a name not present in the discovered set is a hard
error.

### `--list --json` schema

Stable across the v3 plan's lifespan. Tier 2 crates use this at boot to
fail loudly when a required graft is missing.

```json
[
  {
    "name": "settle-graft",
    "version": "0.1.0",
    "priority": 10,
    "blocks": ["imports", "state", "cause", "poke", "peek"],
    "applicable": 5,
    "deferred": false,
    "sha256": "a9c72bbe…"
  }
]
```

`sha256` is the hex sha256 of the manifest's raw TOML bytes — added per
AUDIT 2026-04-19 H-10 so supply-chain reviewers can pin expected digests
without re-reading the file.

Version bumps to this schema append fields, never reshape existing ones.

## Error modes

| Condition | Behavior |
|---|---|
| TOML parse failure | hard error; surface the line number from the parser |
| `[graft]` missing required field (`name`/`version`/`priority`) | hard error |
| `name` not matching `^[a-z][a-z0-9-]*$` | hard error at discovery |
| `after` references an absent graft | stderr `note`; hint silently dropped, priority-based ordering applies (selective composition stays valid) |
| `--grafts` names an absent graft | hard error |
| Two manifests claim the same `name` | hard error at discovery; both source paths named in the message |
| Marker missing from target file | warning; that marker is skipped, others continue |
| All nine markers missing | hard error (nothing to wire) |
| Banner `::  graft-inject:<name>:<marker>:begin` already present | skip that graft-marker pair; log `skipped` |
| Body contains tabs (mixed indentation) | injection proceeds — `honk` may fail downstream |

## `[graft.gates]` — catalog gate selection

EXPANSION Phase 01 (branch `parametize_2`) implements named-gate
selection on top of `settle-graft`'s parameterized verify-gate. Gates
are family 2 in the lattice — a library of parameterized decision
functions shipped from `vesl-core/protocol/lib/vesl-gates.hoon`, not
grafts in their own right.

```toml
[graft.gates]
gate       = "sig-verify-ed25519"                  # single named gate from the catalog
gate-chain = ["sig-verify-ed25519", "manifest-verify"]  # AND-fold composition
```

`gate` and `gate-chain` are mutually exclusive — set one or neither.
When set, the composer rewrites the manifest's `[graft.blocks.poke]`
body: every default 4-line `=/  hash-gate=verify-gate ... =((hash-leaf
;;(@ data)) expected-root)` block is replaced with a binding to the
selected gate, and `[graft.blocks.imports]` gains a `/+  vesl-gates`
line if it wasn't there already. The manifest itself is left on disk
unchanged; the rewrite runs in memory at inject time.

`gate-chain` composes AND-only in v1 (per `vesl-nockup/.dev/OVERVIEW.md`
§Out-of-scope). Each named gate runs against the same `(note-id, data,
expected-root)` triple; the chain returns `%.y` iff every gate does.

### Catalog allowlist

`graft-inject` validates gate names against a hardcoded allowlist of
catalog-shipped gates. Tier 1a (currently shipping):

- `sig-verify-ed25519`
- `sig-verify-schnorr`
- `manifest-verify`
- `set-membership-verify`
- `bounded-value-verify`

Tier 1b additions extend the allowlist as they land. Unknown names hard-
error at discovery with the offending file path and field path
(C2 — see `vesl-nockup/.dev/OVERVIEW.md` §Safety contracts).

### Validation rules

| Condition | Behavior |
|---|---|
| `gate` and `gate-chain` both set | hard error at discovery |
| `gate-chain = []` (empty list) | hard error |
| `gate` or any `gate-chain` entry not matching `^[a-z][a-z0-9-]*$` | hard error |
| `gate` or `gate-chain` entry not in the catalog allowlist | hard error |
| `[graft.gates]` set but the manifest has no `[graft.blocks.poke]` | hard error |
| `[graft.gates]` set but the poke body lacks the default hash-gate block | hard error (the manifest already hand-wrote a custom gate; catalog selection is a no-op or contradicts it — surface the conflict instead of silently picking one) |

### Example: settle-graft with ed25519 selection

```toml
[graft]
name = "settle-graft"
version = "0.1.0"
priority = 10

[graft.gates]
gate = "sig-verify-ed25519"

# [graft.blocks.imports], [graft.blocks.state], [graft.blocks.cause],
# [graft.blocks.poke], [graft.blocks.peek] -- as in the stock manifest.
# The composer rewrites the poke body's three hash-gate blocks to:
#
#   =/  hash-gate=verify-gate  sig-verify-ed25519:vesl-gates
#
# and prepends `/+  vesl-gates` to the imports body. Non-splat: the
# qualified `name:vesl-gates` body needs `vesl-gates` to remain a
# namespace identifier.
```

## Library helpers — `domain-patterns`

`vesl-core/protocol/lib/domain-patterns.hoon` is a library, not a
graft (no manifest, no graft-inject involvement). Import it with
`/+  *domain-patterns` in your `app.hoon` when you write a domain arm
that coordinates more than one graft.

v0.1 ships:

- `++  apply-<graft>` — one wet-gate per shipped data/behavior graft
  (counter, kv, queue, rbac, registry, log, clock, validate, batch).
  Each threads versioned-state by the convention `<graft>.state`,
  calls the underlying `<graft>-poke`, and returns
  `[(list <graft>-effect) versioned-state]` suitable for `=^` binding.
- `++  audit-write` — bundles "delegate to a storage graft (kv,
  registry, queue) + append to log-graft + return combined effects."
  Takes `log-tag` and `log-body` separately so write body and log
  body can differ (R3 B's `%revoke-license` shape).

Idiom:

```hoon
%set-and-log
  =^  efx-k  state  (apply-kv [%kv-set 'k' v] state)
  =^  efx-l  state  (apply-log [%log-append %set (jam v)] state)
  [(weld efx-k efx-l) state]
```

Or, equivalently with `audit-write`:

```hoon
%set-and-log
  (audit-write state [%kv-set 'k' v] %set (jam v))
```

Convention violations (e.g. your kernel stores counter-graft state
at `cnt.state` instead of `counter.state`) surface as a
`find . counter` honk error at the helper call site, not an internal
trace. Out of scope for the helpers: kernel-composite grafts (settle,
mint, guard, forge, intent) — see the library header for rationale.

## Migration: vesl-graft → settle-graft

Phase 12A (landed) renamed the `vesl-graft` package to `settle-graft`
to align with the four-primitive taxonomy (mint / guard / settle /
forge). The manifest moved from `vesl-graft.toml` to `settle-graft.toml`;
`name`, `sentinel`s, and `body`s updated accordingly. Rust-side helper
functions kept `build_vesl_*_poke` aliases marked `#[deprecated]` for
one release cycle — callers should migrate to `build_settle_*_poke`.
