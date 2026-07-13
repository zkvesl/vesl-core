#!/usr/bin/env bash
#
# The SANCTIONED way to format this repo. Use this, NEVER a bare `cargo fmt --all`.
#
# ⚑ WHY: `cargo fmt --all` FOLLOWS PATH-DEPENDENCIES INTO THE PINNED nockchain CHECKOUT.
#
# This repo path-deps into ~/projects/nockchain/nockchain — a pristine, READ-ONLY upstream
# checkout. `cargo fmt --all` sweeps those path-dep packages in as if they were workspace
# members, hands rustfmt 159 files under nockchain/crates/, and REWRITES them in place.
#
# Not hypothetical: on 2026-07-13 a `cargo fmt` sweep did exactly this across the fleet and
# silently dirtied 34 files in the pinned checkout. It was caught only by noticing that
# `git status` in nockchain was not clean.
#
# `cargo fmt -p <pkg>` does NOT do this — it stays inside the named package. So we enumerate
# the workspace members and format them one package at a time, then ASSERT nockchain is
# still pristine. Measured 2026-07-13: `--all` leaks 159 files; `-p` leaks 0.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOCKCHAIN="$(cd "$REPO/../nockchain" && pwd)"
TOOLCHAIN="nightly-2026-04-03"

nockchain_dirty() { git -C "$NOCKCHAIN" status --short --untracked-files=no | wc -l; }

if [ "$(nockchain_dirty)" -ne 0 ]; then
  echo "✗ REFUSING TO RUN: nockchain is already dirty ($(nockchain_dirty) files)." >&2
  echo "  The pinned checkout must be clean before formatting. Inspect:" >&2
  echo "     git -C $NOCKCHAIN status" >&2
  exit 1
fi

# Every workspace root in this repo, minus vendor/ (whose members may be symlinks into
# nockchain — formatting through those writes straight into the pinned checkout).
mapfile -t WORKSPACES < <(
  find "$REPO" -name Cargo.toml -not -path '*/target/*' -not -path '*/vendor/*' \
    -exec grep -l '^\[workspace\]' {} \; 2>/dev/null | xargs -r -n1 dirname | sort -u
)

rc=0
for ws in "${WORKSPACES[@]:-}"; do
  [ -n "$ws" ] || continue
  # A workspace with an unloadable member makes `cargo metadata` fail; skip it loudly
  # rather than aborting the whole run.
  members="$(cd "$ws" && cargo "+$TOOLCHAIN" metadata --no-deps --format-version 1 --offline 2>/dev/null \
    | python3 -c 'import json,sys
try: print(" ".join(p["name"] for p in json.load(sys.stdin)["packages"]))
except Exception: pass')" || members=""
  rel="${ws#"$REPO"}"; rel="${rel#/}"; rel="${rel:-.}"
  if [ -z "$members" ]; then
    echo "⚠ skipped $rel (cargo metadata failed — broken/absent workspace member)"
    continue
  fi
  echo "→ $rel"
  for pkg in $members; do
    ( cd "$ws" && cargo "+$TOOLCHAIN" fmt -p "$pkg" "$@" ) || rc=1
  done
done

AFTER="$(nockchain_dirty)"
if [ "$AFTER" -ne 0 ]; then
  echo >&2
  echo "✗✗ THE PIN LEAKED: formatting wrote $AFTER files into the read-only nockchain checkout." >&2
  echo "   Restore it:  git -C $NOCKCHAIN checkout -- ." >&2
  exit 1
fi

if [ "$rc" -ne 0 ]; then
  echo "✗ some packages failed to format (see above); nockchain is pristine" >&2
  exit 1
fi
echo "✓ formatted; nockchain still pristine (0 dirty files)"
