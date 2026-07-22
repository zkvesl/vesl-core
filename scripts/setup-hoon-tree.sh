#!/usr/bin/env bash
# Creates the nockchain symlinks needed for hoonc compilation.
#
# Usage:
#   NOCK_HOME=~/projects/nockchain/nockchain ./scripts/setup-hoon-tree.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOON_DIR="$SCRIPT_DIR/../hoon"

if [[ -z "${NOCK_HOME:-}" ]]; then
    echo "Error: NOCK_HOME is not set."
    echo "Set it to the nockchain monorepo root:"
    echo "  export NOCK_HOME=~/projects/nockchain/nockchain"
    exit 1
fi

if [[ ! -d "$NOCK_HOME/hoon/common" ]]; then
    echo "Error: $NOCK_HOME/hoon/common not found."
    echo "Is NOCK_HOME pointing to the nockchain monorepo?"
    exit 1
fi

echo "Creating nockchain symlinks in hoon/..."

for dir in common apps dat jams test-jams tests; do
    if [[ -L "$HOON_DIR/$dir" ]]; then
        echo "  $dir: already linked"
    else
        ln -s "$NOCK_HOME/hoon/$dir" "$HOON_DIR/$dir"
        echo "  $dir -> $NOCK_HOME/hoon/$dir"
    fi
done

if [[ -L "$HOON_DIR/trivial.hoon" ]]; then
    echo "  trivial.hoon: already linked"
else
    ln -s "$NOCK_HOME/hoon/trivial.hoon" "$HOON_DIR/trivial.hoon"
    echo "  trivial.hoon -> $NOCK_HOME/hoon/trivial.hoon"
fi

echo "Done. You can now compile with: hoonc protocol/lib/vesl-kernel.hoon hoon/"
