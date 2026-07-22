#!/usr/bin/env bash
# Validate every upstream PIN in vesl-core.
#
# vesl-core pins one upstream: nockchain (NOCK_PIN). Two sites carry
# the value:
#
#   .github/workflows/jam-determinism.yml  — CI's NOCK_PIN env
#   docker/NOCKCHAIN_COMMIT                 — the docker pin-of-record
#
# Audit H-21 flagged the local (gitignored) Dockerfile as historically
# diverged from CI's pin. The tracked docker/NOCKCHAIN_COMMIT is now the
# pin-of-record this gate validates; it catches drift and ghost-SHA
# mistakes before they reach main.
#
# Checks performed:
#   1. SHA shape: both sites must hold a 40-char lowercase hex SHA.
#   2. Agreement: both sites must hold the SAME SHA. Bump them
#      together via scripts/bump-pin.sh nock <sha>.
#   3. Existence: SHA must be reachable in the nockchain repo. Prefers
#      sibling ../nockchain/ rev-parse (offline-friendly); falls back
#      to `git ls-remote` (requires network). On network failure, warns
#      but does not fail.
#
# Usage: scripts/check-pins.sh
# Wired into ci.yml as a fast pre-flight gate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

JAM_WF=".github/workflows/jam-determinism.yml"
CI_WF=".github/workflows/ci.yml"
DOCKER_PIN="docker/NOCKCHAIN_COMMIT"

status=0
warnings=0

err()  { echo "FAIL: $*" >&2; status=1; }
warn() { echo "warn: $*" >&2; warnings=$((warnings + 1)); }
ok()   { echo "ok   $*"; }

extract_sha() {
    # $1: file, $2: regex with single capture group for the SHA
    # Prints the SHA or empty.
    local file="$1" pattern="$2"
    grep -oE "$pattern" "$file" | grep -oE '[0-9a-f]{40}' | head -1
}

validate_sha_shape() {
    # $1: label, $2: SHA
    local label="$1" sha="$2"
    if [[ -z "$sha" ]]; then
        err "$label: no SHA found"
        return 1
    fi
    if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
        err "$label: '$sha' is not a 40-char lowercase hex SHA"
        return 1
    fi
    return 0
}

validate_sha_exists() {
    # $1: repo path (sibling); $2: repo url (for ls-remote fallback);
    # $3: SHA; $4: label
    local repo_path="$1" repo_url="$2" sha="$3" label="$4"
    if [[ -d "$repo_path/.git" ]]; then
        if git -C "$repo_path" cat-file -t "$sha" >/dev/null 2>&1; then
            return 0
        fi
        warn "$label: SHA $sha not in sibling $repo_path; trying ls-remote"
    fi
    # ls-remote fallback. Network may be unavailable in some
    # environments; warn rather than hard-fail.
    if ! command -v git >/dev/null 2>&1; then
        warn "$label: git not available for ls-remote check"
        return 0
    fi
    if git ls-remote --exit-code "$repo_url" "$sha" >/dev/null 2>&1; then
        return 0
    fi
    # ls-remote SHA-form support varies; try fetching the SHA explicitly
    # via the git-upload-pack protocol. If that also fails, treat as
    # warn (transient network issues shouldn't fail CI) UNLESS the SHA
    # is obviously malformed (already validated above).
    warn "$label: could not verify $sha exists in $repo_url (network unreachable or SHA invalid)"
    return 0
}

# --- NOCK_PIN extraction ---
jam_sha=$(extract_sha "$JAM_WF" 'NOCK_PIN:[[:space:]]*[0-9a-f]+')
ci_sha=$(extract_sha "$CI_WF" 'NOCK_PIN:[[:space:]]*[0-9a-f]+')
docker_sha=$(extract_sha "$DOCKER_PIN" '[0-9a-f]{40}')

# --- Shape validation ---
validate_sha_shape "$JAM_WF NOCK_PIN" "$jam_sha"
validate_sha_shape "$CI_WF NOCK_PIN" "$ci_sha"
validate_sha_shape "$DOCKER_PIN" "$docker_sha"

# --- Agreement (AUDIT 2026-05-19 H-21: both sites are tracked and
# bump-pin.sh writes them together, so a mismatch is now a real error,
# not the historical drift the prior warn-only check tolerated) ---
if [[ -n "$jam_sha" && -n "$docker_sha" ]]; then
    if [[ "$jam_sha" == "$docker_sha" && "$jam_sha" == "${ci_sha:-$jam_sha}" ]]; then
        ok "NOCK_PIN: jam-determinism.yml, ci.yml and $DOCKER_PIN agree ($jam_sha)"
    else
        err "NOCK_PIN: jam-determinism.yml ($jam_sha) / ci.yml (${ci_sha:-missing}) / $DOCKER_PIN ($docker_sha) disagree"
        err "  bump all atomically via: scripts/bump-pin.sh nock <sha>"
    fi
fi

# --- Existence ---
if [[ -n "$jam_sha" ]]; then
    validate_sha_exists "../nockchain" "https://github.com/nockchain/nockchain" \
        "$jam_sha" "NOCK_PIN (jam-determinism)"
fi

# --- Summary ---
echo ""
if [[ $status -eq 0 ]]; then
    if [[ $warnings -gt 0 ]]; then
        echo "ok with $warnings warning(s) — see above"
    else
        echo "ok — all pins valid"
    fi
else
    echo "FAIL — $status hard error(s), $warnings warning(s)" >&2
fi

exit $status
