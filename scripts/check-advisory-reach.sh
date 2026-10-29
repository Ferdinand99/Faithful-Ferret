#!/usr/bin/env bash
# Guards the reachability argument for RUSTSEC-2026-0387 (timing variability
# in crypto-bigint 0.5.x, fixed only in 0.7.6).
#
# crypto-bigint 0.5 is in the tree only through elliptic-curve 0.13, which
# only opaque-ke and voprf depend on. The OPAQUE suite is ristretto255, whose
# arithmetic is curve25519-dalek's; the only thing it takes from
# elliptic-curve is the hash-based `ExpandMsgXmd`. That holds as long as no
# other crate is on the old curve generation (a P-256 or K-256 crate of the
# 0.13 line would put crypto-bigint 0.5 arithmetic on secrets).
#
# So this script fails if anything other than those crates depends directly on
# elliptic-curve 0.13 or on crypto-bigint 0.5, on any target, in any
# dependency kind. If it fails, the advisory exception in deny.toml (if there
# is one) no longer rests on the argument and has to be looked at again.
#
# Run it through scripts/lanbox.sh --exec scripts/check-advisory-reach.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

# The package itself and its direct dependents, by name.
direct_dependents() {
  cargo tree --workspace -i "$1" --depth 1 --prefix none --target all -e normal,build,dev 2>/dev/null \
    | sed -E 's/ v[0-9][^ ]*.*$//' | sort -u
}

fail=0
check() {
  local spec="$1"
  shift
  local want got
  want="$(printf '%s\n' "$@" | sort -u)"
  got="$(direct_dependents "$spec")"
  if [ -z "$got" ]; then
    echo "note: $spec is not in the dependency tree" >&2
    return
  fi
  if [ "$got" != "$want" ]; then
    echo "FAIL: direct dependents of $spec (with itself) are not the expected set" >&2
    echo "expected:" >&2
    printf '  %s\n' $want >&2
    echo "found:" >&2
    printf '  %s\n' $got >&2
    fail=1
  fi
}

check "elliptic-curve@0.13" elliptic-curve opaque-ke voprf
check "crypto-bigint@0.5" crypto-bigint elliptic-curve

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: only opaque-ke and voprf reach elliptic-curve 0.13 and crypto-bigint 0.5"
