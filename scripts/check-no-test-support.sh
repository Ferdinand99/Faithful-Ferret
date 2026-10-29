#!/usr/bin/env bash
# The `test-support` feature (replay RNG, unchecked Argon2, intermediate
# results) must never reach a release.
#
#  1. No release dependency graph may enable ferret-core/test-support.
#  2. If a built .wasm file is given (or the default exists), its export list
#     must not contain a function whose name starts with `test_`.
#
# Run it through scripts/lanbox.sh --exec scripts/check-no-test-support.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. Normal (non-dev) dependency graph, with features, of every release crate.
release_crates=(ferret-core)
if [ -d bindings/wasm ]; then
  release_crates+=(ferret-core-wasm)
fi
for crate in "${release_crates[@]}"; do
  tree="$(cargo tree -p "$crate" -e normal,features --prefix none)"
  if printf '%s\n' "$tree" | grep -q 'ferret-core feature "test-support"'; then
    echo "FAIL: $crate enables ferret-core/test-support in its release graph" >&2
    fail=1
  fi
  if printf '%s\n' "$tree" | grep -q '^ferret-vectorgen '; then
    echo "FAIL: $crate depends on ferret-vectorgen in its release graph" >&2
    fail=1
  fi
done

# 2. WASM export list.
wasm="${1:-bindings/wasm/pkg-web/ferret_core_wasm_bg.wasm}"
if [ -f "$wasm" ]; then
  if wasm-tools print "$wasm" | grep -Eq '\(export "test_'; then
    echo "FAIL: $wasm exports a function with the prefix test_" >&2
    fail=1
  fi
else
  echo "note: no .wasm file at $wasm, skipping the export-list check" >&2
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: test-support is not part of any release build"
