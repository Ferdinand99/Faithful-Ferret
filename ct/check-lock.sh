#!/usr/bin/env bash
# The timing tests (ct/dudect) have a Cargo.lock of their own. This checks that
#   * every crate of the tree of ferret-core in ct/dudect has the same version
#     as in the root workspace, so the timing is of the code that ships, and
#     every crate that both locks have at the same version has the same checksum,
#   * the [profile.release] of ct/dudect is a copy of the one in the root.
# Run it where cargo is (the builder image, CI).
set -euo pipefail
cd "$(dirname "$0")/.."

tree() { # manifest, edges
  cargo tree --manifest-path "$1" -p ferret-core -e "$2" --target all --prefix none --locked \
    | sed 's/ (\*)$//; s/ (proc-macro)$//; s/ (build)$//' \
    | grep -v '^ferret-core ' | sort -u
}

fail=0
extra="$(comm -13 <(tree Cargo.toml normal,build,dev) <(tree ct/dudect/Cargo.toml normal,build))"
if [ -n "$extra" ]; then
  echo "FAIL: ct/dudect resolves these crates of the tree of ferret-core to versions that the root lock does not use:" >&2
  echo "$extra" >&2
  fail=1
fi

# The same crate at the same version must have the same checksum in both locks.
ct/check-lock-sums.sh Cargo.lock ct/dudect/Cargo.lock || fail=1

profile() {
  sed -n '/^\[profile\.release\]/,/^$/p;/^\[profile\.release\.package\."argon2@0.6.0"\]/,/^$/p' "$1" \
    | grep -v '^#' | grep -v '^$'
}
if [ "$(profile Cargo.toml)" != "$(profile ct/dudect/Cargo.toml)" ]; then
  echo "FAIL: [profile.release] of ct/dudect/Cargo.toml is not a copy of the root one" >&2
  fail=1
fi
[ "$fail" = 0 ] && echo "ct/dudect: the tree of ferret-core and the release profile agree with the root"
exit "$fail"
