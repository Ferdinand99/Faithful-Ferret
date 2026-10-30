#!/usr/bin/env bash
# The server (crates/ferret-server) is a workspace of its own with its own
# Cargo.lock, because it builds on vole-kit, a git dependency with hundreds of
# crates. This checks that the two graphs do not drift apart where they must
# not:
#
#   * every crate in the tree of ferret-core and ferret-server-auth that the
#     root lock also has in that tree has the same version in the server lock, so the crypto that is
#     served is the crypto that was tested and vetted (vole-kit's own crates,
#     such as a second `rand_core`, are outside that tree and may differ);
#   * every crate that both locks have at the same name and version has the same
#     checksum in both;
#   * `overflow-checks` and `panic` of [profile.release] are the same in both
#     manifests.
#
#   crates/ferret-server/check-lock.sh
#       checks the real locks (needs cargo; run it where cargo is: the builder
#       image, CI)
#   crates/ferret-server/check-lock.sh --compare ROOT_TREE SERVER_TREE
#       compares two listings made by `cargo tree --prefix none` (no cargo; the
#       tests use it to show that a version mismatch is caught)
set -euo pipefail
cd "$(dirname "$0")/../.."

# One line per crate: `name vX.Y.Z`, without the markers of cargo tree and
# without the path of a crate of this repository.
normalise() {
  sed -E ':a; s/ \((\*|proc-macro|build|\/[^)]*)\)$//; ta' | sort -u
}

# `compare ROOT_TREE SERVER_TREE`: the crates that both trees have, at a version
# that the root tree does not have. A crate that only the server tree has is
# not a mismatch: vole-kit switches on features (the password hashing of its own
# `argon2`, for one) that bring crates the root graph does not build.
compare() {
  local extra
  extra="$(awk 'NR==FNR { seen[$1] = seen[$1] " " $2; next }
                ($1 in seen) && index(seen[$1] " ", " " $2 " ") == 0 { print $1, $2 }'     <(normalise < "$1") <(normalise < "$2"))"
  if [ -n "$extra" ]; then
    echo "FAIL: the server resolves these crates of the tree of ferret-core and ferret-server-auth to versions that the root lock does not use:" >&2
    echo "$extra" >&2
    return 1
  fi
}

if [ "${1:-}" = "--compare" ]; then
  [ "$#" -eq 3 ] || { echo "usage: $0 --compare ROOT_TREE SERVER_TREE" >&2; exit 2; }
  compare "$2" "$3"
  exit $?
fi

tree() { # manifest, package, edges
  cargo tree --manifest-path "$1" -p "$2" -e "$3" --target all --prefix none --locked
}

root_tree="$(mktemp)"
server_tree="$(mktemp)"
trap 'rm -f "$root_tree" "$server_tree"' EXIT
for package in ferret-core ferret-server-auth; do
  tree Cargo.toml "$package" normal,build,dev >> "$root_tree"
  tree crates/ferret-server/Cargo.toml "$package" normal,build >> "$server_tree"
done

fail=0
compare "$root_tree" "$server_tree" || fail=1

# The same crate at the same version must have the same checksum in both locks.
ct/check-lock-sums.sh Cargo.lock crates/ferret-server/Cargo.lock || fail=1

profile() {
  sed -n '/^\[profile\.release\]/,/^$/p' "$1" | grep -E '^(overflow-checks|panic) *=' | sort
}
if [ "$(profile Cargo.toml)" != "$(profile crates/ferret-server/Cargo.toml)" ] \
   || [ -z "$(profile crates/ferret-server/Cargo.toml)" ]; then
  echo "FAIL: overflow-checks and panic of [profile.release] in crates/ferret-server/Cargo.toml are not the root ones" >&2
  fail=1
fi

[ "$fail" = 0 ] && echo "crates/ferret-server: the tree of ferret-core and ferret-server-auth, the checksums and the release profile agree with the root"
exit "$fail"
