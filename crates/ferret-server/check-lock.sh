#!/usr/bin/env bash
# The server (crates/ferret-server) is a workspace of its own with its own
# Cargo.lock, because it builds on vole-kit, a git dependency with hundreds of
# crates. This checks that the two graphs do not drift apart where they must
# not:
#
#   * every crate in the tree of ferret-core and ferret-server-auth of the root
#     graph (what the release builds) is in the server's tree at the same
#     version, so the crypto that is served is the crypto that was tested and
#     vetted (vole-kit's own crates, such as a second `rand_core`, are outside
#     that tree and may differ). The server's tree may be a superset: see
#     `compare` below;
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

# `compare ROOT_TREE SERVER_TREE`: the crates (at a version) of the root tree
# that the server tree does not have. The server may have more: vole-kit
# switches on features (the password hashing of its own `argon2`, for one) that
# bring crates the root graph does not build, sometimes at another version of a
# name the root has too. What must not happen is that a crate the root builds is
# not at that version in the server.
#
# Why a superset is sound: cargo never resolves two semver-compatible versions
# of one crate in a graph, so when the version the root builds is in the
# server's subtree, it is the one the server links, and a drifted crate (say
# sha2 0.11.2 against 0.11.1) drops the root's line out of the server set and
# fails here. An extra crate comes from a feature that vole-kit switches on
# (its `argon2` has the password hashing and random salts on, which bring in
# `password-hash 0.6` and `getrandom 0.2`). It adds API and dependencies; the
# source of the crates the root vets is the same (the checksum check below), so
# the hashing the core does is unchanged. A crate that is in both trees under
# another version only because of such an extra edge is not a mismatch and is
# not compared by name.
compare() {
  local missing
  missing="$(comm -23 <(normalise < "$1") <(normalise < "$2"))"
  if [ -n "$missing" ]; then
    echo "FAIL: these crates of the tree of ferret-core and ferret-server-auth in the root lock are not at that version in the server lock:" >&2
    echo "$missing" >&2
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
  tree Cargo.toml "$package" normal,build >> "$root_tree"
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
