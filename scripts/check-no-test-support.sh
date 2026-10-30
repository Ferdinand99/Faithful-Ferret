#!/usr/bin/env bash
# The `test-support` feature (replay RNG, unchecked Argon2, intermediate
# results) must never reach a release, and neither may `server-suite`, which
# opens the OPAQUE suite and the RNG adapter for a server built on the core and
# has no place in the client package.
#
#  1. In the resolved dependency graph of every release crate (normal
#     dependencies only), `ferret-core` must not have the feature
#     `test-support` or `server-suite` enabled. The check reads the feature set
#     of the `ferret-core` node, so it also catches a chain such as
#     `default = ["ferret-core/server-suite"]` in the release crate, which
#     leaves no `feature "..."` line of its own in `cargo tree -e features`.
#     No release crate may have a server crate (`ferret-server-auth`) in that
#     graph either: it enables `server-suite` by design.
#  2. The server crates (`ferret-server-auth`) may enable `server-suite`, and
#     nothing else of the core: in their own normal graph `ferret-core` must not
#     have `test-support`, and the crate's own `test-support` must be off.
#  3. If a built .wasm file is given (or the default exists), its export list
#     must not contain a `test_*` function or method, or a replay function.
#
# Run it through scripts/lanbox.sh --exec scripts/check-no-test-support.sh.
# `--self-test` builds small throwaway crates in a temporary directory that
# enable the features directly and through chains, and checks that the
# detection of steps 1 and 2 sees every one of them and none of the clean ones.
set -euo pipefail

# The resolved graph of a crate: one line per node, `name vX.Y.Z (path) [features]`.
resolved_tree() {
  cargo tree "$@" -e normal -f '{p} [{f}]' --prefix none
}

# The tests below use here-strings, not `printf | grep -q`: under pipefail a grep
# that stops reading early can give printf a SIGPIPE and read as "no match".
#
# feature_enabled <tree> <crate> <feature>: does the node of the crate list the
# feature?
feature_enabled() {
  grep -Eq "^$2 v[^ ]+ .*\[([^]]*,)?$3(,[^]]*)?\]" <<< "$1"
}

# node_present <tree> <crate>: is the crate in the graph at all?
node_present() {
  grep -Eq "^$2 v[^ ]+ " <<< "$1"
}

# check_release_crate <crate>: step 1. Prints a line for each failure.
check_release_crate() {
  local tree feature failed=0
  # Called in an `||` list, where `set -e` is off: a failing `cargo tree`, or a
  # graph without the crate itself, must fail the check and not pass it.
  tree="$(resolved_tree -p "$1")" || { echo "FAIL: cargo tree failed for $1" >&2; return 1; }
  node_present "$tree" "$1" || { echo "FAIL: the graph of $1 is empty" >&2; return 1; }
  for feature in test-support server-suite; do
    if feature_enabled "$tree" ferret-core "$feature"; then
      echo "FAIL: $1 enables ferret-core/$feature in its release graph" >&2
      failed=1
    fi
  done
  if node_present "$tree" ferret-server-auth; then
    echo "FAIL: $1 depends on ferret-server-auth in its release graph" >&2
    failed=1
  fi
  if grep -q '^ferret-vectorgen ' <<< "$tree"; then
    echo "FAIL: $1 depends on ferret-vectorgen in its release graph" >&2
    failed=1
  fi
  return "$failed"
}

# check_server_crate <crate>: step 2.
check_server_crate() {
  local tree failed=0
  tree="$(resolved_tree -p "$1")" || { echo "FAIL: cargo tree failed for $1" >&2; return 1; }
  node_present "$tree" "$1" || { echo "FAIL: the graph of $1 is empty" >&2; return 1; }
  if feature_enabled "$tree" ferret-core test-support; then
    echo "FAIL: $1 enables ferret-core/test-support in its normal graph" >&2
    failed=1
  fi
  if feature_enabled "$tree" "$1" test-support; then
    echo "FAIL: $1 has its own test-support feature on in its normal graph" >&2
    failed=1
  fi
  return "$failed"
}

self_test() {
  local t status=0
  t="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$t'" RETURN
  mkdir -p "$t/ferret-core/src" "$t/ferret-server-auth/src"
  cat > "$t/ferret-core/Cargo.toml" <<'XTOML'
[package]
name = "ferret-core"
version = "0.0.0"
edition = "2021"
[features]
test-support = []
server-suite = []
XTOML
  : > "$t/ferret-core/src/lib.rs"
  # A stand-in server crate: server-suite on, its own test-support off.
  cat > "$t/ferret-server-auth/Cargo.toml" <<'XTOML'
[package]
name = "ferret-server-auth"
version = "0.0.0"
edition = "2021"
[features]
test-support = ["ferret-core/test-support"]
[dependencies]
ferret-core = { path = "../ferret-core", features = ["server-suite"] }
XTOML
  : > "$t/ferret-server-auth/src/lib.rs"

  # mk <name> <features section> <dependencies> <dev-dependencies>
  mk() {
    mkdir -p "$t/$1/src"
    : > "$t/$1/src/lib.rs"
    {
      printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2021"\n' "$1"
      printf '[features]\n%s\n[dependencies]\n%s\n[dev-dependencies]\n%s\n' "$2" "$3" "$4"
    } > "$t/$1/Cargo.toml"
  }
  local plain='ferret-core = { path = "../ferret-core" }'
  local server='ferret-server-auth = { path = "../ferret-server-auth" }'
  mk clean "" "$plain" ""
  mk dev_only "" "$plain" 'ferret-core = { path = "../ferret-core", features = ["server-suite", "test-support"] }'
  mk direct_server "" 'ferret-core = { path = "../ferret-core", features = ["server-suite"] }' ""
  mk direct_test "" 'ferret-core = { path = "../ferret-core", features = ["test-support"] }' ""
  mk chain_server 'default = ["ferret-core/server-suite"]' "$plain" ""
  mk chain_test 'default = ["ferret-core/test-support"]' "$plain" ""
  mk chain_two_steps 'default = ["extra"]
extra = ["ferret-core/server-suite", "ferret-core/test-support"]' "$plain" ""
  # Crates that use the server crate: as a dependency, as a dev-dependency only,
  # with its test-support on, and with that switched on through a chain.
  mk uses_server "" "$server" ""
  mk uses_server_dev "" "$plain" "$server"
  mk uses_server_test "" 'ferret-server-auth = { path = "../ferret-server-auth", features = ["test-support"] }' ""
  mk uses_server_chain 'default = ["ferret-server-auth/test-support"]' "$server" ""
  printf '[workspace]\nresolver = "2"\nmembers = ["ferret-core", "ferret-server-auth", "clean", "dev_only", "direct_server", "direct_test", "chain_server", "chain_test", "chain_two_steps", "uses_server", "uses_server_dev", "uses_server_test", "uses_server_chain"]\n' > "$t/Cargo.toml"

  # expect <crate> <server-suite yes|no> <test-support yes|no>
  expect() {
    local tree got_s=no got_t=no
    tree="$(resolved_tree --manifest-path "$t/Cargo.toml" -p "$1")"
    if feature_enabled "$tree" ferret-core server-suite; then got_s=yes; fi
    if feature_enabled "$tree" ferret-core test-support; then got_t=yes; fi
    if [ "$got_s" != "$2" ] || [ "$got_t" != "$3" ]; then
      echo "self-test FAIL: $1 shows server-suite=$got_s test-support=$got_t, expected $2 $3" >&2
      status=1
    fi
  }
  # expect_server <crate> <server crate present yes|no> <its test-support yes|no>
  expect_server() {
    local tree got_p=no got_t=no
    tree="$(resolved_tree --manifest-path "$t/Cargo.toml" -p "$1")"
    if node_present "$tree" ferret-server-auth; then got_p=yes; fi
    if feature_enabled "$tree" ferret-server-auth test-support; then got_t=yes; fi
    if [ "$got_p" != "$2" ] || [ "$got_t" != "$3" ]; then
      echo "self-test FAIL: $1 shows ferret-server-auth=$got_p test-support=$got_t, expected $2 $3" >&2
      status=1
    fi
  }
  expect clean no no
  expect dev_only no no
  expect direct_server yes no
  expect direct_test no yes
  expect chain_server yes no
  expect chain_test no yes
  expect chain_two_steps yes yes
  # The server crate itself: server-suite is what it is meant to have.
  expect ferret-server-auth yes no
  expect_server ferret-server-auth yes no
  expect_server clean no no
  expect_server uses_server yes no
  expect_server uses_server_dev no no
  expect_server uses_server_test yes yes
  expect_server uses_server_chain yes yes
  # A server crate that pulled in the core's test-support would be caught:
  expect uses_server_test yes yes
  if [ "$status" -eq 0 ]; then
    echo "ok: the feature check sees direct and chained features and server crates, and ignores dev-dependencies"
  fi
  return "$status"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

cd "$(dirname "$0")/.."

fail=0

# 1. Normal (non-dev) dependency graph, with resolved features, of every
# release crate.
release_crates=(ferret-core)
if [ -d bindings/wasm ]; then
  release_crates+=(ferret-core-wasm)
fi
for crate in "${release_crates[@]}"; do
  check_release_crate "$crate" || fail=1
done

# 2. The server crates: `server-suite` only, no `test-support`.
server_crates=()
if [ -d crates/ferret-server-auth ]; then
  server_crates+=(ferret-server-auth)
fi
for crate in "${server_crates[@]}"; do
  check_server_crate "$crate" || fail=1
done

# 3. WASM export list. wasm-bindgen exports a method as `<class>_<method>`
# (`vault_test_vk_region`), so the pattern is a `test_` at the start or after
# an underscore. The list is read with Node, which every build environment
# for the WASM packages has.
wasm="${1:-bindings/wasm/pkg-web/ferret_core_wasm_bg.wasm}"
if [ -f "$wasm" ]; then
  exports="$(node -e '
    const m = new WebAssembly.Module(require("fs").readFileSync(process.argv[1]));
    for (const e of WebAssembly.Module.exports(m)) console.log(e.name);
  ' "$wasm")"
  if [ -z "$exports" ]; then
    echo "FAIL: could not read the export list of $wasm" >&2
    fail=1
  elif grep -Eq '(^|_)test_|replay' <<< "$exports"; then
    echo "FAIL: $wasm exports a test-support function:" >&2
    printf '%s\n' "$exports" | grep -E '(^|_)test_|replay' >&2
    fail=1
  fi
else
  echo "note: no .wasm file at $wasm, skipping the export-list check" >&2
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "ok: test-support and server-suite are not part of any release build"
