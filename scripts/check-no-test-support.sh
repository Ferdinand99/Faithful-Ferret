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
#  2. If a built .wasm file is given (or the default exists), its export list
#     must not contain a `test_*` function or method, or a replay function.
#
# Run it through scripts/lanbox.sh --exec scripts/check-no-test-support.sh.
# `--self-test` builds small throwaway crates in a temporary directory that
# enable the features directly and through chains, and checks that the
# detection of step 1 sees every one of them and none of the clean ones.
set -euo pipefail

# The resolved graph of a crate: one line per node, `name vX.Y.Z (path) [features]`.
resolved_tree() {
  cargo tree "$@" -e normal -f '{p} [{f}]' --prefix none
}

# feature_enabled <tree> <feature>: does the ferret-core node list the feature?
feature_enabled() {
  printf '%s\n' "$1" | grep -Eq "^ferret-core v[^ ]+ .*\[([^]]*,)?$2(,[^]]*)?\]"
}

self_test() {
  local t status=0
  t="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$t'" RETURN
  mkdir -p "$t/ferret-core/src"
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
  mk clean "" "$plain" ""
  mk dev_only "" "$plain" 'ferret-core = { path = "../ferret-core", features = ["server-suite", "test-support"] }'
  mk direct_server "" 'ferret-core = { path = "../ferret-core", features = ["server-suite"] }' ""
  mk direct_test "" 'ferret-core = { path = "../ferret-core", features = ["test-support"] }' ""
  mk chain_server 'default = ["ferret-core/server-suite"]' "$plain" ""
  mk chain_test 'default = ["ferret-core/test-support"]' "$plain" ""
  mk chain_two_steps 'default = ["extra"]
extra = ["ferret-core/server-suite", "ferret-core/test-support"]' "$plain" ""
  printf '[workspace]\nresolver = "2"\nmembers = ["ferret-core", "clean", "dev_only", "direct_server", "direct_test", "chain_server", "chain_test", "chain_two_steps"]\n' > "$t/Cargo.toml"

  # expect <crate> <server-suite yes|no> <test-support yes|no>
  expect() {
    local tree got_s=no got_t=no
    tree="$(resolved_tree --manifest-path "$t/Cargo.toml" -p "$1")"
    if feature_enabled "$tree" server-suite; then got_s=yes; fi
    if feature_enabled "$tree" test-support; then got_t=yes; fi
    if [ "$got_s" != "$2" ] || [ "$got_t" != "$3" ]; then
      echo "self-test FAIL: $1 shows server-suite=$got_s test-support=$got_t, expected $2 $3" >&2
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
  if [ "$status" -eq 0 ]; then
    echo "ok: the feature check sees direct and chained features and ignores dev-dependencies"
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
  tree="$(resolved_tree -p "$crate")"
  for feature in test-support server-suite; do
    if feature_enabled "$tree" "$feature"; then
      echo "FAIL: $crate enables ferret-core/$feature in its release graph" >&2
      fail=1
    fi
  done
  if printf '%s\n' "$tree" | grep -q '^ferret-vectorgen '; then
    echo "FAIL: $crate depends on ferret-vectorgen in its release graph" >&2
    fail=1
  fi
done

# 2. WASM export list. wasm-bindgen exports a method as `<class>_<method>`
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
  elif printf '%s\n' "$exports" | grep -Eq '(^|_)test_|replay'; then
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
