#!/usr/bin/env bash
# Run every test vector twice on the LANBox: through the Rust core (native)
# and through the WASM build in Node (the build with the `test-support`
# feature, which exports the vector operations). Also checks that the
# vectors are up to date (`vectorgen check`).
#
#   scripts/lanbox-vectors.sh
#
# Both runs happen in one container. Nothing is left behind.
set -euo pipefail
cd "$(dirname "$0")/.."

exec scripts/lanbox.sh --exec sh -c '
  set -e
  cargo run -p ferret-vectorgen --bin vectorgen -- check
  cargo test -p ferret-core -- vectors
  scripts/build-wasm.sh --test
  node tests/node/run-vectors.mjs
'
