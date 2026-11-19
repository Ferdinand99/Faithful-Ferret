#!/usr/bin/env bash
# Run every test vector twice on the LANBox: through the Rust core (native)
# and through the WASM build in Node (the build with the `test-support`
# feature, which exports the vector operations). Also checks that the
# vectors are up to date (`vectorgen check`).
#
#   scripts/lanbox-vectors.sh
#
# Both runs happen in one container. Nothing is left behind. Progress markers
# (see scripts/progress.sh), 5 phases: vectors-check, build and test of the native
# vector tests, the WASM test build, the Node vector run.
set -euo pipefail
cd "$(dirname "$0")/.."

exec scripts/lanbox.sh --exec bash -c '
  set -e
  . scripts/progress.sh
  export FERRET_PROGRESS_PHASES=5
  progress_begin 5
  progress_run vectors-check cargo run -p ferret-vectorgen --bin vectorgen -- check
  progress_cargo_test test -p ferret-core -- vectors
  FERRET_PROGRESS_PHASE_BASE=3 scripts/build-wasm.sh --test
  progress_advance 1
  progress_run node-vectors node tests/node/run-vectors.mjs
'
