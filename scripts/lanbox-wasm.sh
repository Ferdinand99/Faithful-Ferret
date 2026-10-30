#!/usr/bin/env bash
# Build the WebAssembly packages on the LANBox (never locally, never Docker
# Desktop, never Tower) and stream them back.
#
#   scripts/lanbox-wasm.sh              pkg-web and pkg-node (the release build)
#   scripts/lanbox-wasm.sh --test       pkg-node-test (the Node tests' build:
#                                       with the `test-support` feature, never
#                                       to be released)
#   scripts/lanbox-wasm.sh --test-web   pkg-web-test (the same build for the
#                                       browser tests in tests/browser)
#
# See scripts/build-wasm.sh for what is built and how.
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  "")
    export FERRET_EXPORT="bindings/wasm/pkg-web bindings/wasm/pkg-node"
    exec scripts/lanbox.sh --exec scripts/build-wasm.sh
    ;;
  --test)
    export FERRET_EXPORT="bindings/wasm/pkg-node-test"
    exec scripts/lanbox.sh --exec scripts/build-wasm.sh --test
    ;;
  --test-web)
    export FERRET_EXPORT="bindings/wasm/pkg-web-test"
    exec scripts/lanbox.sh --exec scripts/build-wasm.sh --test-web
    ;;
  *)
    echo "usage: scripts/lanbox-wasm.sh [--test | --test-web]" >&2
    exit 2
    ;;
esac
