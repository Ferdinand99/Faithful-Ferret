#!/usr/bin/env bash
# Build the WebAssembly packages on the build host (never locally, never Docker
# Desktop, never a production host) and stream them back.
#
#   scripts/lanbox-wasm.sh              pkg-web and pkg-node (the release build)
#   scripts/lanbox-wasm.sh --test       pkg-node-test (the Node tests' build:
#                                       with the `test-support` feature, never
#                                       to be released)
#   scripts/lanbox-wasm.sh --test-web   pkg-web-test (the same build for the
#                                       browser tests in tests/browser)
#   scripts/lanbox-wasm.sh --tree       the release build of this tree, packaged as a release
#                                       is (scripts/wasm-tree.sh), into wasm-package/ (git
#                                       ignores it): the web and Node archives and
#                                       wasm-tree.json with the commit. The web vault's and
#                                       the extension's test builds take it with `--wasm tree`
#                                       (scripts/lanbox-web.sh and scripts/lanbox-ext.sh do)
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
  --tree)
    # The container gets the tree without .git: this side says which commit it is.
    commit="$(git rev-parse HEAD)"
    if [ -n "$(git status --porcelain)" ]; then commit="$commit-dirty"; fi
    # A package already built from this very commit is reused; a tree with changes is built again every time.
    case "$commit" in
      *-dirty) ;;
      *)
        if [ -f wasm-package/wasm-tree.json ] && grep -q "\"commit\":\"$commit\"" wasm-package/wasm-tree.json \
          && [ -n "$(find wasm-package -maxdepth 1 -name 'ferret-core-wasm-web-*.tar.gz' -print -quit)" ]; then
          echo "lanbox-wasm: wasm-package/ is already built from $commit" >&2
          exit 0
        fi
        ;;
    esac
    export FERRET_TREE_COMMIT="$commit"
    export FERRET_PASS_ENV="${FERRET_PASS_ENV:+$FERRET_PASS_ENV }FERRET_TREE_COMMIT"
    export FERRET_EXPORT="wasm-package"
    rm -rf wasm-package
    exec scripts/lanbox.sh --exec scripts/wasm-tree.sh wasm-package
    ;;
  *)
    echo "usage: scripts/lanbox-wasm.sh [--test | --test-web | --tree]" >&2
    exit 2
    ;;
esac
