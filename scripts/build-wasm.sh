#!/usr/bin/env bash
# Builds the WebAssembly packages. Run it inside the builder image
# (scripts/lanbox-wasm.sh does that) or in CI, where wasm-pack, wasm-opt and
# the wasm32 target are installed. Never on a developer PC.
#
#   scripts/build-wasm.sh          pkg-web and pkg-node (the release build)
#   scripts/build-wasm.sh --test   pkg-node-test (the build with `test-support`
#                                  that the Node tests use; never released)
#   scripts/build-wasm.sh --test-web  pkg-web-test (the same build for the
#                                  browser: the Playwright tests in
#                                  tests/browser use it; never released)
#
# The release packages are optimized with wasm-opt -Oz and the features that
# rustc 1.99 switches on for wasm32 (bulk memory, sign extension, saturating
# float conversion, multivalue, reference types, mutable globals). The raw
# size of the .wasm file is printed; the budget is 2 MiB.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "--test" ]; then
  wasm-pack build bindings/wasm --release --no-opt --target nodejs --out-dir pkg-node-test -- --features test-support
  echo "wasm size (test-support build, never released): $(wc -c < bindings/wasm/pkg-node-test/ferret_core_wasm_bg.wasm) bytes" >&2
  exit 0
fi

if [ "${1:-}" = "--test-web" ]; then
  wasm-pack build bindings/wasm --release --no-opt --target web --out-dir pkg-web-test -- --features test-support
  echo "wasm size (web, test-support build, never released): $(wc -c < bindings/wasm/pkg-web-test/ferret_core_wasm_bg.wasm) bytes" >&2
  exit 0
fi

wasm-pack build bindings/wasm --release --no-opt --target web --out-dir pkg-web
wasm-pack build bindings/wasm --release --no-opt --target nodejs --out-dir pkg-node
for f in bindings/wasm/pkg-web/ferret_core_wasm_bg.wasm bindings/wasm/pkg-node/ferret_core_wasm_bg.wasm; do
  raw=$(wc -c < "$f")
  wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int \
    --enable-reference-types --enable-multivalue --enable-mutable-globals "$f" -o "$f"
  echo "wasm size: $f $raw bytes before wasm-opt, $(wc -c < "$f") bytes after" >&2
done
