#!/usr/bin/env bash
# Run the browser smoke tests (tests/browser) in Chromium, Firefox and WebKit
# on the LANBox Docker host (never locally, never Docker Desktop, never Tower).
#
#   scripts/lanbox-browsers.sh                    all three browsers
#   scripts/lanbox-browsers.sh --project=firefox  one browser (any Playwright option)
#
# 1. Builds the web packages on the LANBox (scripts/lanbox-wasm.sh): `pkg-web`
#    (the release build) and `pkg-web-test` (the build with `test-support`).
#    FERRET_SKIP_BUILD=1 reuses the ones in bindings/wasm.
# 2. Streams the tests, the workers, the two packages and the vectors as a tar
#    archive into the pinned Playwright image (no bind mounts from the PC),
#    installs the locked Playwright package with `npm ci`, and runs the tests.
#    The slow test (Argon2id with 256 MiB) is always run here.
# 3. Unpacks tests/browser/results here and prints the pass counts per browser.
#
# Everything created is labelled owner=ferret-core and removed on exit (--rm);
# the work directory, npm's cache and /tmp are tmpfs.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_CPUS
# (default 4, at most 8), FERRET_MEMORY (default 12g), FERRET_SKIP_BUILD.
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

# Playwright 1.60.0 on Ubuntu 24.04. Keep the tag and the digest in step with
# tests/browser/package.json and .github/workflows/browsers.yml.
image="mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948"

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-12g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox-browsers.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})

if [ -z "${FERRET_SKIP_BUILD:-}" ]; then
  scripts/lanbox-wasm.sh
  scripts/lanbox-wasm.sh --test-web
fi
for dir in bindings/wasm/pkg-web bindings/wasm/pkg-web-test; do
  if [ ! -f "$dir/ferret_core_wasm.js" ]; then
    echo "lanbox-browsers.sh: $dir is missing; run without FERRET_SKIP_BUILD" >&2
    exit 2
  fi
done

# Inside the container: unpack, install, run (output on stderr, stdout is
# reserved for the results tar), summarize, then export the results.
inner='set -e
tar -x -C /work
cd /work/tests/browser
npm ci --no-audit --no-fund --ignore-scripts >&2
set +e
FERRET_EXPORT_256=1 npx playwright test "$@" >&2
rc=$?
node summary.mjs >&2
tar -c -C /work/tests/browser results
exit $rc'

run=(docker "${docker_args[@]}" run --rm -i --init
  --label owner=ferret-core
  --cpus "$cpus"
  --memory "$memory"
  --shm-size 2g
  -e CI=1
  --tmpfs /work:exec,size=2g
  --tmpfs /root/.npm:size=512m
  --tmpfs /tmp:exec,size=2g
  -w /work
  "$image"
  sh -c "$inner" sh "$@")

pack() {
  tar -c \
    --exclude='tests/browser/node_modules' \
    --exclude='tests/browser/results' \
    tests/browser bindings/wasm/js bindings/wasm/pkg-web bindings/wasm/pkg-web-test vectors
}

mkdir -p tests/browser/results
rm -f tests/browser/results/*.json
set +e
pack | "${run[@]}" | tar -x -C tests/browser -f -
rc=${PIPESTATUS[1]}
set -e
exit "$rc"
