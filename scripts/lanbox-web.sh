#!/usr/bin/env bash
# Check the web vault (web/) on the LANBox Docker host (never locally, never
# Docker Desktop, never Tower), in the pinned Playwright image.
#
#   scripts/lanbox-web.sh                     build, type check, unit tests, Playwright (3 browsers)
#   scripts/lanbox-web.sh unit                build, type check and unit tests only
#   scripts/lanbox-web.sh e2e [--project=x]   build, then Playwright (any Playwright option)
#   scripts/lanbox-web.sh --lock              refresh web/package-lock.json (npm install --package-lock-only)
#
# The web/ tree and, when it exists, the server's header fixture are streamed
# into the container as a tar archive (no bind mounts from the PC), the locked
# packages are installed with `npm ci --ignore-scripts`, and the build fetches
# the published WASM package named in web/wasm.lock.json and checks its SHA-256.
# Everything created is labelled owner=ferret-core and removed on exit (--rm);
# the work directory, npm's cache and /tmp are tmpfs.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_CPUS
# (default 4, at most 8), FERRET_MEMORY (default 12g).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

# Playwright 1.60.0 on Ubuntu 24.04. Keep the tag and the digest in step with
# web/package.json and .github/workflows/web.yml.
image="mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948"

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-12g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox-web.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})

mode=all
case "${1:-}" in
  --lock) mode=lock; shift ;;
  unit) mode=unit; shift ;;
  e2e) mode=e2e; shift ;;
esac

# Inside the container: unpack, install, run (output on stderr, stdout is
# reserved for the exported lock file).
inner='set -e
tar -x -C /work
cd /work/web
if [ "$FERRET_WEB_MODE" = lock ]; then
  npm install --package-lock-only --ignore-scripts --no-audit --no-fund >&2
  tar -c package-lock.json
  exit 0
fi
npm ci --no-audit --no-fund --ignore-scripts >&2
node scripts/build.mjs >&2
if [ "$FERRET_WEB_MODE" != e2e ]; then
  npx tsc -p jsconfig.json --noEmit >&2
  node --test "test/unit/*.test.mjs" >&2
fi
if [ "$FERRET_WEB_MODE" != unit ]; then
  npx playwright test "$@" >&2
fi'

run=(docker "${docker_args[@]}" run --rm -i --init
  --label owner=ferret-core
  --cpus "$cpus"
  --memory "$memory"
  --shm-size 2g
  -e CI=1
  -e FERRET_WEB_MODE="$mode"
  --tmpfs /work:exec,size=2g
  --tmpfs /root/.npm:size=512m
  --tmpfs /tmp:exec,size=2g
  -w /work
  "$image"
  sh -c "$inner" sh "$@")

pack() {
  local fixture=crates/ferret-server/tests/fixtures/wire/headers.json
  local extra=()
  [ -f "$fixture" ] && extra+=("$fixture")
  tar -c \
    --exclude='web/node_modules' \
    --exclude='web/dist' \
    --exclude='web/test-results' \
    --exclude='web/src/*.gen.mjs' \
    web "${extra[@]}"
}

if [ "$mode" = lock ]; then
  pack | "${run[@]}" | tar -x -C web -f -
else
  pack | "${run[@]}"
fi
