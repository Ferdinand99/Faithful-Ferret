#!/usr/bin/env bash
# Check the web vault (web/) on the LANBox Docker host (never locally, never
# Docker Desktop, never Tower), in the pinned Playwright image.
#
#   scripts/lanbox-web.sh                     build, type check, unit tests, Playwright (3 browsers)
#   scripts/lanbox-web.sh unit                build, type check and unit tests only
#   scripts/lanbox-web.sh e2e [--project=x]   build, then Playwright (any Playwright option)
#   scripts/lanbox-web.sh --lock              refresh web/package-lock.json (npm install --package-lock-only)
#
# The web/ tree and, when it exists, the server's wire fixtures are streamed
# into the container as a tar archive (no bind mounts from the PC), the locked
# packages are installed with `npm ci --ignore-scripts`, and the build fetches
# the published WASM package named in web/wasm.lock.json and checks its SHA-256.
# The container prints progress markers (`::progress:: ...` lines, see
# scripts/progress.sh) for tools that follow the output of a run. The phases are
# install, build, typecheck, unit and e2e (all: 5, unit: 4, e2e: 3, --lock: 1);
# unit counts test files, Playwright prints its own totals.
# Everything created is labelled owner=ferret-core and removed on exit (--rm);
# the work directory, npm's cache and /tmp are tmpfs.
#
# Env overrides:
#   FERRET_DOCKER_ARGS  replaces the default "--context unraid"
#   FERRET_CPUS         CPU limit (default 4, at most 8)
#   FERRET_MEMORY       container memory limit (default 12g)
#   FERRET_PASS_ENV     space-separated names of environment variables that are
#                       passed on into the container
#   DEV_RUN             optional run id (lowercase letters, digits and dashes, at
#                       most 63 characters, starting with a letter or digit). When
#                       set, the container gets the label dev.run=$DEV_RUN and the
#                       name ferret-$DEV_RUN-<pid>, so the run shows up in devdash
#   DEV_TITLE           optional title, added as the label dev.title when DEV_RUN
#                       is set
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

# Playwright 1.65.1 on Ubuntu 24.04. Keep the tag and the digest in step with
# web/package.json and .github/workflows/web.yml.
image="mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579"

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-12g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox-web.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})
pass_env=()
for name in ${FERRET_PASS_ENV:-}; do
  if ! printf '%s' "$name" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    echo "lanbox-web.sh: FERRET_PASS_ENV holds variable names only" >&2
    exit 2
  fi
  pass_env+=(-e "$name")
done

dev_args=()
if [ -n "${DEV_RUN:-}" ]; then
  # bash's own matcher, so an embedded newline cannot slip past the anchors
  dev_run_re='^[a-z0-9][a-z0-9-]{0,62}$'
  if ! (LC_ALL=C; [[ $DEV_RUN =~ $dev_run_re ]]); then
    echo "lanbox-web.sh: DEV_RUN must match $dev_run_re" >&2
    exit 2
  fi
  dev_args+=(--label "dev.run=$DEV_RUN" --name "ferret-$DEV_RUN-$$")
  if [ -n "${DEV_TITLE:-}" ]; then
    dev_args+=(--label "dev.title=$DEV_TITLE")
  fi
fi

# The test server needs the server's header fixture; without it, stop.
if [ ! -f crates/ferret-server/tests/fixtures/wire/headers.json ]; then
  echo "lanbox-web.sh: crates/ferret-server/tests/fixtures/wire/headers.json is missing" >&2
  exit 2
fi

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
. /work/scripts/progress.sh
if [ "$FERRET_WEB_MODE" = lock ]; then
  progress_begin 1
  progress_run lock npm install --package-lock-only --ignore-scripts --no-audit --no-fund >&2
  tar -c package-lock.json
  exit 0
fi
case "$FERRET_WEB_MODE" in
  unit) progress_begin 4 ;;
  e2e) progress_begin 3 ;;
  *) progress_begin 5 ;;
esac
progress_run install npm ci --no-audit --no-fund --ignore-scripts >&2
progress_run build node scripts/build.mjs >&2
if [ "$FERRET_WEB_MODE" != e2e ]; then
  progress_run typecheck npx tsc -p jsconfig.json --noEmit >&2
  progress_node_test unit "test/unit/*.test.mjs"
fi
if [ "$FERRET_WEB_MODE" != unit ]; then
  progress_run e2e npx playwright test "$@" >&2
fi'

run=(docker "${docker_args[@]}" run --rm -i --init
  --label owner=ferret-core
  "${dev_args[@]}"
  --cpus "$cpus"
  --memory "$memory"
  --shm-size 2g
  -e CI=1
  -e FERRET_WEB_MODE="$mode"
  -e FERRET_PROGRESS_PHASE_BASE
  -e FERRET_PROGRESS_PHASES
  "${pass_env[@]}"
  --tmpfs /work:exec,size=2g
  --tmpfs /root/.npm:size=512m
  --tmpfs /tmp:exec,size=2g
  -w /work
  "$image"
  bash -c "$inner" bash "$@")

pack() {
  local fixtures=crates/ferret-server/tests/fixtures/wire
  local extra=()
  [ -d "$fixtures" ] && extra+=("$fixtures")
  tar -c \
    --exclude='web/node_modules' \
    --exclude='web/dist' \
    --exclude='web/test-results' \
    --exclude='web/src/*.gen.mjs' \
    scripts/progress.sh scripts/progress-node-reporter.mjs \
    web "${extra[@]}"
}

if [ "$mode" = lock ]; then
  pack | "${run[@]}" | tar -x -C web -f -
else
  pack | "${run[@]}"
fi
