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
# The containers print progress markers (`::progress:: ...` lines, see
# scripts/progress.sh) for tools that follow the output of a run. The whole run has
# 6 phases: the release web package (web, node, optimize), the test package, install
# and the Playwright run (with FERRET_SKIP_BUILD: 2, install and browsers).
# Everything created is labelled owner=ferret-core and removed on exit (--rm);
# the work directory, npm's cache and /tmp are tmpfs.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_CPUS
# (default 4, at most 8), FERRET_MEMORY (default 12g), FERRET_SKIP_BUILD, and
# DEV_RUN / DEV_TITLE as in scripts/lanbox.sh (labels and a name for the containers
# of the run).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

# Playwright 1.65.1 on Ubuntu 24.04. Keep the tag and the digest in step with
# tests/browser/package.json and .github/workflows/browsers.yml.
image="mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579"

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-12g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox-browsers.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})

dev_args=()
if [ -n "${DEV_RUN:-}" ]; then
  # bash's own matcher, so an embedded newline cannot slip past the anchors
  dev_run_re='^[a-z0-9][a-z0-9-]{0,62}$'
  if ! (LC_ALL=C; [[ $DEV_RUN =~ $dev_run_re ]]); then
    echo "lanbox-browsers.sh: DEV_RUN must match $dev_run_re" >&2
    exit 2
  fi
  dev_args+=(--label "dev.run=$DEV_RUN" --name "ferret-$DEV_RUN-$$")
  if [ -n "${DEV_TITLE:-}" ]; then
    dev_args+=(--label "dev.title=$DEV_TITLE")
  fi
fi

# The numbers of the progress phases, over all containers of the run.
phases=2
phase_base=0
if [ -z "${FERRET_SKIP_BUILD:-}" ]; then
  phases=6
  FERRET_PROGRESS_PHASE_BASE=0 FERRET_PROGRESS_PHASES=$phases scripts/lanbox-wasm.sh
  FERRET_PROGRESS_PHASE_BASE=3 FERRET_PROGRESS_PHASES=$phases scripts/lanbox-wasm.sh --test-web
  phase_base=4
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
. /work/scripts/progress.sh
progress_begin 2
progress_run install npm ci --no-audit --no-fund --ignore-scripts >&2
set +e
export FERRET_EXPORT_256=1
progress_run browsers npx playwright test "$@" >&2
rc=$?
node summary.mjs >&2
tar -c -C /work/tests/browser results
exit $rc'

run=(docker "${docker_args[@]}" run --rm -i --init
  --label owner=ferret-core
  "${dev_args[@]}"
  -e FERRET_PROGRESS_PHASE_BASE="$phase_base"
  -e FERRET_PROGRESS_PHASES="$phases"
  --cpus "$cpus"
  --memory "$memory"
  --shm-size 2g
  -e CI=1
  --tmpfs /work:exec,size=2g
  --tmpfs /root/.npm:size=512m
  --tmpfs /tmp:exec,size=2g
  -w /work
  "$image"
  bash -c "$inner" bash "$@")

pack() {
  tar -c \
    --exclude='tests/browser/node_modules' \
    --exclude='tests/browser/results' \
    scripts/progress.sh tests/browser bindings/wasm/js bindings/wasm/pkg-web bindings/wasm/pkg-web-test vectors
}

mkdir -p tests/browser/results
rm -f tests/browser/results/*.json
set +e
pack | "${run[@]}" | tar -x -C tests/browser -f -
rc=${PIPESTATUS[1]}
set -e
exit "$rc"
