#!/usr/bin/env bash
# Check the browser extension (extension/) on the LANBox Docker host (never
# locally, never Docker Desktop, never Tower), in the pinned Playwright image
# (it carries Node and npm).
#
#   scripts/lanbox-ext.sh unit    build both manifest versions in both variants,
#                                 type check, and run extension/test/unit/*.test.mjs
#   scripts/lanbox-ext.sh lint    build both manifest versions as releases, run
#                                 `web-ext lint` on each and check the packages
#                                 with scripts/check-ext-release.sh
#
# The extension/ tree, the WASM pin (web/wasm.lock.json), the design document
# the CSP test reads and the release check are streamed into the container as a
# tar archive (no bind mounts from the PC). The locked packages are installed
# with `npm ci --ignore-scripts`, and the build fetches the published WASM
# package named in web/wasm.lock.json and checks its SHA-256. Everything created
# is labelled owner=ferret-core and removed on exit (--rm); the work directory,
# npm's cache and /tmp are tmpfs.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_CPUS
# (default 4, at most 8), FERRET_MEMORY (default 8g), DEV_RUN (run id: lowercase
# letters, digits and dashes, at most 63 characters; adds the label dev.run and
# the name ferret-$DEV_RUN-<pid>) and DEV_TITLE (adds the label dev.title).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

# Playwright 1.64.1 on Ubuntu 24.04, the image of scripts/lanbox-web.sh. Keep the
# tag and the digest in step with it and with .github/workflows/extension.yml.
image="mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f"

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-8g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox-ext.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})

dev_args=()
if [ -n "${DEV_RUN:-}" ]; then
  # bash's own matcher, so an embedded newline cannot slip past the anchors
  dev_run_re='^[a-z0-9][a-z0-9-]{0,62}$'
  if ! (LC_ALL=C; [[ $DEV_RUN =~ $dev_run_re ]]); then
    echo "lanbox-ext.sh: DEV_RUN must match $dev_run_re" >&2
    exit 2
  fi
  dev_args+=(--label "dev.run=$DEV_RUN" --name "ferret-$DEV_RUN-$$")
  if [ -n "${DEV_TITLE:-}" ]; then
    dev_args+=(--label "dev.title=$DEV_TITLE")
  fi
fi

mode="${1:-}"
case "$mode" in
  unit | lint) ;;
  *)
    echo "usage: scripts/lanbox-ext.sh unit | lint" >&2
    exit 2
    ;;
esac

# Inside the container: unpack, install, run (output on stderr).
inner='set -e
tar -x -C /work
cd /work/extension
npm ci --no-audit --no-fund --ignore-scripts >&2
if [ "$FERRET_EXT_MODE" = unit ]; then
  for mv in mv3 mv2; do
    for variant in release test; do
      node scripts/build.mjs --browser firefox --manifest "$mv" --variant "$variant" >&2
    done
  done
  npx tsc -p jsconfig.json --noEmit >&2
  node --test "test/unit/*.test.mjs" >&2
else
  for mv in mv3 mv2; do
    node scripts/build.mjs --browser firefox --manifest "$mv" --variant release >&2
    npx web-ext lint --source-dir "dist/ferret-firefox-$mv-release" --warnings-as-errors >&2
  done
  cd /work
  bash scripts/check-ext-release.sh >&2
fi'

run=(docker "${docker_args[@]}" run --rm -i --init
  --label owner=ferret-core
  "${dev_args[@]}"
  --cpus "$cpus"
  --memory "$memory"
  -e CI=1
  -e FERRET_EXT_MODE="$mode"
  --tmpfs /work:exec,size=2g
  --tmpfs /root/.npm:size=512m
  --tmpfs /tmp:exec,size=1g
  -w /work
  "$image"
  sh -c "$inner")

pack() {
  tar -c \
    --exclude='extension/node_modules' \
    --exclude='extension/dist' \
    extension web/wasm.lock.json scripts/check-ext-release.sh docs/design/phase-1-security-design.md
}

pack | "${run[@]}"
