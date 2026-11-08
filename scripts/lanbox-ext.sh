#!/usr/bin/env bash
# Check the browser extension (extension/) on the LANBox Docker host (never
# locally, never Docker Desktop, never Tower).
#
#   scripts/lanbox-ext.sh unit    build both manifest versions in both variants,
#                                 type check, and run extension/test/unit/*.test.mjs
#   scripts/lanbox-ext.sh lint    build both manifest versions as releases, run
#                                 `web-ext lint` on each and check the packages
#                                 with scripts/check-ext-release.sh
#   scripts/lanbox-ext.sh firefox [--channel release|esr] [--manifest mv3|mv2] [--grep <name>] [--headed]
#                                 short probes of the test build in a real Firefox
#                                 (unbranded Release and ESR; both unless --channel
#                                 names one) through geckodriver, in the runner image
#                                 docker/ext-runner.Dockerfile. The step has no
#                                 network at all (--network none).
#   scripts/lanbox-ext.sh e2e [--channel ...] [--manifest ...] [--grep <name>] [--headed] [--no-up]
#                                 the same runner against the end-to-end stack: runs
#                                 `lanbox-ferret-test.sh e2e-up` (not with --no-up, for
#                                 a stack that is already up), takes the stack's CA
#                                 from `e2e-ca` and joins the stack's network, the
#                                 only network that step has (that network is not
#                                 internal, so the step can reach whatever it
#                                 reaches). Afterwards run
#                                 `scripts/lanbox-ferret-test.sh e2e-down`.
#   scripts/lanbox-ext.sh measure [--channel release|esr] [--manifest mv3|mv2] [--scenario <list>] [--window-minutes N]
#                                 the lifetime measurement of the background page: every
#                                 scenario in both manifest versions, a window of 17
#                                 minutes for each cell (about 3 hours per channel). Without
#                                 --channel the two channels run side by side in two
#                                 containers (two Firefox at a time, never more). The
#                                 reports (lifetime-<channel>.json) are unpacked into
#                                 test-results/out/ext-measure/. It ends when the last
#                                 cell is done.
#
# unit and lint: the extension/ tree, the WASM pin (web/wasm.lock.json), the
# design document the CSP test reads and the release check are streamed into the
# container as a tar archive (no bind mounts from the PC). The locked packages are
# installed with `npm ci --ignore-scripts`, and the build fetches the published
# WASM package named in web/wasm.lock.json and checks its SHA-256.
#
# firefox and e2e: the runner image is built once, on first use (the tag follows
# the content of the Dockerfile; the Dockerfile goes in on stdin, so no build
# context is sent). The WASM package is fetched and checked in a step of its own,
# the only step with a network; the Firefox step gets it as --wasm-tar and needs
# no npm package (the harness has no dependencies).
#
# Everything created is labelled owner=ferret-core and removed on exit (--rm); the
# work directory, npm's cache and /tmp are tmpfs.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_EXT_OUT_DIR
# (where measure unpacks its reports, default test-results/out), FERRET_CPUS
# (default 4, at most 8), FERRET_MEMORY (default 8g), DEV_RUN (run id: lowercase
# letters, digits and dashes, at most 63 characters; adds the label dev.run and
# the name ferret-$DEV_RUN-<pid>), DEV_TITLE (adds the label dev.title) and
# FERRET_EXT_STACK_SCRIPT (the script that starts the end-to-end stack, default
# scripts/lanbox-ferret-test.sh).
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

if [ -n "${DEV_RUN:-}" ]; then
  # bash's own matcher, so an embedded newline cannot slip past the anchors
  dev_run_re='^[a-z0-9][a-z0-9-]{0,62}$'
  if ! (LC_ALL=C; [[ $DEV_RUN =~ $dev_run_re ]]); then
    echo "lanbox-ext.sh: DEV_RUN must match $dev_run_re" >&2
    exit 2
  fi
fi

# The labels and the name of a container this script starts: `dev_args [suffix]`
# fills dev_args_out. The name is ferret-$DEV_RUN[-suffix]-<pid>, so a second step
# of one run has a name of its own.
dev_args() {
  dev_args_out=()
  if [ -n "${DEV_RUN:-}" ]; then
    dev_args_out+=(--label "dev.run=$DEV_RUN" --name "ferret-$DEV_RUN${1:+-$1}-$$")
    if [ -n "${DEV_TITLE:-}" ]; then
      dev_args_out+=(--label "dev.title=$DEV_TITLE")
    fi
  fi
}

usage() {
  echo "usage: scripts/lanbox-ext.sh unit | lint | firefox [options] | e2e [options] | measure [options]" >&2
  echo "  options of firefox and e2e: --channel release|esr  --manifest mv3|mv2  --grep <name>  --headed  (e2e only: --no-up)" >&2
  echo "  options of measure: --channel release|esr  --manifest mv3|mv2  --scenario idle,sse,popup,argon,terminate  --window-minutes N" >&2
  exit 2
}

mode="${1:-}"
case "$mode" in
  unit | lint | firefox | e2e | measure) shift ;;
  *) usage ;;
esac

channel=""
manifest=mv3
manifest_given=0
grep_name=""
headed=0
no_up=0
scenario_list=""
window_minutes=""
while [ "$#" -gt 0 ]; do
  case "$mode:$1" in
    firefox:--channel | e2e:--channel | measure:--channel) [ "$#" -ge 2 ] || usage; channel="$2"; shift 2 ;;
    firefox:--manifest | e2e:--manifest | measure:--manifest) [ "$#" -ge 2 ] || usage; manifest="$2"; manifest_given=1; shift 2 ;;
    firefox:--grep | e2e:--grep) [ "$#" -ge 2 ] || usage; grep_name="$2"; shift 2 ;;
    firefox:--headed | e2e:--headed) headed=1; shift ;;
    e2e:--no-up) no_up=1; shift ;;
    measure:--scenario) [ "$#" -ge 2 ] || usage; scenario_list="$2"; shift 2 ;;
    measure:--window-minutes) [ "$#" -ge 2 ] || usage; window_minutes="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$channel" in "" | release | esr) ;; *) usage ;; esac
case "$manifest" in mv3 | mv2) ;; *) usage ;; esac
# A measure run covers both manifest versions unless --manifest names one.
measure_manifests="mv3,mv2"
if [ "$mode" = measure ] && [ "$manifest_given" = 1 ]; then measure_manifests="$manifest"; fi
# bash's own matcher, so an embedded newline cannot slip past the anchors
scenario_re='^(idle|sse|popup|argon|terminate)(,(idle|sse|popup|argon|terminate))*$'
if [ -n "$scenario_list" ] && ! (LC_ALL=C; [[ $scenario_list =~ $scenario_re ]]); then usage; fi
window_re='^[0-9]{1,4}$'
if [ -n "$window_minutes" ] && ! (LC_ALL=C; [[ $window_minutes =~ $window_re ]]); then usage; fi
if [ -n "$window_minutes" ] && [ "$window_minutes" -lt 2 ]; then usage; fi

# ------------------------------------------------------------ unit and lint

if [ "$mode" = unit ] || [ "$mode" = lint ]; then
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
  npm exec --no -- tsc -p jsconfig.json --noEmit >&2
  node --test "test/unit/*.test.mjs" >&2
else
  for mv in mv3 mv2; do
    node scripts/build.mjs --browser firefox --manifest "$mv" --variant release >&2
    npm exec --no -- web-ext lint --source-dir "dist/ferret-firefox-$mv-release" --warnings-as-errors >&2
  done
  cd /work
  bash scripts/check-ext-release.sh >&2
fi'

  dev_args ""
  run=(docker "${docker_args[@]}" run --rm -i --init
    --label owner=ferret-core
    "${dev_args_out[@]}"
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
      extension web/wasm.lock.json scripts/check-ext-release.sh scripts/lanbox-ext.sh \
      scripts/check-lanbox-ext-labels.sh docker/ext-runner.Dockerfile \
      .github/workflows/extension-firefox.yml .github/workflows/extension-sign-measure.yml \
      .github/workflows/extension.yml .github/workflows/release.yml .github/workflows/ci.yml \
      docs/design/phase-1-security-design.md
  }

  pack | "${run[@]}"
  exit 0
fi

# --------------------------------------------------------- firefox and e2e

# The runner image (docker/ext-runner.Dockerfile), built once on first use. The tag
# follows the content of the file. The Dockerfile goes in on stdin, so no build
# context (and nothing from docker/, where other stacks keep their settings) is sent.
runner_hash="$(tr -d '\r' < docker/ext-runner.Dockerfile | sha256sum | cut -c1-12)"
runner_image="ferret-ext-runner:$runner_hash"
if ! docker "${docker_args[@]}" image inspect "$runner_image" > /dev/null 2>&1; then
  tr -d '\r' < docker/ext-runner.Dockerfile \
    | docker "${docker_args[@]}" build --label owner=ferret-core -t "$runner_image" - >&2
  # The images of earlier versions of the Dockerfile (ours, by label) are removed one by
  # one, never pruned. An image that a running container still uses stays.
  for old in $(docker "${docker_args[@]}" image ls --filter label=owner=ferret-core --format '{{.Repository}}:{{.Tag}}' | grep '^ferret-ext-runner:' | grep -v ":$runner_hash\$" || true); do
    docker "${docker_args[@]}" image rm "$old" > /dev/null 2>&1 || true
  done
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Step 1, the only one with a network: fetch the published WASM package named in
# web/wasm.lock.json and check its SHA-256. The archive comes back on stdout. The
# container needs the network and nothing else: no capability, not root, a
# read-only root file system, and a limit on the download.
# The script is in single quotes on purpose.
# shellcheck disable=SC2016
fetch='const lock = JSON.parse(require("fs").readFileSync(0, "utf8"));
fetch(lock.url, { signal: AbortSignal.timeout(120000) }).then((r) => {
  if (!r.ok) throw new Error(lock.url + " answered " + r.status);
  return r.arrayBuffer();
}).then((b) => {
  const buf = Buffer.from(b);
  const sum = require("crypto").createHash("sha256").update(buf).digest("hex");
  if (sum !== lock.sha256) throw new Error("wasm package: checksum mismatch (expected " + lock.sha256 + ", got " + sum + ")");
  process.stdout.write(buf);
}).catch((e) => { console.error("lanbox-ext.sh: " + e.message); process.exit(1); });'
dev_args fetch
docker "${docker_args[@]}" run --rm -i --init \
  --label owner=ferret-core \
  "${dev_args_out[@]}" \
  --cpus 1 --memory 1g \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --read-only \
  -e FERRET_EXT_STEP=fetch \
  --tmpfs /tmp:size=64m \
  "$runner_image" node -e "$fetch" < web/wasm.lock.json > "$work/wasm.tar.gz"
[ -s "$work/wasm.tar.gz" ] || { echo "lanbox-ext.sh: the WASM package came back empty" >&2; exit 1; }

# Step 2: the tests. No network, or only the end-to-end stack's.
network=none
e2e_ca=""
if [ "$mode" = e2e ]; then
  stack="${FERRET_EXT_STACK_SCRIPT:-scripts/lanbox-ferret-test.sh}"
  if [ "$no_up" -eq 0 ]; then
    bash "$stack" e2e-up >&2
  fi
  e2e_ca="$(bash "$stack" e2e-ca)"
  network=ferret-e2e-net
fi

tar -cf "$work/in.tar" \
  --exclude='extension/node_modules' \
  --exclude='extension/dist' \
  extension web/wasm.lock.json
tar -rf "$work/in.tar" -C "$work" wasm.tar.gz

# The tests container for the channels in $1 (a comma list). $2 goes into the name
# and the label (see dev_args). Fills the array `run`.
make_run() {
  dev_args "${2:-}"
  run=(docker "${docker_args[@]}" run --rm -i --init
    --label owner=ferret-core
    "${dev_args_out[@]}"
    --network "$network"
    --cpus "$cpus"
    --memory "$memory"
    --shm-size 2g
    --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID
    --security-opt no-new-privileges:true
    -e CI=1
    -e FERRET_EXT_STEP="$mode"
    -e FERRET_CHANNELS="$1"
    -e FERRET_MANIFEST="$manifest"
    -e FERRET_GREP="$grep_name"
    -e FERRET_HEADLESS="$((1 - headed))"
    -e FERRET_E2E_CA_PEM="$e2e_ca"
    -e FERRET_MEASURE_MANIFESTS="$measure_manifests"
    -e FERRET_MEASURE_SCENARIOS="$scenario_list"
    -e FERRET_MEASURE_MINUTES="$window_minutes"
    -e FERRET_MEASURE_POLL_MS="${FERRET_MEASURE_POLL_MS:-}"
    --tmpfs /work:exec,size=2g
    --tmpfs /tmp:exec,size=2g
    --tmpfs /home/ferret:uid=10001,gid=10001,size=1g
    -w /work
    "$runner_image"
    sh -c 'tar -x --no-same-owner -C /work && exec sh /work/extension/test/firefox/run.sh "$0"' "$mode")
}

if [ "$mode" != measure ]; then
  make_run "${channel:-release,esr}" ""
  "${run[@]}" < "$work/in.tar"
  exit 0
fi

# measure: one container per channel, side by side (two Firefox at a time, never
# more). What a container writes comes out as a tar archive on its stdout, which is
# unpacked here, so a report is on this machine even when a run fails.
out_dir="${FERRET_EXT_OUT_DIR:-test-results/out}"
mkdir -p "$out_dir"
read -r -a measure_channels <<< "${channel:-release esr}"
pids=()
for ch in "${measure_channels[@]}"; do
  make_run "$ch" "measure-$ch"
  (
    rc=0
    "${run[@]}" < "$work/in.tar" > "$work/report-$ch.tar" || rc=$?
    # A container that died before it wrote anything leaves an empty file: nothing to unpack.
    if [ -s "$work/report-$ch.tar" ]; then
      tar -x --no-same-owner -C "$out_dir" -f "$work/report-$ch.tar" || rc=$?
    fi
    exit "$rc"
  ) &
  pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=$?
done
echo "lanbox-ext.sh: reports are in $out_dir/ext-measure/ (exit status $status)" >&2
exit "$status"
