#!/usr/bin/env bash
# Check the browser extension (extension/) on the Docker build host (never
# locally, never Docker Desktop).
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
#                                 the same runner against the end-to-end stack: starts a
#                                 stack of its own with `lanbox-ferret-test.sh e2e-up`
#                                 (a compose project, network, host names and volumes
#                                 named for this run, FERRET_E2E_SUFFIX=x<8 hex>, on a
#                                 free FERRET_E2E_SUBNET), so two runs never touch each
#                                 other's stack, and removes it again (`e2e-down`) when
#                                 the run ends. It takes the stack's CA from `e2e-ca`,
#                                 starts the stack's Chromium browser server
#                                 (`e2e-chromium`) and joins the stack's network, the
#                                 only network that step has. With FERRET_E2E_SUFFIX
#                                 set, it uses that stack (started with `e2e-up` unless
#                                 --no-up) and leaves it up: run
#                                 `scripts/lanbox-ferret-test.sh e2e-down` afterwards.
#                                 --no-up without FERRET_E2E_SUFFIX uses the stack with
#                                 the default names (one user at a time). At most two
#                                 e2e runs at once, counted inside the limit of two
#                                 Firefox runs. A per-run stack that a killed run left
#                                 (older than six hours) is removed by the next run.
#   scripts/lanbox-ext.sh gate [--channel release|esr] [--manifest mv3|mv2]
#                                 the extension's gate run: the firefox step, then
#                                 the e2e step (default manifest mv2, the Firefox
#                                 build), with the screenshots the e2e specs take
#                                 unpacked into test-results/out/gate-shots/ (or
#                                 $FERRET_EXT_OUT_DIR/gate-shots/), then the detection
#                                 matrix of the corpus, of the hold-out set and of the
#                                 autofill-parity set (the matrix step, one channel at
#                                 a time, each on a stack of its own, because every
#                                 channel makes entries in the account and a second
#                                 channel would find twice as many); their reports
#                                 are unpacked into
#                                 $FERRET_EXT_OUT_DIR/gate-matrix/<set>/<channel>/.
#                                 Fails if any step fails.
#   scripts/lanbox-ext.sh matrix [--channel release|esr] [--manifest mv3|mv2] [--part fill|capture|all] [--set corpus|holdout|parity] [--grep <case id>] [--headed] [--no-up]
#                                 the detection matrix: the extension, signed in to the end-to-end
#                                 stack (as for e2e), against the corpus of extension/test/fixtures/forms
#                                 (--set holdout: forms-holdout/; --set parity: forms-parity/, the own-written
#                                 autofill-parity suite, reported on its own in u2-matrix-parity/): the fill phase tries every case, the
#                                 capture phase types what a person types and reads the offers. The default
#                                 manifest is mv2, the Firefox build. --grep keeps the cases whose id
#                                 contains the text. Without --channel each channel runs on a stack of its own, one after the other.
#                                 The reports (<channel>-<manifest>.json and matrix.md)
#                                 are unpacked into test-results/out/u2-matrix/ (or $FERRET_EXT_OUT_DIR/u2-matrix/),
#                                 also after a failure. Stack handling and limits are those of e2e.
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
# unit and lint: the extension/ tree, the shared source files (web/src), the WASM pin (web/wasm.lock.json), the
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
# --wasm tree (or FERRET_WASM_SOURCE=tree), for unit, firefox, e2e, gate, matrix and measure:
# the test variant is built against the WASM package of this commit instead of the published
# one. The package is built on the build host first (scripts/lanbox-wasm.sh --tree, into
# wasm-package/; one built from this very commit is reused), the fetch step is not run, and
# the build writes <name>.wasm.json beside each package with {source, commit, sha256}. The e2e
# stack of the run is built from the same package (scripts/lanbox-ferret-test.sh). The release
# variant (lint, and the release builds of unit) always uses the locked package: lint takes no
# --wasm option.
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
  echo "usage: scripts/lanbox-ext.sh unit | lint | firefox [options] | e2e [options] | gate [options] | matrix [options] | measure [options]" >&2
  echo "  options of firefox and e2e: --channel release|esr  --manifest mv3|mv2  --grep <name>  --headed  --wasm lock|tree  (e2e only: --no-up)" >&2
  echo "  options of gate: --channel release|esr  --manifest mv3|mv2  --wasm lock|tree" >&2
  echo "  options of matrix: --channel release|esr  --manifest mv3|mv2  --part fill|capture|all  --set corpus|holdout|parity  --grep <case id>  --headed  --no-up  --wasm lock|tree" >&2
  echo "  options of measure: --channel release|esr  --manifest mv3|mv2  --scenario idle,sse,popup,argon,terminate  --window-minutes N  --wasm lock|tree" >&2
  echo "  option of unit: --wasm lock|tree (the test variant only; lint is a release check and takes none)" >&2
  exit 2
}

mode="${1:-}"
case "$mode" in
  unit | lint | firefox | e2e | gate | matrix | measure) shift ;;
  *) usage ;;
esac

channel=""
manifest=mv3
manifest_given=0
grep_name=""
matrix_part=all
matrix_set=corpus
headed=0
no_up=0
scenario_list=""
window_minutes=""
# Where the test variant's WASM package comes from: the published one (the default) or one built from this tree.
wasm_source="${FERRET_WASM_SOURCE:-lock}"
while [ "$#" -gt 0 ]; do
  case "$mode:$1" in
    unit:--wasm | firefox:--wasm | e2e:--wasm | gate:--wasm | matrix:--wasm | measure:--wasm) [ "$#" -ge 2 ] || usage; wasm_source="$2"; shift 2 ;;
    firefox:--channel | e2e:--channel | gate:--channel | matrix:--channel | measure:--channel) [ "$#" -ge 2 ] || usage; channel="$2"; shift 2 ;;
    firefox:--manifest | e2e:--manifest | gate:--manifest | matrix:--manifest | measure:--manifest) [ "$#" -ge 2 ] || usage; manifest="$2"; manifest_given=1; shift 2 ;;
    firefox:--grep | e2e:--grep | matrix:--grep) [ "$#" -ge 2 ] || usage; grep_name="$2"; shift 2 ;;
    matrix:--part) [ "$#" -ge 2 ] || usage; matrix_part="$2"; shift 2 ;;
    matrix:--set) [ "$#" -ge 2 ] || usage; matrix_set="$2"; shift 2 ;;
    firefox:--headed | e2e:--headed | matrix:--headed) headed=1; shift ;;
    e2e:--no-up | matrix:--no-up) no_up=1; shift ;;
    measure:--scenario) [ "$#" -ge 2 ] || usage; scenario_list="$2"; shift 2 ;;
    measure:--window-minutes) [ "$#" -ge 2 ] || usage; window_minutes="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$channel" in "" | release | esr) ;; *) usage ;; esac
case "$wasm_source" in lock | tree) ;; *) usage ;; esac
# A release check never takes a package from the tree, not even from the environment.
if [ "$mode" = lint ]; then wasm_source=lock; fi
case "$manifest" in mv3 | mv2) ;; *) usage ;; esac
case "$matrix_part" in fill | capture | all) ;; *) usage ;; esac
case "$matrix_set" in corpus | holdout | parity) ;; *) usage ;; esac
# A case id is lower case letters, digits and dashes; the text goes into the container's environment.
case_re='^[a-z0-9-]{0,80}$'
if [ "$mode" = matrix ] && ! (LC_ALL=C; [[ $grep_name =~ $case_re ]]); then usage; fi
# The gate and the matrix run the Firefox build: MV2 with a persistent background, unless --manifest names another.
if { [ "$mode" = gate ] || [ "$mode" = matrix ]; } && [ "$manifest_given" = 0 ]; then manifest=mv2; fi
# A measure run covers both manifest versions unless --manifest names one.
measure_manifests="mv3,mv2"
if [ "$mode" = measure ] && [ "$manifest_given" = 1 ]; then measure_manifests="$manifest"; fi
# bash's own matcher, so an embedded newline cannot slip past the anchors
scenario_re='^(idle|sse|popup|argon|terminate)(,(idle|sse|popup|argon|terminate))*$'
if [ -n "$scenario_list" ] && ! (LC_ALL=C; [[ $scenario_list =~ $scenario_re ]]); then usage; fi
window_re='^[0-9]{1,4}$'
if [ -n "$window_minutes" ] && ! (LC_ALL=C; [[ $window_minutes =~ $window_re ]]); then usage; fi
if [ -n "$window_minutes" ] && [ "$window_minutes" -lt 2 ]; then usage; fi

# ------------------------------------------------- the package of this tree

# --wasm tree: build the package of this commit on the build host (one built from this very commit
# is reused) and find it. wasm_dir is where scripts/lanbox-wasm.sh --tree leaves it.
wasm_tar=""
wasm_commit=""
if [ "$wasm_source" = tree ]; then
  wasm_dir="${FERRET_WASM_DIR:-wasm-package}"
  bash "${FERRET_WASM_TREE_SCRIPT:-scripts/lanbox-wasm.sh}" --tree >&2
  wasm_tar="$(find "$wasm_dir" -maxdepth 1 -name 'ferret-core-wasm-web-*.tar.gz' -print -quit)"
  wasm_commit="$(sed -n 's/.*"commit":"\([^"]*\)".*/\1/p' "$wasm_dir/wasm-tree.json")"
  if [ -z "$wasm_tar" ] || [ -z "$wasm_commit" ]; then
    echo "lanbox-ext.sh: $wasm_dir holds no web package or no commit (scripts/lanbox-wasm.sh --tree)" >&2
    exit 1
  fi
  echo "lanbox-ext.sh: the test variant is built against the WASM package of $wasm_commit" >&2
  # The e2e stack of a run is built from the same package (scripts/lanbox-ferret-test.sh reads this).
  export FERRET_WASM_SOURCE=tree
else
  export FERRET_WASM_SOURCE=lock
fi

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
      # The release variant takes the locked package whatever the test variant does.
      flags="--wasm lock"
      if [ "$variant" = test ] && [ -n "$FERRET_EXT_TEST_WASM" ]; then flags="$FERRET_EXT_TEST_WASM"; fi
      # shellcheck disable=SC2086
      node scripts/build.mjs --browser firefox --manifest "$mv" --variant "$variant" $flags >&2
    done
  done
  npm exec --no -- tsc -p jsconfig.json --noEmit >&2
  node --test "test/unit/*.test.mjs" >&2
else
  for mv in mv3 mv2; do
    node scripts/build.mjs --browser firefox --manifest "$mv" --variant release >&2
    npm exec --no -- web-ext lint --source-dir "dist/ferret-firefox-$mv-release" --warnings-as-errors --self-hosted >&2
  done
  cd /work
  bash scripts/check-ext-release.sh >&2
fi'

  # What the test variant's build takes in the unit step (the release variant always takes the lock).
  unit_test_wasm=""
  if [ -n "$wasm_tar" ]; then
    unit_test_wasm="--wasm tree --wasm-tar /work/$(basename "$wasm_tar") --wasm-commit $wasm_commit"
  fi
  dev_args ""
  run=(docker "${docker_args[@]}" run --rm -i --init
    --label owner=ferret-core
    "${dev_args_out[@]}"
    --cpus "$cpus"
    --memory "$memory"
    -e CI=1
    -e FERRET_EXT_MODE="$mode"
    -e FERRET_EXT_TEST_WASM="$unit_test_wasm"
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
      extension web/wasm.lock.json web/src crates/ferret-server/static/favicon.svg scripts/check-ext-release.sh scripts/lanbox-ext.sh notices-extra.json \
      scripts/check-lanbox-labels.sh docker/ext-runner.Dockerfile \
      .github/workflows \
      docs/design/phase-1-security-design.md \
      ${wasm_tar:+-C "$(dirname "$wasm_tar")" "$(basename "$wasm_tar")"}
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
# A temp path that comes in Windows form (C:\Users\...\Temp) must not reach tar as it is: GNU tar reads "C:" as the name of a
# remote host and fails. The path is turned into the POSIX form where cygpath exists, and the archives are read through the
# shell's redirections, never through `-f <path>`. The one append (-r) needs a file name, so GNU tar gets --force-local
# (BSD tar has no such option and no such habit).
if command -v cygpath > /dev/null 2>&1; then work="$(cygpath -u "$work")"; fi
tar_local=()
if tar --force-local --version > /dev/null 2>&1; then tar_local=(--force-local); fi
# The end-to-end stack this run started for itself (see the e2e step), removed again on exit.
own_stack=""
stack="${FERRET_EXT_STACK_SCRIPT:-scripts/lanbox-ferret-test.sh}"
# shellcheck disable=SC2317  # called by the trap
cleanup() {
  if [ -n "$own_stack" ]; then
    FERRET_E2E_SUFFIX="$own_stack" bash "$stack" e2e-down >&2 || echo "lanbox-ext.sh: e2e-down of the stack $own_stack failed; run FERRET_E2E_SUFFIX=$own_stack $stack e2e-down" >&2
  fi
  rm -rf "$work"
}
trap cleanup EXIT

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
if [ -n "$wasm_tar" ]; then
  # --wasm tree: the package of this commit is the one that was built above; nothing is fetched.
  cp "$wasm_tar" "$work/wasm.tar.gz"
else
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
fi
[ -s "$work/wasm.tar.gz" ] || { echo "lanbox-ext.sh: the WASM package came back empty" >&2; exit 1; }

# Step 2: the tests. No network, or only the end-to-end stack's.
network=none
e2e_ca=""
e2e_token=""
e2e_evil_url=""
e2e_suffix=""
e2e_chromium_ws=""
e2e_volume_args=()

# A /28 for this run's stack network, the first three octets: 172.30.<n> with n from 200 to 239,
# starting at a random n, that overlaps no network the Docker host has. Prints nothing when every
# one is taken.
free_subnet() {
  local used ids start i n net bits a b c d base size lo hi taken
  used=()
  ids="$(docker "${docker_args[@]}" network ls -q 2> /dev/null || true)"
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    while read -r net; do
      [ -n "$net" ] && used+=("$net")
    done < <(docker "${docker_args[@]}" network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' $ids 2> /dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' || true)
  fi
  start=$((16#$(head -c 1 /dev/urandom | od -An -tx1 | tr -d ' \n') % 40))
  for i in $(seq 0 39); do
    n=$((200 + (start + i) % 40))
    lo=$(((172 << 24) + (30 << 16) + (n << 8)))
    hi=$((lo + 15))
    taken=0
    for net in "${used[@]+"${used[@]}"}"; do
      IFS=./ read -r a b c d bits <<< "$net"
      base=$(((a << 24) + (b << 16) + (c << 8) + d))
      size=$((1 << (32 - bits)))
      base=$((base - base % size))
      if [ "$lo" -le $((base + size - 1)) ] && [ "$hi" -ge "$base" ]; then taken=1; break; fi
    done
    if [ "$taken" = 0 ]; then
      echo "172.30.$n"
      return 0
    fi
  done
}

# A run that was killed hard (no exit trap: SIGKILL, a lost Docker context, a reboot) leaves its
# per-run stack behind. Before a run starts its own, every per-run stack (label owner=ferret-x<8 hex>)
# with a container older than STALE_HOURS is removed with e2e-down. No run lasts that long.
STALE_HOURS=6
sweep_stale_stacks() {
  local now owner created suffix stale=()
  now="$(date +%s)"
  while read -r owner created; do
    [[ $owner =~ ^ferret-(x[0-9a-f]{8})$ ]] || continue
    # CreatedAt reads "2026-11-22 13:05:01 +0100 CET"; the date, time and offset are enough.
    created="$(date -d "$(cut -d' ' -f1-3 <<< "$created")" +%s 2> /dev/null || echo "$now")"
    if [ $((now - created)) -gt $((STALE_HOURS * 3600)) ]; then stale+=("${BASH_REMATCH[1]}"); fi
  done < <(docker "${docker_args[@]}" ps -a --filter label=owner --format '{{.Label "owner"}} {{.CreatedAt}}' 2> /dev/null || true)
  for suffix in $(printf '%s\n' "${stale[@]+"${stale[@]}"}" | sort -u); do
    echo "lanbox-ext.sh: removing the stack ferret-$suffix that a killed run left (older than $STALE_HOURS hours)" >&2
    FERRET_E2E_SUFFIX="$suffix" bash "$stack" e2e-down >&2 || true
  done
}

# Removes the stack this run made (or the one the caller named) so that the next e2e_setup makes a fresh one: a stack has one
# account, made by the first spec that needs it, and a spec that runs again on it finds the entries of the one before.
e2e_reset() {
  # Never the stack with the default name (one user at a time, not this run's to remove).
  if [ -n "${FERRET_E2E_SUFFIX:-}" ] && [ "$FERRET_E2E_SUFFIX" != e2e ]; then
    FERRET_E2E_SUFFIX="$FERRET_E2E_SUFFIX" bash "$stack" e2e-down >&2 || echo "lanbox-ext.sh: e2e-down of the stack $FERRET_E2E_SUFFIX failed" >&2
  fi
  # A stack of this run's own is made again with a new name; a named one keeps its name (and its subnet).
  if [ -n "$own_stack" ]; then
    own_stack=""
    unset FERRET_E2E_SUFFIX FERRET_E2E_SUBNET
  fi
}

# The end-to-end stack: one of this run's own (FERRET_E2E_SUFFIX unset, no --no-up), so two runs on
# the build host never remove each other's stack, or the stack the caller names.
e2e_setup() {
  if [ -z "${FERRET_E2E_SUFFIX:-}" ] && [ "$no_up" -eq 0 ]; then
    sweep_stale_stacks
    FERRET_E2E_SUFFIX="x$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    FERRET_E2E_SUBNET="$(free_subnet)"
    [ -n "$FERRET_E2E_SUBNET" ] || { echo "lanbox-ext.sh: no free 172.30.200-239 /28 for the stack's network" >&2; exit 1; }
    export FERRET_E2E_SUFFIX FERRET_E2E_SUBNET
    # From here on the stack is removed on exit, also when e2e-up fails half way.
    own_stack="$FERRET_E2E_SUFFIX"
    echo "lanbox-ext.sh: this run's stack is ferret-$FERRET_E2E_SUFFIX (network $FERRET_E2E_SUBNET.0/28)" >&2
  fi
  e2e_suffix="${FERRET_E2E_SUFFIX:-e2e}"
  if [ "$no_up" -eq 0 ]; then
    bash "$stack" e2e-up >&2
  fi
  e2e_ca="$(bash "$stack" e2e-ca)"
  # The setup token of the stack (made up by e2e-up): the sign-in specs make the stack's first account with it.
  e2e_token="$(bash "$stack" e2e-token)"
  # The stack's Chromium (a Playwright browser server), for the spec that drives the web vault in it; its
  # client package is in a volume of the stack, mounted read-only.
  e2e_chromium_ws="$(bash "$stack" e2e-chromium)"
  e2e_volume_args=(-v "ferret-$e2e_suffix-pwcore:/pw:ro")
  network="ferret-$e2e_suffix-net"
  # The control port of the stack's malicious proxy, on the stack's network (the sync specs switch its modes).
  e2e_evil_url="http://ferret-e2e-evil:9000"
}

tar ${tar_local[@]+"${tar_local[@]}"} -cf "$work/in.tar" \
  --exclude='extension/node_modules' \
  --exclude='extension/dist' \
  extension web/wasm.lock.json web/src
tar ${tar_local[@]+"${tar_local[@]}"} -rf "$work/in.tar" -C "$work" wasm.tar.gz

# The tests container for the channels in $1 (a comma list). $2 goes into the name
# and the label (see dev_args). $3 is the step of run.sh (firefox, e2e or measure; the
# mode by default), $4 is 1 when the e2e step hands its screenshots back as a tar
# archive on stdout. Fills the array `run`.
make_run() {
  local step="${3:-$mode}" shots="${4:-0}" net=none
  if [ "$step" = e2e ] || [ "$step" = matrix ]; then net="$network"; fi
  dev_args "${2:-}"
  run=(docker "${docker_args[@]}" run --rm -i --init
    --label owner=ferret-core
    "${dev_args_out[@]}"
    --network "$net")
  if [ "$step" = e2e ] || [ "$step" = matrix ]; then run+=("${e2e_volume_args[@]}"); fi
  # The matrix filters by case id (FERRET_MATRIX_GREP), not by test name.
  local test_grep="$grep_name"
  if [ "$step" = matrix ]; then test_grep=""; fi
  run+=(
    --cpus "$cpus"
    --memory "$memory"
    --shm-size 2g
    --cap-drop ALL --cap-add CHOWN --cap-add SETUID --cap-add SETGID
    --security-opt no-new-privileges:true
    -e CI=1
    -e FERRET_EXT_STEP="$step"
    -e FERRET_WASM_SOURCE="$wasm_source"
    -e FERRET_WASM_COMMIT="$wasm_commit"
    -e FERRET_CHANNELS="$1"
    -e FERRET_MANIFEST="$manifest"
    -e FERRET_GREP="$test_grep"
    -e FERRET_MATRIX_PART="$matrix_part"
    -e FERRET_MATRIX_SET="$matrix_set"
    -e FERRET_MATRIX_GREP="$grep_name"
    -e FERRET_HEADLESS="$((1 - headed))"
    -e FERRET_E2E_CA_PEM="$e2e_ca"
    -e FERRET_E2E_SETUP_TOKEN="$e2e_token"
    -e FERRET_E2E_EVIL_URL="$e2e_evil_url"
    -e FERRET_E2E_SUFFIX="$e2e_suffix"
    -e FERRET_E2E_CHROMIUM_WS="$e2e_chromium_ws"
    -e FERRET_EXT_SHOTS="$shots"
    -e FERRET_MEASURE_MANIFESTS="$measure_manifests"
    -e FERRET_MEASURE_SCENARIOS="$scenario_list"
    -e FERRET_MEASURE_MINUTES="$window_minutes"
    -e FERRET_MEASURE_POLL_MS="${FERRET_MEASURE_POLL_MS:-}"
    --tmpfs /work:exec,size=2g
    --tmpfs /tmp:exec,size=2g
    --tmpfs /home/ferret:uid=10001,gid=10001,size=1g
    -w /work
    "$runner_image"
    sh -c 'tar -x --no-same-owner -C /work && exec sh /work/extension/test/firefox/run.sh "$0"' "$step")
}

if [ "$mode" = firefox ]; then
  make_run "${channel:-release,esr}" ""
  "${run[@]}" < "$work/in.tar"
  exit 0
fi

# The unlock specs (extension/test/firefox/unlock.mjs) use PINs that start with this text. None of them may be in a log of the
# stack's containers: a PIN is not sent to the server, and the server logs nothing a person typed. Returns 1 when one is.
SENTINEL_PIN_PREFIX="ferret-sentinel-pin-"
scan_stack_logs_for_sentinels() {
  local id found=0
  for id in $(docker "${docker_args[@]}" ps -a -q --filter "label=owner=ferret-${FERRET_E2E_SUFFIX:-e2e}"); do
    if docker "${docker_args[@]}" logs "$id" 2>&1 | grep -q -F "$SENTINEL_PIN_PREFIX"; then
      echo "lanbox-ext.sh: the log of the container $id of the stack holds a sentinel PIN" >&2
      found=1
    fi
  done
  return "$found"
}

if [ "$mode" = e2e ]; then
  e2e_setup
  make_run "${channel:-release,esr}" ""
  rc=0
  "${run[@]}" < "$work/in.tar" || rc=$?
  scan_stack_logs_for_sentinels || { [ "$rc" -ne 0 ] || rc=1; }
  exit "$rc"
fi

if [ "$mode" = matrix ]; then
  # The e2e stack of this run, then the matrix in the Firefox runner on that stack's network. What the spec
  # writes (FERRET_MATRIX_OUT) comes out as a tar archive on stdout and is unpacked, also after a failure.
  out_dir="${FERRET_EXT_OUT_DIR:-test-results/out}"
  mkdir -p "$out_dir"
  # Each channel runs on a stack of its own (two channels on one account would show each other's entries, and the
  # extension would answer "choose" where a single channel does not). A stack named by the caller is used as it is.
  rc=0
  first_channel=1
  for ch in ${channel:-release esr}; do
    if [ "$first_channel" -eq 0 ] && [ -n "$own_stack" ]; then e2e_reset; fi
    if [ "$first_channel" -eq 1 ] || [ -z "${FERRET_E2E_SUFFIX:-}" ]; then e2e_setup; fi
    first_channel=0
    make_run "$ch" "matrix" matrix 0
    one=0
    "${run[@]}" < "$work/in.tar" > "$work/matrix.tar" || one=$?
    if [ -s "$work/matrix.tar" ]; then
      tar -x --no-same-owner -C "$out_dir" < "$work/matrix.tar" || one=$?
    fi
    [ "$one" -eq 0 ] || rc=$one
  done
  report_dir=u2-matrix
  if [ "$matrix_set" = parity ]; then report_dir=u2-matrix-parity; fi
  echo "lanbox-ext.sh: matrix: the reports are in $out_dir/$report_dir/ (exit status $rc)" >&2
  exit "$rc"
fi

if [ "$mode" = gate ]; then
  # The firefox step, then the e2e step on a stack of this run's own; the screenshots of the e2e
  # step come back as a tar archive on its stdout and are unpacked, also after a failure.
  out_dir="${FERRET_EXT_OUT_DIR:-test-results/out}"
  mkdir -p "$out_dir"
  status=0
  make_run "${channel:-release,esr}" "gate-firefox" firefox
  "${run[@]}" < "$work/in.tar" || { status=$?; echo "lanbox-ext.sh: gate: the firefox step failed ($status)" >&2; }
  e2e_setup
  make_run "${channel:-release,esr}" "gate-e2e" e2e 1
  rc=0
  "${run[@]}" < "$work/in.tar" > "$work/shots.tar" || rc=$?
  if [ -s "$work/shots.tar" ]; then
    tar -x --no-same-owner -C "$out_dir" < "$work/shots.tar" || rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    echo "lanbox-ext.sh: gate: the e2e step failed ($rc)" >&2
    status=$rc
  fi
  echo "lanbox-ext.sh: gate: screenshots are in $out_dir/gate-shots/ (exit status $status)" >&2
  # The detection matrix: the corpus, the hold-out set and the parity set, each channel on a stack of its own. What a container writes comes
  # out as a tar archive on stdout and is unpacked, also after a failure.
  gate_channels="${channel:-release esr}"
  for matrix_set in corpus holdout parity; do
    for ch in $gate_channels; do
      e2e_reset
      e2e_setup
      make_run "$ch" "gate-matrix-$matrix_set-$ch" matrix 0
      rc=0
      "${run[@]}" < "$work/in.tar" > "$work/gate-matrix.tar" || rc=$?
      mkdir -p "$out_dir/gate-matrix/$matrix_set/$ch"
      if [ -s "$work/gate-matrix.tar" ]; then
        tar -x --no-same-owner -C "$out_dir/gate-matrix/$matrix_set/$ch" < "$work/gate-matrix.tar" || rc=$?
      fi
      if [ "$rc" -ne 0 ]; then
        echo "lanbox-ext.sh: gate: the $matrix_set matrix on $ch failed ($rc)" >&2
        status=$rc
      fi
    done
  done
  e2e_reset
  echo "lanbox-ext.sh: gate: the matrix reports are in $out_dir/gate-matrix/ (exit status $status)" >&2
  exit "$status"
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
      tar -x --no-same-owner -C "$out_dir" < "$work/report-$ch.tar" || rc=$?
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
