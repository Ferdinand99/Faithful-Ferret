#!/usr/bin/env bash
# Checks the optional DEV_RUN, DEV_TITLE and FERRET_PASS_ENV settings of
# scripts/lanbox.sh and scripts/lanbox-web.sh, and the container names, labels,
# networks and end-to-end stacks of scripts/lanbox-ext.sh, with stand-in docker
# programs that only record their arguments. Nothing is sent to a Docker host.
#
#   scripts/check-lanbox-labels.sh [all|lanbox|web|ext]   (default all)
#
# `ext` needs no git checkout (the extension's unit step runs it in a container
# with the extension's files only); `lanbox` lists the repo with git.
set -euo pipefail
cd "$(dirname "$0")/.."

part="${1:-all}"
case "$part" in
  all | lanbox | web | ext) ;;
  *) echo "usage: scripts/check-lanbox-labels.sh [all|lanbox|web|ext]" >&2; exit 2 ;;
esac
want() { [ "$part" = all ] || [ "$part" = "$1" ]; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
# `docker run` reads the repo archive from stdin; drain it so the pipe closes.
for arg in "$@"; do
  if [ "$arg" = run ]; then
    printf '%s\n' "$@" > "$DOCKER_STUB_LOG"
    cat > /dev/null
    break
  fi
done
exit 0
STUB
chmod +x "$work/bin/docker"

fail() { echo "check-lanbox-labels: $*" >&2; exit 1; }

bad_ids=(Bad_Name -dash UPPER "two words" "$(printf 'ok\nBAD')" "$(printf 'a%.0s' $(seq 1 64))")

# ------------------------------------------------------------------ lanbox.sh

if want lanbox; then
  # Runs lanbox.sh with the stand-in docker. Extra variables come as arguments.
  run_lanbox() {
    rm -f "$work/log"
    env PATH="$work/bin:$PATH" DOCKER_STUB_LOG="$work/log" "$@" \
      scripts/lanbox.sh --exec true > "$work/out" 2>&1
  }

  # A run id that is not allowed stops the script before it calls docker.
  for id in "${bad_ids[@]}"; do
    if run_lanbox DEV_RUN="$id"; then
      fail "DEV_RUN='$id' was accepted"
    fi
    [ ! -e "$work/log" ] || fail "DEV_RUN='$id' reached docker run"
    grep -q 'DEV_RUN must match' "$work/out" || fail "DEV_RUN='$id' gave no message"
  done

  # A valid run id adds the label and the name.
  run_lanbox DEV_RUN=run-check DEV_TITLE="Ferret tests" || { cat "$work/out" >&2; fail "valid DEV_RUN failed"; }
  grep -qx 'dev.run=run-check' "$work/log" || fail "dev.run label is missing"
  grep -qx 'dev.title=Ferret tests' "$work/log" || fail "dev.title label is missing"
  grep -qxE 'ferret-run-check-[0-9]+' "$work/log" || fail "container name is wrong"
  grep -qx 'owner=ferret-core' "$work/log" || fail "owner label is missing"

  # The longest allowed id is accepted, and a title is optional.
  longest="$(printf 'a%.0s' $(seq 1 63))"
  run_lanbox DEV_RUN="$longest" || fail "a 63 character DEV_RUN was refused"
  grep -qx "dev.run=$longest" "$work/log" || fail "long dev.run label is missing"
  ! grep -q '^dev.title=' "$work/log" || fail "dev.title was added without DEV_TITLE"

  # Without DEV_RUN nothing changes, even if DEV_TITLE is set.
  run_lanbox DEV_TITLE="ignored" || fail "run without DEV_RUN failed"
  ! grep -qE '^(dev\.|--name)' "$work/log" || fail "labels or name added without DEV_RUN"
  grep -qx 'owner=ferret-core' "$work/log" || fail "owner label is missing without DEV_RUN"
fi

# --------------------------------------------------------------- lanbox-web.sh

if want web; then
  # lanbox-web.sh takes the same settings.
  run_web() {
    rm -f "$work/log"
    env PATH="$work/bin:$PATH" DOCKER_STUB_LOG="$work/log" "$@" scripts/lanbox-web.sh unit > "$work/out" 2>&1
  }

  for id in "${bad_ids[@]}"; do
    if run_web DEV_RUN="$id"; then
      fail "web: DEV_RUN='$id' was accepted"
    fi
    [ ! -e "$work/log" ] || fail "web: DEV_RUN='$id' reached docker run"
    grep -q 'DEV_RUN must match' "$work/out" || fail "web: DEV_RUN='$id' gave no message"
  done

  run_web DEV_RUN=web-check DEV_TITLE="Web checks" FERRET_PASS_ENV="FOO BAR_1" FOO=1 \
    || { cat "$work/out" >&2; fail "web: valid settings failed"; }
  grep -qx 'dev.run=web-check' "$work/log" || fail "web: dev.run label is missing"
  grep -qx 'dev.title=Web checks' "$work/log" || fail "web: dev.title label is missing"
  grep -qxE 'ferret-web-check-[0-9]+' "$work/log" || fail "web: container name is wrong"
  grep -qx 'owner=ferret-core' "$work/log" || fail "web: owner label is missing"
  # A passed variable is a bare name after -e: the value never appears on the command line.
  grep -qx 'FOO' "$work/log" || fail "web: FOO is not passed on"
  grep -qx 'BAR_1' "$work/log" || fail "web: BAR_1 is not passed on"
  [ "$(grep -cx -e '-e' "$work/log")" -ge 3 ] || fail "web: -e flags are missing"
  ! grep -q '^FOO=' "$work/log" || fail "web: a value was put on the command line"

  for bad in 'FOO;rm' 'a b=c' '1X' 'FOO=1'; do
    if run_web FERRET_PASS_ENV="$bad"; then
      fail "web: FERRET_PASS_ENV='$bad' was accepted"
    fi
    [ ! -e "$work/log" ] || fail "web: FERRET_PASS_ENV='$bad' reached docker run"
    grep -q 'FERRET_PASS_ENV holds variable names only' "$work/out" || fail "web: FERRET_PASS_ENV='$bad' gave no message"
  done

  run_web DEV_TITLE="ignored" || fail "web: run without DEV_RUN failed"
  ! grep -qE '^(dev\.|--name)' "$work/log" || fail "web: labels or name added without DEV_RUN"
fi

# --------------------------------------------------------------- lanbox-ext.sh

if want ext; then
  ext="$work/ext"
  mkdir -p "$ext/bin"
  cat > "$ext/bin/docker" <<'STUB'
#!/usr/bin/env bash
# One file per call: the arguments, one per line. `run` reads its input from stdin
# (drain it); the fetch step answers with a few bytes, as the real one answers
# with the WASM archive. `image inspect` answers "present" unless told otherwise.
# `network ls` names one network, and `network inspect` gives the subnets in
# DOCKER_STUB_SUBNETS (the networks the host already has).
# The number is taken atomically (mkdir): two containers can start at the same moment.
n=1
until mkdir "$DOCKER_STUB_DIR/.taken-$n" 2> /dev/null; do n=$((n + 1)); done
printf '%s\n' "$@" > "$DOCKER_STUB_DIR/call-$n"
for arg in "$@"; do
  case "$arg" in
    run)
      cat > /dev/null
      if grep -qx 'FERRET_EXT_STEP=fetch' "$DOCKER_STUB_DIR/call-$n"; then printf 'wasm'; fi
      exit 0
      ;;
    build)
      cat > /dev/null
      exit 0
      ;;
    inspect)
      if grep -qx network "$DOCKER_STUB_DIR/call-$n"; then printf '%s\n' "${DOCKER_STUB_SUBNETS:-}" | tr ' ' '\n'; exit 0; fi
      [ "${DOCKER_STUB_IMAGE:-present}" = present ] || exit 1
      exit 0
      ;;
    ls)
      if grep -qx network "$DOCKER_STUB_DIR/call-$n"; then echo stubnet; fi
      exit 0
      ;;
    ps)
      # The containers the host has: "<owner label> <created at>" lines from DOCKER_STUB_PS (| between lines).
      [ -z "${DOCKER_STUB_PS:-}" ] || printf '%s\n' "$DOCKER_STUB_PS" | tr '|' '\n'
      exit 0
      ;;
  esac
done
exit 0
STUB
  chmod +x "$ext/bin/docker"
  cat > "$ext/stack.sh" <<'STUB'
#!/usr/bin/env bash
# Stands in for scripts/lanbox-ferret-test.sh: logs the command, the stack's suffix and subnet.
printf '%s %s %s\n' "$1" "${FERRET_E2E_SUFFIX:--}" "${FERRET_E2E_SUBNET:--}" >> "$STACK_STUB_LOG"
case "$1" in
  e2e-ca) printf -- '-----BEGIN CERTIFICATE-----\nstand-in\n-----END CERTIFICATE-----\n' ;;
  e2e-token) printf 'TOKEN\n' ;;
  e2e-chromium) printf 'ws://ferret-%s-chromium:3000/\n' "${FERRET_E2E_SUFFIX:-e2e}" ;;
esac
STUB

  # Runs lanbox-ext.sh with the stand-in docker. Extra variables, then the mode and options.
  # The calls are in $ext/calls/call-<n>, the stack's commands in $ext/stack.log.
  run_ext() {
    rm -rf "$ext/calls"; mkdir "$ext/calls"
    rm -f "$ext/stack.log"; touch "$ext/stack.log"
    env -u FERRET_E2E_SUFFIX -u FERRET_E2E_SUBNET PATH="$ext/bin:$PATH" DOCKER_STUB_DIR="$ext/calls" STACK_STUB_LOG="$ext/stack.log" \
      FERRET_EXT_STACK_SCRIPT="$ext/stack.sh" "$@" > "$ext/out" 2>&1
  }
  calls() { find "$ext/calls" -name 'call-*' | wc -l; }
  run_calls() { grep -lx run "$ext"/calls/call-* 2> /dev/null || true; }
  # The stack commands of the last run, as "command/suffix" words.
  stack_words() { awk '{ printf "%s/%s ", $1, $2 }' "$ext/stack.log"; }

  # A run id that is not allowed stops the script before it calls docker.
  for id in "${bad_ids[@]}"; do
    if run_ext DEV_RUN="$id" scripts/lanbox-ext.sh firefox; then
      fail "ext: DEV_RUN='$id' was accepted"
    fi
    [ "$(calls)" -eq 0 ] || fail "ext: DEV_RUN='$id' reached docker"
    grep -q 'DEV_RUN must match' "$ext/out" || fail "ext: DEV_RUN='$id' gave no message"
  done

  # Options that do not exist stop the script before docker.
  for bad in "firefox --channel nightly" "firefox --manifest mv4" "firefox --nope" "unit --channel release" "lint --grep x" "firefox --no-up" "other" \
    "measure --scenario nope" "measure --scenario idle,nope" "measure --window-minutes 1" "measure --window-minutes x" "measure --grep x" "measure --headed" \
    "firefox --scenario idle" "firefox --window-minutes 20" "gate --grep x" "gate --no-up" "gate --scenario idle" "gate --channel nightly" \
    "matrix --part some" "matrix --set other" "matrix --grep Bad_Id" "matrix --scenario idle" "firefox --part fill" "e2e --set holdout"; do
    # shellcheck disable=SC2086
    if run_ext scripts/lanbox-ext.sh $bad; then fail "ext: '$bad' was accepted"; fi
    [ "$(calls)" -eq 0 ] || fail "ext: '$bad' reached docker"
  done

  # Every container the firefox step starts is named, labelled and removed on exit.
  run_ext DEV_RUN=ext-probe DEV_TITLE="Probe run" scripts/lanbox-ext.sh firefox --channel esr --grep pinned \
    || { cat "$ext/out" >&2; fail "ext: firefox run failed"; }
  [ "$(run_calls | wc -l)" -eq 2 ] || fail "ext: expected two containers (fetch and tests), saw $(run_calls | wc -l)"
  for f in $(run_calls); do
    grep -qx 'owner=ferret-core' "$f" || fail "ext: owner label is missing in $(basename "$f")"
    grep -qx 'dev.run=ext-probe' "$f" || fail "ext: dev.run label is missing in $(basename "$f")"
    grep -qx 'dev.title=Probe run' "$f" || fail "ext: dev.title label is missing in $(basename "$f")"
    grep -qx -e '--rm' "$f" || fail "ext: --rm is missing in $(basename "$f")"
    grep -qxE 'ferret-ext-probe(-fetch)?-[0-9]+' "$f" || fail "ext: container name is wrong in $(basename "$f")"
  done
  names=$(grep -hxE 'ferret-ext-probe(-fetch)?-[0-9]+' "$ext"/calls/call-* | sort | uniq -d | wc -l)
  [ "$names" -eq 0 ] || fail "ext: two containers have the same name"
  grep -qx 'FERRET_CHANNELS=esr' "$ext"/calls/call-* || fail "ext: the channel is not passed on"
  grep -qx 'FERRET_GREP=pinned' "$ext"/calls/call-* || fail "ext: the test name filter is not passed on"
  [ ! -s "$ext/stack.log" ] || fail "ext: the firefox step touched an end-to-end stack"

  # A missing runner image is built, with the label.
  run_ext DOCKER_STUB_IMAGE=absent DEV_RUN=ext-probe scripts/lanbox-ext.sh firefox \
    || { cat "$ext/out" >&2; fail "ext: firefox run with a missing image failed"; }
  build=$(grep -lx build "$ext"/calls/call-*) || fail "ext: the missing image was not built"
  grep -qx 'owner=ferret-core' "$build" || fail "ext: the image build has no owner label"
  grep -qxE 'ferret-ext-runner:[0-9a-f]{12}' "$build" || fail "ext: the image tag is wrong"

  # unit and lint: one container, named and labelled.
  for mode in unit lint; do
    run_ext DEV_RUN=ext-probe-unit scripts/lanbox-ext.sh "$mode" || { cat "$ext/out" >&2; fail "ext: $mode run failed"; }
    [ "$(calls)" -eq 1 ] || fail "ext: $mode: expected one docker call"
    grep -qx 'owner=ferret-core' "$ext/calls/call-1" || fail "ext: $mode: owner label is missing"
    grep -qx 'dev.run=ext-probe-unit' "$ext/calls/call-1" || fail "ext: $mode: dev.run label is missing"
    grep -qxE 'ferret-ext-probe-unit-[0-9]+' "$ext/calls/call-1" || fail "ext: $mode: container name is wrong"
  done

  # e2e: a stack of the run's own (suffix x<8 hex>, a /28 that overlaps none of the host's networks),
  # up before the tests and down at the end; the test step joins that stack's network only and mounts
  # the stack's client volume read-only.
  run_ext DEV_RUN=ext-probe-e DOCKER_STUB_SUBNETS="172.17.0.0/16 172.30.0.0/18 172.30.200.0/24" scripts/lanbox-ext.sh e2e --channel release \
    || { cat "$ext/out" >&2; fail "ext: e2e run failed"; }
  suffix="$(awk 'NR == 1 { print $2 }' "$ext/stack.log")"
  [[ $suffix =~ ^x[0-9a-f]{8}$ ]] || fail "ext: e2e: the run's stack suffix is '$suffix'"
  subnet="$(awk 'NR == 1 { print $3 }' "$ext/stack.log")"
  [[ $subnet =~ ^172\.30\.(20[1-9]|2[1-3][0-9])$ ]] || fail "ext: e2e: the subnet '$subnet' overlaps a network of the host"
  [ "$(stack_words)" = "e2e-up/$suffix e2e-ca/$suffix e2e-token/$suffix e2e-chromium/$suffix e2e-down/$suffix " ] \
    || fail "ext: e2e: the stack commands were $(stack_words)"
  tests="$(grep -lx FERRET_EXT_STEP=e2e "$ext"/calls/call-*)" || fail "ext: e2e: no test step"
  grep -qx "ferret-$suffix-net" "$tests" || fail "ext: e2e: the test step is not on the run's network"
  [ "$(grep -cx -e '--network' "$tests")" -eq 1 ] || fail "ext: e2e: the test step has more than one network"
  grep -qx "ferret-$suffix-pwcore:/pw:ro" "$tests" || fail "ext: e2e: the client volume is not mounted read-only"
  grep -qx "FERRET_E2E_SUFFIX=$suffix" "$tests" || fail "ext: e2e: the suffix is not passed on"
  grep -qx "FERRET_E2E_CHROMIUM_WS=ws://ferret-$suffix-chromium:3000/" "$tests" || fail "ext: e2e: the browser server is not passed on"
  grep -qx 'FERRET_E2E_SETUP_TOKEN=TOKEN' "$tests" || fail "ext: e2e: the setup token is not passed on"
  grep -qx 'dev.run=ext-probe-e' "$tests" || fail "ext: e2e: dev.run label is missing"
  # A stack that a killed run left (a container older than six hours) is removed before the run starts its own;
  # a younger one (another run that is still going) and the default stack are left alone.
  now_text="$(date -u '+%Y-%m-%d %H:%M:%S +0000 UTC')"
  run_ext DOCKER_STUB_PS="ferret-xdeadbeef 2020-01-01 00:00:00 +0000 UTC|ferret-xcafef00d $now_text|ferret-e2e 2020-01-01 00:00:00 +0000 UTC|ferret-test 2020-01-01 00:00:00 +0000 UTC" \
    scripts/lanbox-ext.sh e2e --channel release || { cat "$ext/out" >&2; fail "ext: e2e run with a stale stack failed"; }
  [ "$(awk 'NR == 1 { print $1 "/" $2 }' "$ext/stack.log")" = "e2e-down/xdeadbeef" ] || fail "ext: e2e: the stale stack was not removed first ($(stack_words))"
  ! grep -q 'xcafef00d' "$ext/stack.log" || fail "ext: e2e: a running stack was removed"
  [ "$(grep -c '^e2e-down' "$ext/stack.log")" -eq 2 ] || fail "ext: e2e: expected the stale stack and the run's own to be removed ($(stack_words))"
  # Two runs get two stacks.
  first="$suffix"
  run_ext scripts/lanbox-ext.sh e2e || { cat "$ext/out" >&2; fail "ext: second e2e run failed"; }
  [ "$(awk 'NR == 1 { print $2 }' "$ext/stack.log")" != "$first" ] || fail "ext: e2e: two runs used one stack"
  # A named stack is used as it is and left up; --no-up leaves the default stack alone.
  run_ext FERRET_E2E_SUFFIX=mine scripts/lanbox-ext.sh e2e || { cat "$ext/out" >&2; fail "ext: e2e with a named stack failed"; }
  [ "$(stack_words)" = "e2e-up/mine e2e-ca/mine e2e-token/mine e2e-chromium/mine " ] \
    || fail "ext: e2e: a named stack was not used as it is ($(stack_words))"
  run_ext scripts/lanbox-ext.sh e2e --no-up || { cat "$ext/out" >&2; fail "ext: e2e --no-up failed"; }
  [ "$(stack_words)" = "e2e-ca/- e2e-token/- e2e-chromium/- " ] || fail "ext: e2e --no-up touched the stack ($(stack_words))"
  grep -qx "ferret-e2e-net" "$(grep -lx FERRET_EXT_STEP=e2e "$ext"/calls/call-*)" || fail "ext: e2e --no-up: not on the default stack's network"

  # gate: the firefox step (no network) and the e2e step (the run's stack), MV2 unless told otherwise.
  run_ext FERRET_EXT_OUT_DIR="$ext/gate-out" DEV_RUN=ext-probe-g scripts/lanbox-ext.sh gate \
    || { cat "$ext/out" >&2; fail "ext: gate run failed"; }
  ff="$(grep -lx FERRET_EXT_STEP=firefox "$ext"/calls/call-*)" || fail "ext: gate: no firefox step"
  ee="$(grep -lx FERRET_EXT_STEP=e2e "$ext"/calls/call-*)" || fail "ext: gate: no e2e step"
  grep -qx none "$ff" || fail "ext: gate: the firefox step has a network"
  grep -qxE 'ferret-x[0-9a-f]{8}-net' "$ee" || fail "ext: gate: the e2e step is not on the run's stack"
  grep -qx 'FERRET_EXT_SHOTS=1' "$ee" || fail "ext: gate: the e2e step does not hand back its screenshots"
  grep -qx 'FERRET_EXT_SHOTS=0' "$ff" || fail "ext: gate: the firefox step was asked for screenshots"
  grep -qx 'FERRET_E2E_SETUP_TOKEN=' "$ff" || fail "ext: gate: the firefox step got the stack's setup token"
  grep -qx 'FERRET_E2E_SETUP_TOKEN=TOKEN' "$ee" || fail "ext: gate: the e2e step has no setup token"
  for f in "$ff" "$ee"; do
    grep -qx 'FERRET_MANIFEST=mv2' "$f" || fail "ext: gate: not the MV2 build"
    grep -qxE 'ferret-ext-probe-g-gate-(firefox|e2e)-[0-9]+' "$f" || fail "ext: gate: container name is wrong"
    grep -qx 'owner=ferret-core' "$f" || fail "ext: gate: owner label is missing"
  done
  [ "$(awk 'END { print $1 }' "$ext/stack.log")" = e2e-down ] || fail "ext: gate: the run's stack was not removed"
  [ -d "$ext/gate-out" ] || fail "ext: gate: the screenshot folder was not made"
  # The matrix of both sets follows, one channel at a time, each on a stack of its own that is removed again: the e2e step and
  # four matrix steps, so five stacks, up and down in pairs, with five different names.
  [ "$(grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-* | wc -l)" -eq 4 ] || fail "ext: gate: expected four matrix steps"
  [ "$(grep -c '^e2e-up' "$ext/stack.log")" -eq 5 ] || fail "ext: gate: expected five stacks up ($(stack_words))"
  [ "$(grep -c '^e2e-down' "$ext/stack.log")" -eq 5 ] || fail "ext: gate: expected five stacks down ($(stack_words))"
  [ "$(grep '^e2e-up' "$ext/stack.log" | awk '{ print $2 }' | sort -u | wc -l)" -eq 5 ] || fail "ext: gate: two steps used one stack"
  for want in corpus holdout; do
    for ch in release esr; do
      grep -lx "FERRET_MATRIX_SET=$want" "$ext"/calls/call-* | xargs grep -lx "FERRET_CHANNELS=$ch" | xargs grep -lx FERRET_EXT_STEP=matrix > /dev/null || fail "ext: gate: no $want matrix step for $ch"
    done
  done
  while read -r f; do
    grep -qx 'FERRET_MANIFEST=mv2' "$f" || fail "ext: gate: a matrix step is not the MV2 build"
    grep -qx 'FERRET_MATRIX_PART=all' "$f" || fail "ext: gate: a matrix step does not run every part"
    grep -qx 'FERRET_MATRIX_GREP=' "$f" || fail "ext: gate: a matrix step has a case filter"
    grep -qxE 'ferret-x[0-9a-f]{8}-net' "$f" || fail "ext: gate: a matrix step is not on a stack of the run"
    grep -qxE 'ferret-ext-probe-g-gate-matrix-(corpus|holdout)-(release|esr)-[0-9]+' "$f" || fail "ext: gate: a matrix container name is wrong"
  done < <(grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-*)
  [ -d "$ext/gate-out/gate-matrix/corpus/release" ] || fail "ext: gate: the matrix report folder was not made"
  run_ext FERRET_EXT_OUT_DIR="$ext/gate-out" scripts/lanbox-ext.sh gate --manifest mv3 --channel esr || fail "ext: gate --manifest mv3 failed"
  grep -qx 'FERRET_MANIFEST=mv3' "$(grep -lx FERRET_EXT_STEP=e2e "$ext"/calls/call-*)" || fail "ext: gate: --manifest is not passed on"
  [ "$(grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-* | wc -l)" -eq 2 ] || fail "ext: gate --channel esr: expected a matrix step for each set"
  grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-* | xargs grep -qx 'FERRET_MANIFEST=mv3' || fail "ext: gate: --manifest is not passed on to the matrix"

  # matrix: the e2e step on the run's own stack (not the firefox step), MV2 unless told otherwise, the choices of the
  # run in the environment, and the reports unpacked into the folder named by FERRET_EXT_OUT_DIR.
  run_ext FERRET_EXT_OUT_DIR="$ext/matrix-out" DEV_RUN=ext-probe-x scripts/lanbox-ext.sh matrix --channel release --part fill --set holdout --grep login-basic \
    || { cat "$ext/out" >&2; fail "ext: matrix run failed"; }
  [ "$(run_calls | wc -l)" -eq 2 ] || fail "ext: matrix: expected the fetch step and one test container"
  mx="$(grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-*)" || fail "ext: matrix: no test step"
  grep -qxE 'ferret-x[0-9a-f]{8}-net' "$mx" || fail "ext: matrix: not on the run's stack"
  grep -qx 'FERRET_MANIFEST=mv2' "$mx" || fail "ext: matrix: not the MV2 build"
  grep -qx 'FERRET_MATRIX_PART=fill' "$mx" || fail "ext: matrix: --part is not passed on"
  grep -qx 'FERRET_MATRIX_SET=holdout' "$mx" || fail "ext: matrix: --set is not passed on"
  grep -qx 'FERRET_MATRIX_GREP=login-basic' "$mx" || fail "ext: matrix: --grep is not passed on"
  grep -qx 'FERRET_GREP=' "$mx" || fail "ext: matrix: the case filter must not become a test-name filter"
  grep -qx 'FERRET_E2E_SETUP_TOKEN=TOKEN' "$mx" || fail "ext: matrix: no setup token"
  grep -qx 'owner=ferret-core' "$mx" || fail "ext: matrix: owner label is missing"
  grep -qxE 'ferret-ext-probe-x-matrix-[0-9]+' "$mx" || fail "ext: matrix: container name is wrong"
  [ "$(awk 'END { print $1 }' "$ext/stack.log")" = e2e-down ] || fail "ext: matrix: the run's stack was not removed"
  [ -d "$ext/matrix-out" ] || fail "ext: matrix: the report folder was not made"
  run_ext FERRET_EXT_OUT_DIR="$ext/matrix-out" scripts/lanbox-ext.sh matrix --manifest mv3 --channel esr || { cat "$ext/out" >&2; fail "ext: matrix --manifest mv3 failed"; }
  grep -qx 'FERRET_MANIFEST=mv3' "$(grep -lx FERRET_EXT_STEP=matrix "$ext"/calls/call-*)" || fail "ext: matrix: --manifest is not passed on"

  # measure: the fetch step and one container per channel (two Firefox side by side),
  # each named for its channel, labelled and removed on exit; the options reach the
  # container; the reports are unpacked into the folder named by FERRET_EXT_OUT_DIR.
  run_ext FERRET_EXT_OUT_DIR="$ext/out-dir" DEV_RUN=ext-probe-m DEV_TITLE="Measure probe" \
    scripts/lanbox-ext.sh measure --manifest mv2 --scenario idle,sse --window-minutes 3 \
    || { cat "$ext/out" >&2; fail "ext: measure run failed"; }
  [ "$(run_calls | wc -l)" -eq 3 ] || fail "ext: measure: expected the fetch step and two containers"
  for ch in release esr; do
    f=$(grep -lx "FERRET_CHANNELS=$ch" "$ext"/calls/call-*) || fail "ext: measure: no container for $ch"
    [ "$(echo "$f" | wc -l)" -eq 1 ] || fail "ext: measure: two containers for $ch"
    grep -qx 'owner=ferret-core' "$f" || fail "ext: measure $ch: owner label is missing"
    grep -qx 'dev.run=ext-probe-m' "$f" || fail "ext: measure $ch: dev.run label is missing"
    grep -qxE "ferret-ext-probe-m-measure-$ch-[0-9]+" "$f" || fail "ext: measure $ch: container name is wrong"
    grep -qx -e '--rm' "$f" || fail "ext: measure $ch: --rm is missing"
    grep -qx 'FERRET_EXT_STEP=measure' "$f" || fail "ext: measure $ch: step is not passed on"
    grep -qx 'FERRET_MEASURE_MANIFESTS=mv2' "$f" || fail "ext: measure $ch: manifest is not passed on"
    grep -qx 'FERRET_MEASURE_SCENARIOS=idle,sse' "$f" || fail "ext: measure $ch: scenarios are not passed on"
    grep -qx 'FERRET_MEASURE_MINUTES=3' "$f" || fail "ext: measure $ch: window is not passed on"
    grep -qx 'none' "$f" || fail "ext: measure $ch: the test step has a network"
  done
  [ -d "$ext/out-dir" ] || fail "ext: measure: the report folder was not made"
  # One channel only, and both manifest versions by default.
  run_ext FERRET_EXT_OUT_DIR="$ext/out-dir" scripts/lanbox-ext.sh measure --channel esr \
    || { cat "$ext/out" >&2; fail "ext: measure --channel esr failed"; }
  [ "$(run_calls | wc -l)" -eq 2 ] || fail "ext: measure --channel esr: expected the fetch step and one container"
  grep -qx 'FERRET_MEASURE_MANIFESTS=mv3,mv2' "$ext"/calls/call-* || fail "ext: measure: both manifest versions are not the default"
  ! grep -qx 'FERRET_CHANNELS=release' "$ext"/calls/call-* || fail "ext: measure --channel esr started the other channel"

  # Without DEV_RUN nothing changes, even if DEV_TITLE is set, and the owner label stays.
  run_ext DEV_TITLE=ignored scripts/lanbox-ext.sh firefox || fail "ext: run without DEV_RUN failed"
  for f in $(run_calls); do
    ! grep -qE '^(dev\.|--name)' "$f" || fail "ext: labels or name added without DEV_RUN"
    grep -qx 'owner=ferret-core' "$f" || fail "ext: owner label is missing without DEV_RUN"
  done
fi

echo "check-lanbox-labels: ok ($part)"
