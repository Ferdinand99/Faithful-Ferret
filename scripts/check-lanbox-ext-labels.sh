#!/usr/bin/env bash
# Checks the container names, labels and networks of scripts/lanbox-ext.sh with a
# stand-in docker program that only records its arguments. Nothing is sent to a
# Docker host.
#
#   scripts/check-lanbox-ext-labels.sh
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat > "$work/bin/docker" <<'STUB'
#!/usr/bin/env bash
# One file per call: the arguments, one per line. `run` reads its input from stdin
# (drain it); the fetch step answers with a few bytes, as the real one answers
# with the WASM archive. `image inspect` answers "present" unless told otherwise.
n=$(( $(ls "$DOCKER_STUB_DIR" 2>/dev/null | wc -l) + 1 ))
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
      [ "${DOCKER_STUB_IMAGE:-present}" = present ] || exit 1
      exit 0
      ;;
  esac
done
exit 0
STUB
chmod +x "$work/bin/docker"
cat > "$work/stack.sh" <<'STUB'
#!/usr/bin/env bash
# Stands in for scripts/lanbox-ferret-test.sh.
printf '%s\n' "$1" >> "$STACK_STUB_LOG"
case "$1" in
  e2e-ca) printf -- '-----BEGIN CERTIFICATE-----\nstand-in\n-----END CERTIFICATE-----\n' ;;
esac
STUB

fail() { echo "check-lanbox-ext-labels: $*" >&2; exit 1; }

# Runs lanbox-ext.sh with the stand-in docker. Extra variables, then the mode and options.
# The calls are in $work/calls/call-<n>.
run_ext() {
  rm -rf "$work/calls"; mkdir "$work/calls"
  rm -f "$work/stack.log"
  env PATH="$work/bin:$PATH" DOCKER_STUB_DIR="$work/calls" STACK_STUB_LOG="$work/stack.log" \
    FERRET_EXT_STACK_SCRIPT="$work/stack.sh" "$@" > "$work/out" 2>&1
}
calls() { ls "$work/calls" | wc -l; }
# The calls of one kind (the second word of the call: run, build, image).
call_files() { grep -lx "$1" "$work"/calls/call-* 2>/dev/null || true; }

# A run id that is not allowed stops the script before it calls docker.
bad_ids=(Bad_Name -dash UPPER "two words" "$(printf 'ok\nBAD')" "$(printf 'a%.0s' $(seq 1 64))")
for id in "${bad_ids[@]}"; do
  if run_ext DEV_RUN="$id" scripts/lanbox-ext.sh firefox; then
    fail "DEV_RUN='$id' was accepted"
  fi
  [ "$(calls)" -eq 0 ] || fail "DEV_RUN='$id' reached docker"
  grep -q 'DEV_RUN must match' "$work/out" || fail "DEV_RUN='$id' gave no message"
done

# Options that do not exist stop the script before docker.
for bad in "firefox --channel nightly" "firefox --manifest mv4" "firefox --nope" "unit --channel release" "lint --grep x" "firefox --no-up" "other"; do
  # shellcheck disable=SC2086
  if run_ext scripts/lanbox-ext.sh $bad; then fail "'$bad' was accepted"; fi
  [ "$(calls)" -eq 0 ] || fail "'$bad' reached docker"
done

# Every container the firefox step starts is named, labelled and removed on exit.
run_ext DEV_RUN=ext-probe DEV_TITLE="Probe run" scripts/lanbox-ext.sh firefox --channel esr --grep pinned \
  || { cat "$work/out" >&2; fail "firefox run failed"; }
runs=$(grep -lx run "$work"/calls/call-* | wc -l)
[ "$runs" -eq 2 ] || fail "expected two containers (fetch and tests), saw $runs"
for f in $(grep -lx run "$work"/calls/call-*); do
  grep -qx 'owner=ferret-core' "$f" || fail "owner label is missing in $(basename "$f")"
  grep -qx 'dev.run=ext-probe' "$f" || fail "dev.run label is missing in $(basename "$f")"
  grep -qx 'dev.title=Probe run' "$f" || fail "dev.title label is missing in $(basename "$f")"
  grep -qx -e '--rm' "$f" || fail "--rm is missing in $(basename "$f")"
  grep -qxE 'ferret-ext-probe(-fetch)?-[0-9]+' "$f" || fail "container name is wrong in $(basename "$f")"
done
names=$(grep -hxE 'ferret-ext-probe(-fetch)?-[0-9]+' "$work"/calls/call-* | sort | uniq -d | wc -l)
[ "$names" -eq 0 ] || fail "two containers have the same name"
grep -qx 'FERRET_CHANNELS=esr' "$work"/calls/call-* || fail "the channel is not passed on"
grep -qx 'FERRET_GREP=pinned' "$work"/calls/call-* || fail "the test name filter is not passed on"

# A missing runner image is built, with the label.
run_ext DOCKER_STUB_IMAGE=absent DEV_RUN=ext-probe scripts/lanbox-ext.sh firefox \
  || { cat "$work/out" >&2; fail "firefox run with a missing image failed"; }
build=$(grep -lx build "$work"/calls/call-*) || fail "the missing image was not built"
grep -qx 'owner=ferret-core' "$build" || fail "the image build has no owner label"
grep -qxE 'ferret-ext-runner:[0-9a-f]{12}' "$build" || fail "the image tag is wrong"

# unit and lint: one container, named and labelled.
for mode in unit lint; do
  run_ext DEV_RUN=ext-probe-unit scripts/lanbox-ext.sh "$mode" || { cat "$work/out" >&2; fail "$mode run failed"; }
  [ "$(calls)" -eq 1 ] || fail "$mode: expected one docker call"
  grep -qx 'owner=ferret-core' "$work/calls/call-1" || fail "$mode: owner label is missing"
  grep -qx 'dev.run=ext-probe-unit' "$work/calls/call-1" || fail "$mode: dev.run label is missing"
  grep -qxE 'ferret-ext-probe-unit-[0-9]+' "$work/calls/call-1" || fail "$mode: container name is wrong"
done

# Without DEV_RUN nothing changes, even if DEV_TITLE is set, and the owner label stays.
run_ext DEV_TITLE=ignored scripts/lanbox-ext.sh firefox || fail "run without DEV_RUN failed"
for f in $(grep -lx run "$work"/calls/call-*); do
  ! grep -qE '^(dev\.|--name)' "$f" || fail "labels or name added without DEV_RUN"
  grep -qx 'owner=ferret-core' "$f" || fail "owner label is missing without DEV_RUN"
done

echo "check-lanbox-ext-labels: ok"
