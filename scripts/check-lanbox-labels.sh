#!/usr/bin/env bash
# Checks the optional DEV_RUN and DEV_TITLE settings of scripts/lanbox.sh with a
# stand-in docker program that only records its arguments. Nothing is sent to a
# Docker host.
set -euo pipefail
cd "$(dirname "$0")/.."

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

# Runs lanbox.sh with the stand-in docker. Extra variables come as arguments.
run_lanbox() {
  rm -f "$work/log"
  env PATH="$work/bin:$PATH" DOCKER_STUB_LOG="$work/log" "$@" \
    scripts/lanbox.sh --exec true > "$work/out" 2>&1
}

# A run id that is not allowed stops the script before it calls docker.
bad_ids=(Bad_Name -dash UPPER "two words" "$(printf 'ok\nBAD')" "$(printf 'a%.0s' $(seq 1 64))")
for id in "${bad_ids[@]}"; do
  if run_lanbox DEV_RUN="$id"; then
    fail "DEV_RUN='$id' was accepted"
  fi
  [ ! -e "$work/log" ] || fail "DEV_RUN='$id' reached docker run"
  grep -q 'DEV_RUN must match' "$work/out" || fail "DEV_RUN='$id' gave no message"
done

# A valid run id adds the label and the name.
run_lanbox DEV_RUN=m1-t13-test DEV_TITLE="Ferret tests" || { cat "$work/out" >&2; fail "valid DEV_RUN failed"; }
grep -qx 'dev.run=m1-t13-test' "$work/log" || fail "dev.run label is missing"
grep -qx 'dev.title=Ferret tests' "$work/log" || fail "dev.title label is missing"
grep -qxE 'ferret-m1-t13-test-[0-9]+' "$work/log" || fail "container name is wrong"
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

echo "check-lanbox-labels: ok"
