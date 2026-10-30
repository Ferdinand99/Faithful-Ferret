#!/usr/bin/env bash
# Checks of the Faithful Ferret test stacks that need the LANBox Docker host
# (never Docker Desktop, never Tower). The checks that need no host are in
# scripts/check-ferret-test-stack.sh.
#
#   scripts/lanbox-ferret-e2e-check.sh          all checks
#   scripts/lanbox-ferret-e2e-check.sh images   the image checks only (no e2e stack)
#   scripts/lanbox-ferret-e2e-check.sh reset    the reset check only
#   scripts/lanbox-ferret-e2e-check.sh stack    the e2e stack checks only
#
# What it checks:
#  * release_image_has_no_e2e_clock: an image built without FEATURES says
#    `features: none`, and its binary holds neither the clock hook nor the name
#    of its variable; the image of the e2e stack says `features: e2e-clock`.
#  * e2e_clock_cannot_be_enabled_by_environment_alone: the release image ignores
#    FERRET_E2E_CLOCK_FILE.
#  * image_runs_as_uid_1000: the server process of the image runs as uid/gid 1000
#    with no capabilities, and owns its data.
#  * reset_removes_only_ferret_test_resources: the reset step removes the
#    resources that carry its label and nothing else (decoys with another label,
#    no label or another name survive; the owner's container and volume are
#    still there), and the confirmation cancels on anything but "reset".
#  * the e2e stack: shares no container, network or volume with the owner's
#    stack and leaves it running; has one network, no volume, no published
#    port; starts fresh each time; moves its clock on request; the browsers of
#    scripts/lanbox-ferret-test.sh e2e-run reach it over https, and the TLS
#    terminator is the only trusted proxy.
#
# Everything this creates is named ferret-e2e* and labelled owner=ferret-e2e (the
# reset check also uses owner=ferret-e2e-resettest on its decoys) and is removed
# on exit. The owner's stack (ferret-test) is only read.
#
# Env overrides: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_E2E_BROWSERS
# (the Playwright projects of the stack check, default "chromium firefox webkit").
# The Go templates and awk programs below are in single quotes on purpose.
# shellcheck disable=SC2016
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."

# The functions and names of the deploy script (only defined, not run).
# shellcheck disable=SC1091
source scripts/lanbox-ferret-test.sh

ok=0
bad=0
pass() { echo "  ok    $1"; ok=$((ok + 1)); }
fail() { echo "  FAIL  $1"; bad=$((bad + 1)); }
expect() { # name, expected, got
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
contains() { # name, text, needle
  case "$2" in *"$3"*) pass "$1" ;; *) fail "$1 (no '$3' in '$2')" ;; esac
}
# Whether a line is in a text.
has() { printf '%s\n' "$2" | grep -qxF -- "$1"; }

release_image=ferret-e2e-check-release:latest
probe=ferret-e2e-check-run
uid_probe=ferret-e2e-check-uid
markers=(FERRET_E2E_CLOCK_FILE e2e-clock e2e_clock)

cleanup() {
  dk rm -f "$uid_probe" "$probe" >/dev/null 2>&1 || true
  dk image rm "$release_image" >/dev/null 2>&1 || true
  e2e_down >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Whether the server binary in an image holds a string.
binary_has() { # image, string
  if dk run --rm --name "$probe" --label "$e2e_label" --entrypoint grep "$1" -q -- "$2" /usr/local/bin/ferret 2>/dev/null; then echo yes; else echo no; fi
}
# How many of the marker strings the binary holds.
marker_count() { # image
  local n=0 m
  for m in "${markers[@]}"; do
    [ "$(binary_has "$1" "$m")" = yes ] && n=$((n + 1))
  done
  echo "$n"
}

check_images() {
  echo "images"
  local log
  log="$(mktemp)"
  dk build --label "$e2e_label" -t "$release_image" --build-arg FEATURES= -f docker/server.Dockerfile . >"$log" 2>&1 \
    || { tail -n 40 "$log" >&2; rm -f "$log"; echo "the release image did not build" >&2; exit 1; }
  rm -f "$log"
  local info
  info="$(dk run --rm --name "$probe" --label "$e2e_label" "$release_image" --build-info)"
  contains "release_image_has_no_e2e_clock: --build-info" "$info" "features: none"
  expect "release_image_has_no_e2e_clock: the binary holds none of ${markers[*]}" 0 "$(marker_count "$release_image")"
  info="$(dk run --rm --name "$probe" --label "$e2e_label" -e FERRET_E2E_CLOCK_FILE=/tmp/clock "$release_image" --build-info)"
  contains "e2e_clock_cannot_be_enabled_by_environment_alone" "$info" "features: none"

  # image_runs_as_uid_1000: start the release image and look at the process.
  dk run -d --name "$uid_probe" --label "$e2e_label" --tmpfs /data --cpus 1 --memory 256m \
    -e FERRET_VAULT_URL=https://vault-check.test -e FERRET_ADMIN_URL=https://admin-check.test \
    "$release_image" >/dev/null
  local up=no
  for _ in $(seq 1 40); do
    if dk exec "$uid_probe" wget -q -O /dev/null http://127.0.0.1:3041/healthz 2>/dev/null; then up=yes; break; fi
    sleep 1
  done
  expect "image_runs_as_uid_1000: the server is up" yes "$up"
  expect "image_runs_as_uid_1000: uid and gid of the server process (real, effective, saved, fs)" \
    "1000 1000 1000 1000/1000 1000 1000 1000" \
    "$(dk exec "$uid_probe" sh -c 'u=$(awk "/^Uid:/{print \$2,\$3,\$4,\$5}" /proc/1/status); g=$(awk "/^Gid:/{print \$2,\$3,\$4,\$5}" /proc/1/status); echo "$u/$g"')"
  expect "image_runs_as_uid_1000: the process is the server" ferret "$(dk exec "$uid_probe" cat /proc/1/comm)"
  expect "image_runs_as_uid_1000: no capabilities" 0000000000000000 "$(dk exec "$uid_probe" awk '/^CapEff:/{print $2}' /proc/1/status)"
  expect "image_runs_as_uid_1000: the database belongs to 1000:1000" "1000:1000" "$(dk exec "$uid_probe" stat -c %u:%g /data/ferret.sqlite)"
  dk rm -f "$uid_probe" >/dev/null
}

# Everything on the host, one line per resource: "c:name", "v:name", "n:name",
# "i:repository:tag". Sorted.
all_resources() {
  {
    dk ps -a --format 'c:{{.Names}}'
    dk volume ls --format 'v:{{.Name}}'
    dk network ls --format 'n:{{.Name}}'
    dk images --format 'i:{{.Repository}}:{{.Tag}}'
  } | sort -u
}

check_reset() {
  echo "reset"
  local decoy_label=owner=ferret-e2e-resettest
  local victim=ferret-e2e-reset-victim bystander=ferret-e2e-reset-bystander
  local base="alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f"
  # The resources the reset is meant to remove (they carry the label it is given)...
  dk create --name "$victim" --label "$decoy_label" "$base" true >/dev/null
  dk volume create --label "$decoy_label" "$victim" >/dev/null
  dk network create --label "$decoy_label" "$victim" >/dev/null
  dk tag "$base" "$victim:latest"
  # ... and the ones it must leave alone: another label value, the label of the
  # e2e stack, and no label at all.
  dk create --name "$bystander-a" --label owner=ferret-e2e-resettest-not "$base" true >/dev/null
  dk create --name "$bystander-b" --label "$e2e_label" "$base" true >/dev/null
  dk create --name "$bystander-c" "$base" true >/dev/null
  dk volume create --label owner=ferret-e2e-resettest-not "$bystander-a" >/dev/null
  dk volume create "$bystander-c" >/dev/null
  dk network create --label "$e2e_label" "$bystander-b" >/dev/null
  dk network create "$bystander-c" >/dev/null
  dk tag "$base" "$bystander-c:latest"

  local before after owner_id
  before="$(all_resources)"
  owner_id="$(dk inspect -f '{{.Id}} {{.State.StartedAt}}' ferret-test-app 2>/dev/null || true)"

  # The reset step of the deploy script, with the decoy label and image.
  (
    label=$decoy_label
    image="$victim:latest"
    reset_resources
  )

  after="$(all_resources)"
  local line
  for line in "c:$victim" "v:$victim" "n:$victim" "i:$victim:latest"; do
    if has "$line" "$before" && ! has "$line" "$after"; then pass "reset: $line was removed"; else fail "reset: $line was removed"; fi
  done
  for line in "c:$bystander-a" "c:$bystander-b" "c:$bystander-c" "v:$bystander-a" "v:$bystander-c" \
              "n:$bystander-b" "n:$bystander-c" "i:$bystander-c:latest" "v:ferret-test-data" "c:ferret-test-app"; do
    if has "$line" "$after"; then pass "reset: $line survived"; else fail "reset: $line survived"; fi
  done
  # What disappeared in all: the four labelled resources and nothing that anyone
  # would miss. (A throwaway container of another job, which has an automatic
  # name, may end while this runs; a volume, network, image or named container
  # may not.)
  local gone extra
  gone="$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))"
  extra="$(printf '%s\n' "$gone" | grep -vxF -e "c:$victim" -e "v:$victim" -e "n:$victim" -e "i:$victim:latest" \
           | grep -vE '^c:[a-z]+_[a-z]+$' | grep -v '^$' || true)"
  expect "reset: nothing else was removed" "" "$extra"
  expect "reset: the owner's container is untouched" "$owner_id" "$(dk inspect -f '{{.Id}} {{.State.StartedAt}}' ferret-test-app 2>/dev/null || true)"

  # The confirmation: anything but "reset" cancels and removes nothing. The real
  # script runs against a Docker host that does not exist, never against the live
  # stack: if the confirmation ever stopped working, the reset would fail on the
  # missing host instead of removing the owner's container and volume. A cancel
  # touches no host at all, so the output must hold no Docker error.
  local out rc=0
  out="$(echo no | FERRET_DOCKER_ARGS="-H unix:///ferret-e2e-no-such-host.sock" scripts/lanbox-ferret-test.sh reset 2>&1)" || rc=$?
  expect "reset: a wrong answer cancels" 1 "$rc"
  expect "reset: a wrong answer cancels (message)" "This removes the ferret-test container, network, image and the data volume ferret-test-data.
Type \"reset\" to go on: cancelled" "$out"
  case "$out" in *ocker*|*rror*|*annot*) fail "reset: the cancel touched a Docker host ($out)" ;; *) pass "reset: the cancel touched no Docker host" ;; esac
  after="$(all_resources)"
  if has c:ferret-test-app "$after" && has v:ferret-test-data "$after"; then
    pass "reset: after the cancelled reset the owner's container and volume are there"
  else
    fail "reset: after the cancelled reset the owner's container and volume are there"
  fi

  dk rm -f "$bystander-a" "$bystander-b" "$bystander-c" >/dev/null
  dk volume rm "$bystander-a" "$bystander-c" >/dev/null
  dk network rm "$bystander-b" "$bystander-c" >/dev/null
  dk image rm "$bystander-c:latest" >/dev/null
}

# Runs e2e-up quietly (compose is noisy) and shows the end of its output on failure.
quiet_up() {
  local log
  log="$(mktemp)"
  e2e_up >"$log" 2>&1 || { tail -n 40 "$log" >&2; rm -f "$log"; echo "e2e-up failed" >&2; exit 1; }
  rm -f "$log"
}

check_stack() {
  echo "e2e stack"
  local owner_before owner_after
  owner_before="$(dk inspect -f '{{.Id}} {{.State.StartedAt}} {{.HostConfig.NetworkMode}}' ferret-test-app)"
  quiet_up
  # Fresh every time: markers in the data directory and in /tmp are gone after
  # the next e2e-up.
  dk exec -u 1000:1000 "$e2e_app" sh -c 'echo x > /data/marker && echo x > /tmp/scratch'
  local first_id
  first_id="$(dk inspect -f '{{.Id}}' "$e2e_app")"
  quiet_up
  expect "e2e-up: an empty data directory and /tmp" "none" \
    "$(dk exec "$e2e_app" sh -c 'if [ -e /data/marker ] || [ -e /tmp/scratch ]; then echo found; else echo none; fi')"
  if [ "$first_id" != "$(dk inspect -f '{{.Id}}' "$e2e_app")" ]; then pass "e2e-up: the container is new"; else fail "e2e-up: the container is new"; fi

  # Isolation.
  expect "e2e: the containers of the project" "$e2e_app $e2e_tls" \
    "$(dk ps -a --filter "label=$e2e_label" --format '{{.Names}}' | sort | tr '\n' ' ' | sed 's/ $//')"
  expect "e2e: the app is on its own network only" "$e2e_network" \
    "$(dk inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$e2e_app" | sed 's/ $//')"
  expect "e2e: the terminator is on its own network only" "$e2e_network" \
    "$(dk inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$e2e_tls" | sed 's/ $//')"
  expect "e2e: no volumes or bind mounts" "" \
    "$(dk inspect -f '{{range .Mounts}}{{.Type}}:{{.Name}}{{.Source}} {{end}}' "$e2e_app" "$e2e_tls" | tr -d ' \n')"
  expect "e2e: no published port (a port the image declares is only exposed)" "" \
    "$(dk inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$e2e_app" "$e2e_tls" | tr -d ' \n')"
  expect "e2e: the network has only the two containers" "$e2e_app $e2e_tls" \
    "$(dk network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$e2e_network" | tr ' ' '\n' | grep -v '^$' | sort | tr '\n' ' ' | sed 's/ $//')"
  expect "e2e: the server runs as uid 1000" "1000" "$(dk exec "$e2e_app" awk '/^Uid:/{print $2}' /proc/1/status)"
  contains "e2e: the e2e image says so" "$(dk run --rm --name "$probe" --label "$e2e_label" "$e2e_image" --build-info)" "features: e2e-clock"
  expect "e2e: the e2e binary holds the clock hook (the variable name and the feature name)" "yes yes" \
    "$(binary_has "$e2e_image" FERRET_E2E_CLOCK_FILE) $(binary_has "$e2e_image" e2e-clock)"
  contains "e2e: the server started with the test clock" "$(dk logs "$e2e_app" 2>&1)" "TEST BUILD: the clock is moved"
  expect "e2e: the server trusts the terminator only" "172.30.250.2" "$(dk exec "$e2e_app" printenv FERRET_TRUSTED_PROXIES)"

  # The clock.
  scripts/lanbox-ferret-test.sh e2e-clock 43200 >/dev/null
  expect "e2e-clock: the server user can read the file" 43200 "$(dk exec -u 1000:1000 "$e2e_app" cat /tmp/e2e-clock)"
  scripts/lanbox-ferret-test.sh e2e-clock 0 >/dev/null
  expect "e2e-clock: and put it back" 0 "$(dk exec -u 1000:1000 "$e2e_app" cat /tmp/e2e-clock)"
  local rc=0
  scripts/lanbox-ferret-test.sh e2e-clock '1; touch /tmp/x' >/dev/null 2>&1 || rc=$?
  expect "e2e-clock: anything but digits is refused" 2 "$rc"

  # The browsers.
  local project rc2=0
  local args=()
  for project in ${FERRET_E2E_BROWSERS:-chromium firefox webkit}; do args+=("--project=$project"); done
  scripts/lanbox-ferret-test.sh e2e-run "${args[@]}" || rc2=$?
  expect "e2e-run: the stack tests pass in every browser" 0 "$rc2"
  contains "e2e: the terminator was seen as a trusted proxy" "$(dk logs "$e2e_app" 2>&1)" "trusted=true"

  # The owner's stack was only read.
  owner_after="$(dk inspect -f '{{.Id}} {{.State.StartedAt}} {{.HostConfig.NetworkMode}}' ferret-test-app)"
  expect "e2e: the owner's container is untouched" "$owner_before" "$owner_after"

  e2e_down >/dev/null
  expect "e2e-down: nothing of the project is left" "" \
    "$( { dk ps -a --filter "label=$e2e_label" --format '{{.Names}}'; dk network ls --filter "label=$e2e_label" --format '{{.Name}}'; dk images -q "$e2e_image"; } | tr -d '\n')"
}

which="${1:-all}"
case "$which" in
  all | images | reset | stack) ;;
  *) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
if [ "$which" = all ] || [ "$which" = images ]; then check_images; fi
if [ "$which" = all ] || [ "$which" = reset ]; then check_reset; fi
if [ "$which" = all ] || [ "$which" = stack ]; then check_stack; fi
echo
echo "$ok ok, $bad failed"
[ "$bad" -eq 0 ]
