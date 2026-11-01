#!/usr/bin/env bash
# The end-to-end gate of the web vault milestone, on the LANBox. It drives the
# separate end-to-end stack (compose project ferret-e2e, scripts/lanbox-ferret-test.sh
# e2e-up) with the Playwright scenarios of web/test/e2e-stack, and does the parts
# that only the Docker host can do: search the server's data files, restart the
# container, move the server's test clock. Never the stack of the owner.
#
#   scripts/lanbox-ferret-e2e-gate.sh            everything
#   scripts/lanbox-ferret-e2e-gate.sh browsers   the scenarios in every browser (and the data search)
#   scripts/lanbox-ferret-e2e-gate.sh restart    restart the container; lost opaque_setup refuses to start
#   scripts/lanbox-ferret-e2e-gate.sh limits     session limits with the moved clock
#
# Steps:
#  1. For each browser: a fresh stack, the scenarios 01 to 09 (setup, sign-in,
#     items, two browsers, lock, hand-over to the admin origin, transport, no
#     plaintext in the traffic, no policy violation), then the search for the
#     secrets of the run in the data directory and the server log.
#  2. On the first browser's stack: restart the container and sign in again; then
#     remove opaque_setup and check that the server refuses to start.
#  3. A fresh stack: make the account and four sessions at clock offset 0, then
#     move the clock forward only, asking Ferret's guard about each session at
#     every step: the vault session ends after 12 hours idle or 7 days in all, the
#     admin session after 1 hour idle or 12 hours in all.
#
# Env: FERRET_DOCKER_ARGS (default "--context unraid"), FERRET_E2E_BROWSERS
# (default "chromium firefox webkit"), FERRET_WASM_LOCAL=1 (build against web/wasm.local.tar.gz;
# the gate says which package it ran against).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."
# The helpers of the stack script (it only defines functions when sourced).
# shellcheck source=scripts/lanbox-ferret-test.sh
. scripts/lanbox-ferret-test.sh

browsers="${FERRET_E2E_BROWSERS:-chromium firefox webkit}"
main_specs=(01-setup 02-signin 03-vault 04-sync 05-lock 06-admin 07-transport 08-plaintext 09-csp)
failures=0
vault_origin=https://vault-e2e.test
admin_origin=https://admin-e2e.test

say() { printf '\n== %s\n' "$*" >&2; }
ok() { printf '  ok    %s\n' "$*" >&2; }
bad() {
  printf '  FAIL  %s\n' "$*" >&2
  failures=$((failures + 1))
}
check() { # label, wanted, got
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (wanted $2, got $3)"; fi
}

# The JSON a phase left, by name (the runner prints `name`, the JSON, an empty line).
left() { # output, name
  printf '%s\n' "$1" | awk -v n="$2" '$0 == n { getline; print; exit }'
}
# A member of a JSON document on stdin; the path is dot separated.
jget() {
  node -e 'let o = JSON.parse(require("fs").readFileSync(0, "utf8")); for (const k of process.argv[1].split(".")) o = o[k]; process.stdout.write(typeof o === "string" ? o : JSON.stringify(o));' "$1"
}

# Runs the Playwright files on the stack in one browser. The state the run leaves is
# in $phase_out; the result is the tests' exit code.
phase_out=""
run_phase() { # phase name, browser, files...
  local phase="$1" browser="$2" rc=0
  shift 2
  phase_out="$(FERRET_E2E_PHASE="$phase" e2e_run "--project=$browser" "$@")" || rc=$?
  return "$rc"
}

# --------------------------------------------------------------- data search

# Searches the data directory of the app, and separately its log, for each secret
# of the run. The files are read as bytes: the database file, its write-ahead log,
# the secrets, the backups. Each half has a control that must be found, so an empty
# capture cannot pass.
search_data() { # needles json, state json
  local needles="$1" state="$2" data log name value count total=0 line
  data="$(mktemp)"
  log="$(mktemp)"
  # As the server user: the secret files are mode 0600 and the container has no capability to override that.
  dk exec -u 1000:1000 "$e2e_app" tar -c -C / data > "$data"
  dk logs "$e2e_app" > "$log" 2>&1
  # The controls: the account's e-mail is stored in the clear on purpose, and the
  # log names the data directory at start-up.
  count="$(grep -aFc -- "$(printf '%s' "$state" | jget email)" "$data" || true)"
  if [ "${count:-0}" -ge 1 ]; then ok "data search: the control in the data files (the e-mail address) is found"; else bad "data search: the control in the data files (the e-mail address) was not found"; fi
  count="$(grep -aFc -- "data_dir=/data" "$log" || true)"
  if [ "${count:-0}" -ge 1 ]; then ok "data search: the control in the log (the start-up line) is found"; else bad "data search: the control in the log (the start-up line) was not found"; fi
  while IFS=$'	' read -r name value; do
    total=$((total + 1))
    for line in data log; do
      count="$(grep -aFc -- "$value" "$([ "$line" = data ] && echo "$data" || echo "$log")" || true)"
      check "server_never_sees_plaintext: no $name in the $line" 0 "${count:-0}"
    done
  done < <(printf '%s' "$needles" | node -e 'for (const n of JSON.parse(require("fs").readFileSync(0, "utf8"))) console.log(n.name + "	" + n.value);')
  # A list that failed to parse would search for nothing and pass.
  if [ "$total" -ge 8 ]; then ok "data search: $total secrets searched"; else bad "data search: only $total secrets were searched"; fi
  rm -f "$data" "$log"
}

# Says which WebAssembly package the stack under test was built against.
note_wasm() {
  local local_pkg
  local_pkg="$(dk image inspect -f '{{index .Config.Labels "ferret.wasm.local"}}' "$e2e_image" 2>/dev/null || true)"
  if [ "$local_pkg" = 1 ]; then
    say "WebAssembly package: LOCAL (web/wasm.local.tar.gz), not the published one"
  else
    say "WebAssembly package: the published one (web/wasm.lock.json)"
  fi
}

# ------------------------------------------------------------------ browsers

browsers_phase() {
  local browser state needles first=1
  for browser in $browsers; do
    say "scenarios in $browser on a fresh stack"
    e2e_up >&2
    note_wasm
    if run_phase main "$browser" "${main_specs[@]}"; then ok "$browser: scenarios 01 to 09 passed"; else bad "$browser: the scenarios failed"; fi
    state="$(left "$phase_out" state)"
    needles="$(left "$phase_out" needles)"
    if [ -z "$state" ] || [ -z "$needles" ]; then
      bad "$browser: the run left no state, so the data was not searched"
    else
      search_data "$needles" "$state"
    fi
    if [ "$first" = 1 ]; then
      first=0
      restart_phase "$browser" "$state"
    fi
  done
}

# ------------------------------------------------------------------- restart

wait_healthy() {
  for _ in $(seq 1 60); do
    [ "$(dk inspect -f '{{.State.Health.Status}}' "$e2e_app" 2>/dev/null || true)" = healthy ] && return 0
    sleep 1
  done
  return 1
}

restart_phase() { # browser, state
  local browser="$1" state="$2" running exitcode logs
  say "restart_container_keeps_data"
  if [ -z "$state" ]; then
    bad "restart: no state from the main run"
    return 0
  fi
  dk restart "$e2e_app" > /dev/null
  if wait_healthy; then ok "the container is healthy again after the restart"; else
    bad "the container did not become healthy after the restart"
    return 0
  fi
  if FERRET_E2E_STATE="$state" run_phase restart "$browser" phase-restart && [ -n "$(left "$phase_out" restart)" ]; then
    ok "restart_container_keeps_data: signed in again, the data is there"
  else
    bad "restart_container_keeps_data: the sign-in or the data check failed"
  fi

  say "a lost opaque_setup refuses to start"
  dk stop "$e2e_app" > /dev/null
  dk run --rm --name ferret-e2e-wipe --label "$e2e_label" --entrypoint rm \
    -v ferret-e2e-data:/data "$e2e_image" -f /data/opaque_setup
  dk start "$e2e_app" > /dev/null
  running=true
  for _ in $(seq 1 30); do
    running="$(dk inspect -f '{{.State.Running}}' "$e2e_app")"
    [ "$running" = false ] && break
    sleep 1
  done
  exitcode="$(dk inspect -f '{{.State.ExitCode}}' "$e2e_app")"
  logs="$(dk logs "$e2e_app" 2>&1 | tail -20)"
  check "the server did not stay up without opaque_setup" false "$running"
  if [ "$exitcode" != 0 ]; then ok "the server exited with a failure (code $exitcode)"; else bad "the server exited with code 0"; fi
  case "$logs" in
    # The file check comes first: a secret file that is missing is never made again once the
    # server has run. (The same loss with the file check passed is the start-up decision
    # SetupLostWhileAccountsExist, tested in the server library.)
    *"secret file is missing"*"restore it from a backup"*) ok "the refusal says a secret file is missing and to restore it from a backup" ;;
    *) bad "the log does not hold the refusal text: $(printf '%s' "$logs" | tail -3)" ;;
  esac
}

# -------------------------------------------------------------------- limits

# The status of GET /api/auth/session with a cookie header, asked from a throwaway
# container on the stack's network (no browser).
# The script for the container is in single quotes on purpose.
# shellcheck disable=SC2016
probe() { # origin, cookie header
  local pem
  pem="$(e2e_ca)"
  e2e_runner_image
  dk run --rm -i --init --name "ferret-e2e-probe-$$-$RANDOM" --label "$e2e_label" --network "$e2e_network" --cpus 1 --memory 512m \
    -e CA_PEM="$pem" "$runner_image" \
    sh -c 'printf "%s\n" "$CA_PEM" > /tmp/ca.crt; NODE_EXTRA_CA_CERTS=/tmp/ca.crt exec node --input-type=module - "$@"' sh "$1" "$2" \
    < web/test/e2e-stack/probe.mjs
}

# Moves the clock forward to this offset (seconds from the real time).
step_to() { e2e_clock "$1" > /dev/null; }

limits_phase() {
  local browser state sessions t idle_v idle_a kept_v kept_a
  browser="$(printf '%s' "$browsers" | awk '{print $1}')"
  say "session_limits at the guard, with the moved clock"
  e2e_up >&2
  note_wasm
  if ! run_phase limits-setup "$browser" phase-limits; then
    bad "limits: the account was not made"
    return 0
  fi
  state="$(left "$phase_out" state)"
  if ! FERRET_E2E_STATE="$state" run_phase limits-signin "$browser" phase-limits; then
    bad "limits: the sign-ins failed"
    return 0
  fi
  sessions="$(left "$phase_out" sessions)"
  if [ -z "$sessions" ]; then
    bad "limits: no sessions were left"
    return 0
  fi
  idle_v="$(printf '%s' "$sessions" | jget idle.vault)"
  idle_a="$(printf '%s' "$sessions" | jget idle.admin)"
  kept_v="$(printf '%s' "$sessions" | jget kept.vault)"
  kept_a="$(printf '%s' "$sessions" | jget kept.admin)"
  # The clock was at offset 0 for all of this; it only goes forward from here.
  check "offset 0: kept vault session" 200 "$(probe "$vault_origin" "$kept_v")"
  check "offset 0: kept admin session" 200 "$(probe "$admin_origin" "$kept_a")"

  # Admin, 1 hour idle: the kept admin session is used every 55 minutes and lives
  # on; the idle one is not used again and is over at +65 minutes. (The idle sessions
  # are asked only at the time they should be over, because asking is using.)
  step_to 3300
  check "+55 min: kept admin session" 200 "$(probe "$admin_origin" "$kept_a")"
  check "+55 min: kept vault session" 200 "$(probe "$vault_origin" "$kept_v")"
  step_to 3900
  check "admin ends after 1 hour idle: idle admin session at +65 min" 401 "$(probe "$admin_origin" "$idle_a")"
  check "+65 min: kept admin session" 200 "$(probe "$admin_origin" "$kept_a")"
  check "+65 min: kept vault session" 200 "$(probe "$vault_origin" "$kept_v")"
  t=3900
  while [ $((t + 3300)) -lt 42300 ]; do
    t=$((t + 3300))
    step_to "$t"
    check "+$((t / 60)) min: kept admin session (used within the hour)" 200 "$(probe "$admin_origin" "$kept_a")"
    check "+$((t / 60)) min: kept vault session" 200 "$(probe "$vault_origin" "$kept_v")"
  done

  # Admin, 12 hours in all: good at 11 h 45 min, over at 12 h 10 min although it was used 25 minutes before.
  step_to 42300
  check "+11 h 45 min: kept admin session is within 12 hours" 200 "$(probe "$admin_origin" "$kept_a")"
  check "+11 h 45 min: kept vault session" 200 "$(probe "$vault_origin" "$kept_v")"
  step_to 43800
  check "admin ends after 12 hours in all: kept admin session at +12 h 10 min" 401 "$(probe "$admin_origin" "$kept_a")"
  # Vault, 12 hours idle: the idle vault session was never used since the sign-in.
  check "vault ends after 12 hours idle: idle vault session at +12 h 10 min" 401 "$(probe "$vault_origin" "$idle_v")"
  check "+12 h 10 min: the kept vault session was used 25 minutes ago and is good" 200 "$(probe "$vault_origin" "$kept_v")"

  # Vault, 7 days in all: the kept vault session is used every 11 hours.
  t=43800
  while [ $((t + 39600)) -lt 600000 ]; do
    t=$((t + 39600))
    step_to "$t"
    check "+$((t / 3600)) h: kept vault session (used within 12 hours)" 200 "$(probe "$vault_origin" "$kept_v")"
  done
  step_to 603000
  check "+6 d 23 h 30 min: kept vault session is within 7 days" 200 "$(probe "$vault_origin" "$kept_v")"
  step_to 606600
  check "vault ends after 7 days in all: kept vault session at +7 d 30 min" 401 "$(probe "$vault_origin" "$kept_v")"
  # The clock is not set back: the next e2e-up makes a new stack with no offset.
}

# ---------------------------------------------------------------------- main

main_gate() {
  local first
  case "${1:-all}" in
    all)
      browsers_phase
      limits_phase
      ;;
    browsers) browsers_phase ;;
    restart)
      first="$(printf '%s' "$browsers" | awk '{print $1}')"
      e2e_up >&2
      run_phase main "$first" "${main_specs[@]}" || bad "the scenarios failed"
      restart_phase "$first" "$(left "$phase_out" state)"
      ;;
    limits) limits_phase ;;
    *)
      sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
      exit 2
      ;;
  esac
  say "the stack is left running for a look; remove it with: scripts/lanbox-ferret-test.sh e2e-down"
  if [ "$failures" -eq 0 ]; then
    echo "e2e gate: all checks passed" >&2
  else
    echo "e2e gate: $failures check(s) failed" >&2
    exit 1
  fi
}

main_gate "$@"
