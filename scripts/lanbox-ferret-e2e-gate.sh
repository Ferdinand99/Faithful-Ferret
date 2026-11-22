#!/usr/bin/env bash
# The end-to-end gate of the web vault milestone, on the build host. It drives the
# separate end-to-end stack (compose project ferret-e2e, scripts/lanbox-ferret-test.sh
# e2e-up) with the Playwright scenarios of web/test/e2e-stack, and does the parts
# that only the Docker host can do: search the server's data files, restart the
# container, move the server's test clock. Never the stack of the owner.
#
#   scripts/lanbox-ferret-e2e-gate.sh            everything
#   scripts/lanbox-ferret-e2e-gate.sh browsers   the scenarios in every browser (and the data search)
#   scripts/lanbox-ferret-e2e-gate.sh restart    restart the container; lost opaque_setup refuses to start
#   scripts/lanbox-ferret-e2e-gate.sh limits     session limits with the moved clock
#   scripts/lanbox-ferret-e2e-gate.sh m2         the sync scenarios 10 to 17 in every browser
#   scripts/lanbox-ferret-e2e-gate.sh m3         the recovery, export, import and backup scenarios 18 to 26 in every browser
#   scripts/lanbox-ferret-e2e-gate.sh m5a        the device scenarios (27) in every browser, a fresh stack for each
#   scripts/lanbox-ferret-e2e-gate.sh --parallel [step]   (or all-parallel) the same, but one stack per browser, all at once
#
# With --parallel every browser runs the steps on a stack of its own, at the same time: its own suffix (the
# name of the browser), network and, when DEV_RUN is set, dev.run=<DEV_RUN>-<browser>. What each one prints
# goes to its own log file (test-results/out/parallel/<browser>.log), and when all have ended one table
# says which passed. The exit code is not 0 when any of them failed. The stacks are left running, as after
# a single run; the table says how to remove them.
#
# Steps:
#  1. For each browser: a fresh stack, the scenarios 01 to 09 (setup, sign-in,
#     items, folders, two browsers, lock, unlock after the session has ended,
#     hand-over to the admin origin, transport, no
#     plaintext in the traffic, no policy violation), then the search for the
#     secrets of the run in the data directory and the server log.
#  2. On the first browser's stack: restart the container and sign in again; then
#     remove opaque_setup and check that the server refuses to start.
#  3. A fresh stack: make the account and four sessions at clock offset 0, then
#     move the clock forward only, asking Ferret's guard about each session at
#     every step: the vault session ends after 12 hours idle or 7 days in all, the
#     admin session after 1 hour idle or 12 hours in all.
#  4. The sync scenarios (step m2), in each browser on a fresh stack: the account, then
#     10 conflict, 11 live updates, 12 offline, 13 trash, 14 a malicious server, 15 a
#     restored server (with the browsers kept open while this script takes the snapshot
#     and puts it back), 16 forget this server, 17 one tab runs the sync (the second tab
#     shows the notice, "Use here" moves the vault). The screenshots of every phase are
#     saved in test-results/out/m2-shots/.
#
#  5. The recovery scenarios (step m3), in each browser on a fresh stack, in one run with the host
#     script at hand (it makes the sign-in codes, empties the server, makes and restores a backup
#     set): 18 the emergency sheet, 19 a new browser with the sheet text, 20 a password change, 21
#     recovery with a one-time code, 22 a new recovery key and the backup that follows it, 23 an
#     encrypted export that goes into a fresh account on a wiped server, 24 the foreign import
#     formats and a thousand items, 25 backup, wipe and restore, 26 two tabs. Afterwards the data
#     directory, the backup sets and the server log are searched for the secrets of the run.
#
# Env: FERRET_DOCKER_ARGS (default "--context lanbox"), FERRET_E2E_SUFFIX and FERRET_E2E_SUBNET (another stack name
# and network, see scripts/lanbox-ferret-test.sh), FERRET_E2E_BROWSERS (default "chromium firefox webkit"),
# DEV_RUN and DEV_TITLE (labels for the containers, see scripts/lanbox-ferret-test.sh).
# For --parallel: FERRET_E2E_PARALLEL_SUBNETS (the first three octets of one network for each browser, in the
# order of the browsers; default "172.30.241 172.30.242 172.30.243"), FERRET_E2E_PARALLEL_LOGS (the folder of
# the logs; default test-results/out/parallel) and FERRET_E2E_PARALLEL_WRAP (a command put in front of each
# browser's run of the gate; it sees DEV_RUN and FERRET_E2E_SUFFIX of that run).
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."
# The helpers of the stack script (it only defines functions when sourced).
# shellcheck source=scripts/lanbox-ferret-test.sh
. scripts/lanbox-ferret-test.sh

browsers="${FERRET_E2E_BROWSERS:-chromium firefox webkit}"
m2_sync_specs=(10-conflict 11-live 12-offline 13-trash 14-evil)
m3_specs=(18-sheet 19-new-device 20-password 21-recover 22-recovery-key 23-export-import 24-import-foreign 25-backup-restore 26-tabs)
shots_dir=test-results/out/m2-shots
m5a_specs=(01-setup 27-device)
main_specs=(01-setup 02-signin 03-vault 03-folders 04-sync 05-lock 05-unlock 06-admin 06-admin-signout 07-transport 08-plaintext 09-csp)
failures=0
vault_origin="$e2e_vault_url"
admin_origin="$e2e_admin_url"

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

# ------------------------------------------------------------------ browsers

browsers_phase() {
  local browser state needles first=1
  for browser in $browsers; do
    say "scenarios in $browser on a fresh stack"
    e2e_up >&2
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
  dk run --rm --name "$e2e_project-wipe" --label "$e2e_label" "${e2e_dev_labels[@]}" --entrypoint rm \
    -v "$e2e_data_volume:/data" "$e2e_image" -f /data/opaque_setup
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
  dk run --rm -i --init --name "$e2e_project-probe-$$-$RANDOM" --label "$e2e_label" "${e2e_dev_labels[@]}" --network "$e2e_network" --cpus 1 --memory 512m \
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

# ------------------------------------------------------------------------ m2

# Saves the screenshots a phase left (each is a JSON file with the name and the PNG as base64 on
# the phase's stdout, in the form of `left`: the name, the JSON, an empty line).
save_shots() { # phase output
  mkdir -p "$shots_dir"
  printf '%s\n' "$1" | SHOTS_DIR="$shots_dir" node -e '
const fs = require("fs");
const lines = fs.readFileSync(0, "utf8").split(/\r?\n/);
let n = 0;
for (let i = 0; i < lines.length; i += 1) {
  if (!lines[i].startsWith("shot-")) continue;
  const shot = JSON.parse(lines[i + 1]);
  if (!/^[A-Za-z0-9._-]+$/.test(shot.name)) continue;
  fs.writeFileSync(process.env.SHOTS_DIR + "/" + shot.name + ".png", Buffer.from(shot.png, "base64"));
  n += 1;
}
console.error("  shots: " + n + " saved in " + process.env.SHOTS_DIR);
'
}

# A phase of the sync scenarios: the account of the run is in $2, the files follow.
run_m2() { # phase name, state, browser, files...
  local phase="$1" state="$2" browser="$3" rc=0
  shift 3
  FERRET_E2E_STATE="$state" run_phase "$phase" "$browser" "$@" || rc=$?
  save_shots "$phase_out"
  return "$rc"
}

# What the hosted phase below leaves behind if the script ends in the middle of it (a failure, Ctrl-C): the
# background phase, its output file and the runner container are removed.
hosted_pid=""
hosted_out=""
hosted_cleanup() {
  [ -z "$hosted_pid" ] || kill "$hosted_pid" 2>/dev/null || true
  [ -z "$hosted_out" ] || rm -f "$hosted_out"
  dk rm -f "$e2e_playwright" > /dev/null 2>&1 || true
  hosted_pid=""
  hosted_out=""
}

# One step the tests asked for, in a subshell of its own: a step that fails ends the subshell (the helpers of the stack
# script call exit), never the gate, and is reported to the test as a failure.
host_answer=""
host_step() { # step
  local rc
  host_answer=""
  set +e
  case "$1" in
    snapshot) (set -e; e2e_snapshot) >&2 ;;
    restore) (set -e; e2e_restore_snapshot) >&2 ;;
    clock-[0-9]*) (set -e; e2e_clock "${1#clock-}") >&2 ;;
    reset) (set -e; e2e_reset) >&2 ;;
    backup) host_answer="$(e2e_backup)" ;;
    restore-backup) (set -e; e2e_restore_backup) >&2 ;;
    restore-backup-*) (set -e; e2e_restore_backup "${1#restore-backup-}") >&2 ;;
    code-*) host_answer="$(e2e_code "${1#code-}")" ;;
    set-count) host_answer="$(e2e_set_count | tr -d ' ')" ;;
    *)
      echo "the tests asked for a step the host does not know: $1" >&2
      false
      ;;
  esac
  rc=$?
  set -e
  # The test asks for the name of the set that a backup made, so that it can be put back later.
  if [ "$rc" = 0 ] && [ "$1" = backup ]; then
    host_answer="$(printf '%s\n' "$host_answer" | sed -n 's/.*backup set \([A-Za-z0-9._-]*\) made.*/\1/p' | head -n 1)"
  fi
  return "$rc"
}

# The same as run_m2, with the browsers kept open while this script does the steps that the tests ask for
# (a snapshot of the server's data, putting it back, moving the server's clock). A test asks by
# writing /tmp/host-request-<step> in the runner container and waits for /tmp/host-done-<step>, or
# /tmp/host-failed-<step> when the step failed (the test then fails). The tests of this phase fail, and
# do not skip, when this script is not there.
hosted_markers="m2-restore"
run_m2_hosted() { # phase name, state, browser, files...
  local phase="$1" state="$2" browser="$3" rc=0 requests request step marker
  shift 3
  hosted_out="$(mktemp)"
  trap 'hosted_cleanup' EXIT INT TERM
  (FERRET_E2E_STATE="$state" FERRET_E2E_PHASE="$phase" e2e_run "--project=$browser" "$@" > "$hosted_out") &
  hosted_pid=$!
  # The runner container has a fixed name for the stack (scripts/lanbox-ferret-test.sh, e2e_run).
  for _ in $(seq 1 600); do
    [ "$(dk inspect -f '{{.State.Running}}' "$e2e_playwright" 2>/dev/null || true)" = true ] && break
    kill -0 "$hosted_pid" 2>/dev/null || break
    sleep 1
  done
  if ! dk exec "$e2e_playwright" touch /tmp/host-ready; then
    bad "$browser: the runner container did not come up, so the tests have no host"
    hosted_cleanup
    trap - EXIT INT TERM
    return 1
  fi
  while kill -0 "$hosted_pid" 2>/dev/null; do
    requests="$(dk exec "$e2e_playwright" sh -c 'ls /tmp/host-request-* 2>/dev/null' 2>/dev/null || true)"
    for request in $requests; do
      step="${request#/tmp/host-request-}"
      dk exec "$e2e_playwright" rm -f "$request" > /dev/null 2>&1 || true
      say "host step for the tests: $step"
      if host_step "$step"; then
        # What the step printed for the test (a sign-in code), before the done file that the test waits for.
        if [ -n "$host_answer" ]; then
          printf '%s' "$host_answer" | dk exec -i "$e2e_playwright" sh -c "cat > '/tmp/host-out-$step'" > /dev/null 2>&1 || true
        fi
        dk exec "$e2e_playwright" touch "/tmp/host-done-$step" > /dev/null 2>&1 || true
      else
        bad "the host step $step failed"
        dk exec "$e2e_playwright" touch "/tmp/host-failed-$step" > /dev/null 2>&1 || true
      fi
    done
    sleep 2
  done
  wait "$hosted_pid" || rc=$?
  phase_out="$(cat "$hosted_out")"
  rm -f "$hosted_out"
  hosted_pid=""
  hosted_out=""
  trap - EXIT INT TERM
  save_shots "$phase_out"
  # Playwright exits 0 when every test of the file was skipped: the tests leave a marker when they have run.
  if [ "$rc" = 0 ]; then
    for marker in $hosted_markers; do
      if [ -z "$(left "$phase_out" "$marker")" ]; then
        echo "the scenarios of $marker left no marker: they did not run" >&2
        rc=1
      fi
    done
  fi
  return "$rc"
}

m2_phase() {
  local browser state
  for browser in $browsers; do
    say "sync scenarios in $browser on a fresh stack"
    e2e_up >&2
    if ! run_phase m2-account "$browser" phase-m2-account; then
      bad "$browser: the account for the sync scenarios was not made"
      continue
    fi
    state="$(left "$phase_out" state)"
    if run_m2 m2-sync "$state" "$browser" "${m2_sync_specs[@]}"; then ok "$browser: scenarios 10 to 14 passed"; else bad "$browser: scenarios 10 to 14 failed"; fi
    if run_m2_hosted m2-restore "$state" "$browser" 15-restored; then ok "$browser: scenario 15 (restored server) passed"; else bad "$browser: scenario 15 (restored server) failed"; fi
    if run_m2 m2-forget "$state" "$browser" 16-forget; then ok "$browser: scenario 16 (forget this server) passed"; else bad "$browser: scenario 16 (forget this server) failed"; fi
    # Last: it signs in and unlocks several times, and the server limits how often an account may.
    if run_m2 m2-owner "$state" "$browser" 17-owner; then ok "$browser: scenario 17 (one tab runs the sync) passed"; else bad "$browser: scenario 17 (one tab runs the sync) failed"; fi
  done
}

# ------------------------------------------------------------------------ m5a

# The device scenarios (27): a device client in Node signs in as its own device, syncs, is revoked from the
# page "Devices" and by a password change, and stays out of the admin listener; the web vault sends no token
# header; contexts of one browser renew at once. Each browser gets a fresh stack and its own account (01-setup).
# Run it on a stack of its own, so the stack of another run is left alone:
#   FERRET_E2E_SUFFIX=m5a FERRET_E2E_SUBNET=172.30.248 scripts/lanbox-ferret-e2e-gate.sh m5a
m5a_phase() {
  local browser
  for browser in $browsers; do
    say "device scenarios in $browser on a fresh stack"
    e2e_up >&2
    if run_phase m5a "$browser" "${m5a_specs[@]}"; then ok "$browser: the device scenarios passed"; else bad "$browser: the device scenarios failed"; fi
  done
}

# ------------------------------------------------------------------------ m3

# The same search as search_data, in the backup sets of the stack: they hold a copy of the database and of the secret files, so
# a secret of the run must not be in them either. The control is the account's e-mail address, which is stored in the clear.
search_backups() { # needles json, state json
  local needles="$1" state="$2" data name value count sets total=0
  data="$(mktemp)"
  dk run --rm --name "$e2e_project-backup-read" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none     --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges:true --memory 128m     -v "$e2e_backups_volume:/backups:ro" "$alpine_image" tar -c -C / backups > "$data"
  sets="$(tar -tf "$data" | grep -c 'MANIFEST.json$' || true)"
  if [ "${sets:-0}" -ge 1 ]; then ok "backup search: the volume holds $sets set(s)"; else bad "backup search: the volume holds no set"; fi
  count="$(grep -aFc -- "$(printf '%s' "$state" | jget email)" "$data" || true)"
  # The sets are tar members here, so a database that is not compressed shows its e-mail address as bytes.
  if [ "${count:-0}" -ge 1 ]; then ok "backup search: the control in the sets (the e-mail address) is found"; else bad "backup search: the control in the sets (the e-mail address) was not found"; fi
  while IFS=$'	' read -r name value; do
    total=$((total + 1))
    count="$(grep -aFc -- "$value" "$data" || true)"
    check "backup sets never hold plaintext: no $name in the sets" 0 "${count:-0}"
  done < <(printf '%s' "$needles" | node -e 'for (const n of JSON.parse(require("fs").readFileSync(0, "utf8"))) console.log(n.name + "	" + n.value);')
  if [ "$total" -ge 8 ]; then ok "backup search: $total secrets searched"; else bad "backup search: only $total secrets were searched"; fi
  rm -f "$data"
}

# The recovery, export, import and backup scenarios, in each browser on a fresh stack, all in one run (the account moves from
# one scenario to the next) with the host script at hand for what only the Docker host can do. Then the search for the secrets.
m3_phase() {
  local browser state needles spec specs=("${m3_specs[@]}")
  # While the scenarios are written: FERRET_E2E_M3_SPECS picks some of them, and FERRET_E2E_REUSE=1 empties the running stack
  # (e2e-reset) instead of building a new one. The gate itself always runs all of them on a fresh stack.
  # shellcheck disable=SC2206
  [ -z "${FERRET_E2E_M3_SPECS:-}" ] || specs=($FERRET_E2E_M3_SPECS)
  local markers=""
  for spec in "${specs[@]}"; do markers="$markers m3-${spec%%-*}"; done
  for browser in $browsers; do
    say "recovery scenarios in $browser on a fresh stack"
    hosted_markers="$markers"
    if [ "${FERRET_E2E_REUSE:-}" = 1 ] && e2e_running; then e2e_reset >&2; else e2e_up >&2; fi
    if run_m2_hosted m3 "" "$browser" "${specs[@]}"; then ok "$browser: scenarios ${specs[*]} passed"; else bad "$browser: scenarios ${specs[*]} failed"; fi
    hosted_markers="m2-restore"
    state="$(left "$phase_out" state)"
    needles="$(left "$phase_out" needles)"
    if [ -z "$state" ] || [ -z "$needles" ]; then
      bad "$browser: the run left no state, so the data and the backup sets were not searched"
    else
      search_data "$needles" "$state"
      search_backups "$needles" "$state"
    fi
  done
}

# ---------------------------------------------------------------------- main

# --------------------------------------------------------------- parallel

# One stack per browser, all at the same time. Each browser runs this script again for the same step on
# its own suffix and network (and dev.run), with its output in a log file of its own. When all have ended,
# one table says what each did. The exit code is 1 when any of them failed.
parallel_gate() { # step
  local step="$1" engine index=0 logs subnets=() subnet title start now pid engines=() pids=() subnets_used=() rcs=() ends=() failed_total=0 running=1
  local oks fails verdict elapsed
  logs="${FERRET_E2E_PARALLEL_LOGS:-test-results/out/parallel}"
  # shellcheck disable=SC2206
  subnets=(${FERRET_E2E_PARALLEL_SUBNETS:-172.30.241 172.30.242 172.30.243})
  # shellcheck disable=SC2206
  engines=($browsers)
  if [ "${#engines[@]}" -eq 0 ] || [ "${#engines[@]}" -gt "${#subnets[@]}" ]; then
    echo "e2e gate: --parallel needs a network for every browser (FERRET_E2E_PARALLEL_SUBNETS has ${#subnets[@]}, there are ${#engines[@]} browsers)" >&2
    exit 2
  fi
  mkdir -p "$logs"
  start=$SECONDS
  for engine in "${engines[@]}"; do
    subnet="${subnets[$index]}"
    subnets_used+=("$subnet")
    title="${DEV_TITLE:-}"
    rm -f "$logs/$engine.log"
    say "$engine: starting its own stack (network $subnet.0/28), log $logs/$engine.log"
    (
      export FERRET_E2E_SUFFIX="$engine" FERRET_E2E_SUBNET="$subnet" FERRET_E2E_BROWSERS="$engine"
      if [ -n "${DEV_RUN:-}" ]; then
        export DEV_RUN="$DEV_RUN-$engine"
        [ -z "$title" ] || export DEV_TITLE="$title ($engine)"
      else
        unset DEV_RUN DEV_TITLE
      fi
      # shellcheck disable=SC2086
      exec ${FERRET_E2E_PARALLEL_WRAP:-} bash "$0" "$step" > "$logs/$engine.log" 2>&1
    ) &
    pids+=($!)
    rcs+=("")
    ends+=("")
    index=$((index + 1))
    # A short stagger: every stack starts by removing what carries its own label, then builds the same images.
    sleep 2
  done
  # shellcheck disable=SC2064
  trap "kill ${pids[*]} 2>/dev/null || true" INT TERM
  # Wait for all of them, and say when each one ends.
  while [ "$running" -gt 0 ]; do
    running=0
    index=0
    for pid in "${pids[@]}"; do
      if [ -z "${ends[$index]}" ]; then
        if kill -0 "$pid" 2>/dev/null; then
          running=$((running + 1))
        else
          rcs[index]=0
          wait "$pid" || rcs[index]=$?
          ends[index]=$((SECONDS - start))
          say "${engines[$index]}: ended after $((ends[index] / 60)) min (exit ${rcs[$index]})"
        fi
      fi
      index=$((index + 1))
    done
    [ "$running" -eq 0 ] || sleep 10
  done
  trap - INT TERM
  now=$((SECONDS - start))

  # One table for all of them.
  printf '\n%-10s %-7s %8s %6s %6s  %s\n' browser result time ok failed log >&2
  index=0
  for engine in "${engines[@]}"; do
    elapsed="${ends[$index]}"
    oks="$(grep -c '^  ok ' "$logs/$engine.log" 2>/dev/null || true)"
    fails="$(grep -c '^  FAIL ' "$logs/$engine.log" 2>/dev/null || true)"
    if [ "${rcs[$index]}" = 0 ] && grep -q '^e2e gate: all checks passed$' "$logs/$engine.log" 2>/dev/null; then
      verdict=passed
    else
      verdict=FAILED
      failed_total=$((failed_total + 1))
    fi
    printf '%-10s %-7s %5dm%02ds %6s %6s  %s\n' "$engine" "$verdict" $((elapsed / 60)) $((elapsed % 60)) "${oks:-0}" "${fails:-0}" "$logs/$engine.log" >&2
    index=$((index + 1))
  done
  printf '%-10s %-7s %5dm%02ds\n' total "" $((now / 60)) $((now % 60)) >&2
  # What failed, in the words of the logs.
  for engine in "${engines[@]}"; do
    if grep -q '^  FAIL ' "$logs/$engine.log" 2>/dev/null; then
      printf '\n== %s: failed checks\n' "$engine" >&2
      grep '^  FAIL ' "$logs/$engine.log" >&2 || true
    elif ! grep -q '^e2e gate: all checks passed$' "$logs/$engine.log" 2>/dev/null; then
      printf '\n== %s: no pass line; the end of its log\n' "$engine" >&2
      tail -n 15 "$logs/$engine.log" >&2 || true
    fi
  done
  index=0
  printf '\n== the stacks are left running; remove each one with:\n' >&2
  for engine in "${engines[@]}"; do
    printf '   FERRET_E2E_SUFFIX=%s FERRET_E2E_SUBNET=%s scripts/lanbox-ferret-test.sh e2e-down\n' "$engine" "${subnets_used[$index]}" >&2
    index=$((index + 1))
  done
  if [ "$failed_total" -eq 0 ]; then
    echo "e2e gate (parallel): all ${#engines[@]} browsers passed" >&2
  else
    echo "e2e gate (parallel): $failed_total of ${#engines[@]} browsers failed" >&2
    exit 1
  fi
}

main_gate() {
  local first step=all arg parallel=0
  for arg in "$@"; do
    case "$arg" in
      --parallel) parallel=1 ;;
      all-parallel) parallel=1 step=all ;;
      *) step="$arg" ;;
    esac
  done
  if [ "$parallel" = 1 ]; then
    case "$step" in
      all | browsers | m2 | m3 | m5a | restart | limits)
        parallel_gate "$step"
        return
        ;;
    esac
  fi
  case "$step" in
    all)
      browsers_phase
      m2_phase
      m3_phase
      limits_phase
      ;;
    browsers) browsers_phase ;;
    m2) m2_phase ;;
    m3) m3_phase ;;
    m5a) m5a_phase ;;
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
  if [ "$e2e_suffix" = e2e ]; then
    say "the stack is left running for a look; remove it with: scripts/lanbox-ferret-test.sh e2e-down"
  else
    say "the stack is left running for a look; remove it with: FERRET_E2E_SUFFIX=$e2e_suffix FERRET_E2E_SUBNET=$e2e_subnet scripts/lanbox-ferret-test.sh e2e-down"
  fi
  if [ "$failures" -eq 0 ]; then
    echo "e2e gate: all checks passed" >&2
  else
    echo "e2e gate: $failures check(s) failed" >&2
    exit 1
  fi
}

main_gate "$@"
