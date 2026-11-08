#!/usr/bin/env bash
# The Faithful Ferret test stacks on the LANBox. Everything goes through the Docker
# context `unraid`; never Docker Desktop, never Tower.
#
# The test stack (compose project ferret-test, behind Pangolin). Only resources
# named ferret-test* and labelled owner=ferret-test are created, changed or removed:
#
#   scripts/lanbox-ferret-test.sh up       build and start (alias: redeploy); refuses when the
#                                          trusted proxy is not the tunnel client's address
#   scripts/lanbox-ferret-test.sh down     stop and remove the container (the data stays)
#   scripts/lanbox-ferret-test.sh reset    also remove the data volume (asks first)
#   scripts/lanbox-ferret-test.sh logs     follow the server log
#   scripts/lanbox-ferret-test.sh status   container, health, volume
#   scripts/lanbox-ferret-test.sh smoke    check /healthz and the headers on both ports
#   scripts/lanbox-ferret-test.sh peers    peer addresses the server has seen since start
#   scripts/lanbox-ferret-test.sh token    print the setup link with the setup token
#                                          (`up` prints it on the first deploy only)
#   scripts/lanbox-ferret-test.sh snapshot --yes-ferret-test
#                                          stop the app, copy its data volume to the volume
#                                          ferret-test-snapshot (label owner=ferret-test), start it
#   scripts/lanbox-ferret-test.sh restore-snapshot --yes-ferret-test
#                                          stop the app, copy the snapshot back, raise the
#                                          restore epoch (`restore-epoch bump --yes`), start it
#                                          Both stop the app for a short while and replace data: they
#                                          are run after an explicit yes, never by a test run.
#
# The end-to-end stack (compose project ferret-e2e: its own app with the test clock,
# a TLS terminator and the test host names vault-e2e.test and admin-e2e.test on a
# network of its own; no published port; the data in a volume that every start removes). Only resources named
# ferret-e2e* and labelled owner=ferret-e2e are created or removed, and it never
# touches the stack above:
#
#   scripts/lanbox-ferret-test.sh e2e-up       build and start a fresh, empty stack
#   scripts/lanbox-ferret-test.sh e2e-run [args]  run the Playwright tests of web/ in a container on the
#                                          stack's network (args go to `playwright test`; the
#                                          default config is web/playwright.e2e.config.mjs)
#   scripts/lanbox-ferret-test.sh e2e-clock <seconds>  move the server's clock forward by <seconds>
#                                          (0 puts it back)
#   scripts/lanbox-ferret-test.sh e2e-token    print the setup token of the running stack
#   scripts/lanbox-ferret-test.sh e2e-ca       print the certificate of the stack's test CA
#   scripts/lanbox-ferret-test.sh e2e-evil <mode> [json]  switch the malicious server of the stack to a
#                                          mode (honest, swap_blobs, replay_old, hide, gone,
#                                          fake_tombstone, seq_lie, rollback, fork, forge_checkpoint,
#                                          drop_checkpoint_head); json holds the parameters, for
#                                          example e2e-evil hide '{"id":"<32 hex>"}'. The modes are
#                                          in web/test/e2e-stack/evil/modes.mjs
#   scripts/lanbox-ferret-test.sh e2e-snapshot  stop the app, copy the volume ferret-e2e-data to the
#                                          volume ferret-e2e-snapshot (label owner=ferret-e2e), start the app
#   scripts/lanbox-ferret-test.sh e2e-restore-snapshot  stop the app, copy the snapshot back, raise the
#                                          restore epoch, start the app (the clock offset is kept)
#   scripts/lanbox-ferret-test.sh e2e-down     remove the stack and its image
#
# docker/.env (not in git; on a Unix host it is made with mode 600) holds
# FERRET_SETUP_TOKEN and FERRET_TRUSTED_PROXIES of the test stack. It is made on
# the first `up`: the proxy address is the one of the Newt container on the LANBox
# (read only, `docker inspect`), or FERRET_TRUSTED_PROXIES from the environment. Like compose,
# a variable in the environment of the shell wins over the file. Edit the file and
# run `up` again to change it; `peers` shows which addresses the server has seen.
#
# Newt outside Docker (Proxmox CT 130 at 10.0.3.169, which `docker inspect` cannot see):
# set FERRET_TRUSTED_PROXIES=10.0.3.169 in docker/.env. When no Docker container of the
# tunnel client exists, `up` accepts that value only as exactly one valid IPv4 address
# (no list, no network, no loopback, not .0 or .255, not link-local) and warns when the build VM gets no ping answer
# from it. With a Docker container, its address is still the only one that is accepted;
# a container that exists but has no readable address (stopped, host network) is refused,
# never treated as "outside Docker". The CT needs a static IP (a fixed address or a DHCP
# reservation), because the server trusts exactly this address.
#
# Env overrides:
#   FERRET_DOCKER_ARGS  replaces the default "--context unraid"
#   FERRET_LANBOX       address of the LANBox (default 10.0.3.152, the build VM)
#   FERRET_PROXY_CONTAINER  name of the tunnel client container (default Newt)
# The snapshot steps are handed to take_snapshot and restore_snapshot by name.
# shellcheck disable=SC2329
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

project=ferret-test
container=ferret-test-app
volume=ferret-test-data
label=owner=ferret-test
lanbox="${FERRET_LANBOX:-10.0.3.152}"
admin_port=3040
vault_port=3041
envfile="${FERRET_ENV_FILE:-docker/.env}"
composefile=docker/compose.ferret-test.yml

# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})
dk() { docker "${docker_args[@]}" "$@"; }
dc() { dk compose -p "$project" -f "$composefile" --env-file "$envfile" "$@"; }

# The end-to-end stack: everything it uses is named ferret-e2e* and has this label.
e2e_project=ferret-e2e
e2e_label=owner=ferret-e2e
e2e_composefile=docker/compose.ferret-e2e.yml
e2e_app=ferret-e2e-app
e2e_tls=ferret-e2e-tls
e2e_network=ferret-e2e-net
e2e_image=ferret-e2e-app:latest
# The malicious server between the terminator and the app (web/test/e2e-stack/evil), and the
# volumes of the app's data and of its snapshot.
e2e_evil=ferret-e2e-evil
e2e_evil_image=ferret-e2e-evil:latest
e2e_data_volume=ferret-e2e-data
e2e_snapshot_volume=ferret-e2e-snapshot
# The compose file wants the setup token of the run; commands that only stop or
# list the stack do not need the real one.
dce() { FERRET_E2E_SETUP_TOKEN="${FERRET_E2E_SETUP_TOKEN:-unused}" dk compose -p "$e2e_project" -f "$e2e_composefile" "$@"; }

# The tunnel client of the proxy (the Newt container) as Docker on the build VM
# knows it, read only. The container name can be changed with
# FERRET_PROXY_CONTAINER. Prints exactly one of:
#   address <ip>  the container runs on a network with an address
#   notfound      Docker answered that there is no container with that name (the
#                 tunnel client runs outside Docker, for example in a Proxmox CT)
#   unreadable    anything else: the container exists but is stopped or has no
#                 address of its own (host, none or another container's network),
#                 or Docker could not be asked (a failed ssh or daemon call).
#                 This fails closed: it is never treated as "outside Docker".
tunnel_container="${FERRET_PROXY_CONTAINER:-Newt}"
tunnel_lookup() {
  local out running mode ip
  if ! out="$(dk container inspect "$tunnel_container" --format '{{.State.Running}} {{.HostConfig.NetworkMode}}' 2>&1)"; then
    case "$out" in
      *"No such object"* | *"No such container"*) echo notfound ;;
      *) echo unreadable ;;
    esac
    return 0
  fi
  out="$(printf '%s\n' "$out" | tail -n 1)"
  running="${out%% *}"
  mode="${out#* }"
  if [ "$running" != true ]; then
    echo unreadable
    return 0
  fi
  case "$mode" in
    "" | host | none | container:*) echo unreadable; return 0 ;;
    default) mode=bridge ;;
  esac
  ip="$(dk container inspect "$tunnel_container" \
    --format "{{with index .NetworkSettings.Networks \"$mode\"}}{{.IPAddress}}{{end}}" 2>/dev/null || true)"
  if [ -n "$ip" ]; then echo "address $ip"; else echo unreadable; fi
}

# The address from tunnel_lookup, or nothing when there is none to read.
tunnel_address() {
  local found
  found="$(tunnel_lookup)"
  case "$found" in "address "*) echo "${found#address }" ;; esac
}

# The values compose will inject, asked from compose itself (last definition
# wins, `export ` prefixes and spaces are understood, the shell wins over the
# file) and never read from the file by hand. The output holds the setup token,
# so it is kept in a variable and only the one wanted line is printed.
#
# The listing prints a value raw, so a value with a line break in it (in the
# file or in the environment of the shell) can hold a line that looks like the
# key. The real key is always listed once, so an answer counts only when exactly
# one line starts with `KEY=`. With more, nothing is returned, and the callers
# refuse to go on.
compose_value() {
  local out
  out="$(dc config --environment 2>/dev/null)" || return 0
  [ "$(printf '%s\n' "$out" | grep -c "^$1=")" = 1 ] || return 0
  printf '%s\n' "$out" | sed -n "s/^$1=//p"
}
configured_proxies() { compose_value FERRET_TRUSTED_PROXIES; }

# Addresses without a host-only prefix (/32, /128), one per line, so that
# 172.17.0.2 and 172.17.0.2/32 are the same address.
normalized_addresses() {
  printf '%s\n' "$1" | tr ',' '\n' | sed -e 's/[[:space:]]//g' -e 's#/32$##' -e 's#/128$##' | grep -v '^$' | sort -u
}

# Whether two lists hold the same addresses.
same_addresses() {
  [ -n "$1" ] && [ "$(normalized_addresses "$1")" = "$(normalized_addresses "$2")" ]
}

make_env() {
  if [ -f "$envfile" ]; then
    return
  fi
  local proxies="${FERRET_TRUSTED_PROXIES:-}"
  if [ -z "$proxies" ]; then
    proxies="$(tunnel_address)"
  fi
  if [ -z "$proxies" ]; then
    echo "lanbox-ferret-test: no $envfile yet and no proxy address. Run again with" >&2
    echo "FERRET_TRUSTED_PROXIES set to the address the Pangolin tunnel traffic reaches the" >&2
    echo "server from (never a Docker bridge gateway), or FERRET_PROXY_CONTAINER set to the" >&2
    echo "name of the tunnel client container (default Newt)." >&2
    exit 2
  fi
  local token
  token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  umask 077
  {
    echo "FERRET_SETUP_TOKEN=$token"
    echo "FERRET_TRUSTED_PROXIES=$proxies"
  } > "$envfile"
  echo "lanbox-ferret-test: wrote $envfile (trusted proxy: $proxies)" >&2
  first_deploy=1
}

# Whether the text is one plain IPv4 address (four numbers from 0 to 255, no
# leading zeros, no prefix length, no list) that can be a tunnel client: not the
# unspecified address, not loopback, not a multicast or the broadcast address, not
# a link-local address (169.254.0.0/16), and not the first or last address of a
# /24 (.0 and .255: network and broadcast forms).
single_ipv4() {
  local ip="$1" octet
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  local IFS=.
  # shellcheck disable=SC2086
  set -- $ip
  for octet in "$@"; do
    [ "${#octet}" -eq 1 ] || [ "${octet#0}" = "$octet" ] || return 1
    [ "$octet" -le 255 ] || return 1
  done
  [ "$1" -ne 0 ] && [ "$1" -ne 127 ] && [ "$1" -lt 224 ] || return 1
  [ "$4" -ne 0 ] && [ "$4" -ne 255 ] || return 1
  ! { [ "$1" -eq 169 ] && [ "$2" -eq 254 ]; }
}

# Whether the build VM can reach the address (one ping from a throwaway container
# on the host network). Only a warning when it cannot: a tunnel client may drop
# ping, and a wrong address fails closed (nobody is trusted).
reachable() {
  dk run --rm --name ferret-test-reachcheck --network host --label "$label" \
    --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true --read-only \
    --pids-limit 16 --memory 16m \
    "$alpine_image" ping -c 1 -W 3 "$1" >/dev/null 2>&1
}

# Whether the trusted proxy that compose will use is exactly the address of the
# tunnel client now. Prints the reason when it is not.
#
# The tunnel client is found in two ways (see tunnel_lookup):
#  * As a Docker container on the build VM. Its address is then the only one that
#    is believed: any other FERRET_TRUSTED_PROXIES is a mismatch. When the
#    container exists but its address cannot be read (stopped, host or none
#    network, another container's network) or Docker cannot be asked, the answer
#    is a refusal, never the explicit value below.
#  * Outside Docker: only when Docker answers that there is no container with that
#    name (since the move to Proxmox, Newt runs in its own CT). Then
#    FERRET_TRUSTED_PROXIES is the one source of the address and it is accepted
#    only as exactly one valid IPv4 address. A list, a network, a name, an empty
#    value or an address that cannot be a client is refused.
tunnel_mismatch() {
  local found now configured
  found="$(tunnel_lookup)"
  configured="$(configured_proxies)"
  case "$found" in
    "address "*)
      now="${found#address }"
      if ! same_addresses "$now" "$configured"; then
        echo "$tunnel_container is at $now but FERRET_TRUSTED_PROXIES is ${configured:-empty}"
        return 0
      fi
      return 1
      ;;
    notfound) ;;
    *)
      echo "cannot read the address of $tunnel_container on the network it uses to reach the LANBox (the container exists but is stopped or has no address of its own, or Docker on the LANBox could not be asked)"
      return 0
      ;;
  esac
  if [ -z "$configured" ]; then
    echo "there is no Docker container named $tunnel_container on the LANBox, and FERRET_TRUSTED_PROXIES is empty"
    return 0
  fi
  if ! single_ipv4 "$configured"; then
    echo "there is no Docker container named $tunnel_container on the LANBox, so FERRET_TRUSTED_PROXIES must be exactly one IPv4 address (no list, no network, no loopback, not .0 or .255), but it is $configured"
    return 0
  fi
  return 1
}

# Prints a warning when the address of a tunnel client that runs outside Docker
# does not answer from the build VM. Nothing when the address comes from Docker.
unreachable_warning() {
  local configured
  [ "$(tunnel_lookup)" = notfound ] || return 0
  configured="$(configured_proxies)"
  single_ipv4 "$configured" || return 0
  reachable "$configured" || echo "the address $configured does not answer ping from the LANBox (a tunnel client may block ping; check that it is the right address, and run the peers command after a sign-in to see which addresses the server sees)"
}

# `up` refuses to start on a mismatch: a proxy address that is not the tunnel
# client's would trust some other host, or nobody.
require_tunnel() {
  local why warning
  if why="$(tunnel_mismatch)"; then
    echo "lanbox-ferret-test: refusing to start: $why." >&2
    echo "Set FERRET_TRUSTED_PROXIES in $envfile (and not in the shell) to the address of" >&2
    echo "$tunnel_container. When it runs outside Docker (a Proxmox CT, for example), that is" >&2
    echo "its own LAN address, as one single IPv4 address (not a list, not a network), and that" >&2
    echo "CT needs a static IP (a fixed address or a DHCP reservation)." >&2
    echo "Run up again." >&2
    exit 1
  fi
  warning="$(unreachable_warning)"
  [ -z "$warning" ] || echo "lanbox-ferret-test: WARNING: $warning." >&2
}

# `status` only warns.
check_tunnel() {
  local why
  if why="$(tunnel_mismatch)"; then
    echo "WARNING: $why." >&2
    echo "         Until they match, sign-in through Pangolin fails closed. Edit $envfile and run up." >&2
  else
    why="$(unreachable_warning)"
    [ -z "$why" ] || echo "WARNING: $why." >&2
  fi
}

# Refuses to start when something else on the LANBox already listens on one of
# the two ports (the stack uses the host network, so `docker ps` cannot tell).
# A throwaway container on the host network lists the listening ports.
alpine_image=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
check_ports() {
  if [ "$(dk inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" = true ]; then
    return # ours: the ports are ours
  fi
  local port listeners
  listeners="$(dk run --rm --name ferret-test-portcheck --network host --label "$label" "$alpine_image" netstat -ltn)"
  for port in "$admin_port" "$vault_port"; do
    if printf '%s\n' "$listeners" | grep -Eq "[:.]${port}[[:space:]]"; then
      echo "lanbox-ferret-test: port $port is already in use on the LANBox" >&2
      exit 1
    fi
  done
}

print_addresses() {
  echo
  echo "Admin  (Pangolin) https://ferret-test.opland.net    direct http://$lanbox:$admin_port"
  echo "Vault  (Pangolin) https://vault-test.opland.net     direct http://$lanbox:$vault_port"
}

print_setup_link() {
  echo "First administrator: open https://ferret-test.opland.net/setup?token=$(compose_value FERRET_SETUP_TOKEN)"
}

# Both listeners: 200 on /healthz, no Server header, the security headers of the
# listener, and application/wasm for the WebAssembly file on the vault listener.
smoke() {
  local fail=0 port wasm response
  check() { # name, "ok" or anything else
    if [ "$2" = ok ]; then echo "  ok    $1"; else echo "  FAIL  $1"; fail=1; fi
  }
  # The status line and headers of a GET, without the body.
  headers_of() { curl -sS -m 10 -i "$1" 2>/dev/null | tr -d '\r' | sed '/^$/q' || true; }
  has() { printf '%s\n' "$1" | grep -qi "^$2:" && echo ok || echo no; }
  absent() { printf '%s\n' "$1" | grep -qi "^$2:" && echo no || echo ok; }
  for port in "$admin_port" "$vault_port"; do
    echo "http://$lanbox:$port"
    response="$(headers_of "http://$lanbox:$port/healthz")"
    check "/healthz answers 200" "$(printf '%s\n' "$response" | head -n 1 | grep -q ' 200' && echo ok || echo no)"
    check "no Server header" "$(absent "$response" server)"
    if [ "$port" = "$vault_port" ]; then
      for h in content-security-policy cross-origin-opener-policy cross-origin-resource-policy \
               referrer-policy strict-transport-security x-content-type-options; do
        check "$h present" "$(has "$response" "$h")"
      done
    else
      for h in content-security-policy referrer-policy x-content-type-options x-frame-options; do
        check "$h present" "$(has "$response" "$h")"
      done
    fi
  done
  wasm="$(curl -sS -m 10 "http://$lanbox:$vault_port/" 2>/dev/null | grep -oE '/[A-Za-z0-9_./-]*\.wasm' | head -n 1 || true)"
  wasm="${wasm:-/pkg-web/ferret_core_wasm_bg.wasm}"
  response="$(headers_of "http://$lanbox:$vault_port$wasm")"
  check "$wasm is application/wasm" "$(printf '%s\n' "$response" | grep -qi '^content-type: application/wasm' && echo ok || echo no)"
  check "$wasm has no Server header" "$(absent "$response" server)"
  if [ "$fail" -ne 0 ]; then
    echo "smoke: FAILED" >&2
    return 1
  fi
  echo "smoke: ok"
}

# Removes every container, volume and network that carries `$label`, and the
# image `$image`. Nothing else: no prune, no name patterns, no other labels.
image=ferret-test-app:latest
reset_resources() {
  local id name
  for id in $(dk ps -aq --filter "label=$label"); do dk rm -f "$id" >/dev/null; done
  for name in $(dk volume ls -q --filter "label=$label"); do dk volume rm "$name" >/dev/null; done
  for name in $(dk network ls -q --filter "label=$label"); do dk network rm "$name" >/dev/null; done
  dk image rm "$image" >/dev/null 2>&1 || true
}

# --- The end-to-end stack ----------------------------------------------------

# Removes the stack of the last run and anything else that carries its label (a
# crashed test container, for example). Only ferret-e2e resources.
e2e_remove() {
  local id name
  dce down -v --remove-orphans >/dev/null 2>&1 || true
  for id in $(dk ps -aq --filter "label=$e2e_label"); do dk rm -f "$id" >/dev/null; done
  for name in $(dk network ls -q --filter "label=$e2e_label"); do dk network rm "$name" >/dev/null; done
  for name in $(dk volume ls -q --filter "label=$e2e_label"); do dk volume rm "$name" >/dev/null; done
}

e2e_running() {
  local name
  for name in "$e2e_app" "$e2e_evil" "$e2e_tls"; do
    [ "$(dk inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = true ] || return 1
  done
}

e2e_require_running() {
  e2e_running || { echo "lanbox-ferret-test: the end-to-end stack is not running; run e2e-up first" >&2; exit 1; }
}

# The setup token of the running stack, as the server has it.
e2e_token() { dk exec "$e2e_app" printenv FERRET_SETUP_TOKEN; }

# The certificate of the stack's test CA (a new one for every start).
e2e_ca() { dk exec "$e2e_tls" cat /data/caddy/pki/authorities/local/root.crt; }

# Moves the server's clock forward by this many seconds from the real time (0 puts
# it back). The file is read on every call of the clock, so no restart is needed.
e2e_clock() {
  case "${1:-}" in
    '' | *[!0-9]* | ??????????????*) echo "usage: e2e-clock <seconds> (digits only, at most 13)" >&2; exit 2 ;;
  esac
  e2e_require_running
  # Written to a file next to it and renamed, so the server never reads it half-written
  # (an empty file would read as a failed clock).
  dk exec "$e2e_app" sh -c "echo $1 > /tmp/e2e-clock.new && mv -f /tmp/e2e-clock.new /tmp/e2e-clock"
  echo "e2e-clock: the server's clock is now $1 seconds ahead"
}

e2e_up() {
  local token
  # A fresh stack every time: the stack and its data volume are removed first, so the
  # database starts empty.
  e2e_remove
  token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FERRET_E2E_SETUP_TOKEN="$token" dce up -d --build --wait
  echo
  echo "End-to-end stack is up (project $e2e_project, no published ports):"
  echo "  vault  https://vault-e2e.test  admin  https://admin-e2e.test   (only on the network $e2e_network)"
  echo "  run the tests:  scripts/lanbox-ferret-test.sh e2e-run    setup token:  scripts/lanbox-ferret-test.sh e2e-token"
}

e2e_down() {
  e2e_remove
  dk image rm "$e2e_image" >/dev/null 2>&1 || true
  dk image rm "$e2e_evil_image" >/dev/null 2>&1 || true
  for id in $(dk images -q --filter "label=$e2e_label"); do dk image rm "$id" >/dev/null 2>&1 || true; done
  echo "e2e-down: done"
}

# Waits until a container reports healthy (the server has a health check).
wait_container_healthy() { # container
  local status=""
  for _ in $(seq 1 90); do
    status="$(dk inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$1" 2>/dev/null || true)"
    [ "$status" = healthy ] && return 0
    sleep 1
  done
  echo "lanbox-ferret-test: $1 is not healthy after 90 seconds (status: ${status:-unknown})" >&2
  return 1
}

# The jobs on volumes, each in a helper container of the pinned Alpine image: no network, no
# capability but the ones that a copy as root needs, no new privileges, a memory limit. A snapshot
# is complete only with the marker .snapshot-complete, which is the last thing written, and a
# database file that is not empty; a source that is not good is never copied, and a target is
# emptied only after the source is known to be good.
#   verify   the snapshot has the marker and a database (mounted read-only, nothing is written)
#   make     the data -> a fresh volume, then the marker. Every job removes a marker in the target first,
#            and checks the copy before the marker is written: the same files on both sides and every
#            file equal (cmp); a copy that fails or differs ends the job with a failure.
#   move     a complete snapshot -> a fresh volume, then the marker
#   restore  a complete snapshot -> the data (no marker in the data)
# The apps must be stopped for make and restore.
# shellcheck disable=SC2016
volume_script='set -e
from="${FROM:-/from}"
to="${TO:-/to}"
good() { [ -f "$1/.snapshot-complete" ] && [ -s "$1/ferret.sqlite" ]; }
case "$MODE" in
  verify | move | restore) good "$from" || { echo "the snapshot has no completion marker or no database" >&2; exit 3; } ;;
  make) [ -s "$from/ferret.sqlite" ] || { echo "the data holds no database" >&2; exit 3; } ;;
  *) exit 2 ;;
esac
if [ "$MODE" = verify ]; then exit 0; fi
rm -f "$to/.snapshot-complete"
find "$to" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
[ -z "$(ls -A "$to")" ] || { echo "the target was not emptied" >&2; exit 4; }
cp -a "$from/." "$to/"
rm -f "$to/.snapshot-complete"
[ -s "$to/ferret.sqlite" ] || { echo "the copy holds no database" >&2; exit 4; }
list() { (cd "$1" && find . -mindepth 1 ! -name .snapshot-complete | sort); }
[ "$(list "$from")" = "$(list "$to")" ] || { echo "the copy has other files than the source" >&2; exit 4; }
(cd "$from" && find . -type f ! -name .snapshot-complete) | while read -r f; do
  cmp -s "$from/$f" "$to/$f" || { echo "the copy of $f differs from the source" >&2; exit 4; }
done
case "$MODE" in
  make) date > "$to/.snapshot-complete" ;;
  move) cp -a "$from/.snapshot-complete" "$to/" ;;
esac
sync'

volume_job() { # mode, from, to (not used by verify), label, helper container name
  local mounts=(-v "$2:/from:ro")
  [ "$1" = verify ] || mounts+=(-v "$3:/to")
  dk run --rm --name "$5" --label "$4" --network none \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add FSETID \
    --security-opt no-new-privileges:true --memory 256m \
    -e "MODE=$1" "${mounts[@]}" \
    "$alpine_image" \
    sh -c "$volume_script"
}

# A volume of this name that exists must carry our label; one that does not is not touched.
require_ours() { # volume, label (key=value)
  local have
  dk volume inspect "$1" >/dev/null 2>&1 || return 0
  have="$(dk volume inspect -f '{{index .Labels "owner"}}' "$1" 2>/dev/null || true)"
  if [ "$have" != "${2#*=}" ]; then
    echo "lanbox-ferret-test: the volume $1 exists and does not carry the label $2; not touching it" >&2
    return 1
  fi
}

# Takes a snapshot: the data goes into a fresh volume <snapshot>-new while the app is stopped
# (and the app is started again at once), then the old snapshot is swapped for the finished one.
# A failed copy leaves the old snapshot as it was.
take_snapshot() { # data volume, snapshot volume, label, name prefix, stop function, start function
  local data="$1" snap="$2" lbl="$3" prefix="$4" stop="$5" start="$6" tmp rc=0
  tmp="$snap-new"
  require_ours "$snap" "$lbl" || exit 1
  # A temporary volume that is still there holds a copy of an earlier snapshot whose swap did not
  # finish: it may be the only finished copy, so it is never deleted here.
  if dk volume inspect "$tmp" >/dev/null 2>&1; then
    echo "lanbox-ferret-test: the volume $tmp exists: an earlier snapshot was not swapped in and it may hold the only finished copy." >&2
    echo "Remove it (docker volume rm $tmp) to start over, or swap it in by hand, and run the snapshot again." >&2
    exit 1
  fi
  dk volume create --label "$lbl" "$tmp" >/dev/null
  "$stop"
  volume_job make "$data" "$tmp" "$lbl" "$prefix-copy" || rc=$?
  "$start"
  if [ "$rc" -ne 0 ]; then
    dk volume rm "$tmp" >/dev/null 2>&1 || true
    echo "snapshot: the copy failed (exit $rc); the old snapshot, if there was one, is untouched" >&2
    exit "$rc"
  fi
  dk volume rm "$snap" >/dev/null 2>&1 || true
  dk volume create --label "$lbl" "$snap" >/dev/null
  volume_job move "$tmp" "$snap" "$lbl" "$prefix-swap" \
    || { echo "snapshot: the swap failed; the finished copy is in the volume $tmp" >&2; exit 1; }
  dk volume rm "$tmp" >/dev/null
}

# Puts a snapshot back: refuses unless it is complete (nothing is stopped or changed before that),
# stops the app, copies, raises the restore epoch (the entrypoint already runs `ferret`; the bump
# refuses while a server runs on the data and a database from before migration 0005), starts the
# app. When a step fails the app stays stopped: it must not run on data that is half restored.
restore_snapshot() { # snapshot volume, data volume, label, name prefix, stop function, bump function, start function
  local snap="$1" data="$2" lbl="$3" prefix="$4" stop="$5" bump="$6" start="$7"
  dk volume inspect "$snap" >/dev/null 2>&1 || { echo "lanbox-ferret-test: there is no snapshot ($snap); take one first" >&2; exit 1; }
  require_ours "$snap" "$lbl" || exit 1
  volume_job verify "$snap" - "$lbl" "$prefix-verify" \
    || { echo "lanbox-ferret-test: the snapshot $snap is not complete (no marker or no database); nothing was changed" >&2; exit 1; }
  "$stop"
  volume_job restore "$snap" "$data" "$lbl" "$prefix-restore" \
    || { echo "restore: the copy failed; the app stays stopped" >&2; exit 1; }
  "$bump" || { echo "restore: the restore epoch was not raised; the app stays stopped" >&2; exit 1; }
  "$start"
}

# The clock offset of the app (seconds), 0 when there is none. A restart of the container
# empties /tmp, where the test clock lives, so the offset is read before and set again after.
e2e_clock_offset() {
  local offset
  offset="$(dk exec "$e2e_app" cat /tmp/e2e-clock 2>/dev/null | tr -dc '0-9' || true)"
  echo "${offset:-0}"
}

# Switches the malicious server to a mode: `e2e_evil <mode> [json parameters]`. The call is made
# by Node inside its own container, to its control port, which is on the network of the stack
# only. The mode and the parameters are given as arguments, never put into the program text.
e2e_evil() {
  local mode="${1:-}" params="${2:-}"
  case "$mode" in
    '' | *[!a-z_]*) echo "usage: e2e-evil <mode> [json] (a mode name is lower case letters and underscores)" >&2; exit 2 ;;
  esac
  e2e_require_running
  [ "$(dk inspect -f '{{.State.Running}}' "$e2e_evil" 2>/dev/null || true)" = true ] || { echo "lanbox-ferret-test: $e2e_evil is not running" >&2; exit 1; }
  dk exec "$e2e_evil" node --input-type=module -e '
const [mode, text] = process.argv.slice(1);
let params;
try { params = JSON.parse(text || "{}"); } catch { console.error("the parameters must be JSON"); process.exit(2); }
const answer = await fetch("http://127.0.0.1:9000/mode", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ ...params, mode }),
});
console.log(await answer.text());
process.exit(answer.ok ? 0 : 1);
' "$mode" "$params"
}

e2e_clock_before=0
e2e_stop_app() { dk stop "$e2e_app" >/dev/null; }
e2e_bump() { dce run --rm -T --no-deps "$e2e_app" restore-epoch bump --yes; }
# A restart empties /tmp of the app, where the clock offset is: it is put back.
e2e_start_app() {
  dk start "$e2e_app" >/dev/null
  wait_container_healthy "$e2e_app"
  e2e_clock "$e2e_clock_before" >/dev/null
}
# What the malicious server has recorded belongs to the data that was there before.
e2e_evil_reset() {
  dk exec "$e2e_evil" node --input-type=module -e '
const answer = await fetch("http://127.0.0.1:9000/reset", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
process.exit(answer.ok ? 0 : 1);
' >/dev/null
}

# Copies the data of the app to the snapshot volume while the app is stopped, then starts it.
e2e_snapshot() {
  e2e_require_running
  e2e_clock_before="$(e2e_clock_offset)"
  take_snapshot "$e2e_data_volume" "$e2e_snapshot_volume" "$e2e_label" ferret-e2e-snapshot e2e_stop_app e2e_start_app
  echo "e2e-snapshot: the data of $e2e_app is in the volume $e2e_snapshot_volume"
}

# Puts the snapshot back with a higher restore epoch.
e2e_restore_snapshot() {
  e2e_require_running
  e2e_clock_before="$(e2e_clock_offset)"
  restore_snapshot "$e2e_snapshot_volume" "$e2e_data_volume" "$e2e_label" ferret-e2e-snapshot e2e_stop_app e2e_bump e2e_start_app
  e2e_evil_reset
  echo "e2e-restore-snapshot: $e2e_app runs on the snapshot, with a higher restore epoch"
}

# The runner image (docker/e2e-runner.Dockerfile: the Playwright image of
# scripts/lanbox-browsers.sh plus certutil), built on first use. The tag follows the
# content of the file. The Dockerfile goes in on stdin, so no build context (and
# nothing from docker/, where the .env of the test stack lives) is sent.
runner_hash="$(tr -d '' < docker/e2e-runner.Dockerfile | sha256sum | cut -c1-12)"
runner_image="ferret-e2e-playwright:$runner_hash"
e2e_runner_image() {
  if ! dk image inspect "$runner_image" >/dev/null 2>&1; then
    dk build --label "$e2e_label" -t "$runner_image" - < docker/e2e-runner.Dockerfile >&2
  fi
}

# Runs the Playwright tests of web/ in a throwaway container on the stack's
# network, so the test hosts resolve and no port is published. The web/ folder is
# streamed in as a tar archive (no bind mounts from this PC). The test CA is
# trusted by the system store (WebKit), by Node and by Chromium (an NSS database made
# with certutil, which the runner image docker/e2e-runner.Dockerfile has). Firefox has its own list: web/playwright.e2e.config.mjs lets it accept the
# certificate of the stack.
# The tests find the stack in FERRET_E2E_VAULT_URL, FERRET_E2E_ADMIN_URL and
# FERRET_E2E_SETUP_TOKEN, and FERRET_E2E_STATE when the host script has the state of an
# earlier phase. Output of the tests on stderr; what a phase leaves in /work/out/*.json
# (name, then the JSON) on stdout; the exit code is the tests' one.
e2e_run() {
  e2e_require_running
  local inner pem token
  e2e_runner_image
  pem="$(e2e_ca)"
  token="$(e2e_token)"
  # The script for the container is in single quotes on purpose.
  # shellcheck disable=SC2016
  inner='set -e
tar -x -C /work
printf "%s\n" "$FERRET_E2E_CA_PEM" > /work/e2e-ca.crt
cp /work/e2e-ca.crt /usr/local/share/ca-certificates/ferret-e2e.crt
update-ca-certificates >&2
# Chromium reads its trusted authorities from an NSS database; the runner image has certutil.
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n ferret-e2e -i /work/e2e-ca.crt
export NODE_EXTRA_CA_CERTS=/work/e2e-ca.crt
mkdir -p /work/out
export FERRET_E2E_OUT=/work/out
cd /work/web
npm ci --no-audit --no-fund --ignore-scripts >&2
set +e
if [ "$#" -eq 0 ] || ! printf "%s\n" "$@" | grep -q "^--config"; then
  set -- --config playwright.e2e.config.mjs "$@"
fi
npx playwright test "$@" >&2
status=$?
# After a failure, what the page looked like (the container is gone afterwards).
if [ "$status" -ne 0 ]; then
  for f in test-results/*/error-context.md; do
    [ -f "$f" ] || continue
    echo "--- $f" >&2
    head -c 2500 "$f" >&2
    echo >&2
  done
fi
# What a phase leaves for the host script (the state of the run), on stdout.
for f in /work/out/*.json; do
  [ -f "$f" ] || continue
  basename "$f" .json
  cat "$f"
  echo
done
exit $status'
  tar -c --exclude='web/node_modules' --exclude='web/test-results' --exclude='web/dist' web \
    | dk run --rm -i --init \
        --name ferret-e2e-playwright \
        --label "$e2e_label" \
        --network "$e2e_network" \
        --cpus 4 --memory 8g --shm-size 2g \
        -e CI=1 \
        -e FERRET_E2E_VAULT_URL=https://vault-e2e.test \
        -e FERRET_E2E_ADMIN_URL=https://admin-e2e.test \
        -e FERRET_E2E_EVIL_URL=http://$e2e_evil:9000 \
        -e FERRET_E2E_SETUP_TOKEN="$token" \
        -e FERRET_E2E_CA_PEM="$pem" \
        -e FERRET_E2E_STATE="${FERRET_E2E_STATE:-}" \
        -e FERRET_E2E_PHASE="${FERRET_E2E_PHASE:-}" \
        --tmpfs /work:exec,size=2g \
        --tmpfs /root/.npm:size=512m \
        --tmpfs /tmp:exec,size=2g \
        -w /work \
        "$runner_image" \
        sh -c "$inner" sh "$@"
}

# --- Snapshot and restore of the stack behind Pangolin ---------------------------
# These two replace data of that stack, so they refuse without --yes-ferret-test. A test
# run never calls them; they are run after an explicit yes.
snapshot_volume=ferret-test-snapshot
require_yes_ferret_test() {
  local arg
  for arg in "$@"; do
    [ "$arg" = --yes-ferret-test ] && return 0
  done
  echo "lanbox-ferret-test: this stops the stack $project for a short while and replaces data." >&2
  echo "Run it again with --yes-ferret-test after an explicit yes." >&2
  exit 2
}

snapshot_was_running=false
test_stop_app() {
  snapshot_was_running="$(dk inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo false)"
  dc stop "$container" >/dev/null
}
# An app that was stopped before the snapshot stays stopped.
test_start_after_snapshot() {
  [ "$snapshot_was_running" = true ] || return 0
  dc start "$container" >/dev/null
  wait_container_healthy "$container"
}
test_bump() { dc run --rm -T --no-deps "$container" restore-epoch bump --yes; }
test_start_app() {
  dc start "$container" >/dev/null
  wait_container_healthy "$container"
}

test_snapshot() {
  require_yes_ferret_test "$@"
  [ -f "$envfile" ] || { echo "no $envfile: nothing to copy" >&2; exit 1; }
  take_snapshot "$volume" "$snapshot_volume" "$label" ferret-test-snapshot test_stop_app test_start_after_snapshot
  echo "snapshot: the data of $container is in the volume $snapshot_volume"
}

test_restore_snapshot() {
  require_yes_ferret_test "$@"
  [ -f "$envfile" ] || { echo "no $envfile: nothing to restore" >&2; exit 1; }
  restore_snapshot "$snapshot_volume" "$volume" "$label" ferret-test-snapshot test_stop_app test_bump test_start_app
  echo "restore-snapshot: $container runs on the snapshot, with a higher restore epoch"
}

main() {
case "${1:-}" in
  up | redeploy)
    first_deploy=0
    make_env
    require_tunnel
    check_ports
    dc up -d --build
    print_addresses
    if [ "$first_deploy" = 1 ]; then
      print_setup_link
    else
      echo "Setup link: run $0 token"
    fi
    ;;
  down)
    [ -f "$envfile" ] || { echo "no $envfile: nothing to stop" >&2; exit 0; }
    dc down
    ;;
  reset)
    # Only resources of this stack: the compose project, then anything that still
    # carries the label owner=ferret-test. No prune, nothing else is touched.
    echo "This removes the ferret-test container, network, image, the data volume $volume and the snapshot volume $snapshot_volume."
    printf 'Type "reset" to go on: '
    read -r answer
    [ "$answer" = reset ] || { echo "cancelled"; exit 1; }
    if [ -f "$envfile" ]; then dc down -v --remove-orphans; fi
    reset_resources
    rm -f "$envfile"
    echo "reset: done (docker/.env removed; the next up makes a new setup token)"
    ;;
  logs)
    dk logs -f --tail 200 "$container"
    ;;
  status)
    dk ps -a --filter "label=$label" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    dk inspect "$container" --format 'health: {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}; restarts: {{.RestartCount}}' 2>/dev/null || true
    dk top "$container" -o user,pid,comm 2>/dev/null || true
    dk volume ls --filter "label=$label"
    check_tunnel
    ;;
  smoke)
    smoke
    ;;
  peers)
    dk logs "$container" 2>&1 | grep -i 'new peer address' || echo "no peer address seen yet"
    ;;
  token)
    [ -f "$envfile" ] || { echo "no $envfile yet: run up first" >&2; exit 1; }
    print_setup_link
    ;;
  e2e-up)
    e2e_up
    ;;
  e2e-down)
    e2e_down
    ;;
  e2e-evil)
    shift
    e2e_evil "$@"
    ;;
  e2e-snapshot)
    e2e_snapshot
    ;;
  e2e-restore-snapshot)
    e2e_restore_snapshot
    ;;
  snapshot)
    shift
    test_snapshot "$@"
    ;;
  restore-snapshot)
    shift
    test_restore_snapshot "$@"
    ;;
  e2e-run)
    shift
    e2e_run "$@"
    ;;
  e2e-clock)
    e2e_clock "${2:-}"
    ;;
  e2e-token)
    e2e_require_running
    e2e_token
    ;;
  e2e-ca)
    e2e_require_running
    e2e_ca
    ;;
  *)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
}

# Run only when executed, not when sourced (scripts/check-ferret-test-stack.sh).
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
