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
  for name in "$e2e_app" "$e2e_tls"; do
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
  for id in $(dk images -q --filter "label=$e2e_label"); do dk image rm "$id" >/dev/null 2>&1 || true; done
  echo "e2e-down: done"
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
    echo "This removes the ferret-test container, network, image and the data volume $volume."
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
