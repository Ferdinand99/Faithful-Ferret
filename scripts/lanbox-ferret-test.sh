#!/usr/bin/env bash
# The Faithful Ferret test stack on the LANBox (compose project ferret-test).
# Everything goes through the Docker context `unraid`; never Docker Desktop,
# never Tower. Only resources named ferret-test* and labelled
# owner=ferret-test are created, changed or removed.
#
#   scripts/lanbox-ferret-test.sh up       build, start, print addresses and setup token
#   scripts/lanbox-ferret-test.sh down     stop and remove the container (the data stays)
#   scripts/lanbox-ferret-test.sh reset    also remove the data volume (asks first)
#   scripts/lanbox-ferret-test.sh logs     follow the server log
#   scripts/lanbox-ferret-test.sh status   container, health, volume
#   scripts/lanbox-ferret-test.sh smoke    check /healthz and the headers on both ports
#   scripts/lanbox-ferret-test.sh peers    peer addresses the server has seen since start
#   scripts/lanbox-ferret-test.sh token    print the setup token and the setup link
#
# docker/.env (not in git, mode 600) holds FERRET_SETUP_TOKEN and
# FERRET_TRUSTED_PROXIES. It is made on the first `up`: the proxy address is the
# one of the Newt container on the LANBox (read only, `docker inspect`), or
# FERRET_TRUSTED_PROXIES from the environment. Edit the file and run `up` again to
# change it; `peers` shows which addresses the server has seen.
#
# Env overrides:
#   FERRET_DOCKER_ARGS  replaces the default "--context unraid"
#   FERRET_LANBOX       address of the LANBox (default 10.0.3.26)
#   FERRET_PROXY_CONTAINER  name of the tunnel client container (default Newt)
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

project=ferret-test
container=ferret-test-app
volume=ferret-test-data
label=owner=ferret-test
lanbox="${FERRET_LANBOX:-10.0.3.26}"
admin_port=3040
vault_port=3041
envfile=docker/.env
composefile=docker/compose.ferret-test.yml

# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})
dk() { docker "${docker_args[@]}" "$@"; }
dc() { dk compose -p "$project" -f "$composefile" --env-file "$envfile" "$@"; }

# The address of the proxy's tunnel client (the Newt container) on the LANBox,
# read only. The container name can be changed with FERRET_PROXY_CONTAINER.
tunnel_container="${FERRET_PROXY_CONTAINER:-Newt}"
tunnel_address() {
  dk inspect "$tunnel_container" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
    | awk '{print $1}'
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
}

# Warns when the trusted proxy in docker/.env is no longer the address of the
# tunnel client (a recreated container may get another address on the bridge).
check_tunnel() {
  local now configured
  now="$(tunnel_address || true)"
  configured="$(env_value FERRET_TRUSTED_PROXIES)"
  if [ -n "$now" ] && [ "$now" != "$configured" ]; then
    echo "WARNING: $tunnel_container is now at $now but FERRET_TRUSTED_PROXIES is $configured." >&2
    echo "         Until they match, sign-in through Pangolin fails closed. Edit $envfile and run up." >&2
  fi
}

env_value() { sed -n "s/^$1=//p" "$envfile" | head -n 1; }

# Refuses to start when something else on the LANBox already listens on one of
# the two ports (the stack uses the host network, so `docker ps` cannot tell).
# A throwaway container on the host network lists the listening ports.
alpine_image=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
check_ports() {
  if [ "$(dk inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" = true ]; then
    return # ours: the ports are ours
  fi
  local port listeners
  listeners="$(dk run --rm --network host --label "$label" "$alpine_image" netstat -ltn)"
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
  echo "First administrator: open https://ferret-test.opland.net/setup?token=$(env_value FERRET_SETUP_TOKEN)"
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

cmd="${1:-}"
case "$cmd" in
  up)
    make_env
    check_ports
    dc up -d --build
    check_tunnel
    print_addresses
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
    for id in $(dk ps -aq --filter "label=$label"); do dk rm -f "$id" >/dev/null; done
    for name in $(dk volume ls -q --filter "label=$label"); do dk volume rm "$name" >/dev/null; done
    for name in $(dk network ls -q --filter "label=$label"); do dk network rm "$name" >/dev/null; done
    dk image rm ferret-test-app:latest >/dev/null 2>&1 || true
    rm -f "$envfile"
    echo "reset: done (docker/.env removed; the next up makes a new setup token)"
    ;;
  logs)
    dk logs -f --tail 200 "$container"
    ;;
  status)
    dk ps -a --filter "label=$label" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    dk inspect "$container" --format 'health: {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}; restarts: {{.RestartCount}}; user: {{.Config.User}}' 2>/dev/null || true
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
    print_addresses
    ;;
  *)
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 2
    ;;
esac
