#!/usr/bin/env bash
# The passkey fixture container of the U4 tests, on the Docker build host (never locally, never
# Docker Desktop): two relying parties (webauthn-rs and @simplewebauthn/server), the test pages and a
# test certificate authority, behind the host names of test/passkey-rp/hosts.json.
#
#   scripts/lanbox-passkey-rp.sh up       build the image (once per content), make the test network and
#                                         start the container (a second `up` replaces it)
#   scripts/lanbox-passkey-rp.sh down [--purge]  remove the container and the test network (--purge: and the volume with the CA)
#   scripts/lanbox-passkey-rp.sh status   one line: running or not, and the image
#   scripts/lanbox-passkey-rp.sh ca       print the test CA (PEM): the profile of the test browser trusts it, nothing else does
#   scripts/lanbox-passkey-rp.sh network  print the name of the test network
#   scripts/lanbox-passkey-rp.sh logs     the container's log
#   scripts/lanbox-passkey-rp.sh test     the checks of the fixtures themselves (test/passkey-rp/test): they
#                                         must refuse a tampered signature, RP ID hash, origin, crossOrigin
#                                         and flags, and accept the untampered response
#
# The test CA lives in the volume ferret-u4-passkey-rp-state (30 days, made once and kept over restarts of the container, so a
# test browser that trusts it keeps working; down --purge removes it).
# The container is named ferret-u4-passkey-rp and carries the labels owner=ferret and dev.run (a long-lived
# environment, dev.kind=env). It sits on the network ferret-u4-passkey-rp-net, which is created with
# --internal: it has no route to anywhere. Every host name of hosts.json is a network alias of the
# container, so a test browser has to join that network to see them (docker run --network
# ferret-u4-passkey-rp-net ...), and has no other network. The names resolve nowhere else: no name is
# ever sent to a public server, and the CA is limited to these names. localhost (http and https) is
# served by the test browser's own container: forward.mjs (test/passkey-rp) pipes its ports 80 and 443
# to the fixture.
#
# Env: FERRET_DOCKER_ARGS (default "--context lanbox").
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
cd "$(dirname "$0")/.."

# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context lanbox})
dir=test/passkey-rp
hosts_json=$dir/hosts.json
container="$(sed -n 's/.*"container": *"\([^"]*\)".*/\1/p' "$hosts_json")"
network="$(sed -n 's/.*"network": *"\([^"]*\)".*/\1/p' "$hosts_json")"
[ -n "$container" ] && [ -n "$network" ] || { echo "lanbox-passkey-rp.sh: $hosts_json names no container or network" >&2; exit 1; }
# The host names: the quoted strings between "hosts": [ and the closing bracket.
mapfile -t hosts < <(sed -n '/"hosts": *\[/,/\]/p' "$hosts_json" | grep -o '"[^"]*"' | tr -d '"' | grep -v '^hosts$')
[ "${#hosts[@]}" -gt 0 ] || { echo "lanbox-passkey-rp.sh: $hosts_json lists no host" >&2; exit 1; }

# The tag follows the content of the build context (without the tests).
image_hash() {
  tar -c --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --exclude=node_modules --exclude=target --exclude="$dir/test" "$dir" \
    | sha256sum | cut -c1-12
}

usage() {
  echo "usage: scripts/lanbox-passkey-rp.sh up | down | status | ca | network | logs | test" >&2
  exit 2
}

cmd="${1:-}"
case "$cmd" in
  up | down | status | ca | network | logs | test) ;;
  *) usage ;;
esac

volume="$container-state"
running() { [ "$(docker "${docker_args[@]}" inspect -f '{{.State.Running}}' "$container" 2> /dev/null || true)" = true ]; }

case "$cmd" in
  network)
    echo "$network"
    ;;
  status)
    if running; then
      echo "$container is running on $network ($(docker "${docker_args[@]}" inspect -f '{{.Config.Image}}' "$container"))"
    else
      echo "$container is not running"
      exit 1
    fi
    ;;
  ca)
    running || { echo "lanbox-passkey-rp.sh: $container is not running (scripts/lanbox-passkey-rp.sh up)" >&2; exit 1; }
    docker "${docker_args[@]}" exec "$container" cat /work/ca.pem
    ;;
  logs)
    docker "${docker_args[@]}" logs "$container"
    ;;
  down)
    if docker "${docker_args[@]}" inspect "$container" > /dev/null 2>&1; then
      docker "${docker_args[@]}" rm -f "$container" > /dev/null
    fi
    # Our network, and only ours: it must be ours by label, and empty (a test browser may still sit on it).
    if [ "$(docker "${docker_args[@]}" network inspect -f '{{index .Labels "owner"}}' "$network" 2> /dev/null || true)" = ferret ]; then
      docker "${docker_args[@]}" network rm "$network" > /dev/null 2>&1 || echo "lanbox-passkey-rp.sh: the network $network still has a container on it; it stays" >&2
    fi
    if [ "${2:-}" = --purge ] && [ "$(docker "${docker_args[@]}" volume inspect -f '{{index .Labels "owner"}}' "$volume" 2> /dev/null || true)" = ferret ]; then
      docker "${docker_args[@]}" volume rm "$volume" > /dev/null
    fi
    echo "lanbox-passkey-rp.sh: down"
    ;;
  up)
    tag="ferret-passkey-rp:$(image_hash)"
    if ! docker "${docker_args[@]}" image inspect "$tag" > /dev/null 2>&1; then
      tar -c --exclude=node_modules --exclude=target --exclude="$dir/test" -C "$dir" . \
        | docker "${docker_args[@]}" build --label owner=ferret -t "$tag" - >&2
      # The images of earlier content (ours, by label) are removed one by one, never pruned.
      for old in $(docker "${docker_args[@]}" image ls --filter label=owner=ferret --format '{{.Repository}}:{{.Tag}}' | grep '^ferret-passkey-rp:' | grep -v ":${tag#*:}\$" || true); do
        docker "${docker_args[@]}" image rm "$old" > /dev/null 2>&1 || true
      done
    fi
    if ! docker "${docker_args[@]}" network inspect "$network" > /dev/null 2>&1; then
      docker "${docker_args[@]}" network create --internal --label owner=ferret "$network" > /dev/null
    fi
    if [ "$(docker "${docker_args[@]}" network inspect -f '{{.Internal}}' "$network")" != true ]; then
      echo "lanbox-passkey-rp.sh: the network $network exists but is not internal; refusing to use it" >&2
      exit 1
    fi
    if docker "${docker_args[@]}" inspect "$container" > /dev/null 2>&1; then
      docker "${docker_args[@]}" rm -f "$container" > /dev/null
    fi
    aliases=()
    for h in "${hosts[@]}"; do aliases+=(--network-alias "$h"); done
    if ! docker "${docker_args[@]}" volume inspect "$volume" > /dev/null 2>&1; then
      docker "${docker_args[@]}" volume create --label owner=ferret "$volume" > /dev/null
    fi
    docker "${docker_args[@]}" run -d --init --name "$container" \
      --label owner=ferret \
      --label dev.run="$container" \
      --label dev.kind=env \
      --label "dev.title=Passkey fixtures for U4 (two relying parties, test CA)" \
      --network "$network" "${aliases[@]}" \
      --cpus 2 --memory 1g \
      --cap-drop ALL \
      --security-opt no-new-privileges:true \
      --sysctl net.ipv4.ip_unprivileged_port_start=0 \
      --read-only \
      -v "$volume":/work \
      --tmpfs /tmp:size=16m \
      "$tag" > /dev/null
    for _ in $(seq 1 60); do
      if docker "${docker_args[@]}" exec "$container" node -e 'fetch("http://127.0.0.1/healthz").then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))' > /dev/null 2>&1 \
        && docker "${docker_args[@]}" exec "$container" node -e 'fetch("http://127.0.0.1:8081/healthz").then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))' > /dev/null 2>&1; then
        echo "lanbox-passkey-rp.sh: $container is up on the network $network (image $tag)" >&2
        echo "  hosts: ${hosts[*]} (and localhost, through forward.mjs in the test browser's container)" >&2
        echo "  trust the CA with: scripts/lanbox-passkey-rp.sh ca > ca.pem" >&2
        exit 0
      fi
      sleep 1
    done
    echo "lanbox-passkey-rp.sh: $container did not become healthy; its log:" >&2
    docker "${docker_args[@]}" logs "$container" >&2 || true
    exit 1
    ;;
  test)
    running || { echo "lanbox-passkey-rp.sh: $container is not running (scripts/lanbox-passkey-rp.sh up)" >&2; exit 1; }
    ca="$(docker "${docker_args[@]}" exec "$container" cat /work/ca.pem)"
    # The names stay inside the test network: a container on the ordinary bridge must not resolve any of the .test names (the
    # github.io names are real public names that the network's aliases only take over, so they are not asked about).
    for h in "${hosts[@]}"; do
      case "$h" in *.test) ;; *) continue ;; esac
      if ! docker "${docker_args[@]}" run --rm --init --label owner=ferret --label dev.run=ferret-u4-passkey-rp-selftest \
        --name "ferret-u4-passkey-rp-dns-$$" --network bridge --cap-drop ALL --security-opt no-new-privileges:true --cpus 1 --memory 128m \
        node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee \
        node -e 'require("dns").lookup(process.argv[1], (e) => process.exit(e ? 0 : 1))' "$h"; then
        echo "lanbox-passkey-rp.sh: $h resolves outside the test network" >&2
        exit 1
      fi
    done
    echo "lanbox-passkey-rp.sh: no .test name of the fixture resolves outside the test network" >&2
    # A node container on the test network, with the CA, and nothing else: it reaches the fixture by its host names.
    tar -c -C "$dir" test hosts.json \
      | docker "${docker_args[@]}" run --rm -i --init \
        --label owner=ferret --label dev.run=ferret-u4-passkey-rp-selftest --label "dev.title=Passkey fixture self-test" \
        --name "ferret-u4-passkey-rp-selftest-$$" \
        --network "$network" \
        --cpus 1 --memory 512m \
        --cap-drop ALL --security-opt no-new-privileges:true \
        --user 10001:10001 --read-only --tmpfs /work:uid=10001,gid=10001,exec,size=64m --tmpfs /tmp:size=16m \
        -e FIXTURE_CA_PEM="$ca" -w /work \
        node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee \
        sh -c 'tar -x -C /work && printf "%s\n" "$FIXTURE_CA_PEM" > /tmp/ca.pem && NODE_EXTRA_CA_CERTS=/tmp/ca.pem node --test --test-timeout=60000 /work/test/*.test.mjs'
    ;;
esac
