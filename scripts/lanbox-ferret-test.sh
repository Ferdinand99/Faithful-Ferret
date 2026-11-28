#!/usr/bin/env bash
# The Faithful Ferret test stacks on the build host. Everything goes through the Docker
# context `lanbox` (see FERRET_DOCKER_ARGS); never Docker Desktop, never a production host.
#
# The test stack (compose project ferret-test, behind a reverse proxy). Only resources
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
#                                          restore epoch (`restore-epoch bump --yes`, which also ends every
#                                          session and pending sign-in code of the snapshot), start it
#                                          Both stop the app for a short while and replace data: they
#                                          are run after an explicit yes, never by a test run.
#   scripts/lanbox-ferret-test.sh label-data --yes-ferret-test
#                                          the data volume carries the label owner=ferret-test (`up` refuses a
#                                          volume that was made without it). Docker cannot add a label to a volume,
#                                          so this stops the app, copies the data to a temporary labelled volume
#                                          (checked file by file), replaces the data volume by a labelled one, copies
#                                          the data back, and removes the temporary volume. `up` starts the app again.
#
# The end-to-end stack (compose project ferret-e2e: its own app with the test clock,
# a TLS terminator and the test host names vault-e2e.test and admin-e2e.test on a
# network of its own; no published port; the data in a volume that every start removes). Only resources named
# ferret-e2e* and labelled owner=ferret-e2e are created or removed, and it never
# touches the stack above. FERRET_E2E_SUFFIX (letters and digits, default e2e) and FERRET_E2E_SUBNET (the
# first three octets of the network, default 172.30.250) put another stack beside it: every name above
# then has the suffix in place of "e2e", and only the resources labelled owner=ferret-<suffix> are touched.
# With DEV_RUN set (and DEV_TITLE), every container of the stack gets the labels dev.run and dev.title.
# The server image is built with at most FERRET_E2E_CARGO_JOBS (1 to 4, default 4) parallel cargo jobs: the
# build host is shared.
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
#                                          restore epoch (every session of the snapshot ends), start the app
#                                          (the clock offset is kept)
#   scripts/lanbox-ferret-test.sh e2e-reset    stop the app, empty the data volume (and nothing else: the backup sets in
#                                          ferret-e2e-backups stay), start the app: a new, empty server with a new server key
#                                          (the clock offset is kept)
#   scripts/lanbox-ferret-test.sh e2e-backup   stop the app, make a backup set in the volume ferret-e2e-backups with
#                                          `ferret backup create`, start the app; prints the name of the set
#   scripts/lanbox-ferret-test.sh e2e-restore-backup [set]  stop the app, empty the data volume, restore a set from
#                                          ferret-e2e-backups (the newest one without a name) with `ferret backup restore`,
#                                          start the app (the clock offset is kept)
#   scripts/lanbox-ferret-test.sh e2e-code <e-mail>  make a one-time sign-in code for the account while the app runs
#                                          (`ferret sign-in-code issue`) and print it
#   scripts/lanbox-ferret-test.sh e2e-chromium  start a Playwright browser server (Chromium, trusting the
#                                          stack's CA) on the stack's network, for a test that drives the web vault
#                                          in Chromium while it drives something else: prints its address
#                                          (ws://ferret-e2e-chromium:3000/). Its client package, playwright-core from
#                                          web/package-lock.json (checked against the lock's integrity), is in the
#                                          volume ferret-e2e-pwcore, which a test container mounts read-only on /pw
#   scripts/lanbox-ferret-test.sh e2e-down     remove the stack and its image
#   scripts/lanbox-ferret-test.sh upgrade-drill <release tag>  the upgrade from a release (for example v0.12.1) on an
#                                          end-to-end stack of its own: the suffix upg and the network 172.30.246 unless
#                                          FERRET_E2E_SUFFIX and FERRET_E2E_SUBNET say others (never the suffix e2e). The app
#                                          runs the published image of the tag (FERRET_IMAGE_REPO, default
#                                          ghcr.io/ferdinand99/faithful-ferret) by digest, refused unless its revision is
#                                          the commit of the tag and its version, cargo features and WebAssembly package are
#                                          a release's; its signature is checked with cosign 3 or newer (the release
#                                          workflow signs with cosign 3, and cosign 2 finds no signature): the cosign
#                                          installed here when it is 3 or newer, else a container of FERRET_COSIGN_IMAGE
#                                          (pinned by digest, and refused unless it is cosign 3 or newer); an older cosign
#                                          here with no such image is refused, and so is no cosign at all unless
#                                          FERRET_UPGRADE_NO_COSIGN=1 says openly that the signature is not checked. In Chromium: the first half of the scenarios
#                                          (web/test/e2e-stack/phase-upgrade-before.spec.mjs: an account with everything in
#                                          it), a backup set made by the release, the app's image swapped for a release build
#                                          of this checkout (the cargo features of a release, no test feature, the locked
#                                          WebAssembly package) on the same data while the browser and the device stay
#                                          open, then phase-upgrade-after.spec.mjs in a fresh browser. The stack is left
#                                          running: FERRET_E2E_SUFFIX=upg scripts/lanbox-ferret-test.sh e2e-down removes it
#                                          with the candidate image; the release image is removed by the drill when it
#                                          pulled it and no container uses it any more
#
# docker/.env (not in git; on a Unix host it is made with mode 600) holds
# FERRET_SETUP_TOKEN and FERRET_TRUSTED_PROXIES of the test stack. It is made on
# the first `up`: the proxy address is the one of the Newt container on the build host
# (read only, `docker inspect`), or FERRET_TRUSTED_PROXIES from the environment. Like compose,
# a variable in the environment of the shell wins over the file. Edit the file and
# run `up` again to change it; `peers` shows which addresses the server has seen.
#
# Newt outside Docker (on a host of its own, which `docker inspect` cannot see):
# set FERRET_TRUSTED_PROXIES=<its address> in docker/.env. When no Docker container of the
# tunnel client exists, `up` accepts that value only as exactly one valid IPv4 address
# (no list, no network, no loopback, not .0 or .255, not link-local) and warns when the build host gets no ping answer
# from it. With a Docker container, its address is still the only one that is accepted;
# a container that exists but has no readable address (stopped, host network) is refused,
# never treated as "outside Docker". That host needs a static IP (a fixed address or a DHCP
# reservation), because the server trusts exactly this address.
#
# Env overrides:
#   FERRET_DOCKER_ARGS  replaces the default "--context lanbox"
#   FERRET_TEST_HOST    address or name of the build host, for the direct addresses that
#                       `up` prints and for `smoke` (no default: they refuse without it)
#   FERRET_VAULT_URL, FERRET_ADMIN_URL  the public https addresses of the vault and the
#                       admin pages behind the proxy, for example https://vault.example.test
#                       and https://admin.example.test (no default: `up` writes them to
#                       docker/.env on the first run, and compose refuses to start without them)
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
test_host="${FERRET_TEST_HOST:-}"
admin_port=3040
vault_port=3041
envfile="${FERRET_ENV_FILE:-docker/.env}"
composefile=docker/compose.ferret-test.yml

# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context lanbox})
dk() { docker "${docker_args[@]}" "$@"; }
dc() { dk compose -p "$project" -f "$composefile" --env-file "$envfile" "$@"; }

# The end-to-end stack: everything it uses is named ferret-<suffix>* and has this label. The
# suffix is `e2e` unless FERRET_E2E_SUFFIX says another one (letters and digits), and the
# network's first three octets are FERRET_E2E_SUBNET (default 172.30.250), so a second stack can
# run beside the first: another project, containers, volumes, network, label and host names
# (vault-<suffix>.test), and nothing of the first is touched. The upgrade drill has a stack of its
# own: the suffix upg and the network 172.30.246 when nothing else is set.
if [ "${BASH_SOURCE[0]}" = "$0" ] && [ "${1:-}" = upgrade-drill ]; then
  : "${FERRET_E2E_SUFFIX:=upg}" "${FERRET_E2E_SUBNET:=172.30.246}"
fi
e2e_suffix="${FERRET_E2E_SUFFIX:-e2e}"
case "$e2e_suffix" in
  '' | *[!a-z0-9]* | ?????????????*) echo "lanbox-ferret-test: FERRET_E2E_SUFFIX is 1 to 12 lower-case letters and digits" >&2; exit 2 ;;
esac
e2e_subnet="${FERRET_E2E_SUBNET:-172.30.250}"
if ! printf '%s' "$e2e_subnet" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
  echo "lanbox-ferret-test: FERRET_E2E_SUBNET is the first three octets of a /28, for example 172.30.250" >&2
  exit 2
fi
case "${FERRET_E2E_CARGO_JOBS:-4}" in
  1 | 2 | 3 | 4) ;;
  *) echo "lanbox-ferret-test: FERRET_E2E_CARGO_JOBS is 1 to 4 (the build host is shared)" >&2; exit 2 ;;
esac
export FERRET_E2E_SUFFIX="$e2e_suffix" FERRET_E2E_SUBNET="$e2e_subnet" FERRET_E2E_CARGO_JOBS="${FERRET_E2E_CARGO_JOBS:-4}"
e2e_project="ferret-$e2e_suffix"
e2e_label="owner=ferret-$e2e_suffix"
e2e_composefile=docker/compose.ferret-e2e.yml
e2e_app="ferret-$e2e_suffix-app"
e2e_tls="ferret-$e2e_suffix-tls"
e2e_network="ferret-$e2e_suffix-net"
e2e_image="ferret-$e2e_suffix-app:latest"
e2e_vault_url="https://vault-$e2e_suffix.test"
e2e_admin_url="https://admin-$e2e_suffix.test"
e2e_playwright="ferret-$e2e_suffix-playwright"
# The services of the compose file keep their names (the containers' addresses on the network).
e2e_app_service=ferret-e2e-app
e2e_evil_service=ferret-e2e-evil
e2e_monitor_service=ferret-e2e-monitor
e2e_tls_service=ferret-e2e-tls
# The malicious server between the terminator and the app (web/test/e2e-stack/evil), and the
# volumes of the app's data and of its snapshot.
e2e_evil="ferret-$e2e_suffix-evil"
e2e_evil_image="ferret-$e2e_suffix-evil:latest"
e2e_data_volume="ferret-$e2e_suffix-data"
e2e_snapshot_volume=ferret-e2e-snapshot
[ "$e2e_suffix" = e2e ] || e2e_snapshot_volume="ferret-$e2e_suffix-snapshot"
# The volume of the backup sets (the app's FERRET_BACKUP_DIR), and the stand-in for the push monitor.
e2e_backups_volume="ferret-$e2e_suffix-backups"
e2e_monitor="ferret-$e2e_suffix-monitor"
e2e_monitor_image="ferret-$e2e_suffix-monitor:latest"
# The Playwright browser server of `e2e-chromium`, and the volume with its client package.
e2e_chromium="ferret-$e2e_suffix-chromium"
e2e_pwcore_volume="ferret-$e2e_suffix-pwcore"
# With DEV_RUN set (lower-case letters, digits and dashes, at most 63, as for scripts/lanbox.sh), every
# container of the stack and every helper container it starts gets the label dev.run=$DEV_RUN, and
# dev.title=$DEV_TITLE when that is set too, next to the label owner=ferret-<suffix>. Without DEV_RUN nothing is added.
e2e_dev_labels=()
if [ -n "${DEV_RUN:-}" ]; then
  if ! (LC_ALL=C; [[ $DEV_RUN =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]]); then
    echo "lanbox-ferret-test: DEV_RUN must match ^[a-z0-9][a-z0-9-]{0,62}$" >&2
    exit 2
  fi
  e2e_dev_labels+=(--label "dev.run=$DEV_RUN")
  [ -z "${DEV_TITLE:-}" ] || e2e_dev_labels+=(--label "dev.title=$DEV_TITLE")
fi
# The same labels for the services of the compose file, as a second compose file on stdout. Compose
# cannot leave a label out when a variable is empty, so this file is used only when DEV_RUN is set.
e2e_dev_override() {
  local title service
  title="$(printf '%s' "${DEV_TITLE:-}" | tr -d '\000-\037')"
  # A double-quoted YAML string, and no $ that compose would take for a variable.
  title="${title//\\/\\\\}"
  title="${title//\"/\\\"}"
  title="${title//\$/\$\$}"
  echo "services:"
  for service in "$e2e_app_service" "$e2e_evil_service" "$e2e_monitor_service" "$e2e_tls_service"; do
    echo "  $service:"
    echo "    labels:"
    echo "      dev.run: \"$DEV_RUN\""
    [ -z "$title" ] || echo "      dev.title: \"$title\""
  done
}
# The compose file wants the setup token of the run; commands that only stop or
# list the stack do not need the real one.
dce() {
  local files=(-f "$e2e_composefile") override="" rc=0
  if [ -n "${DEV_RUN:-}" ]; then
    override="$(mktemp)"
    e2e_dev_override > "$override"
    # Git Bash: the Docker program on Windows does not know the /tmp of the shell.
    if command -v cygpath > /dev/null 2>&1; then files+=(-f "$(cygpath -m "$override")"); else files+=(-f "$override"); fi
  fi
  FERRET_E2E_SETUP_TOKEN="${FERRET_E2E_SETUP_TOKEN:-unused}" FERRET_E2E_PUSH_TOKEN="${FERRET_E2E_PUSH_TOKEN:-unused}" dk compose -p "$e2e_project" "${files[@]}" "$@" || rc=$?
  [ -z "$override" ] || rm -f "$override"
  return "$rc"
}

# The tunnel client of the proxy (the Newt container) as Docker on the build host
# knows it, read only. The container name can be changed with
# FERRET_PROXY_CONTAINER. Prints exactly one of:
#   address <ip>  the container runs on a network with an address
#   notfound      Docker answered that there is no container with that name (the
#                 tunnel client runs outside Docker, for example on a separate host)
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
  local vault_url="${FERRET_VAULT_URL:-}" admin_url="${FERRET_ADMIN_URL:-}"
  if [ -z "$vault_url" ] || [ -z "$admin_url" ]; then
    echo "lanbox-ferret-test: no $envfile yet and no public addresses. Run again with" >&2
    echo "FERRET_VAULT_URL and FERRET_ADMIN_URL set to the https addresses of the vault and" >&2
    echo "of the admin pages behind the proxy (for example https://vault.example.test and" >&2
    echo "https://admin.example.test)." >&2
    exit 2
  fi
  local token
  token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  umask 077
  {
    echo "FERRET_SETUP_TOKEN=$token"
    echo "FERRET_TRUSTED_PROXIES=$proxies"
    echo "FERRET_VAULT_URL=$vault_url"
    echo "FERRET_ADMIN_URL=$admin_url"
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

# Whether the build host can reach the address (one ping from a throwaway container
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
#  * As a Docker container on the build host. Its address is then the only one that
#    is believed: any other FERRET_TRUSTED_PROXIES is a mismatch. When the
#    container exists but its address cannot be read (stopped, host or none
#    network, another container's network) or Docker cannot be asked, the answer
#    is a refusal, never the explicit value below.
#  * Outside Docker: only when Docker answers that there is no container with that
#    name (Newt may run on a host of its own). Then
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
      echo "cannot read the address of $tunnel_container on the network it uses to reach the build host (the container exists but is stopped or has no address of its own, or Docker on the build host could not be asked)"
      return 0
      ;;
  esac
  if [ -z "$configured" ]; then
    echo "there is no Docker container named $tunnel_container on the build host, and FERRET_TRUSTED_PROXIES is empty"
    return 0
  fi
  if ! single_ipv4 "$configured"; then
    echo "there is no Docker container named $tunnel_container on the build host, so FERRET_TRUSTED_PROXIES must be exactly one IPv4 address (no list, no network, no loopback, not .0 or .255), but it is $configured"
    return 0
  fi
  return 1
}

# Prints a warning when the address of a tunnel client that runs outside Docker
# does not answer from the build host. Nothing when the address comes from Docker.
unreachable_warning() {
  local configured
  [ "$(tunnel_lookup)" = notfound ] || return 0
  configured="$(configured_proxies)"
  single_ipv4 "$configured" || return 0
  reachable "$configured" || echo "the address $configured does not answer ping from the build host (a tunnel client may block ping; check that it is the right address, and run the peers command after a sign-in to see which addresses the server sees)"
}

# `up` refuses to start on a mismatch: a proxy address that is not the tunnel
# client's would trust some other host, or nobody.
require_tunnel() {
  local why warning
  if why="$(tunnel_mismatch)"; then
    echo "lanbox-ferret-test: refusing to start: $why." >&2
    echo "Set FERRET_TRUSTED_PROXIES in $envfile (and not in the shell) to the address of" >&2
    echo "$tunnel_container. When it runs outside Docker (a separate host, for example), that is" >&2
    echo "its own LAN address, as one single IPv4 address (not a list, not a network), and that" >&2
    echo "host needs a static IP (a fixed address or a DHCP reservation)." >&2
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

# Refuses to start when something else on the build host already listens on one of
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
      echo "lanbox-ferret-test: port $port is already in use on the build host" >&2
      exit 1
    fi
  done
}

# The address of the build host for the direct addresses; no default, so a missing
# value stops the command with a clear message instead of using someone else's host.
require_test_host() {
  if [ -z "$test_host" ]; then
    echo "lanbox-ferret-test: set FERRET_TEST_HOST to the address or name of the build host" >&2
    exit 2
  fi
}

# A public address that compose will inject (the environment of the shell wins over
# docker/.env); stops with a clear message when it is not set.
public_url() {
  local url
  url="$(compose_value "$1")"
  if [ -z "$url" ]; then
    echo "lanbox-ferret-test: $1 is not set (docker/.env or the environment of the shell)" >&2
    exit 2
  fi
  printf '%s\n' "$url"
}

print_addresses() {
  local admin_url vault_url
  require_test_host
  admin_url="$(public_url FERRET_ADMIN_URL)" || exit 2
  vault_url="$(public_url FERRET_VAULT_URL)" || exit 2
  echo
  echo "Admin  (proxy) $admin_url    direct http://$test_host:$admin_port"
  echo "Vault  (proxy) $vault_url    direct http://$test_host:$vault_port"
}

print_setup_link() {
  local admin_url
  admin_url="$(public_url FERRET_ADMIN_URL)" || exit 2
  echo "First administrator: open $admin_url/setup?token=$(compose_value FERRET_SETUP_TOKEN)"
}

# Compose must accept the env file: the setup token, the proxy address and the two
# public addresses are all required. Compose prints which one is missing.
require_compose_env() {
  if ! dc config --quiet >/dev/null; then
    echo "lanbox-ferret-test: compose does not accept $envfile (see above)." >&2
    exit 2
  fi
}

# Both listeners: 200 on /healthz, no Server header, the security headers of the
# listener, and application/wasm for the WebAssembly file on the vault listener.
smoke() {
  local fail=0 port wasm response
  require_test_host
  check() { # name, "ok" or anything else
    if [ "$2" = ok ]; then echo "  ok    $1"; else echo "  FAIL  $1"; fail=1; fi
  }
  # The status line and headers of a GET, without the body.
  headers_of() { curl -sS -m 10 -i "$1" 2>/dev/null | tr -d '\r' | sed '/^$/q' || true; }
  has() { printf '%s\n' "$1" | grep -qi "^$2:" && echo ok || echo no; }
  absent() { printf '%s\n' "$1" | grep -qi "^$2:" && echo no || echo ok; }
  for port in "$admin_port" "$vault_port"; do
    echo "http://$test_host:$port"
    response="$(headers_of "http://$test_host:$port/healthz")"
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
  wasm="$(curl -sS -m 10 "http://$test_host:$vault_port/" 2>/dev/null | grep -oE '/[A-Za-z0-9_./-]*\.wasm' | head -n 1 || true)"
  wasm="${wasm:-/pkg-web/ferret_core_wasm_bg.wasm}"
  response="$(headers_of "http://$test_host:$vault_port$wasm")"
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
  for name in "$e2e_app" "$e2e_evil" "$e2e_tls" "$e2e_monitor"; do
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

# Which WebAssembly package the web vault of a running stack was built with, as its server says it
# (`lock <sha256>`, `release <sha256>`, `tree <sha256>` or `none`): the server's own --build-info,
# so the stack never has to be trusted to say it some other way.
wasm_of() {
  dk exec "$1" /usr/local/bin/ferret --build-info 2>/dev/null | sed -n 's/^wasm: //p'
}

# FERRET_WASM_SOURCE=tree: the e2e stack's web vault is built with the WebAssembly package of this
# commit (scripts/lanbox-wasm.sh --tree builds it on the build host; one built from this commit is
# reused) instead of the published one, and the commit goes into the image build as WASM_COMMIT.
# The default (lock) is the published package of web/wasm.lock.json. Only the e2e stack can do this:
# the ferret-test stack and the stack with real data never take a tree package.
e2e_wasm_prepare() {
  case "${FERRET_WASM_SOURCE:-lock}" in
    lock) export FERRET_WASM_SOURCE=lock FERRET_WASM_COMMIT="" ;;
    tree)
      bash scripts/lanbox-wasm.sh --tree >&2
      FERRET_WASM_COMMIT="$(sed -n 's/.*"commit":"\([^"]*\)".*/\1/p' wasm-package/wasm-tree.json)"
      [ -n "$FERRET_WASM_COMMIT" ] || { echo "lanbox-ferret-test: wasm-package/wasm-tree.json names no commit" >&2; exit 1; }
      export FERRET_WASM_SOURCE=tree FERRET_WASM_COMMIT
      ;;
    *) echo "lanbox-ferret-test: FERRET_WASM_SOURCE is lock or tree" >&2; exit 2 ;;
  esac
}

e2e_up() {
  local token push
  e2e_wasm_prepare
  # A fresh stack every time: the stack and its data volume are removed first, so the
  # database starts empty.
  e2e_remove
  token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  push="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FERRET_E2E_SETUP_TOKEN="$token" FERRET_E2E_PUSH_TOKEN="$push" dce up -d --build --wait
  echo
  echo "End-to-end stack is up (project $e2e_project, no published ports):"
  echo "  vault  $e2e_vault_url  admin  $e2e_admin_url   (only on the network $e2e_network)"
  echo "  wasm   $(wasm_of "$e2e_app")   (what the web vault of the server was built with: lock = published, tree = this commit)"
  echo "  run the tests:  scripts/lanbox-ferret-test.sh e2e-run    setup token:  scripts/lanbox-ferret-test.sh e2e-token"
}

e2e_down() {
  e2e_remove
  dk image rm "$e2e_image" >/dev/null 2>&1 || true
  dk image rm "$e2e_evil_image" >/dev/null 2>&1 || true
  dk image rm "$e2e_monitor_image" >/dev/null 2>&1 || true
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
e2e_bump() { dce run --rm -T --no-deps "$e2e_app_service" restore-epoch bump --yes; }
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
  take_snapshot "$e2e_data_volume" "$e2e_snapshot_volume" "$e2e_label" "$e2e_snapshot_volume" e2e_stop_app e2e_start_app
  echo "e2e-snapshot: the data of $e2e_app is in the volume $e2e_snapshot_volume"
}

# Puts the snapshot back with a higher restore epoch.
e2e_restore_snapshot() {
  e2e_require_running
  e2e_clock_before="$(e2e_clock_offset)"
  restore_snapshot "$e2e_snapshot_volume" "$e2e_data_volume" "$e2e_label" "$e2e_snapshot_volume" e2e_stop_app e2e_bump e2e_start_app
  e2e_evil_reset
  echo "e2e-restore-snapshot: $e2e_app runs on the snapshot, with a higher restore epoch"
}

# Empties the data volume of the app (the app must be stopped) and nothing else: the volume of the backup sets is not
# mounted. The job runs in a helper container of the pinned Alpine image: no network, no capability but the ones that
# removing files of another user needs, no new privileges, a memory limit. The script for the container is in single quotes on
# purpose.
# shellcheck disable=SC2016
e2e_wipe_data() {
  dk run --rm --name "$e2e_project-wipe" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true --memory 64m \
    -v "$e2e_data_volume:/data" \
    "$alpine_image" sh -c 'find /data -mindepth 1 -maxdepth 1 -exec rm -rf {} + && [ -z "$(ls -A /data)" ]' \
    || { echo "e2e-reset: the data volume was not emptied; the app stays stopped" >&2; exit 1; }
}

# The newest backup set in the volume (a name; nothing when there is none). Mounted read-only.
e2e_newest_set() {
  dk run --rm --name "$e2e_project-lsbackups" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none \
    --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges:true --memory 64m \
    -v "$e2e_backups_volume:/backups:ro" \
    "$alpine_image" sh -c 'ls -1t /backups | grep -v "^\." | head -n 1'
}

# How many backup sets the volume holds (folders; the status file is not one). Mounted read-only.
e2e_set_count() {
  dk run --rm --name "$e2e_project-countbackups" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none     --cap-drop ALL --cap-add DAC_OVERRIDE --security-opt no-new-privileges:true --memory 64m     -v "$e2e_backups_volume:/backups:ro"     "$alpine_image" sh -c 'find /backups -mindepth 1 -maxdepth 1 -type d ! -name ".*" | wc -l'
}

# A new, empty server: the app is stopped, the data is emptied, the app is started (a new server key, no account, the setup
# token of the stack still works). The backup sets stay. Nothing the malicious server recorded belongs to it any more.
e2e_reset() {
  e2e_require_running
  e2e_clock_before="$(e2e_clock_offset)"
  e2e_stop_app
  e2e_wipe_data
  e2e_start_app
  e2e_evil_reset
  echo "e2e-reset: $e2e_app runs on empty data (the backup sets are still in $e2e_backups_volume)"
}

# A backup set made by the server's own command while the app is stopped (the command takes the lock of the data directory).
e2e_backup() {
  e2e_require_running
  e2e_clock_before="$(e2e_clock_offset)"
  e2e_stop_app
  local out rc=0
  out="$(dce run --rm -T --no-deps "$e2e_app_service" backup create 2>&1)" || rc=$?
  e2e_start_app
  [ "$rc" -eq 0 ] || { echo "e2e-backup: the backup failed (exit $rc): $out" >&2; exit 1; }
  echo "e2e-backup: $out"
}

# Puts a backup set back on empty data: the app is stopped, the data is emptied, the set is restored by `ferret backup restore`
# (the restore epoch goes above the time, every session and code ends), the app is started.
e2e_restore_backup() {
  e2e_require_running
  local name="${1:-}" out rc=0
  [ -n "$name" ] || name="$(e2e_newest_set)"
  case "$name" in
    '' | *[!A-Za-z0-9._-]* | .*) echo "e2e-restore-backup: no usable backup set (${name:-none}); make one with e2e-backup" >&2; exit 1 ;;
  esac
  e2e_clock_before="$(e2e_clock_offset)"
  e2e_stop_app
  e2e_wipe_data
  out="$(dce run --rm -T --no-deps "$e2e_app_service" backup restore --from "/backups/$name" --yes 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "e2e-restore-backup: the restore failed (exit $rc): $out; the app stays stopped" >&2
    exit 1
  fi
  e2e_start_app
  e2e_evil_reset
  echo "e2e-restore-backup: $out"
}

# A one-time sign-in code for an account, made while the app runs. Prints the code only.
e2e_code() {
  local email="${1:-}" out
  case "$email" in
    '' | *[!A-Za-z0-9._@+-]*) echo "usage: e2e-code <e-mail> (letters, digits and . _ @ + - only)" >&2; exit 2 ;;
  esac
  e2e_require_running
  out="$(dk exec -u 1000:1000 "$e2e_app" ferret sign-in-code issue --email "$email" --yes)" || { echo "e2e-code: no code was made: $out" >&2; exit 1; }
  printf '%s\n' "$out" | sed -n 's/^sign-in code for [^ ]*: //p' | head -n 1
}

# The runner image (docker/e2e-runner.Dockerfile: the Playwright image of
# scripts/lanbox-browsers.sh plus certutil), built on first use. The tag follows the
# content of the file. The Dockerfile goes in on stdin, so no build context (and
# nothing from docker/, where the .env of the test stack lives) is sent.
runner_hash="$(tr -d '' < docker/e2e-runner.Dockerfile | sha256sum | cut -c1-12)"
runner_image="ferret-$e2e_suffix-playwright:$runner_hash"
e2e_runner_image() {
  if ! dk image inspect "$runner_image" >/dev/null 2>&1; then
    dk build --label "$e2e_label" -t "$runner_image" - < docker/e2e-runner.Dockerfile >&2
  fi
}

# Runs the Playwright tests of web/ in a throwaway container on the stack's
# network, so the test hosts resolve and no port is published. The network of the stack
# has no way out, so the packages are installed first, in a container of its own on the
# default network (npm ci, the only step that needs the internet), and the tests run in a
# container on the stack's network only. The web/ folder is
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
  local pem token
  pem="$(e2e_ca)"
  token="$(e2e_token)"
  PW_NETWORK="$e2e_network" PW_NAME="$e2e_playwright" PW_LABEL="$e2e_label" \
    PW_VAULT_URL="$e2e_vault_url" PW_ADMIN_URL="$e2e_admin_url" PW_EVIL_URL="http://$e2e_evil_service:9000" \
    PW_TOKEN="$token" PW_CA_PEM="$pem" PW_HOSTS="" \
    PW_MONITOR_URL="http://$e2e_monitor_service:9100" PW_PUSH_TOKEN="$(e2e_push_token)" \
    playwright_run "$@"
}

# A Playwright browser server on the stack's network (see e2e-chromium in the head of this file). The
# client package is fetched in a container of its own on the default network (the only step with the
# internet), checked against the integrity that web/package-lock.json records, and unpacked into a
# labelled volume; the server runs the same package with the Chromium of the runner image (the same
# Playwright version as web/package.json), trusts the stack's CA through an NSS database, publishes no
# port and is removed with the rest of the stack (e2e-down removes everything with the stack's label).
e2e_chromium() {
  e2e_require_running
  e2e_runner_image
  local pem fetch
  pem="$(e2e_ca)"
  dk rm -f "$e2e_chromium" >/dev/null 2>&1 || true
  dk volume rm "$e2e_pwcore_volume" >/dev/null 2>&1 || true
  dk volume create --label "$e2e_label" "$e2e_pwcore_volume" >/dev/null
  # The script for the container is in single quotes on purpose.
  # shellcheck disable=SC2016
  fetch='const lock = JSON.parse(require("fs").readFileSync(0, "utf8"));
const entry = lock.packages && lock.packages["node_modules/playwright-core"];
if (!entry || !/^https:\/\/registry\.npmjs\.org\//.test(entry.resolved) || !/^sha512-/.test(entry.integrity)) throw new Error("web/package-lock.json has no usable playwright-core entry");
fetch(entry.resolved, { signal: AbortSignal.timeout(120000) }).then((r) => {
  if (!r.ok) throw new Error(entry.resolved + " answered " + r.status);
  return r.arrayBuffer();
}).then((b) => {
  const buf = Buffer.from(b);
  const sum = "sha512-" + require("crypto").createHash("sha512").update(buf).digest("base64");
  if (sum !== entry.integrity) throw new Error("playwright-core: integrity mismatch");
  process.stdout.write(buf);
}).catch((e) => { console.error("e2e-chromium: " + e.message); process.exit(1); });'
  # shellcheck disable=SC2016
  dk run --rm -i --init \
    --name "$e2e_chromium-fetch" \
    --label "$e2e_label" "${e2e_dev_labels[@]}" \
    --network bridge \
    --cpus 1 --memory 1g \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --read-only \
    --tmpfs /work:exec,size=256m \
    --tmpfs /tmp:size=64m \
    -v "$e2e_pwcore_volume:/pw" \
    -w /work \
    -e FETCH="$fetch" \
    "$runner_image" \
    sh -c 'node -e "$FETCH" > /work/core.tgz && mkdir -p /pw/node_modules/playwright-core && tar -xzf /work/core.tgz -C /pw/node_modules/playwright-core --strip-components=1 --no-same-owner && chmod -R a+rX /pw' \
    < web/package-lock.json >&2
  # shellcheck disable=SC2016
  dk run -d --rm --init \
    --name "$e2e_chromium" \
    --label "$e2e_label" "${e2e_dev_labels[@]}" \
    --network "$e2e_network" \
    --cpus 2 --memory 3g --shm-size 1g \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:exec,size=1g \
    -v "$e2e_pwcore_volume:/pw:ro" \
    -e FERRET_E2E_CA_PEM="$pem" \
    "$runner_image" \
    sh -c 'set -e
printf "%s\n" "$FERRET_E2E_CA_PEM" > /tmp/e2e-ca.crt
mkdir -p "$HOME/.pki/nssdb"
certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n ferret-e2e -i /tmp/e2e-ca.crt
exec node /pw/node_modules/playwright-core/cli.js run-server --port 3000 --host 0.0.0.0' >/dev/null
  # Up once it takes connections on its port.
  local _
  for _ in $(seq 1 60); do
    if dk exec "$e2e_chromium" node -e 'require("net").connect(3000, "127.0.0.1").on("connect", () => process.exit(0)).on("error", () => process.exit(1))' >/dev/null 2>&1; then
      echo "ws://$e2e_chromium:3000/"
      return 0
    fi
    sleep 1
  done
  dk logs "$e2e_chromium" >&2 2>&1 || true
  echo "e2e-chromium: the browser server did not start" >&2
  exit 1
}

# The token in the push address of the app (the tests look for it in what the server shows and logs).
e2e_push_token() { dk exec "$e2e_app" printenv FERRET_BACKUP_PUSH_URL | sed 's#.*/##'; }

# The runner itself, for a stack that is reached over a docker network (the e2e stack) or on
# the host's loopback (the drill stack of scripts/ferret-home.sh). The caller gives, in the
# environment: PW_NETWORK (a docker network, or host), PW_NAME and PW_LABEL (the container),
# PW_VAULT_URL, PW_ADMIN_URL, PW_EVIL_URL, PW_TOKEN (the setup token), PW_CA_PEM (the test
# CA) and PW_HOSTS (space separated name=address pairs for the runner's hosts file).
playwright_run() {
  local inner hosts=() pair
  e2e_runner_image
  for pair in ${PW_HOSTS:-}; do hosts+=(--add-host "${pair%%=*}:${pair#*=}"); done
  # The script for the container is in single quotes on purpose.
  # shellcheck disable=SC2016
  inner='set -e
tar -x -i -C /work
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
  # The packages are installed first, in a container of its own on the default network (the only
  # step that needs the internet); node_modules comes out as a tar. The tests then run in a
  # container on the stack's network only, which has no way out.
  local deps
  deps="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$deps'" RETURN
  # A stack built against the package of this commit (FERRET_WASM_SOURCE=tree) has its device client run the
  # Node build of the same package; the stack must be the one that was asked for.
  # The upgrade drill runs its first half on a release image, whose web vault has the package of its own release run
  # (e2e_wasm_stack=release); its device client still runs the locked package, which a release's core matches.
  local node_env=() node_pack=() want have node_tar
  want="${FERRET_WASM_SOURCE:-lock}"
  have="$(wasm_of "$e2e_app")"
  case "$have" in
    "" | "${e2e_wasm_stack:-$want} "*) ;;
    *) echo "lanbox-ferret-test: the web vault of the stack was built with the WebAssembly package '$have', but FERRET_WASM_SOURCE says $want; run e2e-up again" >&2; exit 1 ;;
  esac
  if [ "$want" = tree ]; then
    node_tar="$(find wasm-package -maxdepth 1 -name 'ferret-core-wasm-node-*.tar.gz' -print -quit)"
    [ -n "$node_tar" ] || { echo "lanbox-ferret-test: wasm-package/ has no Node package (scripts/lanbox-wasm.sh --tree)" >&2; exit 1; }
    node_env=(-e "FERRET_E2E_WASM_NODE_TAR=/work/$node_tar")
    node_pack=("$node_tar")
  fi
  tar -c --exclude='web/node_modules' --exclude='web/test-results' --exclude='web/dist' web ${node_pack[@]+"${node_pack[@]}"} \
    | dk run --rm -i --init \
        --name "$PW_NAME-install" \
        --label "$PW_LABEL" "${e2e_dev_labels[@]}" \
        ${node_env[@]+"${node_env[@]}"} \
        --network bridge \
        --cpus 2 --memory 2g \
        --tmpfs /work:exec,size=1g \
        --tmpfs /root/.npm:size=512m \
        -w /work \
        "$runner_image" \
        sh -c 'tar -x -C /work && cd /work/web && npm ci --no-audit --no-fund --ignore-scripts >&2 && node -e '"'"'import("./test/e2e-stack/deviceClient.mjs").then((m) => m.prepareWasmNode())'"'"' >&2 && tar -c -C /work web/node_modules web/.wasm-node' > "$deps"
  { tar -c --exclude='web/node_modules' --exclude='web/test-results' --exclude='web/dist' web; cat "$deps"; } \
    | {
      dk create --rm -i --init \
        --name "$PW_NAME" \
        --label "$PW_LABEL" "${e2e_dev_labels[@]}" \
        --network "$PW_NETWORK" \
        "${hosts[@]}" \
        --cpus 4 --memory 8g --shm-size 2g \
        -e CI=1 \
        -e FERRET_E2E_VAULT_URL="$PW_VAULT_URL" \
        -e FERRET_E2E_ADMIN_URL="$PW_ADMIN_URL" \
        -e FERRET_E2E_EVIL_URL="$PW_EVIL_URL" \
        -e FERRET_E2E_SETUP_TOKEN="$PW_TOKEN" \
        -e FERRET_E2E_CA_PEM="$PW_CA_PEM" \
        -e FERRET_E2E_MONITOR_URL="${PW_MONITOR_URL:-}" \
        -e FERRET_E2E_PUSH_TOKEN="${PW_PUSH_TOKEN:-}" \
        -e FERRET_E2E_STATE="${FERRET_E2E_STATE:-}" \
        -e FERRET_E2E_PHASE="${FERRET_E2E_PHASE:-}" \
        --tmpfs /work:exec,size=2g \
        --tmpfs /root/.npm:size=512m \
        --tmpfs /tmp:exec,size=2g \
        -w /work \
        "$runner_image" \
        sh -c "$inner" sh "$@" > /dev/null
      dk start -a -i "$PW_NAME"
    }
}

# --- The upgrade drill --------------------------------------------------------------
# A release image on an end-to-end stack, an account with everything in it, a backup set of the release, the image
# swapped for a release build of this checkout on the same data, and the checks after it (see the head of this file).

upgrade_repo="${FERRET_IMAGE_REPO:-ghcr.io/ferdinand99/faithful-ferret}"
upgrade_signer="${FERRET_RELEASE_REPO:-Ferdinand99/Faithful-Ferret}"
upgrade_candidate="ferret-$e2e_suffix-candidate:latest"
upgrade_token=""
upgrade_push=""
upgrade_set=""
upgrade_release=""
upgrade_pulled=0

upgrade_refuse() { echo "upgrade-drill: $*" >&2; exit 1; }

# The JSON a phase left, by name (the runner prints the name, the JSON, an empty line).
upgrade_left() { # output, name
  printf '%s\n' "$1" | awk -v n="$2" '$0 == n { getline; print; exit }'
}

# The major version of cosign in the output of `cosign version` on stdin (the text form `GitVersion: v3.0.2` or the
# JSON form `"gitVersion": "v3.0.2"`), or nothing.
upgrade_cosign_major() {
  sed -n -e 's/^GitVersion:[[:space:]]*v\{0,1\}\([0-9][0-9]*\)\..*/\1/p' \
    -e 's/.*"gitVersion"[[:space:]]*:[[:space:]]*"v\{0,1\}\([0-9][0-9]*\)\..*/\1/p' | head -n 1 || true
}

# Which cosign checks the signature of the release image, decided before anything is pulled. The release workflow signs
# with cosign 3, and cosign 2 finds no signature on those images, so it must be cosign 3 or newer, as
# `scripts/ferret-home.sh up` requires: the cosign here when it is, else a container of FERRET_COSIGN_IMAGE (pinned by
# digest; its version is checked before it verifies). An older cosign here with no such image is refused, and so is no
# cosign at all unless FERRET_UPGRADE_NO_COSIGN=1 says openly that the signature is not checked.
upgrade_cosign=""
upgrade_require_cosign() {
  local major=""
  if command -v cosign > /dev/null 2>&1; then major="$( (cosign version 2>&1 || true) | upgrade_cosign_major)"; fi
  if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 3 ]; then
    upgrade_cosign=local
  elif [ -n "${FERRET_COSIGN_IMAGE:-}" ]; then
    [[ "$FERRET_COSIGN_IMAGE" =~ @sha256:[0-9a-f]{64}$ ]] || upgrade_refuse "FERRET_COSIGN_IMAGE must be pinned by digest (…@sha256:<64 hex>)"
    upgrade_cosign=image
  elif command -v cosign > /dev/null 2>&1; then
    upgrade_refuse "the cosign here is ${major:-of a version that cannot be read}, but cosign 3 or newer is needed to check the signature (the release images are signed with cosign 3, and cosign 2 finds no signature on them); install cosign 3, or set FERRET_COSIGN_IMAGE to an image of cosign 3 pinned by digest"
  elif [ "${FERRET_UPGRADE_NO_COSIGN:-}" = 1 ]; then
    upgrade_cosign=none
  else
    upgrade_refuse "no cosign here and no FERRET_COSIGN_IMAGE, so the signature of the release image cannot be checked; install cosign 3, set FERRET_COSIGN_IMAGE to an image of cosign 3 pinned by digest, or say so openly with FERRET_UPGRADE_NO_COSIGN=1"
  fi
}

# The release image of the tag, pulled and checked; sets upgrade_release to its digest reference.
upgrade_release_image() { # tag, commit of the tag
  local tag="$1" commit="$2" version="${1#v}" ref info cosign_state=verified
  local identity="^https://github.com/${upgrade_signer}/\\.github/workflows/release\\.yml@refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+)$"
  ref="$upgrade_repo:$version"
  dk image inspect "$ref" > /dev/null 2>&1 || upgrade_pulled=1
  dk pull -q "$ref" > /dev/null || upgrade_refuse "could not pull $ref"
  upgrade_release="$(dk image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -E "^${upgrade_repo//./\\.}@sha256:[0-9a-f]{64}$" | head -n 1 || true)"
  [ -n "$upgrade_release" ] || upgrade_refuse "the pulled image has no digest of $upgrade_repo"
  case "$upgrade_cosign" in
    local)
      cosign verify "$upgrade_release" --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null \
        || upgrade_refuse "the signature of $upgrade_release is not good"
      ;;
    image)
      local image_major
      image_major="$( (dk run --rm --name "$e2e_project-cosign" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --tmpfs /tmp:size=64m -e HOME=/tmp \
        "$FERRET_COSIGN_IMAGE" version 2>&1 || true) | upgrade_cosign_major)"
      [[ "$image_major" =~ ^[0-9]+$ ]] || upgrade_refuse "cannot read the version of cosign in FERRET_COSIGN_IMAGE; cosign 3 or newer is needed to check the signature"
      [ "$image_major" -ge 3 ] || upgrade_refuse "FERRET_COSIGN_IMAGE is cosign $image_major, but cosign 3 or newer is needed: the release images are signed with cosign 3, and cosign 2 finds no signature on them"
      dk run --rm --name "$e2e_project-cosign" --label "$e2e_label" "${e2e_dev_labels[@]}" --network bridge \
        --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 256m --tmpfs /tmp:size=64m -e HOME=/tmp \
        "$FERRET_COSIGN_IMAGE" verify "$upgrade_release" --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null \
        || upgrade_refuse "the signature of $upgrade_release is not good"
      ;;
    *)
      cosign_state=SKIPPED
      echo "upgrade-drill: WARNING: the signature of the release image was NOT checked (FERRET_UPGRADE_NO_COSIGN=1);" >&2
      echo "upgrade-drill: the checks below read labels of a tag that anyone with write access to the registry can move." >&2
      ;;
  esac
  [ "$(dk image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$upgrade_release")" = "$commit" ] \
    || upgrade_refuse "the revision of $upgrade_release is not the commit of $tag ($commit)"
  [ "$(dk image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$upgrade_release")" = "$version" ] \
    || upgrade_refuse "the version label of $upgrade_release is not $version"
  info="$(dk run --rm --name "$e2e_project-info" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --entrypoint /usr/local/bin/ferret "$upgrade_release" --build-info)"
  printf '%s\n' "$info" | grep -qx "ferret $version" || upgrade_refuse "the image says it is not version $version"
  printf '%s\n' "$info" | grep -Eqx 'features: (none|quick-unlock|passkey-import, quick-unlock)' \
    || upgrade_refuse "the image has the cargo features of a test build: $(printf '%s' "$info" | sed -n 's/^features: //p')"
  printf '%s\n' "$info" | grep -Eqx 'wasm: (lock|release) [0-9a-f]{64}' || upgrade_refuse "the web vault of the image was not built from a released WebAssembly package"
  echo "release: $upgrade_release (cosign=$cosign_state)"
  printf '%s\n' "$info" | sed 's/^/  /'
}

# The candidate: a release build of this checkout (the release's cargo features, the locked WebAssembly package, a
# revision), labelled as the stack's, so e2e-down removes it.
upgrade_build_candidate() {
  local info revision
  revision="$(git rev-parse HEAD)"
  [ -z "$(git status --porcelain --untracked-files=no)" ] || echo "upgrade-drill: the checkout has changes that are not committed; the candidate holds them" >&2
  dk build --label "$e2e_label" -t "$upgrade_candidate" \
    --build-arg FEATURES=passkey-import,quick-unlock --build-arg VERSION=candidate --build-arg REVISION="$revision" \
    --build-arg WASM_SOURCE=lock --build-arg CARGO_JOBS="$FERRET_E2E_CARGO_JOBS" \
    -f docker/server.Dockerfile . >&2
  info="$(dk run --rm --name "$e2e_project-info" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --entrypoint /usr/local/bin/ferret "$upgrade_candidate" --build-info)"
  printf '%s\n' "$info" | grep -qx 'features: passkey-import, quick-unlock' \
    || upgrade_refuse "the candidate has other cargo features than a release: $(printf '%s' "$info" | sed -n 's/^features: //p')"
  printf '%s\n' "$info" | grep -Eqx 'wasm: lock [0-9a-f]{64}' || upgrade_refuse "the candidate's web vault was not built from the locked WebAssembly package"
  echo "candidate: $upgrade_candidate (revision $revision)"
  printf '%s\n' "$info" | sed 's/^/  /'
}

# The image the app container runs.
upgrade_running_image() { dk inspect -f '{{.Image}}' "$e2e_app"; }

# The swap: the candidate takes the place of the release on the same data volume, with the same settings.
upgrade_swap() {
  dk tag "$upgrade_candidate" "$e2e_image" || { echo "could not tag the candidate as the stack's image" >&2; return 1; }
  FERRET_E2E_SETUP_TOKEN="$upgrade_token" FERRET_E2E_PUSH_TOKEN="$upgrade_push" \
    dce up -d --no-build --no-deps --force-recreate --wait "$e2e_app_service" >&2 \
    || { echo "the app did not come up healthy on the candidate" >&2; return 1; }
  [ "$(upgrade_running_image)" = "$(dk image inspect -f '{{.Id}}' "$upgrade_candidate")" ] || { echo "the app does not run the candidate" >&2; return 1; }
  echo "the app runs the candidate on the data of the release" >&2
  # The set the release made, checked by the new build (in a container of its own: the app keeps its address).
  [ -z "$upgrade_set" ] || dk run --rm --name "$e2e_project-verify" --label "$e2e_label" "${e2e_dev_labels[@]}" --network none \
    --read-only --cap-drop ALL --security-opt no-new-privileges:true --memory 256m -u 1000:1000 \
    -v "$e2e_backups_volume:/backups:ro" --entrypoint /usr/local/bin/ferret \
    "$upgrade_candidate" backup verify "/backups/$upgrade_set" >&2
}

# One step the first half asks for while its browser and device stay open. Bash ignores `set -e` in every subshell
# of a command that runs under `if`, `||` or `&&`, so the step and the first half are called as commands of their
# own, between `set +e` and `set -e`: the subshells below then stop at the first command that fails, and the step
# reports it (a failing `up --wait` of the swap included).
upgrade_step() { # step
  local out rc=0
  case "$1" in
    backup)
      out="$( (set -e; e2e_backup) 2>&1)"
      rc=$?
      printf '%s\n' "$out" >&2
      [ "$rc" = 0 ] || return "$rc"
      upgrade_set="$(printf '%s\n' "$out" | sed -n 's/.*backup set \([A-Za-z0-9._-]*\) made.*/\1/p' | head -n 1)"
      [ -n "$upgrade_set" ] || { echo "the backup named no set" >&2; return 1; }
      printf '%s' "$upgrade_set" | dk exec -i "$e2e_playwright" sh -c "cat > /tmp/host-out-backup" > /dev/null
      ;;
    upgrade)
      (set -e; upgrade_swap)
      rc=$?
      return "$rc"
      ;;
    *) echo "the tests asked for a step the drill does not know: $1" >&2; return 1 ;;
  esac
}

# The first half, with this script as its host: the runner container asks for a step by writing
# /tmp/host-request-<step> and waits for /tmp/host-done-<step> or /tmp/host-failed-<step> (web/test/e2e-stack/support.mjs).
upgrade_before_out=""
upgrade_before() { # state left by the phase goes to upgrade_before_out
  local out pid rc=0 request step step_rc
  out="$(mktemp)"
  (FERRET_E2E_PHASE=upgrade-before e2e_wasm_stack=release e2e_run --project=chromium phase-upgrade-before > "$out") &
  pid=$!
  for _ in $(seq 1 900); do
    [ "$(dk inspect -f '{{.State.Running}}' "$e2e_playwright" 2>/dev/null || true)" = true ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  dk exec "$e2e_playwright" touch /tmp/host-ready > /dev/null 2>&1 || { wait "$pid" || true; rm -f "$out"; echo "upgrade-drill: the runner did not come up" >&2; return 1; }
  while kill -0 "$pid" 2>/dev/null; do
    for request in $(dk exec "$e2e_playwright" sh -c 'ls /tmp/host-request-* 2>/dev/null' 2>/dev/null || true); do
      step="${request#/tmp/host-request-}"
      dk exec "$e2e_playwright" rm -f "$request" > /dev/null 2>&1 || true
      echo "== host step for the tests: $step" >&2
      set +e
      upgrade_step "$step"
      step_rc=$?
      set -e
      if [ "$step_rc" = 0 ]; then
        dk exec "$e2e_playwright" touch "/tmp/host-done-$step" > /dev/null 2>&1 || true
      else
        echo "upgrade-drill: the host step $step failed" >&2
        dk exec "$e2e_playwright" touch "/tmp/host-failed-$step" > /dev/null 2>&1 || true
      fi
    done
    sleep 2
  done
  wait "$pid" || rc=$?
  upgrade_before_out="$(cat "$out")"
  rm -f "$out"
  return "$rc"
}

upgrade_cleanup() {
  [ "$upgrade_pulled" = 1 ] && [ -n "$upgrade_release" ] || return 0
  dk image rm "$upgrade_repo:${upgrade_tag#v}" > /dev/null 2>&1 || true
  if ! dk image inspect "$upgrade_release" > /dev/null 2>&1; then
    echo "upgrade-drill: the release image it pulled is removed" >&2
  else
    echo "upgrade-drill: the release image is still in use; after e2e-down remove it with: docker image rm $upgrade_release" >&2
  fi
}

upgrade_tag=""
upgrade_drill() { # release tag
  upgrade_tag="${1:-}"
  [[ "$upgrade_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || upgrade_refuse "the tag must be a release tag, for example v0.12.1 (got '${upgrade_tag}')"
  [ "$e2e_suffix" != e2e ] || upgrade_refuse "the drill never runs on the stack of the suffix e2e"
  case "${FERRET_WASM_SOURCE:-lock}" in
    lock) export FERRET_WASM_SOURCE=lock FERRET_WASM_COMMIT="" ;;
    *) upgrade_refuse "the candidate is a release build, with the locked WebAssembly package (FERRET_WASM_SOURCE=lock)" ;;
  esac
  upgrade_require_cosign
  local commit state rc=0 after
  commit="$(git rev-parse --verify -q "refs/tags/${upgrade_tag}^{commit}")" || upgrade_refuse "$upgrade_tag is not a tag of this checkout (fetch the tags)"
  trap upgrade_cleanup EXIT

  echo "== the release image of $upgrade_tag" >&2
  upgrade_release_image "$upgrade_tag" "$commit"
  echo "== the candidate (a release build of $(git rev-parse --short HEAD))" >&2
  upgrade_build_candidate

  echo "== the stack $e2e_project on the release" >&2
  e2e_remove
  dk tag "$upgrade_release" "$e2e_image"
  upgrade_token="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  upgrade_push="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  FERRET_E2E_SETUP_TOKEN="$upgrade_token" FERRET_E2E_PUSH_TOKEN="$upgrade_push" dce build "$e2e_monitor_service" "$e2e_evil_service" >&2
  FERRET_E2E_SETUP_TOKEN="$upgrade_token" FERRET_E2E_PUSH_TOKEN="$upgrade_push" dce up -d --no-build --wait >&2
  [ "$(upgrade_running_image)" = "$(dk image inspect -f '{{.Id}}' "$upgrade_release")" ] || upgrade_refuse "the app does not run the release image"
  echo "the app runs $upgrade_release; open files allowed in it: $(dk exec "$e2e_app" sh -c 'ulimit -n')" >&2

  echo "== the first half on the release, the backup and the swap (phase-upgrade-before)" >&2
  set +e
  upgrade_before
  rc=$?
  set -e
  state="$(upgrade_left "$upgrade_before_out" state)"
  if [ "$rc" != 0 ] || [ -z "$(upgrade_left "$upgrade_before_out" upgrade-before)" ] || [ -z "$state" ]; then
    upgrade_refuse "the first half failed or did not run (exit $rc); the stack is left as it is for a look"
  fi
  [ "$(upgrade_running_image)" = "$(dk image inspect -f '{{.Id}}' "$upgrade_candidate")" ] || upgrade_refuse "the app does not run the candidate after the first half"

  echo "== the second half on the candidate (phase-upgrade-after)" >&2
  after="$(FERRET_E2E_STATE="$state" FERRET_E2E_PHASE=upgrade-after e2e_run --project=chromium phase-upgrade-after)" || rc=$?
  if [ "$rc" != 0 ] || [ -z "$(upgrade_left "$after" upgrade-after)" ]; then
    upgrade_refuse "the second half failed or did not run (exit $rc); the stack is left as it is for a look"
  fi
  echo "upgrade-drill: $upgrade_tag -> $(git rev-parse --short HEAD): passed. Remove the stack with: FERRET_E2E_SUFFIX=$e2e_suffix $0 e2e-down"
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

# The data volume must carry the label of the stack (a volume made before the label was
# there has none: `reset` and every listing by label would miss it). It also refuses while the
# temporary volume of an unfinished label-data exists: that volume may hold the only copy of
# the data, and the data volume may be empty or half filled, so the app must not start.
relabel_tmp=ferret-test-data-relabel
data_volume_label() { dk volume inspect -f '{{index .Labels "owner"}}' "$volume" 2>/dev/null || true; }
refuse_unfinished_relabel() {
  dk volume inspect "$relabel_tmp" >/dev/null 2>&1 || return 0
  echo "lanbox-ferret-test: the volume $relabel_tmp exists: an earlier label-data did not finish." >&2
  echo "It may hold the only copy of the data, and $volume may be empty or half filled: DO NOT run up." >&2
  echo "Look at both volumes. Copy $relabel_tmp into $volume by hand (or remove $volume and run label-data again), and remove $relabel_tmp only when the data is back and checked." >&2
  return 1
}
require_data_label() {
  refuse_unfinished_relabel || return 1
  dk volume inspect "$volume" >/dev/null 2>&1 || return 0
  [ "$(data_volume_label)" = "${label#*=}" ] && return 0
  echo "lanbox-ferret-test: the data volume $volume has no label $label (it was made before the label was added)." >&2
  echo "Take a second copy first: $0 snapshot --yes-ferret-test" >&2
  echo "Then run: $0 label-data --yes-ferret-test    (it keeps the data; run up afterwards to start the app)" >&2
  return 1
}

# Gives the data volume its label by copying the data: the app is stopped, the data goes into a
# temporary labelled volume and is checked there (and checked again before anything is removed),
# the old volume is replaced by a labelled one, and the data goes back. The temporary volume is
# removed only when the copy back is done and checked. Every step after the first copy that
# fails stops the script with "do not run up": the data is in the temporary volume, and `up`
# refuses to start until that volume is gone.
relabel_stuck() { # step text
  echo "label-data: $1" >&2
  echo "The data is in the volume $relabel_tmp. DO NOT run up, and do not remove that volume." >&2
  echo "$volume may be missing, empty or half filled: copy $relabel_tmp into it by hand and check it." >&2
  exit 1
}
test_label_data() {
  require_yes_ferret_test "$@"
  [ -f "$envfile" ] || { echo "no $envfile: nothing to relabel" >&2; exit 1; }
  # An unfinished earlier run comes first, whatever the label says.
  refuse_unfinished_relabel || exit 1
  dk volume inspect "$volume" >/dev/null 2>&1 || { echo "label-data: there is no volume $volume" >&2; exit 1; }
  if [ "$(data_volume_label)" = "${label#*=}" ]; then
    echo "label-data: $volume already has the label $label"
    return 0
  fi
  dk volume create --label "$label" "$relabel_tmp" >/dev/null || { echo "label-data: cannot make the temporary volume; nothing was changed" >&2; exit 1; }
  test_stop_app || { dk volume rm "$relabel_tmp" >/dev/null 2>&1 || true; echo "label-data: cannot stop the app; nothing was changed" >&2; exit 1; }
  if ! volume_job make "$volume" "$relabel_tmp" "$label" ferret-test-relabel-copy; then
    dk volume rm "$relabel_tmp" >/dev/null 2>&1 || true
    echo "label-data: the copy failed; $volume is untouched (the app is stopped: run up)" >&2
    exit 1
  fi
  # The copy is checked once more before the old volume is touched.
  volume_job verify "$relabel_tmp" - "$label" ferret-test-relabel-verify \
    || relabel_stuck "the copy could not be checked again; $volume has NOT been removed, so the data is in both volumes."
  dc down >/dev/null || relabel_stuck "the stack could not be taken down; nothing was removed."
  dk volume rm "$volume" >/dev/null || relabel_stuck "the old volume could not be removed."
  dk volume create --label "$label" "$volume" >/dev/null || relabel_stuck "the new volume could not be made."
  volume_job restore "$relabel_tmp" "$volume" "$label" ferret-test-relabel-back \
    || relabel_stuck "copying the data back failed."
  dk volume rm "$relabel_tmp" >/dev/null || { echo "label-data: the data is back and checked, but $relabel_tmp could not be removed: remove it by hand before run up." >&2; exit 1; }
  echo "label-data: $volume has the label $label, with the same data; run up to start the app"
}

main() {
case "${1:-}" in
  up | redeploy)
    first_deploy=0
    make_env
    require_compose_env
    require_tunnel
    require_data_label
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
    echo "reset: done (docker/.env removed; the next up makes a new setup token and needs FERRET_VAULT_URL and FERRET_ADMIN_URL again)"
    ;;
  logs)
    dk logs -f --tail 200 "$container"
    ;;
  status)
    dk ps -a --filter "label=$label" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
    dk inspect "$container" --format 'health: {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}; restarts: {{.RestartCount}}' 2>/dev/null || true
    dk top "$container" -o user,pid,comm 2>/dev/null || true
    dk volume ls --filter "label=$label"
    echo "wasm: $(wasm_of "$container")"
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
  e2e-chromium)
    e2e_chromium
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
  e2e-reset)
    e2e_reset
    ;;
  e2e-backup)
    e2e_backup
    ;;
  e2e-restore-backup)
    e2e_restore_backup "${2:-}"
    ;;
  e2e-code)
    e2e_code "${2:-}"
    ;;
  label-data)
    shift
    test_label_data "$@"
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
  upgrade-drill)
    upgrade_drill "${2:-}"
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
