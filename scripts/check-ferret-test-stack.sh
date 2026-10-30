#!/usr/bin/env bash
# Checks docker/compose.ferret-test.yml and docker/compose.ferret-e2e.yml without
# a Docker host (`docker compose config` only reads the files). The owner's stack:
#  * the file is valid and every resource is named ferret-test* and carries the
#    label owner=ferret-test;
#  * the stack has one service, built without cargo features, with no test
#    clock and no extra volume;
#  * the container drops every capability but the three the entrypoint needs,
#    cannot gain privileges and has a read-only root file system;
#  * the Dockerfile pins every base image by digest, builds without cargo
#    features by default, uses cache ids of its own and has no setcap or USER root;
#  * it runs on the host network (so the server sees real peer addresses), sets
#    the public https addresses, and takes the setup token and the trusted
#    proxies from docker/.env, which git ignores.
# The end-to-end stack (checked below the owner's):
#  * its own project, containers, network and image, all named ferret-e2e* and
#    labelled owner=ferret-e2e; no volume, no bind mount, no published port, the
#    data in tmpfs; built with the e2e-clock feature; trusts only the TLS
#    terminator; and shares no name, network, volume or address with the
#    owner's stack.
# The deploy script: its drift guard reads what compose injects, refuses a
# mismatch, and is not fooled by crafted values.
# The checks below set FERRET_ENV_FILE in subshells on purpose.
# shellcheck disable=SC2030,SC2031
set -euo pipefail
cd "$(dirname "$0")/.."

file=docker/compose.ferret-test.yml
config="$(FERRET_SETUP_TOKEN=check FERRET_TRUSTED_PROXIES=172.17.0.2 docker compose -f "$file" config --format json)"

printf '%s' "$config" | node -e '
const c = JSON.parse(require("fs").readFileSync(0, "utf8"));
const fail = (m) => { console.error("check-ferret-test-stack: " + m); process.exit(1); };
const names = Object.keys(c.services || {});
if (names.length !== 1 || names[0] !== "ferret-test-app") fail("expected the one service ferret-test-app, got " + names);
const s = c.services["ferret-test-app"];
if (c.name !== "ferret-test") fail("project name must be ferret-test");
if (s.container_name !== "ferret-test-app") fail("container_name");
if (s.labels?.owner !== "ferret-test") fail("service label owner=ferret-test");
if (s.build?.labels?.owner !== "ferret-test") fail("build label owner=ferret-test");
if ((s.build?.args?.FEATURES ?? "") !== "") fail("the image must be built without cargo features");
if (JSON.stringify(s.cap_drop) !== JSON.stringify(["ALL"])) fail("cap_drop must be [ALL]");
if ([...(s.cap_add || [])].sort().join() !== "CHOWN,SETGID,SETUID") fail("cap_add must be CHOWN, SETUID, SETGID only, got " + s.cap_add);
if (!(s.security_opt || []).includes("no-new-privileges:true")) fail("security_opt needs no-new-privileges:true");
if (s.read_only !== true) fail("read_only must be true");
if (s.privileged) fail("privileged");
if (s.restart !== "no") fail("restart must be no: only the deploy script starts the stack, after its proxy check");
if (Object.keys(s.build?.args || {}).join() !== "FEATURES") fail("the only build arg is FEATURES");
if (s.network_mode !== "host") fail("network_mode must be host");
if (s.ports && s.ports.length) fail("no published ports on the host network");
const vols = Object.keys(c.volumes || {});
if (vols.join() !== "ferret-test-data") fail("volumes must be exactly ferret-test-data, got " + vols);
for (const [k, v] of Object.entries(c.volumes)) {
  if (v.name !== k || v.labels?.owner !== "ferret-test") fail("volume " + k + " needs its name and the owner label");
}
if (c.networks && Object.keys(c.networks).length) fail("no networks expected");
const env = s.environment || {};
if (env.FERRET_VAULT_URL !== "https://vault-test.opland.net") fail("FERRET_VAULT_URL");
if (env.FERRET_ADMIN_URL !== "https://ferret-test.opland.net") fail("FERRET_ADMIN_URL");
for (const k of Object.keys(env)) if (/E2E/i.test(k)) fail("no test variable allowed: " + k);
if ("TZ" in env) fail("TZ does nothing without tzdata in the image");
if (env.FERRET_TRUST_PROXY !== "1") fail("FERRET_TRUST_PROXY");
if (env.FERRET_TRUSTED_PROXIES !== "172.17.0.2") fail("FERRET_TRUSTED_PROXIES must come from docker/.env");
if (env.FERRET_SETUP_TOKEN !== "check") fail("FERRET_SETUP_TOKEN must come from docker/.env");
const mem = Number(s.mem_limit);
if (!(mem > 0)) fail("a memory limit is required");
'

# The end-to-end stack, and that it shares nothing with the owner's stack.
e2e_file=docker/compose.ferret-e2e.yml
e2e_config="$(FERRET_E2E_SETUP_TOKEN=e2echeck docker compose -f "$e2e_file" config --format json)"
if grep -qi 'e2e' "$file"; then
  echo "check-ferret-test-stack: $file must not mention the end-to-end stack" >&2
  exit 1
fi
# Without the token that `e2e-up` makes, the stack does not start.
if docker compose -f "$e2e_file" config >/dev/null 2>&1; then
  echo "check-ferret-test-stack: $e2e_file starts without FERRET_E2E_SETUP_TOKEN" >&2
  exit 1
fi

node -e '
const [owner, e2e] = process.argv.slice(1).map((s) => JSON.parse(s));
const fail = (m) => { console.error("check-ferret-test-stack: e2e: " + m); process.exit(1); };
if (e2e.name !== "ferret-e2e") fail("project name must be ferret-e2e");
const names = Object.keys(e2e.services || {}).sort();
if (names.join() !== "ferret-e2e-app,ferret-e2e-tls") fail("expected the services ferret-e2e-app and ferret-e2e-tls, got " + names);
for (const [k, s] of Object.entries(e2e.services)) {
  if (s.container_name !== k) fail(k + ": container_name");
  if (s.labels?.owner !== "ferret-e2e") fail(k + ": label owner=ferret-e2e");
  if (s.ports && s.ports.length) fail(k + ": no published ports");
  if (s.network_mode) fail(k + ": no network_mode (host networking would reach the LANBox)");
  if (s.volumes && s.volumes.length) fail(k + ": no volumes and no bind mounts, the data is in tmpfs");
  if (s.privileged) fail(k + ": privileged");
  if (s.read_only !== true) fail(k + ": read_only");
  if (!(s.security_opt || []).includes("no-new-privileges:true")) fail(k + ": no-new-privileges");
  if (JSON.stringify(s.cap_drop) !== JSON.stringify(["ALL"])) fail(k + ": cap_drop must be [ALL]");
  if (s.restart !== "no") fail(k + ": restart must be no");
  if (!(Number(s.mem_limit) > 0)) fail(k + ": a memory limit is required");
  if (Object.keys(s.networks || {}).join() !== "ferret-e2e-net") fail(k + ": only the network ferret-e2e-net");
}
if (Object.keys(e2e.volumes || {}).length) fail("no named volumes: a volume would outlive the run");
const app = e2e.services["ferret-e2e-app"];
const tls = e2e.services["ferret-e2e-tls"];
if (app.image !== "ferret-e2e-app:latest") fail("image of the app");
if (app.build?.labels?.owner !== "ferret-e2e") fail("build label owner=ferret-e2e");
if (Object.keys(app.build?.args || {}).join() !== "FEATURES" || app.build.args.FEATURES !== "e2e-clock") fail("the app is built with FEATURES=e2e-clock and nothing else");
if ([...(app.cap_add || [])].sort().join() !== "CHOWN,SETGID,SETUID") fail("app cap_add");
if (!(app.tmpfs || []).some((t) => t.startsWith("/data"))) fail("the data directory must be tmpfs");
if (!/^caddy:[0-9.]+-alpine@sha256:[0-9a-f]{64}$/.test(tls.image)) fail("the TLS terminator image must be pinned by digest");
if ([...(tls.cap_add || [])].join() !== "NET_BIND_SERVICE") fail("tls cap_add");
for (const t of ["/data", "/config"]) if (!(tls.tmpfs || []).some((x) => x.startsWith(t))) fail("tls " + t + " must be tmpfs (no anonymous volume)");
const env = app.environment || {};
if (env.FERRET_E2E_CLOCK_FILE !== "/tmp/e2e-clock") fail("FERRET_E2E_CLOCK_FILE");
if (env.FERRET_VAULT_URL !== "https://vault-e2e.test" || env.FERRET_ADMIN_URL !== "https://admin-e2e.test") fail("the test host names");
if (env.FERRET_SETUP_TOKEN !== "e2echeck") fail("FERRET_SETUP_TOKEN must come from FERRET_E2E_SETUP_TOKEN");
if (env.FERRET_TRUST_PROXY !== "1") fail("FERRET_TRUST_PROXY");
// The network, the pinned addresses and the one trusted proxy.
const net = e2e.networks?.["ferret-e2e-net"];
if (!net || Object.keys(e2e.networks).length !== 1) fail("exactly the network ferret-e2e-net");
if (net.name !== "ferret-e2e-net" || net.labels?.owner !== "ferret-e2e") fail("network name and label");
if (net.internal === false || net.external) fail("the network is made here");
const subnet = net.ipam?.config?.[0]?.subnet;
if (subnet !== "172.30.250.0/28") fail("subnet");
const tlsIp = tls.networks["ferret-e2e-net"].ipv4_address;
const appIp = app.networks["ferret-e2e-net"].ipv4_address;
if (!tlsIp || !appIp || tlsIp === appIp) fail("pinned addresses");
if (env.FERRET_TRUSTED_PROXIES !== tlsIp) fail("the only trusted proxy is the TLS terminator at " + tlsIp + ", got " + env.FERRET_TRUSTED_PROXIES);
for (const ip of [tlsIp, appIp]) if (!/^172\.30\.250\.([2-9]|1[0-4])$/.test(ip)) fail(ip + " is not a host address of " + subnet + " (.1 is the gateway)");
const aliases = [...(tls.networks["ferret-e2e-net"].aliases || [])].sort().join();
if (aliases !== "admin-e2e.test,vault-e2e.test") fail("aliases of the TLS terminator: " + aliases);
const caddyfile = tls.environment?.CADDYFILE || "";
if (!/https:\/\/vault-e2e\.test \{[^}]*tls internal[^}]*reverse_proxy ferret-e2e-app:3041/.test(caddyfile)) fail("Caddyfile: vault site");
if (!/https:\/\/admin-e2e\.test \{[^}]*tls internal[^}]*reverse_proxy ferret-e2e-app:3040/.test(caddyfile)) fail("Caddyfile: admin site");
if (/trusted_proxies/.test(caddyfile)) fail("the terminator must not trust forwarding headers from anyone");

// Nothing in common with the owner stack.
const o = owner.services["ferret-test-app"];
const overlap = (what, a, b) => { const x = a.filter((v) => b.includes(v)); if (x.length) fail("shared " + what + ": " + x); };
const hostNames = (c) => Object.keys(c.services).concat(Object.values(c.services).map((s) => s.container_name));
overlap("service or container names", hostNames(owner), hostNames(e2e));
overlap("volumes", Object.values(owner.volumes || {}).map((v) => v.name), Object.values(e2e.volumes || {}).map((v) => v.name));
overlap("networks", Object.values(owner.networks || {}).map((n) => n.name), Object.values(e2e.networks).map((n) => n.name));
overlap("images", [o.image], [app.image, tls.image]);
overlap("labels", [o.labels.owner], [app.labels.owner, tls.labels.owner]);
if (owner.name === e2e.name) fail("same compose project");
if (o.env_file || app.env_file) fail("env_file would pull in the owner secrets");
const oe = o.environment;
for (const k of ["FERRET_VAULT_URL", "FERRET_ADMIN_URL", "FERRET_TRUSTED_PROXIES", "FERRET_SETUP_TOKEN"]) {
  if (oe[k] === env[k]) fail(k + " is the same in both stacks");
}
' "$config" "$e2e_config"

# The deploy script must read the trusted proxy the way compose injects it (last
# definition wins, `export ` prefix, spaces), so a second line in docker/.env
# cannot slip past its check of the tunnel client's address, and a value with a
# line break in it cannot forge a line that is read instead of the real one.
# The tunnel client's address is stubbed: no Docker host is needed.
tmp="$(mktemp -d docker/.check.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
export FERRET_DOCKER_ARGS="--context default"
printf '%s\n' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' > "$tmp/plain.env"
printf '%s\n' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' 'FERRET_TRUSTED_PROXIES=172.17.0.5' > "$tmp/duplicate.env"
printf '%s\n' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' 'export FERRET_TRUSTED_PROXIES=172.17.0.6' > "$tmp/export.env"
printf '%s\n' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' '  FERRET_TRUSTED_PROXIES = 172.17.0.7' > "$tmp/spaces.env"
# Another variable, listed before the key, whose value holds a line that looks
# like the key (the real, later value is .9).
printf '%s\n' 'FERRET_SETUP_TOKEN=check' 'AAA="x\nFERRET_TRUSTED_PROXIES=172.17.0.2"' 'FERRET_TRUSTED_PROXIES=172.17.0.9' > "$tmp/forged.env"
for case in duplicate:172.17.0.5 export:172.17.0.6 spaces:172.17.0.7 forged:; do
  name="${case%%:*}"
  want="${case##*:}"
  (
    export FERRET_ENV_FILE="$tmp/$name.env"
    unset FERRET_TRUSTED_PROXIES FERRET_SETUP_TOKEN
    # shellcheck disable=SC1091
    source scripts/lanbox-ferret-test.sh
    got="$(configured_proxies)"
    [ "$got" = "$want" ] || { echo "check-ferret-test-stack: $name.env: the script reads '$got', expected '$want'" >&2; exit 1; }
    if same_addresses "$got" 172.17.0.2; then echo "check-ferret-test-stack: $name.env passed the address check for 172.17.0.2" >&2; exit 1; fi
    same_addresses 172.17.0.2/32 172.17.0.2 || { echo "check-ferret-test-stack: /32 must equal the plain address" >&2; exit 1; }
    if same_addresses "172.17.0.2,172.17.0.3" 172.17.0.2 || same_addresses "" 172.17.0.2; then echo "check-ferret-test-stack: a list with more or no entries must not match" >&2; exit 1; fi
    # The guard itself, with the tunnel client at 172.17.0.2.
    tunnel_address() { echo 172.17.0.2; }
    tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: $name.env: tunnel_mismatch did not report the mismatch" >&2; exit 1; }
    if (require_tunnel) >/dev/null 2>&1; then echo "check-ferret-test-stack: $name.env: require_tunnel did not refuse" >&2; exit 1; fi
  )
done
(
  export FERRET_ENV_FILE="$tmp/plain.env"
  unset FERRET_TRUSTED_PROXIES FERRET_SETUP_TOKEN
  # shellcheck disable=SC1091
  source scripts/lanbox-ferret-test.sh
  tunnel_address() { echo 172.17.0.2; }
  if tunnel_mismatch >/dev/null; then echo "check-ferret-test-stack: plain.env: a matching address was reported as a mismatch" >&2; exit 1; fi
  (require_tunnel) >/dev/null 2>&1 || { echo "check-ferret-test-stack: plain.env: require_tunnel refused a matching address" >&2; exit 1; }
  # The tunnel client at another address, and at none.
  tunnel_address() { echo 172.17.0.3; }
  tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: plain.env: another tunnel address passed" >&2; exit 1; }
  tunnel_address() { :; }
  tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: plain.env: an unknown tunnel address passed" >&2; exit 1; }
)

# The Dockerfile.
dockerfile=docker/server.Dockerfile
fail() { echo "check-ferret-test-stack: $1" >&2; exit 1; }
if grep -E '^(FROM|ARG [A-Z_]*IMAGE=)' "$dockerfile" | grep -v '@sha256:[0-9a-f]\{64\}' | grep -vE '^FROM \$\{[A-Z_]+\} AS '; then
  fail "a base image in $dockerfile is not pinned by digest"
fi
grep -q '^ARG FEATURES=""$' "$dockerfile" || fail "ARG FEATURES must default to empty"
if grep -qiE 'setcap|^USER root' "$dockerfile"; then fail "$dockerfile must not use setcap or USER root"; fi
if grep -E 'type=cache' "$dockerfile" | grep -v 'id=ferret-'; then fail "every cache mount needs an id starting with ferret-"; fi
grep -q '^\*\*/\.env$' .dockerignore || fail ".dockerignore must list **/.env"

# The runner image of the browser tests: the base is the Playwright image of
# scripts/lanbox-browsers.sh, the package is pinned, and an install cannot fail
# silently.
runner=docker/e2e-runner.Dockerfile
base="$(grep -o 'playwright:v[^@]*@sha256:[0-9a-f]\{64\}' scripts/lanbox-browsers.sh | head -n 1)"
[ -n "$base" ] || fail "no pinned Playwright image in scripts/lanbox-browsers.sh"
grep -qF "FROM mcr.microsoft.com/$base" "$runner" || fail "$runner must start from mcr.microsoft.com/$base"
grep -qE 'libnss3-tools=[0-9]' "$runner" || fail "$runner: libnss3-tools must be pinned to a version"
if grep -F "|| true" "$runner" | grep -q .; then fail "$runner: an install must not be allowed to fail silently"; fi
if grep -F 'apt-get' scripts/lanbox-ferret-test.sh; then fail "the runner script must not install packages: the runner image has them"; fi

# The file with the setup token is never committed.
git check-ignore -q docker/.env || { echo "check-ferret-test-stack: docker/.env is not ignored by git" >&2; exit 1; }
if git ls-files --error-unmatch docker/.env >/dev/null 2>&1; then
  echo "check-ferret-test-stack: docker/.env is tracked" >&2
  exit 1
fi
echo "check-ferret-test-stack: ok"
