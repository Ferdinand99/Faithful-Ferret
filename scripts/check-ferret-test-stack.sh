#!/usr/bin/env bash
# Checks docker/compose.ferret-test.yml without a Docker host (`docker compose
# config` only reads the file):
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

# The deploy script must read the trusted proxy the way compose injects it (last
# definition wins, `export ` prefix, spaces), so a second line in docker/.env
# cannot slip past its check of the tunnel client's address.
tmp="$(mktemp -d docker/.check.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
export FERRET_DOCKER_ARGS="--context default"
printf '%s
' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' 'FERRET_TRUSTED_PROXIES=172.17.0.5' > "$tmp/duplicate.env"
printf '%s
' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' 'export FERRET_TRUSTED_PROXIES=172.17.0.6' > "$tmp/export.env"
printf '%s
' 'FERRET_SETUP_TOKEN=check' 'FERRET_TRUSTED_PROXIES=172.17.0.2' '  FERRET_TRUSTED_PROXIES = 172.17.0.7' > "$tmp/spaces.env"
for case in duplicate:172.17.0.5 export:172.17.0.6 spaces:172.17.0.7; do
  (
    export FERRET_ENV_FILE="$tmp/${case%%:*}.env"
    unset FERRET_TRUSTED_PROXIES FERRET_SETUP_TOKEN
    # shellcheck disable=SC1091
    source scripts/lanbox-ferret-test.sh
    got="$(configured_proxies)"
    [ "$got" = "${case##*:}" ] || { echo "check-ferret-test-stack: ${case%%:*}.env: the script reads '$got', compose injects ${case##*:}" >&2; exit 1; }
    if same_addresses "$got" 172.17.0.2; then echo "check-ferret-test-stack: ${case%%:*}.env passed the address check for 172.17.0.2" >&2; exit 1; fi
    same_addresses 172.17.0.2/32 172.17.0.2 || { echo "check-ferret-test-stack: /32 must equal the plain address" >&2; exit 1; }
    if same_addresses "172.17.0.2,172.17.0.3" 172.17.0.2 || same_addresses "" 172.17.0.2; then echo "check-ferret-test-stack: a list with more or no entries must not match" >&2; exit 1; fi
  )
done

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

# The file with the setup token is never committed.
git check-ignore -q docker/.env || { echo "check-ferret-test-stack: docker/.env is not ignored by git" >&2; exit 1; }
if git ls-files --error-unmatch docker/.env >/dev/null 2>&1; then
  echo "check-ferret-test-stack: docker/.env is tracked" >&2
  exit 1
fi
echo "check-ferret-test-stack: ok"
