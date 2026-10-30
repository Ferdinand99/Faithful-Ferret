#!/usr/bin/env bash
# Checks docker/compose.ferret-test.yml without a Docker host (`docker compose
# config` only reads the file):
#  * the file is valid and every resource is named ferret-test* and carries the
#    label owner=ferret-test;
#  * the stack has one service, built without cargo features, with no test
#    clock and no extra volume;
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
if (env.FERRET_TRUST_PROXY !== "1") fail("FERRET_TRUST_PROXY");
if (env.FERRET_TRUSTED_PROXIES !== "172.17.0.2") fail("FERRET_TRUSTED_PROXIES must come from docker/.env");
if (env.FERRET_SETUP_TOKEN !== "check") fail("FERRET_SETUP_TOKEN must come from docker/.env");
const mem = Number(s.mem_limit);
if (!(mem > 0)) fail("a memory limit is required");
'

# The file with the setup token is never committed.
git check-ignore -q docker/.env || { echo "check-ferret-test-stack: docker/.env is not ignored by git" >&2; exit 1; }
if git ls-files --error-unmatch docker/.env >/dev/null 2>&1; then
  echo "check-ferret-test-stack: docker/.env is tracked" >&2
  exit 1
fi
echo "check-ferret-test-stack: ok"
