#!/usr/bin/env bash
# Checks docker/compose.ferret-test.yml and docker/compose.ferret-e2e.yml without
# a Docker host (`docker compose config` only reads the files). The owner's stack:
#  * the file is valid and every resource is named ferret-test* and carries the
#    label owner=ferret-test;
#  * the stack has one service, built with the cargo features passkey-import and quick-unlock (as a release is) and
#    no other, with no test clock and no extra volume;
#  * the container drops every capability but the three the entrypoint needs,
#    cannot gain privileges and has a read-only root file system;
#  * the Dockerfile pins every base image by digest, builds without cargo
#    features unless told (the release workflow and the stacks name theirs), uses cache ids of its own and has no setcap or USER root;
#  * it runs on the host network (so the server sees real peer addresses), sets
#    the public https addresses, and takes the setup token and the trusted
#    proxies from docker/.env, which git ignores.
# The end-to-end stack (checked below the owner's):
#  * its own project, containers, network and image, all named ferret-e2e* and
#    labelled owner=ferret-e2e; one named volume for the data and no bind mount, no
#    published port; built with the e2e-clock and quick-unlock features; and shares no name,
#    network, volume or address with the ferret-test stack. The volume of the
#    snapshot is made by the script (checked below), with the label owner=ferret-e2e.
#  * the malicious server ferret-e2e-evil, the one place the sync answers are
#    reshaped: it exists in the e2e file only (not in the ferret-test compose file,
#    not in the server's Dockerfile or its build context), publishes no port,
#    sits between the TLS terminator and the app for both hosts, and is the one
#    address that the app trusts as its proxy (FERRET_TRUSTED_PROXIES is that
#    address and nothing else). The ferret-test compose file does not mention it.
# The deploy script: its drift guard reads what compose injects, refuses a
# mismatch, and is not fooled by crafted values.
# The checks below set FERRET_ENV_FILE in subshells on purpose.
# shellcheck disable=SC2030,SC2031
set -euo pipefail
cd "$(dirname "$0")/.."

# The checks read what compose makes of the files with the defaults, whatever the caller has set.
unset FERRET_WASM_SOURCE FERRET_WASM_COMMIT

file=docker/compose.ferret-test.yml
# The public addresses are not in the compose file: they come from the environment or from
# docker/.env, and compose refuses to start without them. Neutral example values for the checks.
export FERRET_VAULT_URL=https://vault.example.test FERRET_ADMIN_URL=https://admin.example.test
for missing in FERRET_VAULT_URL FERRET_ADMIN_URL; do
  if env -u "$missing" FERRET_SETUP_TOKEN=check FERRET_TRUSTED_PROXIES=172.17.0.2 docker compose -f "$file" config >/dev/null 2>&1; then
    echo "check-ferret-test-stack: $file starts without $missing" >&2
    exit 1
  fi
done
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
if ((s.build?.args?.FEATURES ?? "") !== "passkey-import,quick-unlock") fail("the image must be built with the cargo features passkey-import and quick-unlock and no other, as a release is");
if (JSON.stringify(s.cap_drop) !== JSON.stringify(["ALL"])) fail("cap_drop must be [ALL]");
if ([...(s.cap_add || [])].sort().join() !== "CHOWN,SETGID,SETUID") fail("cap_add must be CHOWN, SETUID, SETGID only, got " + s.cap_add);
if (!(s.security_opt || []).includes("no-new-privileges:true")) fail("security_opt needs no-new-privileges:true");
if (s.read_only !== true) fail("read_only must be true");
if (s.privileged) fail("privileged");
if (s.restart !== "no") fail("restart must be no: only the deploy script starts the stack, after its proxy check");
if (Object.keys(s.build?.args || {}).sort().join() !== "FEATURES") fail("the only build arg is FEATURES");
if (s.network_mode !== "host") fail("network_mode must be host");
if (s.ports && s.ports.length) fail("no published ports on the host network");
const vols = Object.keys(c.volumes || {});
if (vols.join() !== "ferret-test-data") fail("volumes must be exactly ferret-test-data, got " + vols);
for (const [k, v] of Object.entries(c.volumes)) {
  if (v.name !== k || v.labels?.owner !== "ferret-test") fail("volume " + k + " needs its name and the owner label");
}
if (c.networks && Object.keys(c.networks).length) fail("no networks expected");
const env = s.environment || {};
if (env.FERRET_VAULT_URL !== process.env.FERRET_VAULT_URL) fail("FERRET_VAULT_URL must come from the environment or docker/.env");
if (env.FERRET_ADMIN_URL !== process.env.FERRET_ADMIN_URL) fail("FERRET_ADMIN_URL must come from the environment or docker/.env");
for (const k of ["FERRET_VAULT_URL", "FERRET_ADMIN_URL"]) if (!(env[k] || "").startsWith("https://")) fail(k + " must be an https address");
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
e2e_config="$(FERRET_E2E_SETUP_TOKEN=e2echeck FERRET_E2E_PUSH_TOKEN=e2epush docker compose -f "$e2e_file" config --format json)"
if grep -qi 'e2e' "$file"; then
  echo "check-ferret-test-stack: $file must not mention the end-to-end stack" >&2
  exit 1
fi
if grep -qiE 'evil|snapshot' "$file"; then
  echo "check-ferret-test-stack: $file must not mention the malicious server or a snapshot" >&2
  exit 1
fi
# Without the tokens that `e2e-up` makes, the stack does not start.
if docker compose -f "$e2e_file" config >/dev/null 2>&1; then
  echo "check-ferret-test-stack: $e2e_file starts without FERRET_E2E_SETUP_TOKEN and FERRET_E2E_PUSH_TOKEN" >&2
  exit 1
fi
if FERRET_E2E_SETUP_TOKEN=e2echeck docker compose -f "$e2e_file" config >/dev/null 2>&1; then
  echo "check-ferret-test-stack: $e2e_file starts without FERRET_E2E_PUSH_TOKEN" >&2
  exit 1
fi

node -e '
const [owner, e2e] = process.argv.slice(1).map((s) => JSON.parse(s));
const fail = (m) => { console.error("check-ferret-test-stack: e2e: " + m); process.exit(1); };
if (e2e.name !== "ferret-e2e") fail("project name must be ferret-e2e");
const names = Object.keys(e2e.services || {}).sort();
if (names.join() !== "ferret-e2e-app,ferret-e2e-evil,ferret-e2e-monitor,ferret-e2e-tls") fail("expected the services ferret-e2e-app, ferret-e2e-evil, ferret-e2e-monitor and ferret-e2e-tls, got " + names);
for (const [k, s] of Object.entries(e2e.services)) {
  if (s.container_name !== k) fail(k + ": container_name");
  if (s.labels?.owner !== "ferret-e2e") fail(k + ": label owner=ferret-e2e");
  if (s.ports && s.ports.length) fail(k + ": no published ports");
  if (s.network_mode) fail(k + ": no network_mode (host networking would reach the build host)");
  // Only the app has volumes: the named volume ferret-e2e-data on /data and the named volume ferret-e2e-backups on /backups, nothing else.
  const mounts = (s.volumes || []).map((v) => (typeof v === "string" ? v : v.source + ":" + v.target));
  const want = k === "ferret-e2e-app" ? ["ferret-e2e-data:/data", "ferret-e2e-backups:/backups"] : [];
  if (JSON.stringify(mounts) !== JSON.stringify(want)) fail(k + ": mounts must be " + JSON.stringify(want) + ", got " + JSON.stringify(mounts) + " (no bind mounts)");
  if (s.privileged) fail(k + ": privileged");
  if (s.read_only !== true) fail(k + ": read_only");
  if (!(s.security_opt || []).includes("no-new-privileges:true")) fail(k + ": no-new-privileges");
  if (JSON.stringify(s.cap_drop) !== JSON.stringify(["ALL"])) fail(k + ": cap_drop must be [ALL]");
  if (s.restart !== "no") fail(k + ": restart must be no");
  if (!(Number(s.mem_limit) > 0)) fail(k + ": a memory limit is required");
  if (Object.keys(s.networks || {}).join() !== "ferret-e2e-net") fail(k + ": only the network ferret-e2e-net");
}
{
  const volumes = Object.entries(e2e.volumes || {});
  if (volumes.map(([k]) => k).sort().join() !== "ferret-e2e-backups,ferret-e2e-data" || volumes.some(([k, v]) => v.name !== k || v.labels?.owner !== "ferret-e2e")) {
    fail("the only volumes are ferret-e2e-data and ferret-e2e-backups, named so and labelled owner=ferret-e2e");
  }
}
const app = e2e.services["ferret-e2e-app"];
const tls = e2e.services["ferret-e2e-tls"];
const evil = e2e.services["ferret-e2e-evil"];
const monitor = e2e.services["ferret-e2e-monitor"];
if (app.image !== "ferret-e2e-app:latest") fail("image of the app");
if (app.build?.labels?.owner !== "ferret-e2e") fail("build label owner=ferret-e2e");
if (Object.keys(app.build?.args || {}).sort().join() !== "CARGO_JOBS,FEATURES,WASM_COMMIT,WASM_SOURCE" || app.build.args.FEATURES !== "e2e-clock,quick-unlock") fail("the app is built with FEATURES=e2e-clock,quick-unlock, CARGO_JOBS and the source of the WebAssembly package, nothing else");
// The web vault of the stack is built against the published package unless the script says tree (FERRET_WASM_SOURCE).
if (app.build.args.WASM_SOURCE !== "lock" || app.build.args.WASM_COMMIT !== "") fail("the e2e app takes the published WebAssembly package by default, got " + app.build.args.WASM_SOURCE + " " + app.build.args.WASM_COMMIT);
// The build host is shared: the server build runs at most 4 jobs at a time.
if (!/^[1-4]$/.test(String(app.build.args.CARGO_JOBS))) fail("CARGO_JOBS of the app build must be 1 to 4, got " + app.build.args.CARGO_JOBS);
if ([...(app.cap_add || [])].sort().join() !== "CHOWN,SETGID,SETUID") fail("app cap_add");
if ((app.tmpfs || []).some((t) => t.startsWith("/data"))) fail("the data directory is the named volume, not tmpfs");
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
if (net.external) fail("the network is made here");
if (net.internal !== true) fail("e2e_network_is_internal: the network of the stack has no way out (internal: true)");
const subnet = net.ipam?.config?.[0]?.subnet;
if (subnet !== "172.30.250.0/28") fail("subnet");
const tlsIp = tls.networks["ferret-e2e-net"].ipv4_address;
const appIp = app.networks["ferret-e2e-net"].ipv4_address;
const evilIp = evil.networks["ferret-e2e-net"].ipv4_address;
const monitorIp = monitor.networks["ferret-e2e-net"].ipv4_address;
if (!tlsIp || !appIp || !evilIp || !monitorIp || new Set([tlsIp, appIp, evilIp, monitorIp]).size !== 4) fail("pinned addresses");
if (env.FERRET_TRUSTED_PROXIES !== evilIp) fail("the only trusted proxy is the malicious server at " + evilIp + ", got " + env.FERRET_TRUSTED_PROXIES);
for (const ip of [tlsIp, appIp, evilIp, monitorIp]) if (!/^172\.30\.250\.([2-9]|1[0-4])$/.test(ip)) fail(ip + " is not a host address of " + subnet + " (.1 is the gateway)");

// The malicious server: made here and nowhere else, in a pinned image, with no way in from outside and no right in the container.
if (evil.image !== "ferret-e2e-evil:latest") fail("image of the malicious server");
if (evil.build?.labels?.owner !== "ferret-e2e") fail("build label of the malicious server");
if (!String(evil.build?.context || "").replace(/\\/g, "/").endsWith("/web/test/e2e-stack/evil") || (evil.build?.dockerfile || "") !== "Dockerfile") fail("the malicious server is built from web/test/e2e-stack/evil/Dockerfile");
if (Object.keys(evil.build?.args || {}).length) fail("the malicious server takes no build argument");
if ((evil.cap_add || []).length) fail("the malicious server needs no capability");
if (evil.user || evil.pid || evil.ipc || evil.devices?.length || evil.volumes?.length || evil.volumes_from?.length) fail("the malicious server has no extra user, namespace, device or mount");
if (evil.expose?.length) fail("the malicious server exposes no port to publish");
if (Object.keys(evil.environment || {}).sort().join() !== "EVIL_UPSTREAM_ADMIN,EVIL_UPSTREAM_VAULT") fail("environment of the malicious server");
if (evil.environment.EVIL_UPSTREAM_VAULT !== "http://ferret-e2e-app:3041" || evil.environment.EVIL_UPSTREAM_ADMIN !== "http://ferret-e2e-app:3040") fail("the malicious server reaches the vault listener and the admin listener of the app, and nothing else");
if (app.depends_on?.["ferret-e2e-evil"] || !evil.depends_on?.["ferret-e2e-app"] || !tls.depends_on?.["ferret-e2e-evil"] || tls.depends_on?.["ferret-e2e-app"]) fail("start order: app, then the malicious server, then the terminator");
if (!evil.healthcheck) fail("the malicious server needs a health check (the terminator waits for it)");
if (!(evil.tmpfs || []).every((t) => t.startsWith("/tmp"))) fail("the malicious server writes to /tmp only");
const aliases = [...(tls.networks["ferret-e2e-net"].aliases || [])].sort().join();
if (aliases !== "admin-e2e.test,vault-e2e.test") fail("aliases of the TLS terminator: " + aliases);
const caddyfile = tls.environment?.CADDYFILE || "";
if (!/https:\/\/vault-e2e\.test \{[^}]*tls internal[^}]*reverse_proxy ferret-e2e-evil:8041/.test(caddyfile)) fail("Caddyfile: vault site goes to the malicious server (8041)");
if (!/https:\/\/admin-e2e\.test \{[^}]*tls internal[^}]*reverse_proxy ferret-e2e-evil:8040/.test(caddyfile)) fail("Caddyfile: admin site goes to the malicious server (8040)");
if (/ferret-e2e-app/.test(caddyfile) || /:9000/.test(caddyfile)) fail("Caddyfile: nothing goes to the app directly, and nothing to the control port");
if (/trusted_proxies/.test(caddyfile)) fail("the terminator must not trust forwarding headers from anyone");

// The stand-in for the push monitor: made here and nowhere else, in a pinned image, with no way in from outside and no right in the
// container; the app is told where it is (the token in the address is made up by e2e-up for every start) and waits for it.
if (monitor.image !== "ferret-e2e-monitor:latest") fail("image of the stand-in monitor");
if (monitor.build?.labels?.owner !== "ferret-e2e") fail("build label of the stand-in monitor");
if (!String(monitor.build?.context || "").replace(/\\/g, "/").endsWith("/web/test/e2e-stack/monitor") || (monitor.build?.dockerfile || "") !== "Dockerfile") fail("the stand-in monitor is built from web/test/e2e-stack/monitor/Dockerfile");
if (Object.keys(monitor.build?.args || {}).length) fail("the stand-in monitor takes no build argument");
if ((monitor.cap_add || []).length) fail("the stand-in monitor needs no capability");
if (monitor.user || monitor.pid || monitor.ipc || monitor.devices?.length || monitor.volumes?.length || monitor.volumes_from?.length) fail("the stand-in monitor has no extra user, namespace, device or mount");
if (monitor.expose?.length || Object.keys(monitor.environment || {}).length) fail("the stand-in monitor exposes no port to publish and takes no environment");
if (!monitor.healthcheck) fail("the stand-in monitor needs a health check (the app waits for it)");
if (!(monitor.tmpfs || []).every((t) => t.startsWith("/tmp"))) fail("the stand-in monitor writes to /tmp only");
if (env.FERRET_BACKUP_DIR !== "/backups") fail("the backup sets go to /backups, a volume of their own");
if (!/^http:\/\/ferret-e2e-monitor:9100\/api\/push\/[0-9A-Za-z]+$/.test(env.FERRET_BACKUP_PUSH_URL || "")) fail("the push address is the stand-in monitor with the token of the run");
if (!app.depends_on?.["ferret-e2e-monitor"]) fail("the app starts after the stand-in monitor");

// Nothing in common with the owner stack.
const o = owner.services["ferret-test-app"];
const overlap = (what, a, b) => { const x = a.filter((v) => b.includes(v)); if (x.length) fail("shared " + what + ": " + x); };
const hostNames = (c) => Object.keys(c.services).concat(Object.values(c.services).map((s) => s.container_name));
overlap("service or container names", hostNames(owner), hostNames(e2e));
overlap("volumes", Object.values(owner.volumes || {}).map((v) => v.name), Object.values(e2e.volumes || {}).map((v) => v.name));
overlap("networks", Object.values(owner.networks || {}).map((n) => n.name), Object.values(e2e.networks).map((n) => n.name));
overlap("images", [o.image], [app.image, tls.image, evil.image, monitor.image]);
overlap("labels", [o.labels.owner], [app.labels.owner, tls.labels.owner, monitor.labels.owner]);
if (owner.name === e2e.name) fail("same compose project");
if (o.env_file || app.env_file) fail("env_file would pull in the owner secrets");
const oe = o.environment;
for (const k of ["FERRET_VAULT_URL", "FERRET_ADMIN_URL", "FERRET_TRUSTED_PROXIES", "FERRET_SETUP_TOKEN"]) {
  if (oe[k] === env[k]) fail(k + " is the same in both stacks");
}
' "$config" "$e2e_config"

# The same stack under another suffix and network (FERRET_E2E_SUFFIX, FERRET_E2E_SUBNET): every name, the label,
# the host names and the addresses follow, so that it can run beside the first and touch nothing of it.
alt_config="$(FERRET_E2E_SUFFIX=alt FERRET_E2E_SUBNET=172.30.249 FERRET_E2E_SETUP_TOKEN=e2echeck FERRET_E2E_PUSH_TOKEN=e2epush docker compose -f "$e2e_file" config --format json)"
node -e '
const [base, alt] = process.argv.slice(1).map((s) => JSON.parse(s));
const fail = (m) => { console.error("check-ferret-test-stack: e2e suffix: " + m); process.exit(1); };
const rename = (text) => String(text).replaceAll("ferret-e2e-", "ferret-alt-").replaceAll("-e2e.test", "-alt.test").replaceAll("172.30.250", "172.30.249");
if (alt.name !== "ferret-e2e") fail("the file names the project; the script gives it with -p");
for (const [k, s] of Object.entries(alt.services)) {
  const b = base.services[k];
  if (s.container_name !== rename(b.container_name)) fail(k + ": container name " + s.container_name);
  if (s.image !== rename(b.image) && !b.image.startsWith("caddy:")) fail(k + ": image " + s.image);
  if (s.labels?.owner !== "ferret-alt") fail(k + ": label " + s.labels?.owner);
  if (b.build && s.build.labels?.owner !== "ferret-alt") fail(k + ": build label");
  for (const [net, n] of Object.entries(s.networks)) {
    if (n.ipv4_address !== b.networks[net].ipv4_address.replace("172.30.250", "172.30.249")) fail(k + ": address " + n.ipv4_address);
  }
}
const app = alt.services["ferret-e2e-app"];
if (app.environment.FERRET_VAULT_URL !== "https://vault-alt.test" || app.environment.FERRET_ADMIN_URL !== "https://admin-alt.test") fail("the host names of the app");
if (app.environment.FERRET_TRUSTED_PROXIES !== "172.30.249.4") fail("the trusted proxy is the malicious server of this stack");
const tls = alt.services["ferret-e2e-tls"];
if ([...tls.networks["ferret-e2e-net"].aliases].sort().join() !== "admin-alt.test,vault-alt.test") fail("the aliases of the terminator");
const caddy = tls.environment.CADDYFILE;
if (!caddy.includes("https://vault-alt.test {") || !caddy.includes("https://admin-alt.test {") || caddy.includes("-e2e.test")) fail("the Caddyfile host names");
if (Object.keys(alt.volumes).sort().join() !== "ferret-e2e-backups,ferret-e2e-data" || Object.values(alt.volumes).some((v) => !v.name.startsWith("ferret-alt-") || v.labels.owner !== "ferret-alt")) fail("volumes");
const net = alt.networks["ferret-e2e-net"];
if (net.name !== "ferret-alt-net" || net.labels.owner !== "ferret-alt" || net.ipam.config[0].subnet !== "172.30.249.0/28") fail("network");
' "$e2e_config" "$alt_config"
# A suffix or a network that is not allowed stops the script before it calls docker, and the labels of DEV_RUN
# are added only when it is set (the second compose file is made only then).
for bad in 'FERRET_E2E_SUFFIX=Bad' 'FERRET_E2E_SUFFIX=waytoolongsuffix' 'FERRET_E2E_SUFFIX=a-b' 'FERRET_E2E_SUBNET=1.2' 'FERRET_E2E_SUBNET=a.b.c' 'DEV_RUN=Bad_Name' 'DEV_RUN=-dash'; do
  if env "$bad" FERRET_DOCKER_ARGS="--context stub" bash scripts/lanbox-ferret-test.sh e2e-down >/dev/null 2>&1; then
    echo "check-ferret-test-stack: $bad was accepted" >&2
    exit 1
  fi
done
labels_out="$(DEV_RUN=check-run DEV_TITLE='A "title" $x' bash -c '
  FERRET_DOCKER_ARGS="--context stub"
  source scripts/lanbox-ferret-test.sh
  printf "%s\n" "${e2e_dev_labels[@]}"
  e2e_dev_override' scripts/check-ferret-test-stack.sh)"
# shellcheck disable=SC2016
for want in 'dev.run=check-run' 'dev.title=A "title" $x' '      dev.run: "check-run"' '      dev.title: "A \"title\" $$x"'; do
  printf '%s\n' "$labels_out" | grep -qxF -- "$want" || { echo "check-ferret-test-stack: the labels of DEV_RUN lack: $want" >&2; exit 1; }
done
# shellcheck disable=SC2016
no_labels="$(env -u DEV_RUN -u DEV_TITLE bash -c 'FERRET_DOCKER_ARGS="--context stub"; source scripts/lanbox-ferret-test.sh; echo "${#e2e_dev_labels[@]}"' scripts/check-ferret-test-stack.sh)"
if [ "$no_labels" != 0 ]; then
  echo "check-ferret-test-stack: labels are added without DEV_RUN" >&2
  exit 1
fi

# The malicious server exists in the e2e stack only: no other compose file, no
# Dockerfile of the server, nothing of its folder in the server's build context.
for f in docker/*; do
  [ "$f" = "$e2e_file" ] && continue
  if grep -qiE 'e2e-evil|e2e-stack/evil' "$f"; then
    echo "check-ferret-test-stack: $f must not mention the malicious server; only $e2e_file may" >&2
    exit 1
  fi
done
if ! tr -d '\r' < .dockerignore | grep -qx 'web/test/e2e-stack/evil'; then
  echo "check-ferret-test-stack: .dockerignore must list web/test/e2e-stack/evil" >&2
  exit 1
fi
# The stand-in monitor too: only the e2e compose file mentions it, and the server's build context leaves its folder out.
for f in docker/*; do
  [ "$f" = "$e2e_file" ] && continue
  if grep -qiE 'e2e-monitor|e2e-stack/monitor' "$f"; then
    echo "check-ferret-test-stack: $f must not mention the stand-in monitor; only $e2e_file may" >&2
    exit 1
  fi
done
if ! grep -qxE 'web/test/e2e-stack/monitor.?' .dockerignore; then
  echo "check-ferret-test-stack: .dockerignore must list web/test/e2e-stack/monitor" >&2
  exit 1
fi
monitor_dockerfile=web/test/e2e-stack/monitor/Dockerfile
monitor_node="$(sed -n 's/^ARG NODE_IMAGE=//p' docker/server.Dockerfile)"
if [ -z "$monitor_node" ] || ! grep -qx "FROM $monitor_node" "$monitor_dockerfile"; then
  echo "check-ferret-test-stack: $monitor_dockerfile must start from the Node image of docker/server.Dockerfile, pinned by digest" >&2
  exit 1
fi
grep -q 'monitor.mjs' "$monitor_dockerfile" || { echo "check-ferret-test-stack: $monitor_dockerfile must copy monitor.mjs" >&2; exit 1; }
# The server image takes the built web vault (web/dist, web/admin) from the web stage and nothing else.
if grep -E '^COPY --from=web ' docker/server.Dockerfile | grep -vE ' /src/web/(dist|admin)( |$)'; then
  echo "check-ferret-test-stack: docker/server.Dockerfile must copy only web/dist and web/admin from the web stage" >&2
  exit 1
fi
# The folder of the malicious server: its image is pinned by the digest of the server's Node image, and
# it is the only place that the stack's snapshot helper (a pinned Alpine) is named the same as the server's.
evil_dockerfile=web/test/e2e-stack/evil/Dockerfile
server_node="$(sed -n 's/^ARG NODE_IMAGE=//p' docker/server.Dockerfile)"
if [ -z "$server_node" ] || ! grep -qx "FROM $server_node" "$evil_dockerfile"; then echo "check-ferret-test-stack: $evil_dockerfile must start from the Node image of docker/server.Dockerfile, pinned by digest" >&2; exit 1; fi
server_alpine="$(sed -n 's/^ARG ALPINE_IMAGE=//p' docker/server.Dockerfile)"
if [ -z "$server_alpine" ] || ! grep -qx "alpine_image=$server_alpine" scripts/lanbox-ferret-test.sh; then echo "check-ferret-test-stack: the snapshot helper image of scripts/lanbox-ferret-test.sh must be the pinned Alpine of docker/server.Dockerfile" >&2; exit 1; fi
for f in proxy.mjs modes.mjs recorder.mjs; do
  grep -q "$f" "$evil_dockerfile" || { echo "check-ferret-test-stack: $evil_dockerfile must copy $f" >&2; exit 1; }
done
# The snapshot of the ferret-test stack and of the e2e stack: the label of the e2e one is its own.
grep -q '^e2e_snapshot_volume=ferret-e2e-snapshot$' scripts/lanbox-ferret-test.sh || { echo "check-ferret-test-stack: the e2e snapshot volume must be ferret-e2e-snapshot" >&2; exit 1; }
# shellcheck disable=SC2016
grep -q 'take_snapshot "$e2e_data_volume" "$e2e_snapshot_volume" "$e2e_label"' scripts/lanbox-ferret-test.sh || { echo "check-ferret-test-stack: the e2e snapshot volume must be made with the label owner=ferret-e2e" >&2; exit 1; }
# The snapshot of the ferret-test stack refuses without --yes-ferret-test, before any Docker call.
for command in snapshot restore-snapshot; do
  if FERRET_DOCKER_ARGS="--context check-no-such-context" scripts/lanbox-ferret-test.sh "$command" >/dev/null 2>&1; then
    echo "check-ferret-test-stack: $command ran without --yes-ferret-test" >&2
    exit 1
  fi
  rc=0
  FERRET_DOCKER_ARGS="--context check-no-such-context" scripts/lanbox-ferret-test.sh "$command" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] || { echo "check-ferret-test-stack: $command without --yes-ferret-test must stop with exit 2, got $rc" >&2; exit 1; }
done

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
    tunnel_lookup() { echo "address 172.17.0.2"; }
    tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: $name.env: tunnel_mismatch did not report the mismatch" >&2; exit 1; }
    if (require_tunnel) >/dev/null 2>&1; then echo "check-ferret-test-stack: $name.env: require_tunnel did not refuse" >&2; exit 1; fi
  )
done
(
  export FERRET_ENV_FILE="$tmp/plain.env"
  unset FERRET_TRUSTED_PROXIES FERRET_SETUP_TOKEN
  # shellcheck disable=SC1091
  source scripts/lanbox-ferret-test.sh
  tunnel_lookup() { echo "address 172.17.0.2"; }
  if tunnel_mismatch >/dev/null; then echo "check-ferret-test-stack: plain.env: a matching address was reported as a mismatch" >&2; exit 1; fi
  (require_tunnel) >/dev/null 2>&1 || { echo "check-ferret-test-stack: plain.env: require_tunnel refused a matching address" >&2; exit 1; }
  # The tunnel client at another address, and at none.
  tunnel_lookup() { echo "address 172.17.0.3"; }
  tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: plain.env: another tunnel address passed" >&2; exit 1; }
  # A tunnel client that Docker cannot see (on a host of its own) is believed only through
  # the explicit value, which is a valid single address here: no mismatch.
  tunnel_lookup() { echo notfound; }
  if tunnel_mismatch >/dev/null; then echo "check-ferret-test-stack: plain.env: an explicit single address was refused when the tunnel client is outside Docker" >&2; exit 1; fi
  # An unreadable tunnel client is a refusal, whatever the explicit value is.
  tunnel_lookup() { echo unreadable; }
  tunnel_mismatch >/dev/null || { echo "check-ferret-test-stack: plain.env: an unreadable tunnel client did not refuse" >&2; exit 1; }
  if (require_tunnel) >/dev/null 2>&1; then echo "check-ferret-test-stack: plain.env: require_tunnel accepted an unreadable tunnel client" >&2; exit 1; fi
)

# The snapshot guards, with a stand-in for docker that records its arguments and answers from
# the environment (STUB_VOLUMES: name=label pairs; STUB_VERIFY_RC and STUB_JOB_RC: the exit codes
# of the volume jobs; STUB_BUMP_RC: the restore epoch bump; STUB_RUNNING: the state of the
# container). Nothing is sent to a Docker host. A restore refuses before anything is stopped or
# emptied unless the snapshot has its label, the completion marker and a database; a failed copy
# leaves the old snapshot and restarts the app; a snapshot of an app that was stopped does not
# start it; a volume with another label is not touched.
mkdir "$tmp/bin"
cat > "$tmp/bin/docker" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
if [ -n "${STUB_FAIL:-}" ] && printf '%s' "$*" | grep -qE -- "$STUB_FAIL"; then exit 1; fi
last="${*: -1}"
has_volume() { for pair in $STUB_VOLUMES; do [ "${pair%%=*}" = "$1" ] && return 0; done; return 1; }
case "$*" in
  *"volume inspect -f"*)
    has_volume "$last" || exit 1
    for pair in $STUB_VOLUMES; do [ "${pair%%=*}" = "$last" ] && echo "${pair#*=}"; done
    exit 0 ;;
  *"volume inspect"*) has_volume "$last"; exit $? ;;
  *"inspect -f {{.State.Running}}"*) echo "${STUB_RUNNING:-true}" ;;
  *"inspect -f"*Health*) echo healthy ;;
  *compose*" run "*) exit "${STUB_BUMP_RC:-0}" ;;
  *" run "*"MODE="*)
    if [ -n "${STUB_REAL_JOBS:-}" ]; then
      # The job script of the stack script runs for real, on folders, with the folders as /from and /to.
      mode=""
      for a in "$@"; do case "$a" in MODE=*) mode="${a#MODE=}" ;; esac; done
      case "$mode" in
        verify) from="$STUB_SNAP"; to="" ;;
        make) from="$STUB_DATA"; to="$STUB_NEW" ;;
        move) from="$STUB_NEW"; to="$STUB_SNAP" ;;
        restore) from="$STUB_SNAP"; to="$STUB_DATA" ;;
      esac
      FROM="$from" TO="$to" MODE="$mode" sh -c "$last"
      exit $?
    fi
    case "$*" in *MODE=verify*) exit "${STUB_VERIFY_RC:-0}" ;; esac
    case "$*" in *MODE=restore*) [ -n "${STUB_RESTORE_RC:-}" ] && exit "$STUB_RESTORE_RC" ;; esac
    exit "${STUB_JOB_RC:-0}" ;;
esac
exit 0
STUB
chmod +x "$tmp/bin/docker"
# A cp that fails, or that copies and then damages the database, when asked to (the job script uses cp -a).
cat > "$tmp/bin/cp" <<'STUB'
#!/usr/bin/env bash
if [ "${STUB_CP_FAIL:-}" = 1 ]; then echo "cp: stand-in failure" >&2; exit 1; fi
"$STUB_REAL_CP" "$@" || exit $?
if [ "${STUB_CP_CORRUPT:-}" = 1 ]; then
  last="${*: -1}"
  [ -f "${last}ferret.sqlite" ] && printf x >> "${last}ferret.sqlite"
fi
exit 0
STUB
chmod +x "$tmp/bin/cp"
real_cp="$(command -v cp)"
guard_log="$PWD/$tmp/guard.log"
guard_fail() { echo "check-ferret-test-stack: snapshot guard: $1" >&2; exit 1; }
# guard_run <function> [vars...]: runs a function of the script against the stand-in; the exit code is its own.
guard_run() {
  : > "$guard_log"
  (
    export PATH="$PWD/$tmp/bin:$PATH" STUB_LOG="$guard_log" FERRET_DOCKER_ARGS="--context stub" FERRET_ENV_FILE="$tmp/plain.env"
    export STUB_VOLUMES STUB_VERIFY_RC STUB_JOB_RC STUB_RESTORE_RC STUB_FAIL STUB_BUMP_RC STUB_RUNNING STUB_REAL_JOBS STUB_DATA STUB_NEW STUB_SNAP STUB_CP_FAIL STUB_CP_CORRUPT STUB_REAL_CP="$real_cp"
    # shellcheck disable=SC1091
    source scripts/lanbox-ferret-test.sh
    "$@"
  ) > "$guard_log.out" 2>&1
}
logged() { grep -qE -- "$1" "$guard_log"; }
first_line() { grep -nE -- "$1" "$guard_log" | head -n 1 | cut -d: -f1; }
good_e2e="ferret-e2e-data=ferret-e2e ferret-e2e-snapshot=ferret-e2e"
good_test="ferret-test-data=ferret-test ferret-test-snapshot=ferret-test"
unset STUB_VERIFY_RC STUB_JOB_RC STUB_BUMP_RC STUB_RUNNING STUB_REAL_JOBS STUB_CP_FAIL STUB_CP_CORRUPT

# --- restore refuses, and changes nothing, when the snapshot is not good
for kind in e2e test; do
  if [ "$kind" = e2e ]; then
    fn=e2e_restore_snapshot; app=ferret-e2e-app; snap=ferret-e2e-snapshot; good="$good_e2e"; arg=()
  else
    fn=test_restore_snapshot; app=ferret-test-app; snap=ferret-test-snapshot; good="$good_test"; arg=(--yes-ferret-test)
  fi
  # no snapshot volume
  STUB_VOLUMES="${good%% *}"
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a restore without a snapshot went through"; fi
  if logged " stop | MODE=restore"; then guard_fail "$kind: a restore without a snapshot stopped the app or wrote the data"; fi
  # a volume of that name with another label
  STUB_VOLUMES="${good%% *} $snap=somebody-else"
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a snapshot with another label was restored"; fi
  if logged " stop | MODE=verify | MODE=restore"; then guard_fail "$kind: a volume with another label was touched"; fi
  # no completion marker or no database: the check job fails
  STUB_VOLUMES="$good"
  STUB_VERIFY_RC=3
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: an incomplete snapshot was restored"; fi
  logged "MODE=verify" || guard_fail "$kind: the snapshot was not checked"
  if logged " stop | MODE=restore|restore-epoch bump"; then guard_fail "$kind: an incomplete snapshot stopped the app or was copied"; fi
  unset STUB_VERIFY_RC
  # the copy fails half way: the epoch is not raised and the app is not started
  STUB_JOB_RC=4
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a failed copy went through"; fi
  if logged "restore-epoch bump| start $app"; then guard_fail "$kind: after a failed copy the epoch was raised or the app started"; fi
  unset STUB_JOB_RC
  # the bump fails: the app is not started
  STUB_BUMP_RC=1
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a failed bump went through"; fi
  if logged " start $app"; then guard_fail "$kind: the app was started after a failed bump"; fi
  unset STUB_BUMP_RC
  # a good snapshot: checked, then the app is stopped, then copied, then the bump, then the start
  guard_run "$fn" "${arg[@]}" || guard_fail "$kind: a good snapshot was refused"
  verify="$(first_line 'MODE=verify')"; stop="$(first_line " stop ")"; copy="$(first_line 'MODE=restore')"; bump="$(first_line 'restore-epoch bump')"; start="$(first_line " start $app")"
  { [ -n "$verify" ] && [ -n "$stop" ] && [ -n "$copy" ] && [ -n "$bump" ] && [ -n "$start" ] && [ "$verify" -lt "$stop" ] && [ "$stop" -lt "$copy" ] && [ "$copy" -lt "$bump" ] && [ "$bump" -lt "$start" ]; } \
    || guard_fail "$kind: the order must be check, stop, copy, bump, start (got $verify $stop $copy $bump $start)"
  if [ "$kind" = e2e ] && ! logged "127.0.0.1:9000/reset"; then guard_fail "e2e: the recorder of the malicious server was not reset after a restore"; fi
done

# --- a snapshot: a failed copy keeps the old snapshot and restarts the app; a volume with another label is not touched
for kind in e2e test; do
  if [ "$kind" = e2e ]; then
    fn=e2e_snapshot; app=ferret-e2e-app; snap=ferret-e2e-snapshot; good="$good_e2e"; arg=()
  else
    fn=test_snapshot; app=ferret-test-app; snap=ferret-test-snapshot; good="$good_test"; arg=(--yes-ferret-test)
  fi
  STUB_VOLUMES="$good"
  STUB_JOB_RC=3
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a failed copy went through"; fi
  logged " start $app" || guard_fail "$kind: the app was not started after a failed copy"
  if logged "volume rm $snap$|MODE=move"; then guard_fail "$kind: a failed copy replaced the old snapshot"; fi
  unset STUB_JOB_RC
  STUB_VOLUMES="${good%% *} $snap=somebody-else"
  if guard_run "$fn" "${arg[@]}"; then guard_fail "$kind: a volume with another label was replaced"; fi
  if logged " stop |volume rm $snap$|MODE="; then guard_fail "$kind: a volume with another label was touched"; fi
  STUB_VOLUMES="$good"
  guard_run "$fn" "${arg[@]}" || guard_fail "$kind: a good snapshot failed"
  make="$(first_line 'MODE=make')"; started="$(first_line " start $app")"; removed="$(first_line "volume rm $snap$")"; moved="$(first_line 'MODE=move')"
  logged "volume create --label owner=ferret-$kind $snap$" || guard_fail "$kind: the new snapshot volume must carry the label owner=ferret-$kind"
  { [ -n "$make" ] && [ -n "$started" ] && [ -n "$removed" ] && [ -n "$moved" ] && [ "$make" -lt "$started" ] && [ "$started" -lt "$removed" ] && [ "$removed" -lt "$moved" ]; } \
    || guard_fail "$kind: the order must be copy, start, swap (got $make $started $removed $moved)"
done
# --- the job script itself, run for real on folders: a cp that fails, or a copy that differs, writes
# no marker and the restore does not go on; a good copy is the same files with the marker last
vols="$PWD/$tmp/vols"
STUB_REAL_JOBS=1 STUB_DATA="$vols/data" STUB_NEW="$vols/new" STUB_SNAP="$vols/snap"
fresh_folders() {
  rm -rf "$vols"
  mkdir -p "$vols/data/sub" "$vols/new" "$vols/snap"
  printf 'database' > "$vols/data/ferret.sqlite"
  printf 'log' > "$vols/data/ferret.sqlite-wal"
  printf 'x' > "$vols/data/sub/file"
  printf 'old database' > "$vols/snap/ferret.sqlite"
  : > "$vols/snap/.snapshot-complete"
}
same_files() { # a folder, another folder: the same files and the same bytes (the marker aside)
  [ "$(cd "$1" && find . -mindepth 1 ! -name .snapshot-complete | sort)" = "$(cd "$2" && find . -mindepth 1 ! -name .snapshot-complete | sort)" ] \
    && (cd "$1" && find . -type f ! -name .snapshot-complete) | while read -r f; do cmp -s "$1/$f" "$2/$f" || exit 1; done
}
# a good snapshot: the files, the same bytes, the marker in the swapped-in snapshot
fresh_folders
STUB_VOLUMES="$good_e2e"
guard_run e2e_snapshot || guard_fail "real jobs: a good snapshot failed"
{ [ -f "$vols/snap/.snapshot-complete" ] && same_files "$vols/data" "$vols/snap"; } || guard_fail "real jobs: the snapshot is not a copy of the data with the marker"
# a good restore of it: the data is the snapshot again, with no marker in the data
printf 'newer' > "$vols/data/ferret.sqlite"; printf 'junk' > "$vols/data/junk"
guard_run e2e_restore_snapshot || guard_fail "real jobs: a good restore failed"
{ same_files "$vols/snap" "$vols/data" && [ ! -e "$vols/data/.snapshot-complete" ]; } || guard_fail "real jobs: the restored data is not the snapshot"
# a cp that fails, or a copy that differs: no marker, the old snapshot stays, the app of a snapshot is started again
for broken in STUB_CP_FAIL STUB_CP_CORRUPT; do
  fresh_folders
  export "$broken=1"
  STUB_VOLUMES="$good_e2e"
  if guard_run e2e_snapshot; then guard_fail "real jobs: $broken: a snapshot went through"; fi
  [ ! -e "$vols/new/.snapshot-complete" ] || guard_fail "real jobs: $broken: a marker was written for a copy that failed or differs"
  { [ "$(cat "$vols/snap/ferret.sqlite")" = "old database" ] && [ -f "$vols/snap/.snapshot-complete" ]; } || guard_fail "real jobs: $broken: the old snapshot was changed"
  if logged "volume rm ferret-e2e-snapshot$|MODE=move"; then guard_fail "real jobs: $broken: the old snapshot was removed or replaced"; fi
  logged " start ferret-e2e-app" || guard_fail "real jobs: $broken: the app was not started after a failed copy"
  # the same in a restore, for both stacks: it does not go on to the bump or the start
  for kind in e2e test; do
    if [ "$kind" = e2e ]; then fn=e2e_restore_snapshot; app=ferret-e2e-app; good="$good_e2e"; arg=(); else fn=test_restore_snapshot; app=ferret-test-app; good="$good_test"; arg=(--yes-ferret-test); fi
    fresh_folders
    STUB_VOLUMES="$good"
    if guard_run "$fn" "${arg[@]}"; then guard_fail "real jobs: $broken: $kind: a restore went through"; fi
    [ ! -e "$vols/data/.snapshot-complete" ] || guard_fail "real jobs: $broken: $kind: a marker is in the data"
    if logged "restore-epoch bump| start $app"; then guard_fail "real jobs: $broken: $kind: the restore went on after a failed copy"; fi
  done
  unset "$broken"
done
# a snapshot without its marker or database: refused by the real check, nothing stopped
fresh_folders
rm "$vols/snap/.snapshot-complete"
STUB_VOLUMES="$good_e2e"
if guard_run e2e_restore_snapshot; then guard_fail "real jobs: a snapshot without a marker was restored"; fi
if logged " stop |restore-epoch bump"; then guard_fail "real jobs: a snapshot without a marker stopped the app"; fi
# an earlier snapshot that was never swapped in may hold the only finished copy: it is not deleted, and nothing is stopped
fresh_folders
STUB_VOLUMES="$good_e2e ferret-e2e-snapshot-new=ferret-e2e"
if guard_run e2e_snapshot; then guard_fail "a snapshot went on although an unfinished one is still there"; fi
if logged " stop |volume rm ferret-e2e-snapshot-new"; then guard_fail "the volume of an unfinished snapshot was removed or the app stopped"; fi
unset STUB_REAL_JOBS STUB_DATA STUB_NEW STUB_SNAP

# the app of the owner's stack that was stopped before stays stopped
STUB_VOLUMES="$good_test"
STUB_RUNNING=false
guard_run test_snapshot --yes-ferret-test || guard_fail "a snapshot of a stopped app failed"
if logged " start ferret-test-app"; then guard_fail "a snapshot started an app that was stopped before"; fi
unset STUB_RUNNING STUB_VOLUMES

# The runner of the end-to-end tests installs its packages in a container of its own on the default
# network and runs the tests on the stack's network only: it is never joined to a second network.
grep -q -- '--network bridge' scripts/lanbox-ferret-test.sh || guard_fail "the package install must run on the default network"
if grep -n 'network connect' scripts/lanbox-ferret-test.sh; then guard_fail "the test runner must never be joined to a second network"; fi
# ferret_test_data_has_its_label: the data volume of the ferret-test stack carries owner=ferret-test (the compose
# file says so above), `up` refuses a volume that was made without the label, and `label-data` gives it the
# label by copying the data: checked copy first, the old volume removed only after that, the new one made with
# the label, the data copied back, the temporary volume removed last; a failure leaves the data in a volume.
grep -qE '^    require_data_label$' scripts/lanbox-ferret-test.sh || guard_fail "up must call require_data_label"
[ "$(grep -n 'require_data_label$' scripts/lanbox-ferret-test.sh | head -n 1 | cut -d: -f1)" -lt "$(grep -n 'dc up -d --build' scripts/lanbox-ferret-test.sh | head -n 1 | cut -d: -f1)" ] || guard_fail "require_data_label must come before the start"
STUB_VOLUMES="ferret-test-data="
if guard_run require_data_label; then guard_fail "ferret_test_data_has_its_label: a data volume without the label passed"; fi
STUB_VOLUMES="ferret-test-data=somebody-else"
if guard_run require_data_label; then guard_fail "ferret_test_data_has_its_label: a data volume with another label passed"; fi
STUB_VOLUMES="ferret-test-data=ferret-test"
guard_run require_data_label || guard_fail "ferret_test_data_has_its_label: a labelled data volume was refused"
STUB_VOLUMES=""
guard_run require_data_label || guard_fail "ferret_test_data_has_its_label: no data volume at all was refused"
# label-data: refuses without --yes-ferret-test, does nothing when the label is there
STUB_VOLUMES="ferret-test-data="
if guard_run test_label_data; then guard_fail "label-data went on without --yes-ferret-test"; fi
if logged "volume create|volume rm|MODE="; then guard_fail "label-data without a yes touched a volume"; fi
STUB_VOLUMES="ferret-test-data=ferret-test"
guard_run test_label_data --yes-ferret-test || guard_fail "label-data failed on a labelled volume"
if logged "volume create|volume rm|MODE=| stop "; then guard_fail "label-data touched a volume that already had the label"; fi
# a volume without the label: copy, check, replace, copy back, remove the temporary volume
STUB_VOLUMES="ferret-test-data="
guard_run test_label_data --yes-ferret-test || guard_fail "label-data failed"
tmpcreate="$(first_line 'volume create --label owner=ferret-test ferret-test-data-relabel$')"; stop="$(first_line ' stop ')"; copy="$(first_line 'MODE=make')"
down="$(first_line 'compose .* down')"; rm_old="$(first_line 'volume rm ferret-test-data$')"; new="$(first_line 'volume create --label owner=ferret-test ferret-test-data$')"
back="$(first_line 'MODE=restore')"; rm_tmp="$(first_line 'volume rm ferret-test-data-relabel$')"
{ [ -n "$tmpcreate" ] && [ -n "$stop" ] && [ -n "$copy" ] && [ -n "$down" ] && [ -n "$rm_old" ] && [ -n "$new" ] && [ -n "$back" ] && [ -n "$rm_tmp" ] \
  && [ "$tmpcreate" -lt "$stop" ] && [ "$stop" -lt "$copy" ] && [ "$copy" -lt "$down" ] && [ "$down" -lt "$rm_old" ] && [ "$rm_old" -lt "$new" ] && [ "$new" -lt "$back" ] && [ "$back" -lt "$rm_tmp" ]; } \
  || guard_fail "label-data: the order must be temporary volume, stop, checked copy, down, remove old, make labelled, copy back, remove temporary (got $tmpcreate $stop $copy $down $rm_old $new $back $rm_tmp)"
# the copy fails: the data volume is untouched
STUB_JOB_RC=4
if guard_run test_label_data --yes-ferret-test; then guard_fail "label-data went on after a failed copy"; fi
if logged 'volume rm ferret-test-data$|compose .* down'; then guard_fail "label-data removed the data volume after a failed copy"; fi
unset STUB_JOB_RC
# the copy back fails: the temporary volume, which holds the data, is kept
STUB_RESTORE_RC=4
if guard_run test_label_data --yes-ferret-test; then guard_fail "label-data went on after a failed copy back"; fi
if logged 'volume rm ferret-test-data-relabel$'; then guard_fail "label-data removed the temporary volume although the data was not copied back"; fi
unset STUB_RESTORE_RC
# an earlier run that did not finish: nothing is stopped or removed
STUB_VOLUMES="ferret-test-data= ferret-test-data-relabel=ferret-test"
if guard_run test_label_data --yes-ferret-test; then guard_fail "label-data went on although an unfinished run left a volume"; fi
if logged ' stop |volume rm|MODE='; then guard_fail "label-data touched volumes although an unfinished run left one"; fi
unset STUB_VOLUMES
# both volumes labelled (a cut-off after the new volume was made): up and label-data refuse and touch nothing
STUB_VOLUMES="ferret-test-data=ferret-test ferret-test-data-relabel=ferret-test"
if guard_run require_data_label; then guard_fail "up would start although the temporary volume of label-data is still there"; fi
grep -q 'DO NOT run up' "$guard_log.out" || guard_fail "require_data_label must say that up must not be run"
if guard_run test_label_data --yes-ferret-test; then guard_fail "label-data went on with both volumes there"; fi
if logged ' stop |volume rm|volume create|MODE=|compose .* down'; then guard_fail "label-data touched volumes with both volumes there"; fi
STUB_VOLUMES="ferret-test-data-relabel=ferret-test"
if guard_run require_data_label; then guard_fail "up would start with the data volume gone and only the temporary volume left"; fi
# a cut-off or failure at each step: what is removed, what is kept, and what is said
unset STUB_VOLUMES
cut_off() { # step name, failing command (an ERE on the arguments), then what must not and must be logged, and the text
  local name="$1" fail_re="$2" not_re="$3" must_re="$4" text="$5"
  STUB_VOLUMES="ferret-test-data="
  STUB_FAIL="$fail_re"
  if guard_run test_label_data --yes-ferret-test; then guard_fail "label-data: $name: went on after a failure"; fi
  unset STUB_FAIL
  if [ -n "$not_re" ] && logged "$not_re"; then guard_fail "label-data: $name: did something that must not follow: $not_re"; fi
  if [ -n "$must_re" ] && ! logged "$must_re"; then guard_fail "label-data: $name: expected $must_re"; fi
  grep -q "$text" "$guard_log.out" || guard_fail "label-data: $name: the message must say: $text (got: $(tr '\n' ' ' < "$guard_log.out"))"
}
cut_off "the temporary volume cannot be made" 'volume create --label owner=ferret-test ferret-test-data-relabel$' ' stop |volume rm|MODE=' '' 'nothing was changed'
cut_off "the app cannot be stopped" 'compose .* stop ' 'volume rm ferret-test-data$|MODE=make' 'volume rm ferret-test-data-relabel$' 'nothing was changed'
cut_off "the check of the copy" 'MODE=verify' 'volume rm ferret-test-data$|compose .* down|volume rm ferret-test-data-relabel$' 'MODE=make' 'DO NOT run up'
cut_off "the stack cannot be taken down" 'compose .* down' 'volume rm ferret-test-data$|volume rm ferret-test-data-relabel$' 'MODE=verify' 'DO NOT run up'
cut_off "the old volume cannot be removed" 'volume rm ferret-test-data$' 'volume create --label owner=ferret-test ferret-test-data$|volume rm ferret-test-data-relabel$' 'compose .* down' 'DO NOT run up'
cut_off "the new volume cannot be made" 'volume create --label owner=ferret-test ferret-test-data$' 'MODE=restore|volume rm ferret-test-data-relabel$' 'volume rm ferret-test-data$' 'DO NOT run up'
cut_off "the copy back" 'MODE=restore' 'volume rm ferret-test-data-relabel$' 'volume create --label owner=ferret-test ferret-test-data$' 'DO NOT run up'
cut_off "the temporary volume cannot be removed at the end" 'volume rm ferret-test-data-relabel$' '' 'MODE=restore' 'remove it by hand before run up'
unset STUB_VOLUMES

# A tunnel client that runs outside Docker (Newt may run on a host of its own
# that `docker inspect` cannot see). The real tunnel_lookup, reachable and
# require_tunnel run against a stand-in docker program that only answers `inspect`
# and `run` from the environment and records the `run` arguments; `compose` goes to
# the real docker, which only reads the files. Nothing is sent to a Docker host.
real_docker="$(command -v docker)"
mkdir "$tmp/tunnelbin"
cat > "$tmp/tunnelbin/docker" <<'STUB'
#!/usr/bin/env bash
sub=
for a in "$@"; do
  case "$a" in inspect | run | compose) sub="$a"; break ;; esac
done
case "$sub" in
  inspect)
    # Docker cannot be asked: not a "no such container" answer.
    if [ -n "${FAKE_INSPECT_ERROR:-}" ]; then
      echo "error during connect: Cannot connect to the Docker daemon" >&2
      exit 1
    fi
    # Newt as a Docker container only when FAKE_NEWT_MODE is set; else Docker's own
    # "no such container" answer.
    if [ -z "${FAKE_NEWT_MODE:-}" ]; then
      echo "Error response from daemon: No such container: Newt" >&2
      exit 1
    fi
    case "$*" in
      *State.Running*)
        if [ -n "${FAKE_NEWT_STOPPED:-}" ]; then echo "false $FAKE_NEWT_MODE"; else echo "true $FAKE_NEWT_MODE"; fi
        ;;
      *NetworkSettings.Networks*) echo "${FAKE_NEWT_IP:-}" ;;
    esac
    exit 0
    ;;
  run)
    printf '%s\n' "$*" >> "$FAKE_RUN_LOG"
    case "$*" in *ping*) exit "${FAKE_PING_RC:-0}" ;; esac
    exit 0
    ;;
  *) exec "$REAL_DOCKER" "$@" ;;
esac
STUB
chmod +x "$tmp/tunnelbin/docker"
run_log="$tmp/run.log"
: > "$run_log"
cat_env() { printf '%s\n' 'FERRET_SETUP_TOKEN=check' "FERRET_TRUSTED_PROXIES=$1" > "$tmp/case.env"; }
# Runs one script function in a subshell with the stand-in docker. Arguments: the
# value of FERRET_TRUSTED_PROXIES (or the word UNSET), then the function and its
# environment, e.g. outcome 192.0.2.169 require_tunnel. Prints its output; the
# exit code is the function's.
outcome() {
  local value="$1"; shift
  if [ "$value" = UNSET ]; then printf '%s\n' 'FERRET_SETUP_TOKEN=check' > "$tmp/case.env"; else cat_env "$value"; fi
  (
    export PATH="$tmp/tunnelbin:$PATH" REAL_DOCKER="$real_docker" FAKE_RUN_LOG="$run_log"
    export FERRET_ENV_FILE="$tmp/case.env"
    unset FERRET_TRUSTED_PROXIES FERRET_SETUP_TOKEN
    # shellcheck disable=SC1091
    source scripts/lanbox-ferret-test.sh
    "$@"
  ) 2>&1
}
expect_fail() { echo "check-ferret-test-stack: $1" >&2; exit 1; }

# The address of the build host has no default: the commands that print or use it refuse
# without FERRET_TEST_HOST, and use it when it is set.
(
  unset FERRET_TEST_HOST
  # shellcheck disable=SC1091
  source scripts/lanbox-ferret-test.sh
  # shellcheck disable=SC2154
  [ -z "$test_host" ] || expect_fail "FERRET_TEST_HOST must have no default"
  out="$( (require_test_host) 2>&1)" && expect_fail "require_test_host accepted an unset FERRET_TEST_HOST"
  printf '%s' "$out" | grep -q 'FERRET_TEST_HOST' || expect_fail "no message that names FERRET_TEST_HOST: $out"
)
(
  export FERRET_TEST_HOST=build.example.test
  # shellcheck disable=SC1091
  source scripts/lanbox-ferret-test.sh
  [ "$test_host" = build.example.test ] || expect_fail "FERRET_TEST_HOST is not used"
  require_test_host
)

# What counts as a single valid address.
(
  # shellcheck disable=SC1091
  source scripts/lanbox-ferret-test.sh
  for ok in 192.0.2.169 192.168.1.20 172.17.0.2 1.2.3.4 223.255.255.254 169.253.1.1 169.255.1.1 10.0.0.254 10.0.1.1; do
    single_ipv4 "$ok" || expect_fail "single_ipv4 refused $ok"
  done
  for bad in "" 192.0.2 192.0.2.169.1 192.0.2.256 192.0.2.1690 192.0.02.169 192.00.2.169 010.0.2.169 192.0.2.169/32 192.0.2.0/24 \
             "192.0.2.169,192.0.2.170" "192.0.2.169 192.0.2.170" " 192.0.2.169" "192.0.2.169 " newt abc.def.ghi.jkl ::1 fe80::1 \
             0.0.0.0 0.1.2.3 127.0.0.1 127.1.2.3 224.0.0.1 239.1.1.1 255.255.255.255 -1.0.0.1 \
             192.0.2.0 192.0.2.255 192.168.1.0 192.168.1.255 169.254.1.1 169.254.0.0 169.254.169.254 192x0x2x169 "192.0.2.169
1.2.3.4"; do
    if single_ipv4 "$bad"; then expect_fail "single_ipv4 accepted '$bad'"; fi
  done
)

# Newt outside Docker, answering ping: accepted, no warning, one ping with the
# label of the stack and no more privilege than the ping needs.
: > "$run_log"
out="$(FAKE_PING_RC=0 outcome 192.0.2.169 require_tunnel)" || expect_fail "a single address was refused for a tunnel client outside Docker: $out"
[ -z "$out" ] || expect_fail "output for an address that answers ping: $out"
grep -q -- '--label owner=ferret-test' "$run_log" || expect_fail "the reachability check has no owner=ferret-test label"
grep -q -- '--cap-drop ALL' "$run_log" || expect_fail "the reachability check keeps its capabilities"
grep -q -- 'ping -c 1 -W 3 192.0.2.169' "$run_log" || expect_fail "the reachability check does not ping the address"
if grep -qE 'docker\.sock|--privileged|-v ' "$run_log"; then expect_fail "the reachability check has a mount or privilege"; fi
# The ping container is removed when it ends, cannot write, cannot gain privileges
# and is limited in processes and memory.
for flag in '--rm' '--read-only' '--security-opt no-new-privileges:true' '--pids-limit [0-9]' '--memory [0-9]'; do
  grep -q -- "$flag" "$run_log" || expect_fail "the reachability check lacks $flag"
done
# Not answering ping: a warning, not a refusal.
out="$(FAKE_PING_RC=1 outcome 192.0.2.169 require_tunnel)" || expect_fail "a silent address was refused: $out"
printf '%s' "$out" | grep -q 'WARNING.*192.0.2.169 does not answer ping' || expect_fail "no warning for an address that does not answer ping: $out"
# `status` warns the same way and prints nothing for a good one.
out="$(FAKE_PING_RC=1 outcome 192.0.2.169 check_tunnel)"
printf '%s' "$out" | grep -q 'WARNING.*does not answer ping' || expect_fail "status gave no warning for a silent address: $out"
out="$(FAKE_PING_RC=0 outcome 192.0.2.169 check_tunnel)"
[ -z "$out" ] || expect_fail "status warned about a good address: $out"

# Newt exists as a Docker container but its address cannot be read (host, none or
# another container's network, stopped, no address on its network), or Docker cannot
# be asked: refused, even with a valid explicit address, and nothing is pinged. Only
# Docker's answer "no such container" opens the explicit path.
refuse_unreadable() { # description, then VAR=value pairs of the fake docker
  local what="$1"; shift
  : > "$run_log"
  if out="$(for kv in "$@"; do export "${kv?}"; done; FAKE_PING_RC=0 outcome 192.0.2.169 require_tunnel)"; then
    expect_fail "$what: require_tunnel accepted the explicit address"
  fi
  printf '%s' "$out" | grep -q 'refusing to start' || expect_fail "$what: no refusal message: $out"
  printf '%s' "$out" | grep -q 'cannot read the address of Newt' || expect_fail "$what: wrong reason: $out"
  [ ! -s "$run_log" ] || expect_fail "$what: reached docker run"
  # The status command warns for it too.
  out="$(for kv in "$@"; do export "${kv?}"; done; FAKE_PING_RC=0 outcome 192.0.2.169 check_tunnel)"
  printf '%s' "$out" | grep -q 'WARNING: cannot read the address of Newt' || expect_fail "$what: status gave no warning: $out"
}
refuse_unreadable "a host-mode Newt" FAKE_NEWT_MODE=host FAKE_NEWT_IP=192.0.2.152
refuse_unreadable "a Newt without a network of its own" FAKE_NEWT_MODE=none FAKE_NEWT_IP=172.17.0.9
refuse_unreadable "a Newt in another container's network" FAKE_NEWT_MODE=container:abc123 FAKE_NEWT_IP=172.17.0.9
refuse_unreadable "a stopped Newt (bridge)" FAKE_NEWT_MODE=bridge FAKE_NEWT_IP= FAKE_NEWT_STOPPED=1
refuse_unreadable "a stopped Newt with a remembered address" FAKE_NEWT_MODE=bridge FAKE_NEWT_IP=172.17.0.2 FAKE_NEWT_STOPPED=1
refuse_unreadable "a running Newt with no address on its network" FAKE_NEWT_MODE=bridge FAKE_NEWT_IP=
refuse_unreadable "a failed docker inspect (not 'no such container')" FAKE_INSPECT_ERROR=1

# Refused without any ping: not set, and everything that is not one valid address.
for bad in UNSET "" "192.0.2.169,192.0.2.170" "192.0.2.0/24" "192.0.2.169/32" newt 192.0.2.256 192.0.02.169 0.0.0.0 127.0.0.1 224.0.0.1 ::1; do
  : > "$run_log"
  if out="$(FAKE_PING_RC=0 outcome "$bad" require_tunnel)"; then expect_fail "require_tunnel accepted '$bad' for a tunnel client outside Docker"; fi
  printf '%s' "$out" | grep -q 'refusing to start' || expect_fail "no refusal message for '$bad': $out"
  printf '%s' "$out" | grep -q 'outside Docker' || expect_fail "the refusal for '$bad' does not explain the setting for a tunnel client outside Docker: $out"
  [ ! -s "$run_log" ] || expect_fail "'$bad' reached docker run"
done

# Newt as a Docker container: its address stays the only one that is believed.
: > "$run_log"
out="$(FAKE_NEWT_MODE=bridge FAKE_NEWT_IP=172.17.0.2 FAKE_PING_RC=0 outcome 172.17.0.2 require_tunnel)" || expect_fail "the address of the Docker container was refused: $out"
if out="$(FAKE_NEWT_MODE=bridge FAKE_NEWT_IP=172.17.0.2 FAKE_PING_RC=0 outcome 192.0.2.169 require_tunnel)"; then
  expect_fail "an address that is not the Docker container's was accepted: $out"
fi
printf '%s' "$out" | grep -q 'Newt is at 172.17.0.2' || expect_fail "no mismatch message for a Docker container: $out"
[ ! -s "$run_log" ] || expect_fail "a Docker container address was pinged"

# The Dockerfile.
dockerfile=docker/server.Dockerfile
fail() { echo "check-ferret-test-stack: $1" >&2; exit 1; }
if grep -E '^(FROM|ARG [A-Z_]*IMAGE=)' "$dockerfile" | grep -v '@sha256:[0-9a-f]\{64\}' | grep -vE '^FROM \$\{[A-Z_]+\} AS '; then
  fail "a base image in $dockerfile is not pinned by digest"
fi
grep -q '^ARG FEATURES=""$' "$dockerfile" || fail "ARG FEATURES must default to empty"
# The web vault is built against the published WebAssembly package of web/wasm.lock.json unless the
# build says otherwise (WASM_SOURCE): the one other source a stack can name is tree, and a build that
# gets a revision (a release) refuses that. The ferret-test stack and the stack with real
# data never set it (their compose files have FEATURES as the only build argument, checked above).
if grep -qiE 'WASM_LOCAL|wasm[.]local' "$dockerfile"; then fail "$dockerfile must not offer another WebAssembly package"; fi
grep -qx 'ARG WASM_SOURCE=lock' "$dockerfile" || fail "ARG WASM_SOURCE must default to lock"
# shellcheck disable=SC2016
grep -qF 'FERRET_RELEASE_BUILD=${REVISION:+1}' "$dockerfile" || fail "a build with a revision must be a release build (FERRET_RELEASE_BUILD)"
grep -qF 'a release image (REVISION is set) cannot carry a WebAssembly package built from the tree' "$dockerfile" || fail "the web stage must refuse the tree package when there is a revision"
if grep -rqE 'WASM_SOURCE|FERRET_WASM' docker/compose.ferret-test.yml docker/compose.ferret-home.yml docker/compose.ferret-drill.yml; then
  fail "the ferret-test stack and the stacks with real data never name a WebAssembly source"
fi
# The test stack says which WebAssembly package its web vault was built with (the server's own --build-info).
grep -qF 'wasm_of() {' scripts/lanbox-ferret-test.sh || fail "lanbox-ferret-test.sh must be able to say which WebAssembly package a stack runs"
# shellcheck disable=SC2016
grep -qF 'echo "  wasm   $(wasm_of "$e2e_app")' scripts/lanbox-ferret-test.sh || fail "e2e-up must print which WebAssembly package the stack runs"
# shellcheck disable=SC2016
grep -qF 'echo "wasm: $(wasm_of "$container")"' scripts/lanbox-ferret-test.sh || fail "status must print which WebAssembly package the stack runs"
grep -qx 'COPY --chmod=644 LICENSE THIRD-PARTY-NOTICES /usr/share/doc/ferret/' "$dockerfile" || fail "the image must carry LICENSE and THIRD-PARTY-NOTICES in /usr/share/doc/ferret/"
# shellcheck disable=SC1003
grep -qxF '      lock) node scripts/build.mjs ;; \' "$dockerfile" || fail "the web stage must run node scripts/build.mjs, which checks the lock, for the lock source"
if grep -rIlE 'WASM_LOCAL|wasm[.]local' .github docker; then fail "no workflow or compose file may use a local WebAssembly package"; fi
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
