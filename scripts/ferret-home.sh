#!/usr/bin/env bash
# The Faithful Ferret stack for real data (docker/compose.ferret-home.yml) and its drill
# stack (docker/compose.ferret-drill.yml).
#
#   scripts/ferret-home.sh config
#       Checks the compose file of the stack for real data without a Docker host and
#       prints what it will do: no ports but the two loopback ports, the one trusted
#       proxy, the hardening, the volumes. Reads nothing but the compose file and the
#       example settings files (docker/home.env.example, docker/copy.env.example).
#   scripts/ferret-home.sh up <release tag> --yes-ferret-home [--no-cosign]
#       Starts the stack with the image of a release. Refuses (and starts nothing) unless:
#       the tag is a release tag of this checkout and this checkout is at it; the image
#       of that release exists for this machine's architecture and for arm64; its
#       signature is good (cosign, when it is installed; --no-cosign says so openly);
#       the image's revision label is the commit of the tag; it has no test features;
#       and the compose file passes `config`. The digest of the image is written down
#       (docker/home-image, docker/home-releases.log) and the stack runs by digest.
#       Runs on the host of the stack. Never run it without a yes for that host.
#   scripts/ferret-home.sh status
#       Read-only: containers, published ports, the trusted proxy and the addresses the
#       server has seen, the image digest. Prints no setting and no secret.
#   scripts/ferret-home.sh down --yes-ferret-home
#       Stops and removes the containers; the volumes stay.
#   scripts/ferret-home.sh drill
#       The drill, on the build machine: FERRET_DOCKER_ARGS must name its Docker context
#       (it refuses without it). A throwaway stack (compose project ferret-drill, label
#       owner=ferret-drill) with test data and a test target: an account and an item, a
#       backup, the encrypted copy to the test SFTP target, the checks of the copy there,
#       decryption with the test key, a restore into a fresh instance, signing in again.
#       Then everything it made is removed (also after a failure).
#   scripts/ferret-home.sh drill-clean
#       Removes what a drill that was cut short left behind (by label owner=ferret-drill).
#
# What the machine that runs `up` needs: Docker 28 or newer, docker buildx, compose v2, git with
# the release tags, node, and cosign (or --no-cosign, which is recorded as cosign=SKIPPED). The
# release image package must be public in the registry, or the machine must be logged in to it.
# The safety rules for the proxy and for the path to the backup target are in the header of
# docker/compose.ferret-home.yml; read them before the first start.
#
# No part of this script reads docker/home.env or docker/copy.env (the settings and secrets
# of the stack): only docker compose does, when the stack starts. `config` and `up` check
# the compose file with the example files instead, which have names and no values.
#
# Env overrides:
#   FERRET_DOCKER_ARGS  arguments for docker, for example "--context build-machine" (default: none,
#                       the Docker of this machine)
#   FERRET_IMAGE_REPO   where the release images are (default ghcr.io/ferdinand99/faithful-ferret)
#   FERRET_RELEASE_REPO the GitHub repository the images are signed for (default
#                       Ferdinand99/Faithful-Ferret)
# The style notes about `a && b || c` and `ls` are accepted: every use has been read.
# shellcheck disable=SC2015,SC2012
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

home_compose=docker/compose.ferret-home.yml
drill_compose=docker/compose.ferret-drill.yml
home_project=ferret-home
drill_project=ferret-drill
image_repo="${FERRET_IMAGE_REPO:-ghcr.io/ferdinand99/faithful-ferret}"
release_repo="${FERRET_RELEASE_REPO:-Ferdinand99/Faithful-Ferret}"
home_image_record=docker/home-image
home_releases_log=docker/home-releases.log

# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:-})
dk() { docker "${docker_args[@]}" "$@"; }

say() { printf '\n== %s\n' "$*" >&2; }
refuse() { echo "ferret-home: $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# The check of a rendered compose file (`docker compose config --format json` on
# stdin): $1 is home or drill, $2 is `digest` when the image must be given by digest.
# ----------------------------------------------------------------------------
# shellcheck disable=SC2016
validator='
const mode = process.argv[1];
const wantDigest = process.argv[2] === "digest";
const c = JSON.parse(require("fs").readFileSync(0, "utf8"));
const fail = (m) => { console.error("ferret-home: " + mode + " stack: " + m); process.exit(1); };
const P = mode === "home" ? "ferret-home" : "ferret-drill";
const labelValue = P;
if (c.name !== P) fail("project name must be " + P);
const services = c.services || {};
const want = mode === "home"
  ? [P + "-app", P + "-copy"]
  : [P + "-app", P + "-copy", P + "-decrypt", P + "-keys", P + "-target", P + "-tls"];
if (Object.keys(services).sort().join() !== want.slice().sort().join()) fail("services must be " + want.join(", ") + ", got " + Object.keys(services));
// The address rule of the server (src/http/proxy_guard.rs): a trusted proxy is never the .1 of a Docker pool.
const ip4 = (a) => a.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const refusedByServer = (a) => {
  const o = a.split(".").map(Number);
  if (o[3] !== 1) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168 && o[2] % 16 === 0) return true;
  return false;
};
const inSubnet = (a, cidr) => {
  const [base, bits] = cidr.split("/");
  const mask = bits === "0" ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
  return ((ip4(a) & mask) >>> 0) === ((ip4(base) & mask) >>> 0);
};
const ipv4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

for (const [k, s] of Object.entries(services)) {
  if (s.container_name !== k) fail(k + ": container_name");
  if (s.labels?.owner !== labelValue) fail(k + ": label owner=" + labelValue);
  if (s.privileged) fail(k + ": privileged");
  if (s.pid || s.ipc || s.userns_mode || s.uts || s.cgroup_parent || (s.devices || []).length || (s.volumes_from || []).length) fail(k + ": no shared namespace, device or volumes_from");
  if (!(s.security_opt || []).includes("no-new-privileges:true")) fail(k + ": security_opt needs no-new-privileges:true");
  if (JSON.stringify(s.cap_drop) !== JSON.stringify(["ALL"])) fail(k + ": cap_drop must be [ALL]");
  if (!(Number(s.mem_limit) > 0)) fail(k + ": a memory limit is required");
  if (!(Number(s.pids_limit) > 0 && Number(s.pids_limit) <= 1024)) fail(k + ": a pids_limit (at most 1024) is required");
  if (s.logging?.driver !== "local" || !s.logging?.options?.["max-size"] || !s.logging?.options?.["max-file"]) fail(k + ": logging must be the local driver with max-size and max-file");
  if (s.build && s.pull_policy !== "build") fail(k + ": an image that is built here is never pulled (pull_policy: build)");
  if (s.build && s.build.labels?.owner !== labelValue) fail(k + ": build label owner=" + labelValue);
  // Mounts: named volumes of this stack only. No bind mount, no socket.
  for (const v of s.volumes || []) {
    if (typeof v === "string" || v.type !== "volume") fail(k + ": only named volumes may be mounted, got " + JSON.stringify(v));
    if (!String(v.source).startsWith(P + "-")) fail(k + ": volume " + v.source + " is not of this stack");
  }
  if (JSON.stringify(s).includes("docker.sock")) fail(k + ": the Docker socket");
}

// Published ports: the app, on the loopback address, and nowhere else.
const app = services[P + "-app"];
const ports = app.ports || [];
const wantPorts = mode === "home" ? [3040, 3041] : [13040, 13041];
if (ports.length !== 2) fail("the app publishes exactly two ports, got " + ports.length);
for (const p of ports) {
  if (p.host_ip !== "127.0.0.1") fail("a published port must be on 127.0.0.1, got " + JSON.stringify(p));
  if ((p.protocol || "tcp") !== "tcp") fail("tcp only");
}
const publishedList = ports.map((p) => Number(p.published)).sort((a, b) => a - b);
if (publishedList.join() !== wantPorts.join()) fail("the loopback ports must be " + wantPorts + ", got " + publishedList);
if (ports.map((p) => Number(p.target)).sort((a, b) => a - b).join() !== "3040,3041") fail("the container ports must be 3040 and 3041");
for (const [k, s] of Object.entries(services)) if (k !== P + "-app" && (s.ports || []).length) fail(k + ": publishes a port");

// The network of the stack, with a fixed subnet and a fixed gateway; the one trusted proxy is the gateway.
const nets = c.networks || {};
if (Object.keys(nets).join() !== P + "-net") fail("exactly the network " + P + "-net");
const net = nets[P + "-net"];
if (net.name !== P + "-net" || net.labels?.owner !== labelValue) fail("network name and label");
if (net.external || net.internal) fail("the network is made here and is not internal (a published port needs a routed network)");
const cfg = net.ipam?.config || [];
if (cfg.length !== 1 || !/^\d+\.\d+\.\d+\.\d+\/(2[89]|30)$/.test(cfg[0].subnet || "") || !ipv4.test(cfg[0].gateway || "")) fail("one IPv4 subnet (/28 to /30) with a fixed gateway");
const { subnet, gateway } = cfg[0];
if (!inSubnet(gateway, subnet)) fail("the gateway is not in the subnet");
if (refusedByServer(gateway)) fail("the gateway " + gateway + " is a .1 address of a Docker pool: the server refuses to trust it");
const env = app.environment || {};
if (env.FERRET_TRUSTED_PROXIES !== gateway) fail("FERRET_TRUSTED_PROXIES must be exactly the gateway " + gateway + ", got " + env.FERRET_TRUSTED_PROXIES);
if (env.FERRET_TRUST_PROXY !== "1") fail("FERRET_TRUST_PROXY");
for (const [k, s] of Object.entries(services)) {
  if (k === P + "-tls" || k === P + "-keys" || k === P + "-decrypt") continue;
  const keys = Object.keys(s.networks || {});
  if (keys.join() !== P + "-net") fail(k + ": only the network " + P + "-net");
  const a = s.networks[P + "-net"].ipv4_address;
  if (!a || !ipv4.test(a) || !inSubnet(a, subnet) || a === gateway) fail(k + ": a fixed address in the subnet that is not the gateway");
}
const addrs = Object.entries(services).map(([, s]) => s.networks?.[P + "-net"]?.ipv4_address).filter(Boolean);
if (new Set(addrs).size !== addrs.length) fail("two services share an address");

// The app.
if (app.read_only !== true) fail("the app: read_only");
if ([...(app.cap_add || [])].sort().join() !== "CHOWN,SETGID,SETUID") fail("the app: cap_add must be CHOWN, SETUID, SETGID only");
if (app.restart !== "unless-stopped") fail("the app: restart must be unless-stopped (the restore marker stops a start in the middle of a restore)");
if (app.network_mode) fail("the app: no network_mode");
if (app.build) fail("the app is never built here: it is a release image");
const image = String(app.image || "");
if (wantDigest && !/^[a-z0-9./-]+@sha256:[0-9a-f]{64}$/.test(image)) fail("the app image must be given by digest, got " + image);
for (const k of Object.keys(env)) if (/E2E|CLOCK|TEST|DEV_/i.test(k)) fail("no test variable allowed in the app: " + k);
if (env.FERRET_DATA_DIR !== "/data" || env.FERRET_BACKUP_DIR !== "/backups") fail("the app: FERRET_DATA_DIR=/data and FERRET_BACKUP_DIR=/backups");
const mounts = (s) => (s.volumes || []).map((v) => v.source + ":" + v.target + (v.read_only ? ":ro" : "")).sort().join();
if (mounts(app) !== [P + "-backups:/backups", P + "-data:/data"].sort().join()) fail("the app mounts its data and its backups, rw, and nothing else: " + mounts(app));

// The copy container: the backups read-only, no key of the server, no private age key.
const copy = services[P + "-copy"];
if (copy.read_only !== true) fail("the copy container: read_only");
if ((copy.cap_add || []).length) fail("the copy container needs no capability");
if (String(copy.user) !== "1000:1000") fail("the copy container runs as 1000:1000");
if (copy.network_mode) fail("the copy container: no network_mode");
const cm = (copy.volumes || []).map((v) => ({ source: v.source, target: v.target, ro: v.read_only === true }));
const backupsMount = cm.find((v) => v.source === P + "-backups");
if (!backupsMount || backupsMount.target !== "/backups" || !backupsMount.ro) fail("the copy container mounts the backups read-only on /backups");
if (cm.some((v) => v.source === P + "-data")) fail("the copy container never mounts the data");
if (mode === "home" && cm.length !== 1) fail("the copy container mounts the backups and nothing else");
if (mode === "drill" && cm.some((v) => v.source === P + "-age")) fail("the copy container never mounts the private age key");
if (mode === "drill" && cm.some((v) => !v.ro)) fail("the copy container mounts nothing read-write");
const cenv = copy.environment || {};
for (const [k, v] of Object.entries(cenv)) {
  if (/AGE-SECRET-KEY/.test(String(v))) fail("an age secret key in the environment of the copy container");
  if (/IDENTITY|SECRET_KEY|PRIVATE/i.test(k)) fail("the copy container has no private key setting: " + k);
}
if (!/^\/(run\/secrets|client)\//.test(String(cenv.FERRET_COPY_SFTP_KEY_FILE || ""))) fail("the SSH key of the copy container is a file");
const target = String(cenv.FERRET_COPY_SFTP_DIR || "");
if (/^(\/|\.\.)/.test(target) && target !== "") fail("the target folder is a plain relative folder");
if (mode === "home") {
  if (copy.restart !== "unless-stopped") fail("the copy container: restart unless-stopped");
  if (Object.keys(c.secrets || {}).join() !== "copy_sftp_key") fail("the one secret is copy_sftp_key");
  if ((copy.secrets || []).map((x) => x.source).join() !== "copy_sftp_key") fail("the copy container gets the SSH key as a secret file");
}

// Volumes: all named, all of this stack and labelled.
const volumes = Object.entries(c.volumes || {});
const wantVolumes = mode === "home"
  ? [P + "-backups", P + "-data"]
  : [P + "-age", P + "-backups", P + "-client", P + "-data", P + "-host", P + "-restore-in", P + "-target"];
if (volumes.map(([k]) => k).sort().join() !== wantVolumes.join()) fail("volumes must be " + wantVolumes.join(", "));
for (const [k, v] of volumes) if (v.name !== k || v.labels?.owner !== labelValue) fail("volume " + k + " needs its name and the label owner=" + labelValue);
for (const [k, v] of volumes) if ((v.driver && v.driver !== "local") || v.driver_opts) fail("volume " + k + ": a plain local volume (no network file system, no driver options)");

// The drill only: the proxy stand-in is the one service on the host network, and nothing else is.
if (mode === "drill") {
  const tls = services[P + "-tls"];
  if (tls.network_mode !== "host") fail("the proxy stand-in runs on the host network, like the proxy of the host");
  if (!/^caddy:[0-9.]+-alpine@sha256:[0-9a-f]{64}$/.test(tls.image)) fail("the proxy stand-in is pinned by digest");
  if ((tls.cap_add || []).join() !== "NET_BIND_SERVICE" || tls.read_only !== true) fail("the proxy stand-in: NET_BIND_SERVICE only (its binary needs it to start), read-only");
  if (!/bind 127\.0\.0\.1/.test(tls.environment?.CADDYFILE || "") || /bind 0\.0\.0\.0/.test(tls.environment?.CADDYFILE || "")) fail("the proxy stand-in listens on 127.0.0.1 only");
  for (const [k, s] of Object.entries(services)) if (k !== P + "-tls" && s.network_mode && s.network_mode !== "none") fail(k + ": only the proxy stand-in is on the host network");
  for (const k of [P + "-keys", P + "-decrypt"]) if (services[k].network_mode !== "none") fail(k + ": no network");
  const age = (k) => (services[k].volumes || []).some((v) => v.source === P + "-age");
  for (const k of Object.keys(services)) if (age(k) !== (k === P + "-keys" || k === P + "-decrypt")) fail("the private age key volume is mounted by the keys and decrypt services only (" + k + ")");
  if (JSON.stringify(c).includes("ferret-home") || JSON.stringify(c).includes("ferret-test") || JSON.stringify(c).includes("ferret-e2e")) fail("the drill shares no name with another stack");
}
console.log("ok: " + mode + " stack, loopback ports " + publishedList.join(" and ") + ", trusted proxy " + gateway + " (the gateway of " + subnet + ")");
'

# The compose file, rendered with the example settings files (names, no values) and a made-up
# image digest, as JSON on stdout. Reads no real settings file.
render() { # home | drill
  local file=$home_compose
  [ "$1" = drill ] && file=$drill_compose
  FERRET_IMAGE="${FERRET_IMAGE:-example.invalid/ferret@sha256:0000000000000000000000000000000000000000000000000000000000000000}" \
    FERRET_DRILL_SETUP_TOKEN=check \
    FERRET_HOME_ENV=home.env.example FERRET_COPY_ENV=copy.env.example \
    docker compose --profile '*' -f "$file" config --format json
}

verify_config() { # home | drill, digest?
  render "$1" | node -e "$validator" "$1" "${2:-}"
}

# ----------------------------------------------------------------------------
# up, status, down
# ----------------------------------------------------------------------------

record_image() { # prints the recorded image reference, or nothing
  [ -s "$home_image_record" ] && sed -n 's/^FERRET_IMAGE=//p' "$home_image_record" | head -n 1 || true
}

dch() { # docker compose of the stack for real data
  FERRET_IMAGE="${FERRET_IMAGE:-$(record_image)}" dk compose -p "$home_project" -f "$home_compose" "$@"
}

engine_arch() {
  case "$(dk info --format '{{.Architecture}}')" in
    aarch64 | arm64) echo arm64 ;;
    x86_64 | amd64) echo amd64 ;;
    *) echo unknown ;;
  esac
}

# The manifest of the release image must list the platform of this machine and arm64.
check_platforms() { # image reference
  local arch raw
  arch="$(engine_arch)"
  raw="$(dk buildx imagetools inspect --raw "$1")" || refuse "cannot read the manifest of $1"
  printf '%s' "$raw" | node -e '
const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
const have = (m.manifests || []).filter((x) => x.platform && x.platform.os === "linux").map((x) => x.platform.architecture);
const need = new Set(["arm64", process.argv[1]]);
const missing = [...need].filter((a) => !have.includes(a));
if (missing.length) { console.error("ferret-home: the image has no linux/" + missing.join(", linux/") + " (it has " + (have.join(", ") || "no platforms") + ")"); process.exit(1); }
' "$arch" || exit 1
}

# What `up` needs on the machine that starts the stack, checked before anything is pulled.
preflight() {
  local tool major server
  for tool in git node; do
    command -v "$tool" > /dev/null || refuse "$tool is not installed here (up needs git with the release tags, node, docker buildx and cosign)"
  done
  dk buildx version > /dev/null 2>&1 || refuse "docker buildx is not installed here (it reads the manifest of the image)"
  server="$(dk version --format '{{.Server.Version}}' 2> /dev/null || true)"
  major="${server%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || refuse "cannot read the version of the Docker engine"
  [ "$major" -ge 28 ] || refuse "Docker 28 or newer is required (older engines can let a neighbour on the network reach ports published on 127.0.0.1); this one is $server"
}

up() {
  local tag="" yes=0 cosign_mode=verify arg
  for arg in "$@"; do
    case "$arg" in
      --yes-ferret-home) yes=1 ;;
      --no-cosign) cosign_mode=skip ;;
      -*) refuse "unknown option $arg" ;;
      *) [ -z "$tag" ] || refuse "one release tag only"; tag="$arg" ;;
    esac
  done
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || refuse "usage: up vX.Y.Z --yes-ferret-home (a release tag; a branch or a commit is never started)"
  [ "$yes" = 1 ] || refuse "this starts the stack for real data on this machine; run it again with --yes-ferret-home after an explicit yes"
  local version="${tag#v}" tag_commit head_commit
  preflight

  tag_commit="$(git rev-parse --verify -q "refs/tags/${tag}^{commit}")" || refuse "$tag is not a tag of this checkout (fetch the tags)"
  head_commit="$(git rev-parse HEAD)"
  [ "$tag_commit" = "$head_commit" ] || refuse "this checkout is not at $tag (HEAD is ${head_commit:0:12}, the tag is ${tag_commit:0:12}); check the tag out first: a branch build is never started"
  if [ -n "$(git status --porcelain --untracked-files=no -- docker scripts)" ]; then
    refuse "docker/ or scripts/ differ from $tag: the files that start the stack must be the released ones"
  fi

  say "the compose file"
  verify_config home

  say "the image of $tag"
  local ref="$image_repo:$version" digest_ref arch
  arch="$(engine_arch)"
  [ "$arch" != unknown ] || refuse "cannot tell the architecture of this machine"
  dk pull -q "$ref" > /dev/null
  digest_ref="$(dk image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep -E "^${image_repo//./\\.}@sha256:[0-9a-f]{64}$" | head -n 1 || true)"
  [ -n "$digest_ref" ] || refuse "the pulled image has no digest of $image_repo"
  # The platforms are read from the digest that is started, not from the tag.
  check_platforms "$digest_ref"
  local cosign_state=verified
  if [ "$cosign_mode" = verify ]; then
    command -v cosign > /dev/null || refuse "cosign is not installed here, so the signature of the image cannot be checked; install it, or say so openly with --no-cosign"
    cosign verify "$digest_ref" \
      --certificate-identity-regexp "^https://github.com/${release_repo}/\\.github/workflows/release\\.yml@refs/(heads/main|tags/v[0-9]+\\.[0-9]+\\.[0-9]+)$" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null \
      || refuse "the signature of the image is not good"
  else
    cosign_state=SKIPPED
    echo "ferret-home: WARNING: the signature of the image was NOT checked (--no-cosign). The revision," >&2
    echo "ferret-home: version and feature checks below read labels of a tag that anyone with write" >&2
    echo "ferret-home: access to the registry can move; this start is recorded as cosign=SKIPPED." >&2
  fi
  local revision built_version info
  revision="$(dk image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$digest_ref")"
  built_version="$(dk image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$digest_ref")"
  [ "$revision" = "$tag_commit" ] || refuse "the revision of the image (${revision:-none}) is not the commit of $tag ($tag_commit): not a release image of this tag"
  [ "$built_version" = "$version" ] || refuse "the version of the image (${built_version:-none}) is not $version"
  info="$(dk run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --entrypoint /usr/local/bin/ferret "$digest_ref" --build-info)"
  printf '%s\n' "$info" | grep -qx "ferret $version" || refuse "the image says it is not version $version"
  printf '%s\n' "$info" | grep -qx 'features: none' || refuse "the image has cargo features ($(printf '%s' "$info" | sed -n 's/^features: //p')); a stack with real data runs a release build"

  say "writing the digest down"
  FERRET_IMAGE="$digest_ref" verify_config home digest
  printf 'FERRET_IMAGE=%s\n# cosign=%s\n' "$digest_ref" "$cosign_state" > "$home_image_record"
  echo "image: $digest_ref (cosign=$cosign_state)"

  say "starting"
  # The copy container is built here, from pinned parts (docker/backup-copy.Dockerfile). Its image ID
  # and the versions of its packages are written down next to the release.
  FERRET_IMAGE="$digest_ref" dch build ferret-home-copy
  local copy_id copy_pkgs
  copy_id="$(dk image inspect --format '{{.Id}}' ferret-home-copy:latest)"
  copy_pkgs="$(dk run --rm --network none --read-only --cap-drop ALL --entrypoint apk ferret-home-copy:latest info -v age openssh-client curl | tr '\n' ' ')"
  printf '%s %s %s %s cosign=%s copy-image=%s packages: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$tag" "$tag_commit" "$digest_ref" "$cosign_state" "$copy_id" "$copy_pkgs" >> "$home_releases_log"
  FERRET_IMAGE="$digest_ref" dch up -d
  status
}

status() {
  local app=ferret-home-app copy=ferret-home-copy
  dk ps -a --filter "label=owner=ferret-home" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
  echo "image recorded: $(record_image)"
  echo "image running:  $(dk inspect --format '{{.Config.Image}}' "$app" 2>/dev/null || echo none)"
  echo "published ports: $(dk port "$app" 2>/dev/null | tr '\n' ' ')"
  echo "network gateway: $(dk network inspect --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' ferret-home-net 2>/dev/null || echo none)"
  echo "trusted proxy:   $(dk inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$app" 2>/dev/null | sed -n 's/^FERRET_TRUSTED_PROXIES=//p')"
  echo "copy container mounts: $(dk inspect --format '{{range .Mounts}}{{.Name}}:{{.Destination}}:{{if .RW}}rw{{else}}ro{{end}} {{end}}' "$copy" 2>/dev/null || echo none)"
  echo "peer addresses the server has seen:"
  dk logs "$app" 2>&1 | grep -i 'new peer address' | sed 's/\x1b\[[0-9;]*m//g' | tail -n 10 || echo "  none yet"
}

down() {
  local arg yes=0
  for arg in "$@"; do [ "$arg" = --yes-ferret-home ] && yes=1; done
  [ "$yes" = 1 ] || refuse "this stops the stack for real data on this machine; run it again with --yes-ferret-home after an explicit yes"
  dch down
}

# ----------------------------------------------------------------------------
# The drill
# ----------------------------------------------------------------------------

dcd() { dk compose -p "$drill_project" -f "$drill_compose" "$@"; }

drill_label=owner=ferret-drill
drill_failures=0
# The JSON a browser phase left, by name (the runner prints the name, the JSON, an empty line).
drill_left() { printf '%s\n' "$1" | awk -v n="$2" '$0 == n { getline; print; exit }'; }
drill_ok() { printf '  ok    %s\n' "$*" >&2; }
drill_bad() { printf '  FAIL  %s\n' "$*" >&2; drill_failures=$((drill_failures + 1)); }
drill_check() { # label, wanted, got
  if [ "$2" = "$3" ]; then drill_ok "$1"; else drill_bad "$1 (wanted $2, got $3)"; fi
}

# Removes everything with the drill's label: containers, volumes, networks, images.
drill_remove() {
  local id name
  dcd --profile tools down -v --remove-orphans > /dev/null 2>&1 || true
  for id in $(dk ps -aq --filter "label=$drill_label"); do dk rm -f "$id" > /dev/null; done
  for name in $(dk network ls -q --filter "label=$drill_label"); do dk network rm "$name" > /dev/null; done
  for name in $(dk volume ls -q --filter "label=$drill_label"); do dk volume rm "$name" > /dev/null; done
  for id in $(dk images -q --filter "label=$drill_label"); do dk image rm "$id" > /dev/null 2>&1 || true; done
  dk image rm ferret-drill-app:local ferret-drill-copy:latest ferret-drill-target:latest > /dev/null 2>&1 || true
}

drill() {
  [ -n "${FERRET_DOCKER_ARGS:-}" ] || refuse "the drill runs on the build machine: set FERRET_DOCKER_ARGS to its Docker context (for example \"--context build-machine\")"
  case "${FERRET_DOCKER_ARGS}" in *desktop*) refuse "never Docker Desktop" ;; esac
  # The helpers of the end-to-end runner (they only define functions when sourced).
  # shellcheck source=scripts/lanbox-ferret-test.sh
  . scripts/lanbox-ferret-test.sh
  # The test script sets its own default arguments; ours were given.
  # shellcheck disable=SC2206
  docker_args=(${FERRET_DOCKER_ARGS})

  [ -z "$(dk ps -aq --filter "label=owner=ferret-home")" ] || refuse "this Docker host runs the stack for real data: the drill runs on the build machine only"
  if [ -n "$(dk ps -aq --filter "label=$drill_label")" ] || [ -n "$(dk volume ls -q --filter "label=$drill_label")" ]; then
    refuse "a drill stack is still there (label $drill_label): run drill-clean first"
  fi

  say "the compose file of the drill"
  verify_config drill
  verify_config home

  trap 'drill_remove' EXIT
  FERRET_DRILL_SETUP_TOKEN="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  export FERRET_DRILL_SETUP_TOKEN
  local revision
  revision="$(git rev-parse HEAD)"

  say "ports free on the build machine"
  local listeners
  listeners="$(dk run --rm --network host --label "$drill_label" --name ferret-drill-portcheck "$alpine_image" netstat -ltn)"
  for p in 13040 13041 18443; do
    if printf '%s\n' "$listeners" | grep -qE "[:.]${p}[[:space:]]"; then refuse "port $p is in use on the build machine"; fi
  done

  say "building the images (the server without cargo features, the copy container, the test target)"
  dk build --label "$drill_label" -t ferret-drill-app:local \
    --build-arg VERSION=drill --build-arg REVISION="$revision" \
    -f docker/server.Dockerfile . >&2
  export FERRET_IMAGE=ferret-drill-app:local
  dcd build ferret-drill-copy ferret-drill-target >&2
  # The info of the build, for the record.
  drill_check "the image has no test features" "features: none" "$(dk run --rm --network none --label "$drill_label" --entrypoint /usr/local/bin/ferret ferret-drill-app:local --build-info | sed -n 's/^\(features: .*\)$/\1/p')"

  say "test keys and the stack"
  dcd run -T --rm ferret-drill-keys >&2
  dcd up -d --wait ferret-drill-app ferret-drill-target ferret-drill-tls >&2
  drill_check "the app is published on the loopback address only" \
    "127.0.0.1:13040 127.0.0.1:13041" \
    "$(dk port ferret-drill-app | sed 's#^[0-9]*/tcp -> ##' | sort | tr '\n' ' ' | sed 's/ $//')"
  drill_check "the proxy stand-in is on the host network and publishes nothing" "host" "$(dk inspect --format '{{.HostConfig.NetworkMode}}' ferret-drill-tls)"

  say "an account and an item (browser, through the proxy stand-in)"
  local ca vault admin state out
  ca="$(dk exec ferret-drill-tls cat /data/caddy/pki/authorities/local/root.crt)"
  vault=https://vault-drill.test:18443
  admin=https://admin-drill.test:18443
  drill_browser() { # phase, spec result name
    local phase="$1" rc=0
    out="$(FERRET_E2E_PHASE="$phase" FERRET_E2E_STATE="${state:-}" PW_NETWORK=host PW_NAME=ferret-drill-playwright PW_LABEL="$drill_label" \
      PW_VAULT_URL="$vault" PW_ADMIN_URL="$admin" PW_EVIL_URL="" PW_TOKEN="$FERRET_DRILL_SETUP_TOKEN" PW_CA_PEM="$ca" \
      PW_HOSTS="vault-drill.test=127.0.0.1 admin-drill.test=127.0.0.1" \
      playwright_run --project=chromium phase-drill.spec.mjs)" || rc=$?
    return "$rc"
  }
  if drill_browser drill-first; then drill_ok "an account and an item were made"; else drill_bad "the first browser phase failed"; fi
  state="$(drill_left "$out" state)"
  [ -n "$state" ] || { drill_bad "the first phase left no state"; return 1; }

  say "a backup (the server is stopped first: the command takes the data lock)"
  dcd stop ferret-drill-app >&2
  dcd run -T --rm --no-deps ferret-drill-app backup create >&2
  local list set
  list="$(dcd run -T --rm --no-deps ferret-drill-app backup list)"
  set="$(printf '%s\n' "$list" | grep -oE '[0-9]{8}T[0-9]{6}Z(-[0-9]+)?' | head -n 1)"
  [ -n "$set" ] || { drill_bad "no backup set was made"; return 1; }
  drill_ok "backup set $set"

  say "the copy to the test target"
  local host_key rc=0
  host_key="$(dk run --rm --network none --label "$drill_label" -v ferret-drill-host:/h:ro --entrypoint cat ferret-drill-copy:latest /h/ssh_host_ed25519_key.pub | cut -d' ' -f1,2)"
  # A host key that is not the target's must stop the copy: the target is never trusted on first use.
  if dcd run -T --rm -e FERRET_COPY_SFTP_HOST_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ferret-drill-copy once >&2; then
    drill_bad "a wrong host key was accepted"
  else
    drill_ok "a wrong host key stops the copy"
  fi
  dcd run -T --rm -e FERRET_COPY_SFTP_HOST_KEY="$host_key" ferret-drill-copy once >&2 || rc=$?
  drill_check "the copy ran" 0 "$rc"
  rc=0
  dcd run -T --rm -e FERRET_COPY_SFTP_HOST_KEY="$host_key" ferret-drill-copy once 2>&1 | grep -q 'nothing new to copy' || rc=$?
  drill_check "a second run finds nothing new" 0 "$rc"

  say "the target holds an age file and its SHA-256, and nothing in plain text"
  drill_check "the target holds exactly the folder, the .tar.age and the .sha256" \
    "./ferret|./ferret/$set.tar.age|./ferret/$set.tar.age.sha256" \
    "$(dcd run -T --rm ferret-drill-decrypt 'cd /target && find . -mindepth 1 | sort' | tr -d '\r' | tr '\n' '|' | sed 's/|$//')"
  drill_check "the SHA-256 on the target is the one of the file" "$set.tar.age: OK" \
    "$(dcd run -T --rm ferret-drill-decrypt "cd /target/ferret && sha256sum -c $set.tar.age.sha256" | tr -d '\r')"
  drill_check "the file on the target is an age file" "age-encryption.org/v1" \
    "$(dcd run -T --rm ferret-drill-decrypt "head -c 21 /target/ferret/$set.tar.age" | tr -d '\r')"
  drill_check "the set's database is not readable in the copy" "0" \
    "$(dcd run -T --rm ferret-drill-decrypt "grep -c 'SQLite format' /target/ferret/$set.tar.age || true" | tr -d '\r')"

  say "decryption: the test key opens it, another key does not"
  if dcd run -T --rm ferret-drill-decrypt "age-keygen -o /tmp/other.txt 2>/dev/null; age -d -i /tmp/other.txt /target/ferret/$set.tar.age > /dev/null" > /dev/null 2>&1; then
    drill_bad "another age key opened the copy"
  else
    drill_ok "another age key does not open the copy"
  fi
  dcd run -T --rm ferret-drill-decrypt "age -d -i /age/key.txt /target/ferret/$set.tar.age | tar -x -C /restore-in" >&2 || drill_bad "the test key did not open the copy"
  drill_check "the decrypted set has its manifest" "MANIFEST.json" \
    "$(dcd run -T --rm ferret-drill-decrypt "ls /restore-in/$set | grep -x MANIFEST.json" | tr -d '\r')"

  say "wiping, a fresh instance, the restore"
  dcd rm -sf ferret-drill-app >&2
  dk volume rm ferret-drill-data ferret-drill-backups > /dev/null
  dcd run -T --rm --no-deps -v ferret-drill-restore-in:/restore-in:ro ferret-drill-app backup restore --from "/restore-in/$set" --yes >&2 \
    && drill_ok "ferret backup restore from the decrypted copy" || drill_bad "the restore failed"
  dcd up -d --wait ferret-drill-app ferret-drill-tls >&2

  say "opening the restored instance (browser, new context, same account)"
  if drill_browser drill-restored; then drill_ok "signed in on the restored instance; the item is there; the restore epoch is higher"; else drill_bad "the restored instance did not open as it should"; fi
  [ -n "$(drill_left "$out" restored)" ] || drill_bad "the second phase left no marker"

  say "what the server saw"
  local peers
  peers="$(dk logs ferret-drill-app 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'new peer address' || true)"
  printf '%s\n' "$peers" >&2
  if printf '%s\n' "$peers" | grep -q 'peer=172.30.252.14 trusted=true'; then
    drill_ok "the proxy on the host was seen as the gateway 172.30.252.14 and believed"
  else
    drill_bad "the server did not log the gateway as a trusted peer"
  fi
  if printf '%s\n' "$peers" | grep -E 'trusted=true' | grep -vq 'peer=172.30.252.14'; then drill_bad "a peer other than the gateway was believed"; fi

  say "removing the drill stack"
  drill_remove
  trap - EXIT
  if [ -n "$(dk ps -aq --filter "label=$drill_label")" ] || [ -n "$(dk volume ls -q --filter "label=$drill_label")" ] || [ -n "$(dk network ls -q --filter "label=$drill_label")" ]; then
    drill_bad "something with the label $drill_label is left"
  else
    drill_ok "no container, volume or network of the drill is left"
  fi
  if [ "$drill_failures" -gt 0 ]; then
    echo "ferret-home: the drill had $drill_failures failure(s)" >&2
    return 1
  fi
  echo "ferret-home: the drill passed" >&2
}

main() {
  case "${1:-}" in
    config)
      verify_config home
      verify_config drill
      ;;
    verify-json)
      # For the check script: a rendered compose file on stdin.
      node -e "$validator" "${2:?home or drill}" "${3:-}"
      ;;
    up) shift; up "$@" ;;
    status) status ;;
    down) shift; down "$@" ;;
    drill) drill ;;
    drill-clean)
      [ -n "${FERRET_DOCKER_ARGS:-}" ] || refuse "set FERRET_DOCKER_ARGS to the Docker context of the build machine"
      drill_remove
      echo "drill-clean: done"
      ;;
    *)
      sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
      exit 2
      ;;
  esac
}

# Run only when executed, not when sourced (scripts/check-ferret-home-stack.sh).
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
