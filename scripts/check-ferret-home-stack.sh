#!/usr/bin/env bash
# Checks the stack for real data (docker/compose.ferret-home.yml), its drill stack
# (docker/compose.ferret-drill.yml), the copy container (docker/backup-copy.sh and
# docker/backup-copy.Dockerfile) and scripts/ferret-home.sh, without a Docker host:
# `docker compose config` only reads the files, and everything else runs against
# stand-ins for docker, cosign, sftp, age and curl that record what they are asked.
# Nothing is sent anywhere.
#
#   scripts/check-ferret-home-stack.sh          everything
#   scripts/check-ferret-home-stack.sh copy     only the tests of the copy script (Linux, not root)
#
# Each check is named for what it guarantees:
#   app_publishes_only_on_loopback
#   trusted_proxy_is_exactly_the_network_gateway
#   copy_target_is_sftp_with_a_key_and_never_nfs
#   image_exists_for_arm64
#   base_images_are_pinned_by_digest
#   the_image_has_no_test_features_and_its_revision_is_the_release_tag
#   up_refuses_a_branch_build
#   up_needs_cosign_3_to_check_the_signature
#   the_app_has_open_files_for_its_event_streams
#   the_copy_container_mounts_the_backups_read_only_and_has_no_private_key
#   the_copy_container_is_never_on_the_app_network
#   peer_log_is_off_by_default
#   copies_on_the_target_are_age_files_never_plain_sets
#   drill_stack_has_its_own_volumes_and_label
#   home_env_is_never_read_by_the_script
# The checks set variables in subshells on purpose; the style notes about `ls` and `a && b || c` are accepted.
# shellcheck disable=SC2030,SC2031,SC2015,SC2012,SC2010
set -euo pipefail
cd "$(dirname "$0")/.."

home_compose=docker/compose.ferret-home.yml
drill_compose=docker/compose.ferret-drill.yml
tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
real_docker="$(command -v docker || true)"

fail() { echo "check-ferret-home-stack: $*" >&2; exit 1; }
pass() { echo "  ok  $1"; }
skip() { echo "  skipped  $1 ($2)"; }

# ---------------------------------------------------------------- the rendered files
# shellcheck source=scripts/ferret-home.sh
. scripts/ferret-home.sh
docker_args=()
home_json=""
drill_json=""
if [ -n "$real_docker" ]; then
  home_json="$(render home)"
  drill_json="$(render drill)"
fi

# A rendered file with one change made to it (a JavaScript statement on `c`), checked by the
# script's own validator: it must refuse, and the refusal must name $4 (an ERE).
refused() { # home|drill, name, change, wanted message
  local json="$home_json" out
  [ "$1" = drill ] && json="$drill_json"
  out="$(printf '%s' "$json" | node -e 'const c = JSON.parse(require("fs").readFileSync(0, "utf8")); '"$3"'; console.log(JSON.stringify(c));' \
    | scripts/ferret-home.sh verify-json "$1" 2>&1 >/dev/null)" && fail "$2: the validator accepted it"
  printf '%s' "$out" | grep -Eq "$4" || fail "$2: refused for another reason: $out"
}
accepted() { # home|drill, name, change
  local json="$home_json"
  [ "$1" = drill ] && json="$drill_json"
  printf '%s' "$json" | node -e 'const c = JSON.parse(require("fs").readFileSync(0, "utf8")); '"$3"'; console.log(JSON.stringify(c));' \
    | scripts/ferret-home.sh verify-json "$1" > /dev/null || fail "$2: the validator refused a good file"
}

app='c.services["ferret-home-app"]'
copy='c.services["ferret-home-copy"]'

app_publishes_only_on_loopback() {
  printf '%s' "$home_json" | scripts/ferret-home.sh verify-json home > /dev/null || fail "the stack for real data does not pass its own check"
  # The two ports, on 127.0.0.1, and nothing else.
  node -e '
const c = JSON.parse(process.argv[1]);
const app = c.services["ferret-home-app"];
const list = app.ports.map((p) => p.host_ip + ":" + p.published + ">" + p.target).sort().join(" ");
if (list !== "127.0.0.1:3040>3040 127.0.0.1:3041>3041") { console.error("ports: " + list); process.exit(1); }
for (const [k, s] of Object.entries(c.services)) {
  if (k !== "ferret-home-app" && (s.ports || []).length) { console.error(k + " publishes a port"); process.exit(1); }
  if (s.network_mode) { console.error(k + " has network_mode"); process.exit(1); }
}' "$home_json" || fail "the app must publish 3040 and 3041 on 127.0.0.1 and nothing else"
  refused home "all interfaces" "${app}.ports[0].host_ip = '0.0.0.0'" "127.0.0.1"
  refused home "an address of the LAN" "${app}.ports[1].host_ip = '192.0.2.10'" "127.0.0.1"
  refused home "no host address" "delete ${app}.ports[0].host_ip" "127.0.0.1"
  refused home "a third port" "${app}.ports.push({ mode: 'ingress', host_ip: '127.0.0.1', target: 9999, published: '9999', protocol: 'tcp' })" "exactly two ports"
  refused home "a port on the copy container" "${copy}.ports = [{ mode: 'ingress', host_ip: '127.0.0.1', target: 22, published: '22', protocol: 'tcp' }]" "publishes a port"
  refused home "udp" "${app}.ports[0].protocol = 'udp'" "tcp"
  refused home "another host port" "${app}.ports[0].published = '8080'" "loopback ports"
  refused home "the host network" "${app}.network_mode = 'host'" "network_mode"
  # The drill publishes on the loopback address too (other ports).
  refused drill "drill on all interfaces" 'c.services["ferret-drill-app"].ports[0].host_ip = "0.0.0.0"' "127.0.0.1"
  pass app_publishes_only_on_loopback
}

trusted_proxy_is_exactly_the_network_gateway() {
  node -e '
const c = JSON.parse(process.argv[1]);
const gw = c.networks["ferret-home-net"].ipam.config[0].gateway;
const trusted = c.services["ferret-home-app"].environment.FERRET_TRUSTED_PROXIES;
if (trusted !== gw) { console.error(trusted + " is not " + gw); process.exit(1); }
if (/[,/]/.test(trusted)) { console.error("a list or a network"); process.exit(1); }
if (c.networks["ferret-home-net"].ipam.config[0].subnet !== "172.30.251.0/28") { console.error("the subnet is fixed"); process.exit(1); }' "$home_json" \
    || fail "FERRET_TRUSTED_PROXIES must be the gateway of ferret-home-net, one address"
  refused home "another trusted address" "${app}.environment.FERRET_TRUSTED_PROXIES = '172.30.251.3'" "exactly the gateway"
  refused home "a list" "${app}.environment.FERRET_TRUSTED_PROXIES = '172.30.251.14,172.30.251.3'" "exactly the gateway"
  refused home "a network" "${app}.environment.FERRET_TRUSTED_PROXIES = '172.30.251.0/28'" "exactly the gateway"
  refused home "no trusted address" "delete ${app}.environment.FERRET_TRUSTED_PROXIES" "exactly the gateway"
  refused home "the gateway moved" "c.networks['ferret-home-net'].ipam.config[0].gateway = '172.30.251.13'" "exactly the gateway"
  # The server refuses a .1 address of a Docker pool as a trusted proxy (src/http/proxy_guard.rs).
  refused home "a .1 gateway" "c.networks['ferret-home-net'].ipam.config[0].gateway = '172.30.251.1'; ${app}.environment.FERRET_TRUSTED_PROXIES = '172.30.251.1'" "refuses to trust it"
  refused home "a gateway outside the subnet" "c.networks['ferret-home-net'].ipam.config[0].gateway = '172.30.9.14'; ${app}.environment.FERRET_TRUSTED_PROXIES = '172.30.9.14'" "not in the subnet"
  refused home "a network without a gateway" "delete c.networks['ferret-home-net'].ipam.config[0].gateway" "fixed gateway"
  refused home "a trusted forwarding switch off" "${app}.environment.FERRET_TRUST_PROXY = '0'" "FERRET_TRUST_PROXY"
  refused home "the app on the wrong network" "${app}.networks = { other: { ipv4_address: '172.30.251.2' } }" "only the network"
  refused home "the app without a fixed address" "delete ${app}.networks['ferret-home-net'].ipv4_address" "fixed address"
  refused home "the app on the gateway address" "${app}.networks['ferret-home-net'].ipv4_address = '172.30.251.14'" "fixed address"
  # The same rule for the drill.
  refused drill "drill trusting another address" 'c.services["ferret-drill-app"].environment.FERRET_TRUSTED_PROXIES = "172.30.252.3"' "exactly the gateway"
  # The safety rules for the proxy and the path to the backup target are written where the operator reads.
  grep -q 'Never add a raw TCP/UDP resource' "$home_compose" || fail "the compose header must forbid a raw TCP/UDP resource for the loopback ports"
  grep -q 'never expose the target.s main sshd' "$home_compose" || fail "the compose header must say that the target's main sshd is never exposed"
  grep -q 'forged X-Forwarded-For' "$home_compose" || fail "the compose header must describe the forged X-Forwarded-For check"
  grep -q 'ssh-keyscan' docker/copy.env.example || fail "docker/copy.env.example must say how to read the host key"
  pass trusted_proxy_is_exactly_the_network_gateway
}

copy_target_is_sftp_with_a_key_and_never_nfs() {
  # No network file system anywhere in the files of the stack, its copy container or its settings.
  if grep -niE '\bnfs\b|type: *nfs|driver_opts|sshfs|cifs|\bsmb\b' "$home_compose" "$drill_compose" docker/backup-copy.sh docker/backup-copy.Dockerfile docker/home.env.example docker/copy.env.example \
    | grep -v '^[^:]*:[0-9]*: *#' > "$tmp/nfs.txt"; then
    cat "$tmp/nfs.txt" >&2
    fail "a network file system is named in the files of the stack"
  fi
  # The copy is SFTP with a key: the settings are the SFTP ones and there is no password setting.
  for name in FERRET_COPY_SFTP_HOST FERRET_COPY_SFTP_PORT FERRET_COPY_SFTP_USER FERRET_COPY_SFTP_HOST_KEY FERRET_COPY_SFTP_DIR FERRET_BACKUP_AGE_RECIPIENT; do
    grep -q "^$name=\$" docker/copy.env.example || fail "docker/copy.env.example must list $name with no value"
  done
  if grep -niE 'password|passwd' docker/copy.env.example docker/backup-copy.sh | grep -v '^[^:]*:[0-9]*: *#'; then
    fail "the copy container has no password setting"
  fi
  if grep -nE 'sshpass|PasswordAuthentication=yes|PreferredAuthentications=[a-z,]*password' docker/backup-copy.sh; then
    fail "the copy container never logs in with a password"
  fi
  grep -q 'BatchMode=yes' docker/backup-copy.sh || fail "the copy script must run ssh in batch mode"
  grep -q 'PreferredAuthentications=publickey' docker/backup-copy.sh || fail "the copy script must offer only the key"
  grep -q 'StrictHostKeyChecking=yes' docker/backup-copy.sh || fail "the copy script must never trust a host on first use"
  grep -q 'GlobalKnownHostsFile=/dev/null' docker/backup-copy.sh || fail "the copy script must use only the pinned host key"
  grep -q 'sftp -q -b -' docker/backup-copy.sh || fail "the copy script must use sftp"
  grep -q 'openssh-client' docker/backup-copy.Dockerfile || fail "the copy image needs the sftp client"
  # The key is a secret file, not a setting; the volumes are plain local volumes.
  accepted home "the good file" "0"
  refused home "an nfs volume" "c.volumes['ferret-home-backups'].driver_opts = { type: 'nfs', o: 'addr=192.0.2.5', device: ':/x' }" "plain local volume"
  refused home "another volume driver" "c.volumes['ferret-home-backups'].driver = 'nfs'" "plain local volume"
  refused home "a bind mount of a share" "${copy}.volumes.push({ type: 'bind', source: '/mnt/share', target: '/share' })" "only named volumes"
  refused home "the key as a setting" "${copy}.environment.FERRET_COPY_SFTP_KEY_FILE = '/tmp/key'" "SSH key of the copy container"
  pass copy_target_is_sftp_with_a_key_and_never_nfs
}

base_images_are_pinned_by_digest() {
  # The copy image starts from the server's Alpine, by digest; the proxy stand-in of the drill is pinned too.
  server_alpine="$(sed -n 's/^ARG ALPINE_IMAGE=//p' docker/server.Dockerfile)"
  [ -n "$server_alpine" ] || fail "docker/server.Dockerfile has no ALPINE_IMAGE"
  grep -qx "ARG ALPINE_IMAGE=$server_alpine" docker/backup-copy.Dockerfile || fail "docker/backup-copy.Dockerfile must use the server's Alpine image ($server_alpine)"
  printf '%s' "$server_alpine" | grep -Eq '@sha256:[0-9a-f]{64}$' || fail "the Alpine image must be pinned by digest"
  [ "$(grep -c '^FROM ' docker/backup-copy.Dockerfile)" = 2 ] || fail "docker/backup-copy.Dockerfile has two stages"
  # shellcheck disable=SC2016
  grep -E '^FROM ' docker/backup-copy.Dockerfile | grep -vq '\${ALPINE_IMAGE}' && fail "every stage of the copy image starts from the pinned Alpine"
  grep -E 'image: *caddy' "$drill_compose" | grep -Eq 'alpine@sha256:[0-9a-f]{64}$' || fail "the proxy stand-in of the drill must be pinned by digest"
  # The same Caddy as the end-to-end stack.
  [ "$(grep -E 'image: *caddy' "$drill_compose" | sed 's/.*image: *//')" = "$(grep -E 'image: *caddy' docker/compose.ferret-e2e.yml | sed 's/.*image: *//')" ] \
    || fail "the drill uses the Caddy image of the end-to-end stack"
  # The app of the stack for real data is a release image by digest; the check refuses a tag or a local build.
  accepted home "an image by digest" "0"
  node -e '
const { execFileSync } = require("child_process");
const c = JSON.parse(process.argv[1]);
c.services["ferret-home-app"].image = "ghcr.io/x/y:0.4.0";
try { execFileSync("scripts/ferret-home.sh", ["verify-json", "home", "digest"], { input: JSON.stringify(c), stdio: ["pipe", "ignore", "ignore"] }); process.exit(1); } catch { process.exit(0); }' "$home_json" \
    || fail "an image given by tag was accepted"
  refused home "the app built here" "${app}.build = { context: '.', labels: { owner: 'ferret-home' } }; ${app}.pull_policy = 'build'" "never built here"
  refused home "no pids limit" "delete ${app}.pids_limit" "pids_limit"
  refused home "a huge pids limit" "${copy}.pids_limit = 100000" "pids_limit"
  refused home "unbounded logs" "${app}.logging = { driver: 'json-file' }" "logging must be"
  refused home "no log limit" "delete ${copy}.logging.options" "logging must be"
  refused home "a built image that is pulled" "delete ${copy}.pull_policy" "never pulled"
  # The copy image is built from pinned parts: the BuildKit frontend and every apk package.
  head -n 1 docker/backup-copy.Dockerfile | grep -Eq '^# syntax=docker/dockerfile:[0-9.]+@sha256:[0-9a-f]{64}$' || fail "the syntax line of docker/backup-copy.Dockerfile must be pinned by digest"
  grep -E 'apk add' docker/backup-copy.Dockerfile | while read -r line; do
    for word in ${line#*--no-cache}; do
      case "$word" in "\\" | '&&') break ;; *=*) ;; *) echo "unpinned apk package: $word" >&2; exit 1 ;; esac
    done
  done || fail "every apk package of docker/backup-copy.Dockerfile must be pinned to a version"
  pass base_images_are_pinned_by_digest
}

# ---------------------------------------------------------------- the release workflow
image_exists_for_arm64() {
  workflow=.github/workflows/release.yml
  grep -q 'platform: linux/arm64' "$workflow" || fail "the release workflow must build linux/arm64"
  grep -q 'platform: linux/amd64' "$workflow" || fail "the release workflow must build linux/amd64"
  grep -qE 'runner: ubuntu-24\.04-arm' "$workflow" || fail "linux/arm64 is built on a native arm64 runner"
  grep -q 'file: docker/server.Dockerfile' "$workflow" || fail "the release image is built from docker/server.Dockerfile"
  # What the workflow builds the image with and what it requires of `ferret --build-info` must agree: one FEATURES line,
  # one `features:` check, the same value (the release has the cargo features passkey-import and quick-unlock and no other).
  [ "$(grep -cE '^ *FEATURES=' "$workflow")" = 1 ] || fail "the release workflow must have exactly one FEATURES= build argument"
  [ "$(grep -c "grep -qx 'features: " "$workflow")" = 1 ] || fail "the release workflow must have exactly one check of the features line of --build-info"
  built_with="$(grep -E '^ *FEATURES=' "$workflow" | sed -E 's/^ *FEATURES=//')"
  required_line="$(grep "grep -qx 'features: " "$workflow" | sed -E "s/.*grep -qx 'features: ([^']*)'.*/\1/")"
  [ "$built_with" = passkey-import,quick-unlock ] || fail "the release image is built with the cargo features passkey-import and quick-unlock and no other (FEATURES=passkey-import,quick-unlock), not '$built_with'"
  # The features line of the build info lists them in alphabetical order with a comma and a space, the build argument with a comma.
  [ "${required_line//, /,}" = "$built_with" ] || fail "the release workflow builds with FEATURES=$built_with but requires 'features: $required_line' of the image"
  grep -q -- "--build-arg FEATURES=$built_with " scripts/ferret-home.sh || fail "the deploy drill must build its image with the release's FEATURES=$built_with"
  grep -q 'REVISION=' "$workflow" || fail "the release image gets its revision"
  grep -q 'imagetools inspect --raw' "$workflow" || fail "the release workflow must check the manifest of what it publishes"
  grep -qE "need = \[.linux/amd64., .linux/arm64.\]|'linux/arm64'|\"linux/arm64\"" "$workflow" || fail "the publish job must require linux/arm64 in the manifest"
  grep -q 'cosign sign' "$workflow" || fail "the image is signed"
  grep -q 'cosign verify' "$workflow" || fail "the signature is verified in the workflow"
  # The up command refuses an image that has no arm64 (and no image for its own machine).
  up_case="$tmp/arm64"
  up_world "$up_case"
  STUB_MANIFEST='{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}' up_run "$up_case" v9.9.9 --yes-ferret-home --no-cosign && fail "an image without linux/arm64 was started"
  grep -q 'no linux/arm64' "$up_case/err" || fail "up must say that the image has no linux/arm64 (got: $(cat "$up_case/err"))"
  STUB_ARCH=x86_64 STUB_MANIFEST='{"manifests":[{"platform":{"os":"linux","architecture":"arm64"}}]}' up_run "$up_case" v9.9.9 --yes-ferret-home --no-cosign && fail "an image without a platform for this machine was started"
  grep -q 'no linux/amd64' "$up_case/err" || fail "up must say that the image has no platform for this machine"
  STUB_MANIFEST='{"manifests":[{"platform":{"os":"linux","architecture":"arm64"}},{"platform":{"os":"linux","architecture":"amd64"}}]}' STUB_ARCH=aarch64 up_run "$up_case" v9.9.9 --yes-ferret-home --no-cosign \
    || fail "a good arm64 image was refused: $(cat "$up_case/err")"
  # Optional, with a network: the base images of the build have an arm64 manifest.
  if [ "${FERRET_CHECK_REGISTRY:-}" = 1 ] && [ -n "$real_docker" ]; then
    for ref in $(grep -hE '^ARG [A-Z_]+_IMAGE=' docker/server.Dockerfile | cut -d= -f2) $(grep -hE 'image: *caddy' "$drill_compose" | sed 's/.*image: *//'); do
      docker buildx imagetools inspect --raw "$ref" | grep -q '"architecture":"arm64"' || fail "$ref has no arm64 image"
    done
  else
    skip "the arm64 manifests of the base images" "set FERRET_CHECK_REGISTRY=1 to ask the registries"
  fi
  pass image_exists_for_arm64
}

# ---------------------------------------------------------------- the up command, against stand-ins
# A copy of the files that start the stack, as a git repository with a release tag, and a stand-in for
# docker, git's neighbours (cosign) and a log of every call.
up_stubs="$tmp/stubs"
mkdir -p "$up_stubs"
cat > "$up_stubs/docker" <<'STUB'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$STUB_LOG"
case "$*" in
  *"compose"*" config "*) exec "$STUB_REAL_DOCKER" "$@" ;;
  *"info --format"*) echo "${STUB_ARCH:-aarch64}" ;;
  *"version --format"*) echo "${STUB_DOCKER_VERSION:-28.1.1}" ;;
  *"ps -aq"*"owner=ferret-home"*) [ -z "${STUB_HOME_RUNNING:-}" ] || echo abc123 ;;
  *"image inspect"*".Id"*) echo "sha256:copyimageid" ;;
  *"imagetools inspect --raw"*)
    manifest="${STUB_MANIFEST:-}"
    [ -n "$manifest" ] || manifest='{"manifests":[{"platform":{"os":"linux","architecture":"arm64"}},{"platform":{"os":"linux","architecture":"amd64"}}]}'
    printf '%s\n' "$manifest" ;;
  *" pull "*) ;;
  *RepoDigests*) echo "ghcr.io/ferdinand99/faithful-ferret@sha256:${STUB_DIGEST:-1111111111111111111111111111111111111111111111111111111111111111}" ;;
  *"image inspect"*opencontainers.image.revision*) echo "${STUB_REVISION:-}" ;;
  *"image inspect"*opencontainers.image.version*) echo "${STUB_VERSION:-}" ;;
  *"--build-info"*)
    printf 'ferret %s\nfeatures: %s\n' "${STUB_BUILD_VERSION:-}" "${STUB_FEATURES:-passkey-import, quick-unlock}"
    [ "${STUB_WASM:-}" = - ] || printf 'wasm: %s\n' "${STUB_WASM:-release 8c50c5ea011c619e63c76c9b4790ba8d873d2077068f82e5712c2f135f5af48c}" ;;
  *"logs"*) ;;
esac
exit 0
STUB
cat > "$up_stubs/cosign" <<'STUB'
#!/usr/bin/env bash
printf 'cosign %s\n' "$*" >> "$STUB_LOG"
if [ "${1:-}" = version ]; then
  # The text form of `cosign version`: a banner, then GitVersion. STUB_COSIGN_VERSION=- prints no version.
  printf '  ______   ______\ncosign: A tool for Container Signing, Verification and Storage in an OCI registry.\n\n'
  [ "${STUB_COSIGN_VERSION:-}" = - ] || printf 'GitVersion:    v%s\nGitCommit:     unknown\n' "${STUB_COSIGN_VERSION:-3.0.2}"
  exit 0
fi
exit "${STUB_COSIGN_RC:-0}"
STUB
chmod +x "$up_stubs/docker" "$up_stubs/cosign"

# up_world <dir>: <dir>/repo is a git repository with the stack's files and the tag v9.9.9 on its HEAD.
up_world() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir/repo/scripts" "$dir/repo/docker"
  cp scripts/ferret-home.sh scripts/lanbox-ferret-test.sh "$dir/repo/scripts/"
  cp docker/compose.ferret-home.yml docker/compose.ferret-drill.yml docker/home.env.example docker/copy.env.example docker/e2e-runner.Dockerfile "$dir/repo/docker/"
  (
    cd "$dir/repo"
    git init -q
    git -c user.name=check -c user.email=check@example.invalid -c commit.gpgsign=false add -A
    git -c user.name=check -c user.email=check@example.invalid -c commit.gpgsign=false commit -q -m release
    git tag v9.9.9
  )
  : > "$dir/log"
}

# up_run <dir> <tag> [args]: runs `up` in the world with the stand-ins; the exit code is up's own.
# The revision, the version and the build info default to the good ones for the tag's commit.
up_run() {
  local dir="$1" tag="$2" commit
  shift 2
  commit="$(cd "$dir/repo" && git rev-parse "refs/tags/v9.9.9^{commit}")"
  : > "$dir/log"
  (
    cd "$dir/repo"
    PATH="$up_stubs:$PATH" STUB_LOG="$dir/log" STUB_REAL_DOCKER="$real_docker" \
      STUB_REVISION="${STUB_REVISION-$commit}" STUB_VERSION="${STUB_VERSION-9.9.9}" STUB_BUILD_VERSION="${STUB_BUILD_VERSION-9.9.9}" \
      FERRET_RELEASE_REPO=Example/Repo \
      scripts/ferret-home.sh up "$tag" "$@"
  ) > "$dir/out" 2> "$dir/err"
}

the_image_has_no_test_features_and_its_revision_is_the_release_tag() {
  # The build gives the image its version and revision, and the release builds with passkey-import and quick-unlock and no test feature.
  grep -q 'org.opencontainers.image.revision' docker/server.Dockerfile || fail "docker/server.Dockerfile must label the revision"
  grep -q 'org.opencontainers.image.version' docker/server.Dockerfile || fail "docker/server.Dockerfile must label the version"
  grep -qE 'FEATURES=passkey-import,quick-unlock$' .github/workflows/release.yml || fail "the release image must be built with passkey-import and quick-unlock and no other feature"
  grep -q 'git rev-parse' .github/workflows/release.yml || fail "the release image gets the commit of the tag as its revision"
  # The compose file of the stack never builds the server and has no test variable.
  accepted home "the good file" "0"
  refused home "a test clock" "${app}.environment.FERRET_E2E_CLOCK_FILE = '/tmp/clock'" "test variable"
  local d="$tmp/features"
  up_world "$d"
  up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "a good release image was refused: $(cat "$d/err")"
  STUB_FEATURES=none up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "a release from before quick-unlock was refused: $(cat "$d/err")"
  STUB_FEATURES=quick-unlock up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "the release from before the passkey import was refused: $(cat "$d/err")"
  STUB_FEATURES=passkey-import up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image with the passkey import and without quick-unlock was started"
  STUB_FEATURES='e2e-clock, passkey-import, quick-unlock' up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "the end-to-end image with the passkey import was started"
  STUB_FEATURES=e2e-clock up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image with a test feature was started"
  grep -q 'cargo features' "$d/err" || fail "up must say why: $(cat "$d/err")"
  STUB_FEATURES='e2e-clock, quick-unlock' up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "the end-to-end image was started"
  # A web vault built with a package from the tree, or with no package record at all, is not a release.
  STUB_WASM='tree 8c50c5ea011c619e63c76c9b4790ba8d873d2077068f82e5712c2f135f5af48c' up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image with a tree-built web vault was started"
  grep -q 'not built with a locked or released WebAssembly package' "$d/err" || fail "up must say why: $(cat "$d/err")"
  STUB_WASM=none up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image without a recorded web vault package was started"
  STUB_WASM=- up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image that says nothing about its web vault package was started"
  STUB_WASM='lock 8c50c5ea011c619e63c76c9b4790ba8d873d2077068f82e5712c2f135f5af48c' up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "an image with the locked package was refused: $(cat "$d/err")"
  STUB_REVISION=0123456789012345678901234567890123456789 up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image of another commit was started"
  grep -q 'not the commit of v9.9.9' "$d/err" || fail "up must say that the revision is not the tag's commit: $(cat "$d/err")"
  STUB_REVISION='' up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image without a revision label was started"
  STUB_VERSION=9.9.8 up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image of another version was started"
  STUB_BUILD_VERSION=9.9.8 up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "an image that says another version was started"
  # Nothing is started after any refusal.
  grep -qE 'compose .* up ' "$d/log" && fail "up started the stack after a refusal"
  pass the_image_has_no_test_features_and_its_revision_is_the_release_tag
}

up_refuses_a_branch_build() {
  local d="$tmp/branch"
  up_world "$d"
  # No yes, no start.
  up_run "$d" v9.9.9 --no-cosign && fail "up started without --yes-ferret-home"
  # Not a release tag: a branch name, a commit, a tag that is not there, a pre-release.
  for what in main HEAD "$(cd "$d/repo" && git rev-parse HEAD)" v9.9.10 v9.9.9-rc1 9.9.9; do
    up_run "$d" "$what" --yes-ferret-home --no-cosign && fail "up accepted '$what'"
  done
  # A tag that exists, but the checkout is a commit after it (a branch build).
  (
    cd "$d/repo"
    echo '# changed' >> docker/compose.ferret-home.yml
    git -c user.name=check -c user.email=check@example.invalid -c commit.gpgsign=false commit -q -am 'after the release'
  )
  up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "up started a checkout that is after the tag"
  grep -q 'not at v9.9.9' "$d/err" || fail "up must say that the checkout is not at the tag: $(cat "$d/err")"
  # At the tag, but the files that start the stack are edited.
  up_world "$d"
  echo '# edited' >> "$d/repo/docker/compose.ferret-home.yml"
  up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "up started edited files"
  grep -q 'differ from v9.9.9' "$d/err" || fail "up must say that the files differ from the tag: $(cat "$d/err")"
  # Without cosign and without --no-cosign it refuses; with a bad signature it refuses; with a good one it starts.
  up_world "$d"
  STUB_COSIGN_RC=1 up_run "$d" v9.9.9 --yes-ferret-home && fail "an image with a bad signature was started"
  grep -q 'signature of the image is not good' "$d/err" || fail "up must say that the signature is not good"
  up_run "$d" v9.9.9 --yes-ferret-home || fail "a good signed release was refused: $(cat "$d/err")"
  grep -q 'cosign verify' "$d/log" || fail "cosign was not asked"
  grep -q "certificate-identity-regexp .*Example/Repo.*release" "$d/log" || fail "cosign must be asked for the identity of the release workflow"
  grep -qE 'compose .* up -d' "$d/log" || fail "a good release was not started"
  # The digest is written down, and the stack is started by that digest.
  grep -q '^FERRET_IMAGE=ghcr.io/ferdinand99/faithful-ferret@sha256:1111' "$d/repo/docker/home-image" || fail "the digest must be written down"
  grep -q ' v9.9.9 ' "$d/repo/docker/home-releases.log" || fail "the release must be logged"
  # No cosign at all on the path: refuses, and says how to go on openly.
  if [ "$(command -v cosign || true)" = "" ]; then
    up_world "$d"
    (
      cd "$d/repo"
      mkdir -p "$d/nocosign"
      cp "$up_stubs/docker" "$d/nocosign/docker"
      PATH="$d/nocosign:$PATH" STUB_LOG="$d/log" STUB_REAL_DOCKER="$real_docker" STUB_REVISION="$(git rev-parse HEAD)" STUB_VERSION=9.9.9 STUB_BUILD_VERSION=9.9.9 \
        scripts/ferret-home.sh up v9.9.9 --yes-ferret-home
    ) > "$d/out" 2> "$d/err" && fail "up started without cosign and without --no-cosign"
    grep -q 'no-cosign' "$d/err" || fail "up must name --no-cosign"
  else
    skip "a missing cosign" "cosign is installed here"
  fi
  pass up_refuses_a_branch_build
}

up_needs_cosign_3_to_check_the_signature() {
  local d="$tmp/cosign3"
  up_world "$d"
  # cosign 2 finds no signature on an image that cosign 3 signed: refused before anything is pulled, and it says why.
  STUB_COSIGN_VERSION=2.4.1 up_run "$d" v9.9.9 --yes-ferret-home && fail "up checked the signature with cosign 2"
  grep -q 'cosign 2 is installed here, but cosign 3 or newer is needed' "$d/err" || fail "up must say that cosign 3 is needed: $(cat "$d/err")"
  grep -q 'no-cosign' "$d/err" || fail "up must name --no-cosign"
  grep -qE 'docker .*pull' "$d/log" && fail "up pulled the image before it checked the version of cosign"
  grep -q 'cosign verify' "$d/log" && fail "up asked cosign 2 to verify"
  # A version that cannot be read is refused too.
  STUB_COSIGN_VERSION=- up_run "$d" v9.9.9 --yes-ferret-home && fail "up checked the signature with a cosign of unknown version"
  grep -q 'cannot read the version of cosign' "$d/err" || fail "up must say that it cannot read the version: $(cat "$d/err")"
  # cosign 3 and later verify.
  for v in 3.0.2 4.1.0; do
    STUB_COSIGN_VERSION=$v up_run "$d" v9.9.9 --yes-ferret-home || fail "a good release was refused with cosign $v: $(cat "$d/err")"
    grep -q 'cosign verify' "$d/log" || fail "cosign $v was not asked to verify"
  done
  # --no-cosign never asks cosign anything, so an old one does not stand in the way of an open skip.
  STUB_COSIGN_VERSION=2.4.1 up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "--no-cosign was refused because of the cosign version: $(cat "$d/err")"
  grep -q '^cosign ' "$d/log" && fail "--no-cosign still called cosign"
  pass up_needs_cosign_3_to_check_the_signature
}

the_app_has_open_files_for_its_event_streams() {
  # The server holds up to 1 024 event streams; a container's default soft limit of 1 024 open files is not enough.
  printf '%s' "$home_json" | node -e '
const c = JSON.parse(require("fs").readFileSync(0, "utf8"));
const n = c.services["ferret-home-app"].ulimits?.nofile;
if (!(n && Number(n.soft) >= 4096 && Number(n.hard) >= 4096)) { console.error("nofile: " + JSON.stringify(n)); process.exit(1); }' \
    || fail "the app must have ulimits nofile of at least 4096"
  refused home "no open-file limit" "delete ${app}.ulimits" "ulimits nofile"
  refused home "the default open-file limit" "${app}.ulimits = { nofile: { soft: 1024, hard: 1024 } }" "ulimits nofile"
  refused home "a hard limit below the soft one" "${app}.ulimits = { nofile: { soft: 4096, hard: 2048 } }" "ulimits nofile"
  accepted home "a higher open-file limit" "${app}.ulimits = { nofile: { soft: 8192, hard: 16384 } }"
  pass the_app_has_open_files_for_its_event_streams
}

up_checks_the_machine_and_records_what_it_started() {
  local d="$tmp/record"
  up_world "$d"
  STUB_DOCKER_VERSION=27.5.1 up_run "$d" v9.9.9 --yes-ferret-home --no-cosign && fail "up started on a Docker engine older than 28"
  grep -q 'Docker 28 or newer' "$d/err" || fail "up must say that Docker 28 is needed: $(cat "$d/err")"
  grep -qE 'compose .* (build|up) ' "$d/log" && fail "up started something on an old engine"
  # --no-cosign is said loudly and recorded; a verified start is recorded as such.
  up_run "$d" v9.9.9 --yes-ferret-home --no-cosign || fail "a good release was refused: $(cat "$d/err")"
  grep -q 'NOT checked' "$d/err" || fail "up must say loudly that the signature was not checked"
  grep -q '^# cosign=SKIPPED' "$d/repo/docker/home-image" || fail "docker/home-image must record cosign=SKIPPED"
  grep -q 'cosign=SKIPPED' "$d/repo/docker/home-releases.log" || fail "the log must record cosign=SKIPPED"
  up_world "$d"
  up_run "$d" v9.9.9 --yes-ferret-home || fail "a good signed release was refused: $(cat "$d/err")"
  grep -q '^# cosign=verified' "$d/repo/docker/home-image" || fail "docker/home-image must record cosign=verified"
  grep -q 'cosign=verified copy-image=sha256:copyimageid' "$d/repo/docker/home-releases.log" || fail "the log must record the signature state and the ID of the copy image: $(cat "$d/repo/docker/home-releases.log")"
  # The platforms are read from the digest that is started, after the pull.
  grep -q 'imagetools inspect --raw ghcr.io/ferdinand99/faithful-ferret@sha256:' "$d/log" || fail "the platforms must be checked on the digest"
  grep -q 'imagetools inspect --raw ghcr.io/ferdinand99/faithful-ferret:9.9.9' "$d/log" && fail "the platforms must not be read from the tag"
  # The drill never runs on a Docker host that runs the stack for real data.
  (
    cd "$d/repo"
    PATH="$up_stubs:$PATH" STUB_LOG="$d/log" STUB_REAL_DOCKER="$real_docker" STUB_HOME_RUNNING=1 FERRET_DOCKER_ARGS="--context stub" \
      scripts/ferret-home.sh drill
  ) > "$d/out" 2> "$d/err" && fail "the drill ran on a host with the stack for real data"
  grep -q 'build machine only' "$d/err" || fail "the drill must say why it refuses: $(cat "$d/err")"
  pass up_checks_the_machine_and_records_what_it_started
}

the_copy_container_mounts_the_backups_read_only_and_has_no_private_key() {
  refused home "backups mounted rw" "${copy}.volumes.find((v) => v.source === 'ferret-home-backups').read_only = false" "read-only"
  refused home "the data mounted" "${copy}.volumes.push({ type: 'volume', source: 'ferret-home-data', target: '/data' })" "never mounts the data"
  refused home "another mount" "${copy}.volumes.push({ type: 'volume', source: 'ferret-home-backups', target: '/more', read_only: true })" "nothing else"
  refused home "the backups gone" "${copy}.volumes = []" "read-only"
  refused home "an age secret key in the environment" "${copy}.environment.FERRET_X = 'AGE-SECRET-KEY-1ABCDEF'" "age secret key"
  refused home "an identity setting" "${copy}.environment.FERRET_BACKUP_AGE_IDENTITY = 'x'" "private key setting"
  refused home "a writable root file system" "${copy}.read_only = false" "read_only"
  refused home "a capability" "${copy}.cap_add = ['CHOWN']" "no capability"
  refused home "root" "${copy}.user = '0:0'" "1000:1000"
  refused home "the app's data in the app, ro" "${app}.volumes.find((v) => v.source === 'ferret-home-data').read_only = true" "rw, and nothing else"
  refused drill "the private age key in the copy container" 'c.services["ferret-drill-copy"].volumes.push({ type: "volume", source: "ferret-drill-age", target: "/age", read_only: true })' "private age key"
  # The container itself (copies_on_the_target_are_age_files_never_plain_sets runs it): it refuses an age
  # secret key in its environment and a writable backup folder.
  grep -q 'AGE-SECRET-KEY-' docker/backup-copy.sh || fail "the copy script must refuse an age secret key"
  grep -q 'must be mounted read-only' docker/backup-copy.sh || fail "the copy script must refuse a writable backup folder"
  pass the_copy_container_mounts_the_backups_read_only_and_has_no_private_key
}

the_copy_container_is_never_on_the_app_network() {
  # The copy container holds an SSH key and talks to another machine: it is on a network of its own,
  # so it cannot open the app's ports 3040 and 3041 without the proxy. The drill tries it for real.
  node -e '
const c = JSON.parse(process.argv[1]);
const fail = (m) => { console.error(m); process.exit(1); };
const nets = (s) => Object.keys(s.networks || {}).sort().join();
if (nets(c.services["ferret-home-app"]) !== "ferret-home-net") fail("the app is on ferret-home-net only");
if (nets(c.services["ferret-home-copy"]) !== "ferret-home-copy-net") fail("the copy container is on ferret-home-copy-net only");
const copyNet = c.networks["ferret-home-copy-net"];
if (copyNet.internal) fail("the copy network needs a way out to the target");
if (copyNet.ipam.config[0].subnet !== "172.30.251.16/28") fail("the copy network has its own fixed subnet");' "$home_json" \
    || fail "the copy container must be on ferret-home-copy-net only, apart from the app"
  node -e '
const c = JSON.parse(process.argv[1]);
const nets = (s) => Object.keys(s.networks || {}).sort().join();
if (nets(c.services["ferret-drill-app"]) !== "ferret-drill-net") process.exit(1);
if (nets(c.services["ferret-drill-copy"]) !== "ferret-drill-copy-net") process.exit(1);
if (nets(c.services["ferret-drill-target"]) !== "ferret-drill-copy-net") process.exit(1);
if (c.services["ferret-drill-copy"].environment.FERRET_COPY_SFTP_HOST !== c.services["ferret-drill-target"].networks["ferret-drill-copy-net"].ipv4_address) process.exit(1);' "$drill_json" \
    || fail "the drill must put the copy container and its test target on ferret-drill-copy-net, apart from the app"
  refused home "the copy container on the app network too" "${copy}.networks['ferret-home-net'] = { ipv4_address: '172.30.251.3' }" "never on the app network"
  refused home "the copy container on the app network only" "${copy}.networks = { 'ferret-home-net': { ipv4_address: '172.30.251.3' } }" "never on the app network"
  refused home "the app on the copy network too" "${app}.networks['ferret-home-copy-net'] = { ipv4_address: '172.30.251.19' }" "only the network ferret-home-net"
  refused home "one network for both" "delete c.networks['ferret-home-copy-net']" "exactly the networks"
  refused home "a third network" "c.networks.extra = { name: 'extra', labels: { owner: 'ferret-home' }, ipam: { config: [{ subnet: '172.30.251.32/28', gateway: '172.30.251.33' }] } }" "exactly the networks"
  refused home "overlapping subnets" "c.networks['ferret-home-copy-net'].ipam.config[0] = { subnet: '172.30.251.0/28', gateway: '172.30.251.13' }; ${copy}.networks['ferret-home-copy-net'].ipv4_address = '172.30.251.4'" "overlap"
  refused home "an internal copy network" "c.networks['ferret-home-copy-net'].internal = true" "not internal"
  refused home "the copy container without a fixed address" "delete ${copy}.networks['ferret-home-copy-net'].ipv4_address" "fixed address"
  refused home "the copy container on an address of the app network" "${copy}.networks['ferret-home-copy-net'].ipv4_address = '172.30.251.3'" "fixed address"
  refused home "a copy network without the label" "delete c.networks['ferret-home-copy-net'].labels.owner" "network name and label"
  refused drill "the copy container of the drill on the app network" 'c.services["ferret-drill-copy"].networks["ferret-drill-net"] = { ipv4_address: "172.30.252.3" }' "never on the app network"
  refused drill "the test target on the app network" 'c.services["ferret-drill-target"].networks = { "ferret-drill-net": { ipv4_address: "172.30.252.4" } }' "only the network ferret-drill-copy-net"
  # The drill tries the app's ports from the copy container, and must fail to reach them.
  grep -q 'the copy container cannot reach' scripts/ferret-home.sh || fail "the drill must try the app's ports from the copy container"
  pass the_copy_container_is_never_on_the_app_network
}

peer_log_is_off_by_default() {
  # IP addresses are not kept longer than needed: the stack for real data starts with the peer log
  # off, and it can be switched on for the forged X-Forwarded-For check.
  local peers='process.stdout.write(String(JSON.parse(require("fs").readFileSync(0, "utf8")).services["ferret-home-app"].environment.FERRET_LOG_PEERS))'
  [ "$(printf '%s' "$home_json" | node -e "$peers")" = 0 ] || fail "FERRET_LOG_PEERS must be 0 on the stack for real data by default"
  local on_json
  on_json="$(FERRET_HOME_LOG_PEERS=1 render home)"
  [ "$(printf '%s' "$on_json" | node -e "$peers")" = 1 ] || fail "FERRET_HOME_LOG_PEERS=1 must switch the peer log on"
  printf '%s' "$on_json" | scripts/ferret-home.sh verify-json home > /dev/null || fail "the stack with the peer log on for a check must pass its own check"
  refused home "a peer log value that is neither 0 nor 1" "${app}.environment.FERRET_LOG_PEERS = 'yes'" "FERRET_LOG_PEERS"
  refused home "no peer log setting" "delete ${app}.environment.FERRET_LOG_PEERS" "FERRET_LOG_PEERS"
  grep -q 'FERRET_HOME_LOG_PEERS=1 scripts/ferret-home.sh up' "$home_compose" || fail "the compose file must say how to switch the peer log on for a check"
  grep -q 'peer log: off' scripts/ferret-home.sh || fail "status must say whether the peer log is on"
  pass peer_log_is_off_by_default
}

drill_stack_has_its_own_volumes_and_label() {
  node -e '
const c = JSON.parse(process.argv[1]);
const text = JSON.stringify(c);
for (const other of ["ferret-home", "ferret-test", "ferret-e2e"]) if (text.includes(other)) { console.error("the drill names " + other); process.exit(1); }
const vols = Object.entries(c.volumes);
if (vols.length < 7 || vols.some(([k, v]) => !k.startsWith("ferret-drill-") || v.labels.owner !== "ferret-drill")) { console.error("volumes"); process.exit(1); }
for (const [k, s] of Object.entries(c.services)) if (s.labels.owner !== "ferret-drill") { console.error(k); process.exit(1); }
for (const n of ["ferret-drill-net", "ferret-drill-copy-net"]) if (c.networks[n].labels.owner !== "ferret-drill") process.exit(1);' "$drill_json" || fail "the drill must have its own names and the label owner=ferret-drill"
  refused drill "a volume of the real stack" "c.volumes['ferret-home-data'] = { name: 'ferret-home-data', labels: { owner: 'ferret-drill' } }" "volumes must be"
  refused drill "a volume without the label" "delete c.volumes['ferret-drill-data'].labels.owner" "label owner=ferret-drill"
  refused drill "a volume with the label of the real stack" "c.volumes['ferret-drill-data'].labels.owner = 'ferret-home'" "label owner=ferret-drill"
  refused drill "the app on a volume of the real stack" 'c.services["ferret-drill-app"].volumes[0].source = "ferret-home-data"' "not of this stack"
  refused drill "a service without the label" 'delete c.services["ferret-drill-keys"].labels.owner' "label owner=ferret-drill"
  refused drill "a bind mount" 'c.services["ferret-drill-keys"].volumes.push({ type: "bind", source: "/srv", target: "/srv" })' "only named volumes"
  refused drill "the private age key in the app" 'c.services["ferret-drill-app"].volumes.push({ type: "volume", source: "ferret-drill-age", target: "/age" })' "mounts its data"
  refused drill "a second service on the host network" 'c.services["ferret-drill-target"].network_mode = "host"' "host network"
  refused drill "the proxy stand-in on all interfaces" 'c.services["ferret-drill-tls"].environment.CADDYFILE = "https://x { tls internal }"' "127.0.0.1 only"
  refused drill "a test target with a port" 'c.services["ferret-drill-target"].ports = [{ mode: "ingress", host_ip: "127.0.0.1", target: 2222, published: "2222", protocol: "tcp" }]' "publishes a port"
  # The files say the same: the drill script removes by the drill's label only.
  grep -q 'drill_label=owner=ferret-drill' scripts/ferret-home.sh || fail "the drill removes by its own label"
  if grep -nE 'volume prune|system prune|image prune|network prune|container prune' scripts/ferret-home.sh; then fail "no prune"; fi
  # The drill refuses to run without a Docker context named for it.
  ( unset FERRET_DOCKER_ARGS; scripts/ferret-home.sh drill > /dev/null 2>&1 ) && fail "the drill ran without FERRET_DOCKER_ARGS"
  pass drill_stack_has_its_own_volumes_and_label
}

home_env_is_never_read_by_the_script() {
  # The scripts and the container script name the settings files only as the examples (names, no
  # values) or in a comment.
  if grep -nE '(home|copy)\.env([^A-Za-z_.]|$)' scripts/ferret-home.sh docker/backup-copy.sh \
      | grep -vE '^[^:]*:[0-9]+:[[:space:]]*#' > "$tmp/env.txt"; then
    cat "$tmp/env.txt" >&2
    fail "a script names the settings files"
  fi
  if grep -nE '(source|\. )[^#]*(home|copy)\.env|set -a' scripts/ferret-home.sh docker/backup-copy.sh; then fail "a script sources a settings file"; fi
  # In a world where the settings files are named pipes, any attempt to open one for reading would block
  # for ever; every command of the script must finish without that.
  local d="$tmp/env" mk=1
  up_world "$d"
  for f in home.env copy.env; do
    mkfifo "$d/repo/docker/$f" 2> /dev/null || { mk=0; echo 'CANARY_VALUE_4711' > "$d/repo/docker/$f"; }
  done
  mkdir -p "$d/repo/docker/secrets"
  echo 'CANARY_VALUE_4711' > "$d/repo/docker/secrets/copy_sftp_key"
  if command -v timeout > /dev/null; then run_limited() { timeout 120 "$@"; }; else run_limited() { "$@"; }; fi
  (
    cd "$d/repo"
    export PATH="$up_stubs:$PATH" STUB_LOG="$d/log" STUB_REAL_DOCKER="$real_docker"
    STUB_REVISION="$(git rev-parse HEAD)"
    export STUB_REVISION STUB_VERSION=9.9.9 STUB_BUILD_VERSION=9.9.9
    run_limited scripts/ferret-home.sh config
    run_limited scripts/ferret-home.sh up v9.9.9 --yes-ferret-home --no-cosign
    run_limited scripts/ferret-home.sh status
    run_limited scripts/ferret-home.sh down --yes-ferret-home
  ) > "$d/out" 2> "$d/err" || fail "a command of the script did not finish with the settings files out of reach: $(tail -n 5 "$d/err")"
  if grep -q 'CANARY_VALUE_4711' "$d/out" "$d/err" "$d/log"; then fail "a value of the settings files reached an output or a command"; fi
  grep -qE 'home\.env\b[^.]|copy\.env\b[^.]' "$d/log" && fail "a docker call names a settings file"
  [ "$mk" = 1 ] || skip "the named pipes" "mkfifo is not available here: the canary file was used"
  pass home_env_is_never_read_by_the_script
}

# ---------------------------------------------------------------- the copy script, against stand-ins
copy_script_tests() {
  copy_ran=0
  [ "$(uname -s)" = Linux ] || { skip "the copy script runs" "not Linux"; return 0; }
  [ "$(id -u)" != 0 ] || { skip "the copy script runs" "running as root: the backup folder cannot be made read-only"; return 0; }
  command -v bash > /dev/null && command -v tar > /dev/null && command -v sha256sum > /dev/null || { skip "the copy script runs" "needs bash, tar and sha256sum"; return 0; }
  local d="$tmp/copy"
  rm -rf "$d"
  mkdir -p "$d/bin" "$d/backups" "$d/work" "$d/target/ferret" "$d/secrets"
  # sftp: runs the batch against a folder that stands for the target. It checks that ssh is asked for the
  # key only, with the pinned host key, and that the host key it was given is the one in the environment.
  cat > "$d/bin/sftp" <<'STUB'
#!/usr/bin/env bash
printf 'sftp %s\n' "$*" >> "$STUB_LOG"
known=""; key=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    UserKnownHostsFile=*) known="${args[i]#UserKnownHostsFile=}" ;;
    -i) key="${args[i + 1]}" ;;
  esac
done
case " $* " in *"StrictHostKeyChecking=yes"*"BatchMode=yes"* | *"BatchMode=yes"*"StrictHostKeyChecking=yes"*) ;; *) echo "stand-in sftp: no strict host key checking" >&2; exit 2 ;; esac
grep -q "$STUB_EXPECT_HOSTKEY" "$known" || { echo "stand-in sftp: host key verification failed" >&2; exit 255; }
[ "$(cat "$key")" = "$STUB_EXPECT_KEY" ] || { echo "stand-in sftp: wrong key" >&2; exit 255; }
[ "$(stat -c %a "$key")" = 600 ] || { echo "stand-in sftp: key mode" >&2; exit 2; }
root="$STUB_TARGET"; cwd=""
while IFS= read -r line; do
  ignore=0
  case "$line" in -*) ignore=1; line="${line#-}" ;; esac
  # shellcheck disable=SC2086
  set -- $line
  cmd="$1"; shift; rc=0
  case "$cmd" in
    cd) cwd="$root/$1"; [ -d "$cwd" ] || rc=1 ;;
    put) cp "$1" "$cwd/$2" || rc=1 ;;
    get) cp "$cwd/$1" "$2" || rc=1; if [ "${STUB_CORRUPT:-}" = 1 ] && [ $rc = 0 ]; then printf x >> "$2"; fi ;;
    rename) if [ -e "$cwd/$2" ]; then rc=1; else mv "$cwd/$1" "$cwd/$2" || rc=1; fi ;;
    rm) rm "$cwd/$1" 2> /dev/null || rc=1 ;;
    chmod) chmod "$1" "$cwd/$2" || rc=1 ;;
    ls) if [ "$1" = -1 ]; then ls -1 "$cwd"; else ls -l "$cwd/$2"; fi ;;
    *) rc=1 ;;
  esac
  if [ "$rc" -ne 0 ] && [ "$ignore" -eq 0 ]; then echo "stand-in sftp: $cmd failed" >&2; exit 1; fi
done
exit 0
STUB
  # age: "encrypts" by putting the age header in front. A failing age leaves no file.
  cat > "$d/bin/age" <<'STUB'
#!/usr/bin/env bash
printf 'age %s\n' "$*" >> "$STUB_LOG"
[ "${STUB_AGE_FAIL:-}" != 1 ] || exit 1
out=""
while [ "$#" -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; esac; shift; done
{ printf 'age-encryption.org/v1\n'; base64; } > "$out"
STUB
  # curl: the address must come on stdin (-K -), never on the command line.
  cat > "$d/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "$STUB_LOG"
cat >> "$STUB_LOG.curl-stdin"
exit "${STUB_CURL_RC:-0}"
STUB
  chmod +x "$d/bin/sftp" "$d/bin/age" "$d/bin/curl"
  # stat that fails when asked to (the mode check of the key must fail closed), else the real one.
  real_stat="$(command -v stat)"
  # shellcheck disable=SC2016
  printf '#!/usr/bin/env bash\n[ "${STUB_STAT_FAIL:-}" != 1 ] || exit 1\n[ "${STUB_STAT_JUNK:-}" != 1 ] || { echo "?"; exit 0; }\nexec %s "$@"\n' "$real_stat" > "$d/bin/stat"
  chmod +x "$d/bin/stat"
  local recipient hostkey
  recipient="age1$(printf 'q%.0s' {1..58})"
  hostkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEHOSTKEYEXAMPLEHOSTKEYEXAMPLEHOSTKEY0"
  echo "-----PRIVATE KEY FOR THE STAND-IN-----" > "$d/secrets/key"
  chmod 400 "$d/secrets/key"
  run_copy() { # mode [env assignments...]
    local mode="$1"
    shift
    : > "$d/log"; rm -f "$d/log.curl-stdin"
    chmod 755 "$d/backups"
    chmod a-w "$d/backups"
    (
      export PATH="$d/bin:$PATH" STUB_LOG="$d/log" STUB_TARGET="$d/target" STUB_EXPECT_HOSTKEY="EXAMPLEHOSTKEY"
      STUB_EXPECT_KEY="$(cat "$d/secrets/key")"
      export STUB_EXPECT_KEY
      export FERRET_COPY_BACKUPS_DIR="$d/backups" FERRET_COPY_WORK="$d/work" FERRET_BACKUP_AGE_RECIPIENT="$recipient"
      export FERRET_COPY_SFTP_HOST=target.example.org FERRET_COPY_SFTP_PORT=2222 FERRET_COPY_SFTP_USER=backup FERRET_COPY_SFTP_HOST_KEY="$hostkey"
      export FERRET_COPY_SFTP_DIR=ferret FERRET_COPY_SFTP_KEY_FILE="$d/secrets/key"
      export FERRET_COPY_PUSH_URL="https://monitor.example.org/api/push/SECRETTOKEN"
      for pair in "$@"; do export "${pair?}"; done
      bash docker/backup-copy.sh "$mode"
    ) > "$d/out" 2>&1
  }
  make_set() { # name
    mkdir -p "$d/backups/$1"
    printf 'SQLite format 3 plain database of %s\n' "$1" > "$d/backups/$1/ferret.sqlite"
    printf '{"format":"ferret-backup/1"}\n' > "$d/backups/$1/MANIFEST.json"
    : > "$d/backups/$1/.complete"
  }
  days_ago() { date -u -d "$1 days ago" +%Y%m%dT%H%M%SZ; }
  chmod u+w "$d/backups"

  # The settings are checked first: a secret key, a writable folder, a bad host.
  run_copy check "FERRET_X=AGE-SECRET-KEY-1ABCDEFGHIJ" && fail "the copy script ran with an age secret key in its environment"
  grep -q 'age secret key' "$d/out" || fail "the copy script must say why (got: $(cat "$d/out"))"
  run_copy check "FERRET_BACKUP_AGE_RECIPIENT=AGE-SECRET-KEY-1ABCDEFGHIJ" && fail "the copy script accepted a secret key as the recipient"
  run_copy check "FERRET_COPY_SFTP_HOST=bad host" && fail "the copy script accepted a bad host name"
  run_copy check "FERRET_COPY_SFTP_HOST_KEY=" && fail "the copy script ran without a host key"
  run_copy check "FERRET_COPY_SFTP_DIR=../x" && fail "the copy script accepted a folder outside"
  run_copy check "FERRET_COPY_PUSH_URL=https://x/\"; rm -rf /" && fail "the copy script accepted a bad push address"
  run_copy check "FERRET_COPY_PUSH_URL=http://monitor.example.org/api/push/SECRETTOKEN" && fail "the copy script accepted a push address without https"
  chmod 644 "$d/secrets/key"
  run_copy check && fail "the copy script accepted an SSH key that others can read"
  grep -q 'readable by group or others' "$d/out" || fail "the copy script must say why the key is refused"
  chmod 400 "$d/secrets/key"
  # The check of the mode fails closed: a stat that fails, or answers nonsense, refuses the key.
  run_copy check "STUB_STAT_FAIL=1" && fail "the copy script accepted a key whose mode could not be read"
  grep -q 'mode of the SSH key cannot be read' "$d/out" || fail "the copy script must say that the mode could not be read: $(cat "$d/out")"
  run_copy check "STUB_STAT_JUNK=1" && fail "the copy script accepted a key whose mode was not a number"
  run_copy check || fail "the copy script refused a key with mode 0400: $(cat "$d/out")"
  chmod u+w "$d/backups"
  if (
    export FERRET_BACKUP_AGE_RECIPIENT="$recipient" FERRET_COPY_SFTP_HOST=h FERRET_COPY_SFTP_USER=u FERRET_COPY_SFTP_HOST_KEY="$hostkey" FERRET_COPY_SFTP_KEY_FILE="$d/secrets/key" FERRET_COPY_BACKUPS_DIR="$d/backups" FERRET_COPY_WORK="$d/work"
    bash docker/backup-copy.sh check
  ) > "$d/out" 2>&1; then fail "the copy script ran with a writable backup folder"; fi
  grep -q 'read-only' "$d/out" || fail "the copy script must say that the backup folder must be read-only"
  run_copy check || fail "the copy script refused good settings: $(cat "$d/out")"

  # Two sets, the old and the new; a copy of each, encrypted, with its SHA-256, and nothing in plain text.
  chmod u+w "$d/backups"
  old="$(days_ago 3)"
  new="$(days_ago 1)"
  make_set "$old"
  make_set "$new"
  make_set "20261301T000000Z"   # not a date: never copied
  mkdir -p "$d/backups/stray"; : > "$d/backups/stray/.complete"   # not a set name
  mkdir -p "$d/backups/.tmp-$new"; printf 'half\n' > "$d/backups/.tmp-$new/ferret.sqlite"   # half written
  run_copy once || fail "the copy script failed: $(cat "$d/out")"
  [ -f "$d/target/ferret/$old.tar.age" ] && [ -f "$d/target/ferret/$new.tar.age" ] || fail "both sets must be copied"
  ls -1 "$d/target/ferret" | grep -Evx '[0-9]{8}T[0-9]{6}Z(-[0-9]+)?\.tar\.age(\.sha256)?' && fail "the target holds something that is not a copy"
  [ "$(ls -1 "$d/target/ferret" | wc -l)" = 4 ] || fail "the target must hold exactly two copies and two checksums (got $(ls -1 "$d/target/ferret" | tr '\n' ' '))"
  for f in "$d/target/ferret/"*.tar.age; do
    [ "$(head -c 21 "$f")" = "age-encryption.org/v1" ] || fail "$f is not an age file"
    (cd "$d/target/ferret" && sha256sum -c "$(basename "$f").sha256" > /dev/null) || fail "the checksum of $f does not match"
  done
  if grep -rl 'SQLite format' "$d/target" > /dev/null; then fail "a plain database reached the target"; fi
  if grep -rlE 'ferret-backup/1' "$d/target" > /dev/null; then fail "a plain manifest reached the target"; fi
  find "$d/target" -name '*.part' | grep -q . && fail "a part file was left on the target"
  grep -q "age -r $recipient" "$d/log" || fail "the copy must be encrypted to the public key"
  [ "$(grep -c '^age ' "$d/log")" = 2 ] || fail "one encryption per set"
  # The push address: told once, on stdin, never on a command line, never in the output.
  grep -q '^curl ' "$d/log" || fail "the monitor was not told after a new copy"
  grep -q 'SECRETTOKEN' "$d/log" && fail "the push address was on a command line"
  grep -q 'SECRETTOKEN' "$d/log.curl-stdin" || fail "the push address must reach curl on stdin"
  grep -q 'SECRETTOKEN' "$d/out" && fail "the push address reached the output"
  grep -q 'target.example.org' "$d/out" && fail "the address of the target reached the output"
  # Nothing new: no copy, and no message to the monitor.
  run_copy once || fail "the second run failed: $(cat "$d/out")"
  grep -q 'nothing new to copy' "$d/out" || fail "a second run must find nothing new"
  grep -q '^age ' "$d/log" && fail "a second run encrypted something again"
  grep -q '^curl ' "$d/log" && fail "a run with nothing new told the monitor"
  # A host that is not the pinned one: nothing is written.
  rm -f "$d/target/ferret/"*
  run_copy once "FERRET_COPY_SFTP_HOST_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHER00" && fail "a copy to a host with another key went through"
  [ -z "$(ls -A "$d/target/ferret")" ] || fail "something was written to a host with another key"
  grep -q '^curl ' "$d/log" && fail "the monitor was told after a refused host"
  # age fails: nothing on the target, no message, a failing exit code.
  run_copy once "STUB_AGE_FAIL=1" && fail "a failing encryption counted as a copy"
  [ -z "$(ls -A "$d/target/ferret")" ] || fail "something was written after a failed encryption"
  grep -q '^curl ' "$d/log" && fail "the monitor was told after a failed encryption"
  # A copy that arrives damaged is not a copy.
  run_copy once "STUB_CORRUPT=1" && fail "a copy that is damaged on the target counted as a copy"
  grep -q '^curl ' "$d/log" && fail "the monitor was told after a damaged copy"
  rm -f "$d/target/ferret/"*

  # Trimming: only the copy script's own names, and the three newest stay whatever their age.
  chmod -R u+w "$d/backups"
  rm -rf "$d/backups"/* "$d/backups"/.tmp-*
  make_set "$(days_ago 1)"
  for n in 60 45 40 5; do
    s="$(days_ago $n)"
    printf 'age-encryption.org/v1\nold %s\n' "$s" > "$d/target/ferret/$s.tar.age"
    printf '%s  %s\n' "$(sha256sum "$d/target/ferret/$s.tar.age" | cut -d' ' -f1)" "$s.tar.age" > "$d/target/ferret/$s.tar.age.sha256"
  done
  echo 'not ours' > "$d/target/ferret/notes.txt"
  echo 'not ours either' > "$d/target/ferret/20200101T000000Z.tar"
  # Sets dated in the future are never ranked, copied or trimmed: three of them must not push the real
  # copies out of the three newest.
  make_set 20991231T000000Z
  for f in 20991231T000001Z 20991231T000002Z 20991231T000003Z; do
    printf 'age-encryption.org/v1\nfuture\n' > "$d/target/ferret/$f.tar.age"
    printf '%s  %s\n' "$(sha256sum "$d/target/ferret/$f.tar.age" | cut -d' ' -f1)" "$f.tar.age" > "$d/target/ferret/$f.tar.age.sha256"
  done
  mkdir -p "$d/target/ferret/20200101T000000Z"
  run_copy once || fail "the run with old copies failed: $(cat "$d/out")"
  left="$(ls -1 "$d/target/ferret" | tr '\n' ' ')"
  for n in 1 5 40; do ls -1 "$d/target/ferret" | grep -q "^$(days_ago $n | cut -c1-8)" || fail "the copy of $n days ago must stay: $left"; done
  for n in 45 60; do ls -1 "$d/target/ferret" | grep -q "^$(days_ago $n | cut -c1-8)T[0-9]*Z.tar.age" && fail "the copy of $n days ago must go: $left"; done
  [ -f "$d/target/ferret/20991231T000001Z.tar.age" ] && [ -f "$d/target/ferret/20991231T000003Z.tar.age.sha256" ] || fail "a copy dated in the future was trimmed: $left"
  ls "$d/target/ferret" | grep -q '^20991231T000000Z' && fail "a set dated in the future was copied"
  grep -q 'ignoring 20991231T000000Z' "$d/out" || fail "the copy script must say that it ignores a set dated in the future"
  [ -f "$d/target/ferret/notes.txt" ] && [ -f "$d/target/ferret/20200101T000000Z.tar" ] && [ -d "$d/target/ferret/20200101T000000Z" ] || fail "the trim touched something that is not a copy of this script: $left"
  copy_ran=1
  echo "  ok  the copy script: refusals, encrypted copies only, checks on the target, trimming, the monitor's address"
}

copy_ran=0
copies_on_the_target_are_age_files_never_plain_sets() {
  copy_script_tests
  if [ "$copy_ran" = 1 ]; then pass copies_on_the_target_are_age_files_never_plain_sets; fi
}

# ---------------------------------------------------------------- run
if [ "${1:-}" = copy ]; then
  copy_script_tests
  exit 0
fi

[ -n "$real_docker" ] || fail "docker (with compose) is needed to render the compose files; nothing is sent to a Docker host"
bash -n docker/backup-copy.sh docker/ferret-entrypoint.sh scripts/ferret-home.sh scripts/check-ferret-home-stack.sh

app_publishes_only_on_loopback
trusted_proxy_is_exactly_the_network_gateway
copy_target_is_sftp_with_a_key_and_never_nfs
base_images_are_pinned_by_digest
image_exists_for_arm64
the_image_has_no_test_features_and_its_revision_is_the_release_tag
up_refuses_a_branch_build
up_needs_cosign_3_to_check_the_signature
the_app_has_open_files_for_its_event_streams
up_checks_the_machine_and_records_what_it_started
the_copy_container_mounts_the_backups_read_only_and_has_no_private_key
the_copy_container_is_never_on_the_app_network
peer_log_is_off_by_default
drill_stack_has_its_own_volumes_and_label
home_env_is_never_read_by_the_script
copies_on_the_target_are_age_files_never_plain_sets
echo "check-ferret-home-stack: all checks passed"
