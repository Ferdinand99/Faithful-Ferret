#!/usr/bin/env bash
# Run `cargo "$@"` inside the Ferret builder image on the LANBox Docker host
# (never locally, never Docker Desktop, never Tower).
#
# The repo is streamed over stdin as a tar archive (no bind mounts from the PC);
# target/ and the cargo registry live in tmpfs inside the container. Everything
# created is labelled owner=ferret-core and removed on exit (--rm).
#
#   scripts/lanbox.sh test -p ferret-core      cargo test -p ferret-core
#   scripts/lanbox.sh --exec <program> <args>  run any program instead of cargo
#   scripts/lanbox.sh --build-image            build the builder image only
#   scripts/lanbox.sh --rm-image               remove this tag's builder image
#
# Env overrides:
#   FERRET_DOCKER_ARGS  replaces the default "--context unraid"
#                       (e.g. "-H ssh://root@10.0.3.26" if the credential helper fails)
#   FERRET_CPUS         CPU limit and cargo jobs (default 4, at most 8)
#   FERRET_MEMORY       container memory limit (default 12g)
#   FERRET_PASS_ENV     space-separated names of environment variables that are
#                       passed on into the container
#   FERRET_EXPORT       space-separated repo paths (e.g. "Cargo.lock vectors") that
#                       are tarred out of the container after a successful run and
#                       unpacked here, for generated files such as Cargo.lock
#   FERRET_EXPORT_ALWAYS  set to 1 to export after a failed run too (reports of a
#                       check that failed are what you want to read)
#   DEV_RUN             optional run id (lowercase letters, digits and dashes, at
#                       most 63 characters, starting with a letter or digit). When
#                       set, the container gets the label dev.run=$DEV_RUN and the
#                       name ferret-$DEV_RUN-<pid>, so the run shows up in devdash
#   DEV_TITLE           optional title, added as the label dev.title when DEV_RUN
#                       is set
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

cd "$(dirname "$0")/.."

cpus="${FERRET_CPUS:-4}"
memory="${FERRET_MEMORY:-12g}"
if [ "$cpus" -gt 8 ]; then
  echo "lanbox.sh: FERRET_CPUS is capped at 8" >&2
  exit 2
fi
# shellcheck disable=SC2206
docker_args=(${FERRET_DOCKER_ARGS:---context unraid})
pass_env=()
for name in ${FERRET_PASS_ENV:-}; do
  if ! printf '%s' "$name" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    echo "lanbox.sh: FERRET_PASS_ENV holds variable names only" >&2
    exit 2
  fi
  pass_env+=(-e "$name")
done

dev_args=()
if [ -n "${DEV_RUN:-}" ]; then
  # bash's own matcher, so an embedded newline cannot slip past the anchors
  dev_run_re='^[a-z0-9][a-z0-9-]{0,62}$'
  if ! (LC_ALL=C; [[ $DEV_RUN =~ $dev_run_re ]]); then
    echo "lanbox.sh: DEV_RUN must match $dev_run_re" >&2
    exit 2
  fi
  dev_args+=(--label "dev.run=$DEV_RUN" --name "ferret-$DEV_RUN-$$")
  if [ -n "${DEV_TITLE:-}" ]; then
    dev_args+=(--label "dev.title=$DEV_TITLE")
  fi
fi

hash="$(tr -d '\r' < docker/builder.Dockerfile | sha256sum | cut -c1-12)"
image="ferret-core-builder:${hash}"

have_image() { docker "${docker_args[@]}" image inspect "$image" >/dev/null 2>&1; }

build_image() {
  echo "lanbox.sh: building $image on the LANBox (this takes a while the first time)" >&2
  docker "${docker_args[@]}" build \
    --label owner=ferret-core \
    -t "$image" \
    -f docker/builder.Dockerfile \
    docker >&2
}

case "${1:-}" in
  --build-image) have_image || build_image; exit 0 ;;
  --rm-image) have_image && docker "${docker_args[@]}" image rm "$image" >&2; exit 0 ;;
esac

have_image || build_image

mode=cargo
if [ "${1:-}" = "--exec" ]; then
  mode=exec
  shift
fi
if [ "$#" -eq 0 ]; then
  echo "usage: scripts/lanbox.sh <cargo args> | --exec <program> <args> | --build-image | --rm-image" >&2
  exit 2
fi

export_paths="${FERRET_EXPORT:-}"
if [ -n "$export_paths" ]; then
  if ! printf '%s' "$export_paths" | grep -Eq '^[A-Za-z0-9_./ -]+$' \
     || printf '%s' "$export_paths" | grep -Eq '(^| )/|\.\.'; then
    echo "lanbox.sh: FERRET_EXPORT must be relative repo paths" >&2
    exit 2
  fi
fi

# Inside the container: unpack the repo, run the command with its output on
# stderr (stdout is reserved for the export tar), then export on success.
inner='set -e
tar -x -C /src
set +e
if [ "$FERRET_MODE" = exec ]; then "$@" >&2; else cargo "$@" >&2; fi
rc=$?
if { [ "$rc" -eq 0 ] || [ "$FERRET_EXPORT_ALWAYS" = 1 ]; } && [ -n "$FERRET_EXPORT" ]; then
  # shellcheck disable=SC2086
  tar -c -C /src $FERRET_EXPORT
fi
exit "$rc"'

run=(docker "${docker_args[@]}" run --rm -i
  --label owner=ferret-core
  "${dev_args[@]}"
  --cpus "$cpus"
  --memory "$memory"
  -e CARGO_BUILD_JOBS="$cpus"
  -e CARGO_TERM_COLOR=never
  -e FERRET_MODE="$mode"
  -e FERRET_EXPORT="$export_paths"
  -e FERRET_EXPORT_ALWAYS="${FERRET_EXPORT_ALWAYS:-}"
  --tmpfs /src/target:exec,size=8g
  --tmpfs /usr/local/cargo/registry:size=2g
  "${pass_env[@]}"
  -w /src
  "$image"
  sh -c "$inner" sh "$@")

# Tracked and untracked-but-not-ignored files (so .gitignore and .git/info/exclude
# keep local-only folders out), without the website and brand assets.
pack() {
  git ls-files -z --cached --others --exclude-standard \
    | { grep -zvE "^(site|assets)/" || true; } \
    | tar --null -T - -cf -
}

if [ -n "$export_paths" ]; then
  pack | "${run[@]}" | tar -x --warning=no-timestamp -f -
else
  pack | "${run[@]}"
fi
