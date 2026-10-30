#!/usr/bin/env bash
# Fuzz a target for a while on the LANBox (never locally, never Docker
# Desktop, never Tower): libFuzzer with AddressSanitizer through cargo-fuzz,
# inside the builder image, with the pinned nightly toolchain of fuzz/NIGHTLY.
#
#   scripts/lanbox-fuzz.sh <target|all> <seconds>   fuzz each target for <seconds>
#   scripts/lanbox-fuzz.sh replay <target|all>      replay the seed corpus and
#                                                   fuzz/regression, no new inputs
#   scripts/lanbox-fuzz.sh --list                   the targets
#
# The container is the one of scripts/lanbox.sh (4 CPUs by default, set
# FERRET_CPUS up to 8; --rm; labelled owner=ferret-core). Results come back to
# fuzz/.out/<target>.{log,summary,status} and fuzz/artifacts/<target>/ (a
# crashing input). The corpus a run grows stays in the container and is gone
# with it: only the seeds in fuzz/corpus (scripts/fuzz-seeds.mjs) and the
# regression inputs in fuzz/regression are kept.
#
# The exit code is 1 if any target crashed or timed out.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = --list ]; then
  sed -n 's/^name = "\(fuzz_[a-z_]*\)"$/\1/p' fuzz/Cargo.toml
  exit 0
fi

mode=run
if [ "${1:-}" = replay ]; then
  mode=replay
  shift
fi
target="${1:-}"
seconds="${2:-60}"
if [ -z "$target" ]; then
  echo "usage: scripts/lanbox-fuzz.sh <target|all> <seconds> | replay <target|all> | --list" >&2
  exit 2
fi
if [ "$target" != all ] && ! grep -q "^name = \"$target\"$" fuzz/Cargo.toml; then
  echo "lanbox-fuzz.sh: unknown target $target (see --list)" >&2
  exit 2
fi
case "$seconds" in '' | *[!0-9]*) echo "lanbox-fuzz.sh: seconds must be a number" >&2; exit 2 ;; esac

rm -rf fuzz/.out
FERRET_EXPORT="fuzz/artifacts fuzz/.out" \
  scripts/lanbox.sh --exec env FUZZ_ALWAYS_EXIT_ZERO=1 \
  bash scripts/fuzz-run.sh "$mode" "$target" "$seconds"

echo "---- results" >&2
fail=0
for status in fuzz/.out/*.status; do
  [ -e "$status" ] || { echo "lanbox-fuzz.sh: no results came back" >&2; exit 1; }
  name="$(basename "$status" .status)"
  cat "fuzz/.out/$name.summary"
  [ "$(cat "$status")" = 0 ] || fail=1
done
if [ "$fail" -ne 0 ]; then
  echo "lanbox-fuzz.sh: at least one target failed; see fuzz/.out/*.log and fuzz/artifacts/" >&2
  exit 1
fi
