#!/usr/bin/env bash
# Fails if the nightly toolchain of fuzz/NIGHTLY (used by the fuzz and coverage
# scripts and the fuzz workflow) is not the one the builder image installs
# (ARG NIGHTLY_TOOLCHAIN in docker/builder.Dockerfile).
set -euo pipefail
cd "$(dirname "$0")/.."

file="$(tr -d '[:space:]' < fuzz/NIGHTLY)"
image="$(sed -n 's/^ARG NIGHTLY_TOOLCHAIN=\(.*\)$/\1/p' docker/builder.Dockerfile | tr -d '[:space:]\r')"

case "$file" in
  nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *) echo "check-nightly-pin: fuzz/NIGHTLY is '$file', not a dated nightly" >&2; exit 1 ;;
esac
if [ "$file" != "$image" ]; then
  echo "check-nightly-pin: fuzz/NIGHTLY is '$file' but docker/builder.Dockerfile installs '$image'" >&2
  exit 1
fi
echo "check-nightly-pin: $file in both"
