#!/usr/bin/env bash
# Checks release packages of the extension: no test file, no test-only page, no
# fixed extension UUID and no test name. Takes .xpi files or unpacked folders;
# without arguments it checks every extension/dist/ferret-*-release.xpi.
#
#   scripts/check-ext-release.sh [package ...]
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
  shopt -s nullglob
  set -- extension/dist/ferret-*-release.xpi
  if [ "$#" -eq 0 ]; then
    echo "check-ext-release: no release package in extension/dist (build one first)" >&2
    exit 1
  fi
fi

exec node extension/scripts/build.mjs --check-release "$@"
