#!/usr/bin/env bash
# Checks release packages of the extension: no test file, no test-only page, no
# fixed extension UUID, no test name, a shared/features.mjs with exactly the
# features a release has on (the `save` feature is required, and so are its
# capture script and the sources it is joined from; the `unlock` feature is
# refused while a release does not have it, and so are its window page and any
# use of its database other than the deletion at start), and a manifest.json with only the release keys and the
# permissions of manifest/permissions.allow.json (no content script, no
# web-accessible resource, no externally_connectable). Takes .xpi files or
# unpacked folders; without arguments it checks every
# extension/dist/ferret-*-release.xpi. It also reads the record that the build writes beside a
# package (<name>.wasm.json): a package without one, from a source other than the lock, or with a
# digest or version other than web/wasm.lock.json's, is refused.
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
