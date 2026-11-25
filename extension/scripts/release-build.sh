#!/usr/bin/env bash
# Builds the release package of one manifest version from the locked WASM package: the build for the CI jobs and for
# scripts/lanbox-ext.sh, which build a release package for every change.
#
#   extension/scripts/release-build.sh mv3|mv2
#
# A release with the unlock feature on is refused by `node scripts/build.mjs` (status 3) when the locked package does not
# have the functions that PIN and passkey unlock call. While web/wasm.lock.json names a release older than the one that
# has them (GATE_LOCK_VERSION, the release of the unlock feature), this script says so loudly and exits with status 10, so
# that a caller can skip what needs a release package and say that it did. The refusal itself is the build's, not this
# script's: it is tested in test/unit/features.test.mjs, and the signing workflow runs the build itself, so a signing run
# before the lock is moved fails in its build job. Once the lock is at that release or a later one the status is passed on
# as an error, and a build that fails for any other reason is an error.
#
# Exit status: 0 the package is built, 10 the lock is behind (nothing built), anything else a failure.
set -uo pipefail

# The release whose WASM package has the functions of the unlock feature. Remove the exit-10 rule with the pin change that moves
# the lock to it.
GATE_LOCK_VERSION=0.11.0

if [ "$#" -ne 1 ] || { [ "$1" != mv3 ] && [ "$1" != mv2 ]; }; then
  echo "usage: release-build.sh mv3|mv2" >&2
  exit 2
fi

cd "$(dirname "$0")/.."

status=0
node scripts/build.mjs --browser firefox --manifest "$1" --variant release --wasm lock || status=$?
if [ "$status" -ne 3 ]; then
  exit "$status"
fi

lock="$(node -p "JSON.parse(require('node:fs').readFileSync('../web/wasm.lock.json', 'utf8')).version")"
behind="$(node -e '
  const [lock, gate] = process.argv.slice(1).map((v) => v.split(".").map(Number));
  let less = false;
  for (let i = 0; i < 3; i += 1) {
    if (lock[i] !== gate[i]) { less = lock[i] < gate[i]; break; }
  }
  process.stdout.write(less ? "yes" : "no");
' "$lock" "$GATE_LOCK_VERSION")"
if [ "$behind" = yes ]; then
  echo "::warning title=No release package::The locked WASM package (core $lock) is older than the release that has the unlock functions ($GATE_LOCK_VERSION), so the release build is refused on purpose. No release package of $1 was built or checked; the pin change that moves web/wasm.lock.json makes this build pass." >&2
  exit 10
fi
echo "release-build: the build refused the locked package (core $lock), and the lock is not behind $GATE_LOCK_VERSION: this is a failure" >&2
exit 3
