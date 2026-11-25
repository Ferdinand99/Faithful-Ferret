#!/usr/bin/env bash
# Builds the release packages of both manifest versions and runs `web-ext lint` on each (the lint step of the CI job and of
# scripts/lanbox-ext.sh lint).
#
#   extension/scripts/lint-release.sh
#
# The release check (scripts/check-ext-release.sh) runs on the packages in extension/dist afterwards. While the lock names a
# WASM package older than the release that has the unlock functions, the release build is refused on purpose (see
# release-build.sh): then there is no release package to lint or to check. This script lints the test variant of the same
# commit instead (errors only: its test-only code has warnings that a release may not have), so that the manifest and the
# pages still get a lint, and it leaves the file dist/.release-skipped so that the caller does not run the release check on
# nothing and says so. Nothing here makes the refusal pass.
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p dist
rm -f dist/.release-skipped
for mv in mv3 mv2; do
  status=0
  bash scripts/release-build.sh "$mv" || status=$?
  if [ "$status" -eq 0 ]; then
    npm exec --no -- web-ext lint --source-dir "dist/ferret-firefox-$mv-release" --warnings-as-errors --self-hosted
  elif [ "$status" -eq 10 ]; then
    node scripts/build.mjs --browser firefox --manifest "$mv" --variant test --wasm lock
    # The test variant has test-only code that `--warnings-as-errors` would refuse (an eval in its test hooks), so only
    # errors fail here. This is less than the release lint, and the line below says so.
    npm exec --no -- web-ext lint --source-dir "dist/ferret-firefox-$mv-test" --self-hosted
    echo "no release package of $mv: the locked WASM package is behind (the test variant was linted instead)" >> dist/.release-skipped
  else
    exit "$status"
  fi
done
