#!/usr/bin/env bash
# Measure the line and branch coverage of ferret-core on the LANBox with
# cargo llvm-cov (the pinned nightly of fuzz/NIGHTLY, for --branch) and check
# it against the thresholds (scripts/coverage-thresholds.json).
#
#   scripts/lanbox-coverage.sh [--report-only]
#
# All tests of the crate run once (property tests at their default 512
# cases). The table is printed at the end; with --report-only a miss does not
# make the script fail. The JSON report comes back as target-cov/cov.json
# (ignored by git), for the markdown table of a report:
#   node scripts/coverage-check.mjs target-cov/cov.json --markdown
set -euo pipefail
cd "$(dirname "$0")/.."

report_only=""
[ "${1:-}" = --report-only ] && report_only=1

mkdir -p target-cov
rc=0
FERRET_EXPORT="target-cov" scripts/lanbox.sh --exec sh -c '
  set -e
  export RUSTUP_TOOLCHAIN="$(tr -d "[:space:]" < fuzz/NIGHTLY)"
  mkdir -p target-cov
  cargo llvm-cov --branch -p ferret-core -p ferret-server-auth --features test-support \
    --json --summary-only --output-path target-cov/cov.json
  node scripts/coverage-check.mjs target-cov/cov.json || echo 1 > target-cov/miss
' || rc=$?
[ "$rc" -eq 0 ] || exit "$rc"

if [ -e target-cov/miss ]; then
  rm -f target-cov/miss
  [ -n "$report_only" ] && exit 0
  echo "lanbox-coverage.sh: below the thresholds" >&2
  exit 1
fi
