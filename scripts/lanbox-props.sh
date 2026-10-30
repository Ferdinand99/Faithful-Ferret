#!/usr/bin/env bash
# Run the property tests of the core on the LANBox with more cases than the
# 512 of the pull request job: 20 000 by default, as in the
# nightly workflow.
#
#   scripts/lanbox-props.sh [cases]
#
# Every property test reads PROPTEST_CASES. A failing case is shrunk and its
# seed is written to a proptest-regressions folder inside the container; the
# log shows the input. The nightly workflow uploads those files, and a
# regression that is committed is replayed first on every run.
set -euo pipefail
cd "$(dirname "$0")/.."

cases="${1:-20000}"
case "$cases" in '' | *[!0-9]*) echo "lanbox-props.sh: cases must be a number" >&2; exit 2 ;; esac

exec scripts/lanbox.sh --exec sh -c '
  PROPTEST_CASES="$1" cargo test -p ferret-core \
    --test "props_*" --test sheet --test opaque_client
' sh "$cases"
