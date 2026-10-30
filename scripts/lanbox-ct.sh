#!/usr/bin/env bash
# The constant-time checks of plan section 10 on the LANBox (never locally,
# never Docker Desktop, never Tower). See ct/run.sh for what each mode does.
#
#   scripts/lanbox-ct.sh                 all checks, 1 000 000 measurements per bench
#   scripts/lanbox-ct.sh analyze         ct_analyzer, x86_64 + arm64, O0 O2 O3 Os
#   scripts/lanbox-ct.sh triage          the analyzer reports against ct/TRIAGE.md
#   scripts/lanbox-ct.sh wasm-scan       the WASM build against ct/wasm-allow.toml
#   scripts/lanbox-ct.sh dudect-native   dudect on the native build
#   scripts/lanbox-ct.sh dudect-wasm     dudect on the WASM build, timed in Node
#
# The results (reports, .wat, dudect output) are streamed back to ct/results/.
#
# Environment:
#   FERRET_CT_N     measurements per dudect bench (default 1000000)
#   CT_PIN_CPU      CPU the dudect runs are pinned to with taskset (default "auto":
#                   the least busy CPU of the last second; a number for a fixed
#                   one; "" for no pinning)
#
# Timing tests are only meaningful on a quiet machine. The LANBox runs other
# containers, so look at its load before you trust a failure, and repeat it.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
case "$mode" in
  all | analyze | triage | wasm-scan | dudect-native | dudect-wasm) ;;
  *)
    echo "usage: scripts/lanbox-ct.sh [all|analyze|triage|wasm-scan|dudect-native|dudect-wasm]" >&2
    exit 2
    ;;
esac

export FERRET_EXPORT="ct/results"
export FERRET_EXPORT_ALWAYS=1
export FERRET_CT_N="${FERRET_CT_N:-1000000}"
export CT_PIN_CPU="${CT_PIN_CPU-auto}"
export FERRET_PASS_ENV="FERRET_CT_N CT_PIN_CPU"
exec scripts/lanbox.sh --exec ct/run.sh "$mode"
