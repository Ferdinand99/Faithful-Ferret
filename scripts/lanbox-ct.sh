#!/usr/bin/env bash
# The constant-time checks of Fase 1 § 14 on the LANBox (never locally,
# never Docker Desktop, never Tower). See ct/run.sh for what each mode does.
#
#   scripts/lanbox-ct.sh                 all checks, 1 000 000 measurements per bench
#   scripts/lanbox-ct.sh lock            ct/dudect agrees with the root lock and profile
#   scripts/lanbox-ct.sh analyze         ct_analyzer, x86_64 + arm64, O0 O2 O3 Os
#   scripts/lanbox-ct.sh triage          the analyzer reports against ct/TRIAGE.md
#   scripts/lanbox-ct.sh select-asm      ct_select_bytes reads both slices
#   scripts/lanbox-ct.sh wasm-selftest   the WASM scan flags its fixtures
#   scripts/lanbox-ct.sh wasm-scan       the WASM build (shipped level) against ct/wasm-allow.toml
#   scripts/lanbox-ct.sh wasm-shipped    the scanned module is the shipped package
#   scripts/lanbox-ct.sh dudect-native   dudect on the native build
#   scripts/lanbox-ct.sh dudect-wasm     dudect on the WASM build, timed in Node
#
# The results (reports, .wat, dudect output) are streamed back to ct/results/.
# After a dudect run the script writes ct/results/dudect-lanbox.md, the decisive
# result with date, commit, host and every t-value, which is the one file of
# ct/results/ that is committed. Run it again before a release and commit the
# new file.
#
# Environment:
#   FERRET_CT_N     measurements per dudect bench (default 1000000; a bench over 4.5
#                   is measured again with ten times as many)
#   CT_PIN_CPU      CPU the dudect runs are pinned to with taskset (default "auto":
#                   the least busy CPU of the last second; a number for a fixed
#                   one; "" for no pinning)
#   CT_ONLY         only the dudect benches whose name contains this
#   CT_REPEAT       measure each selected bench this often (the spread of t)
#
# Timing tests are only meaningful on a quiet machine. The LANBox runs other
# containers, so look at its load before you trust a failure, and repeat it.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
case "$mode" in
  all | lock | lock-selftest | analyze | triage | select-asm | select-asm-negative | wasm-selftest | wasm-scan | wasm-allow-check | wasm-allow-baseline | wasm-shipped | dudect-native | dudect-wasm) ;;
  *)
    echo "usage: scripts/lanbox-ct.sh [all|lock|lock-selftest|analyze|triage|select-asm|select-asm-negative|wasm-selftest|wasm-scan|wasm-allow-check|wasm-allow-baseline|wasm-shipped|dudect-native|dudect-wasm]" >&2
    exit 2
    ;;
esac

export FERRET_EXPORT="ct/results"
export FERRET_EXPORT_ALWAYS=1
export FERRET_CT_N="${FERRET_CT_N:-1000000}"
export CT_PIN_CPU="${CT_PIN_CPU-auto}"
export CT_ONLY="${CT_ONLY:-}"
export CT_REPEAT="${CT_REPEAT:-1}"
export FERRET_PASS_ENV="FERRET_CT_N CT_PIN_CPU CT_ONLY CT_REPEAT"

case "$mode" in all | dudect-native) rm -f ct/results/dudect-native.txt ;; esac
case "$mode" in all | dudect-wasm) rm -f ct/results/dudect-wasm.txt ;; esac

rc=0
scripts/lanbox.sh --exec ct/run.sh "$mode" || rc=$?

# The decisive result, in a file that is committed.
if [ -f ct/results/dudect-native.txt ] || [ -f ct/results/dudect-wasm.txt ]; then
  commit="$(git rev-parse HEAD)"
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then commit="$commit (with uncommitted changes)"; fi
  {
    echo "# Decisive dudect run on the LANBox"
    echo
    echo "Written by \`scripts/lanbox-ct.sh $mode\` ($(date -u +%FT%TZ)). The limit is"
    echo "|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every"
    echo "line of the two outputs is below, runs and reruns included."
    echo
    echo "- commit: \`$commit\`"
    echo "- exit status of the run: $rc"
    echo "- measurements per bench: $FERRET_CT_N"
    echo
    for f in dudect-native dudect-wasm; do
      [ -f "ct/results/$f.txt" ] || continue
      case "$f" in dudect-native) title="Native" ;; *) title="WebAssembly in Node (wasm-opt -Oz)" ;; esac
      echo "## $title"
      echo
      echo '```text'
      cat "ct/results/$f.txt"
      echo '```'
      echo
    done
  } > ct/results/dudect-lanbox.md
  echo "wrote ct/results/dudect-lanbox.md" >&2
fi
exit "$rc"
