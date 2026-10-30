#!/usr/bin/env bash
# Runs the fuzz targets with cargo-fuzz (libFuzzer + AddressSanitizer). This is
# the one runner behind scripts/lanbox-fuzz.sh (inside the builder container)
# and the fuzz workflow (on a GitHub runner).
#
#   scripts/fuzz-run.sh run    <target|all> <seconds>   fuzz for <seconds> per target
#   scripts/fuzz-run.sh replay <target|all>             replay the seed corpus and
#                                                       fuzz/regression/<target>, no new inputs
#
# The pinned nightly toolchain is named in fuzz/NIGHTLY. Each target leaves
# fuzz/.out/<target>.log, .summary (one line: executions, executions per
# second, coverage) and .status (the exit code of libFuzzer). A crash leaves
# the input in fuzz/artifacts/<target>/.
#
# Env:
#   FUZZ_ALWAYS_EXIT_ZERO=1  exit 0 even after a crash (the status files tell);
#                            used inside the container so the results are
#                            exported
#   FUZZ_TARGET_DIR          cargo target dir (default /src/target/fuzz if
#                            /src/target exists, else fuzz/target)
#   FUZZ_EXTRA               extra libFuzzer arguments, e.g. "-max_len=8192"
set -uo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"
target="${2:-}"
seconds="${3:-60}"
if [ -z "$mode" ] || [ -z "$target" ]; then
  echo "usage: scripts/fuzz-run.sh run <target|all> <seconds> | replay <target|all>" >&2
  exit 2
fi
case "$mode" in run | replay) ;; *) echo "fuzz-run.sh: unknown mode $mode" >&2; exit 2 ;; esac

nightly="$(tr -d '[:space:]' < fuzz/NIGHTLY)"
export RUSTUP_TOOLCHAIN="$nightly"
if ! rustc -V >/dev/null 2>&1; then
  echo "fuzz-run.sh: toolchain $nightly is not installed" >&2
  exit 2
fi

if [ -n "${FUZZ_TARGET_DIR:-}" ]; then
  target_dir="$FUZZ_TARGET_DIR"
elif [ -d /src/target ]; then
  target_dir=/src/target/fuzz
else
  target_dir=fuzz/target
fi
fuzz_args=(--fuzz-dir fuzz --target-dir "$target_dir" -s address)

mkdir -p fuzz/.out fuzz/artifacts
if [ "$target" = all ]; then
  mapfile -t targets < <(cargo fuzz list --fuzz-dir fuzz)
else
  targets=("$target")
fi
if [ "${#targets[@]}" -eq 0 ]; then
  echo "fuzz-run.sh: no targets" >&2
  exit 2
fi

# Build once, so that the time of each run is fuzzing and not compiling.
echo "fuzz-run.sh: building ${#targets[@]} target(s) with $nightly" >&2
build_args=()
[ "$target" = all ] || build_args=("$target")
if ! cargo fuzz build "${fuzz_args[@]}" "${build_args[@]}"; then
  echo "fuzz-run.sh: build failed" >&2
  exit 1
fi

worst=0
for t in "${targets[@]}"; do
  log="fuzz/.out/$t.log"
  mkdir -p "fuzz/corpus/$t" "fuzz/regression/$t"
  dict=()
  [ -f "fuzz/dict/$t.dict" ] && dict=("-dict=fuzz/dict/$t.dict")
  # A replay runs every file once (-runs=0 still reads the whole corpus) and
  # never writes a new input; a run adds what it finds to fuzz/corpus/<t>.
  if [ "$mode" = replay ]; then
    limits=(-runs=0)
    corpora=("fuzz/corpus/$t" "fuzz/regression/$t")
  else
    limits=("-max_total_time=$seconds")
    corpora=("fuzz/corpus/$t" "fuzz/regression/$t")
  fi
  # The targets that take bodies, envelopes and byte strings up to their real
  # limits (61 440 padded, 65 536 envelope, 64 KiB strings) get a larger input
  # size; keep this map equal to MAX_LEN_OF in scripts/fuzz-seeds.mjs.
  case "$t" in
    fuzz_envelope | fuzz_item_body | fuzz_cbor_value | fuzz_export_file) maxlen=70000 ;;
    *) maxlen=4096 ;;
  esac
  echo "fuzz-run.sh: $mode $t" >&2
  # shellcheck disable=SC2086
  cargo fuzz run "${fuzz_args[@]}" "$t" "${corpora[@]}" -- \
    "${limits[@]}" "${dict[@]}" -max_len=$maxlen -timeout=60 -rss_limit_mb=4096 -print_final_stats=1 ${FUZZ_EXTRA:-} \
    >"$log" 2>&1
  rc=$?
  echo "$rc" >"fuzz/.out/$t.status"
  # The last status line of libFuzzer: "#N DONE cov: C ft: F corp: K/Sb ... exec/s: E rss: R".
  # With -runs=0 there may be none, so fall back to the counters of the final stats.
  done_line="$(grep -E '^#[0-9]+[[:space:]]+(DONE|pulse|INITED)' "$log" | tail -n 1 || true)"
  runs="$(grep -E '^stat::number_of_executed_units:' "$log" | tail -n 1 | awk '{print $2}')"
  eps="$(grep -E '^stat::average_exec_per_sec:' "$log" | tail -n 1 | awk '{print $2}')"
  cov="$(printf '%s' "$done_line" | sed -n 's/.*cov: \([0-9]*\).*/\1/p')"
  corp="$(printf '%s' "$done_line" | sed -n 's/.*corp: \([0-9]*\).*/\1/p')"
  printf '%s mode=%s status=%s runs=%s exec_per_s=%s cov=%s corpus=%s\n' \
    "$t" "$mode" "$rc" "${runs:-?}" "${eps:-?}" "${cov:-?}" "${corp:-?}" | tee "fuzz/.out/$t.summary"
  if [ "$rc" -ne 0 ]; then
    worst=1
    echo "fuzz-run.sh: $t FAILED (exit $rc); last lines of the log:" >&2
    tail -n 25 "$log" >&2
  fi
done

if [ "${FUZZ_ALWAYS_EXIT_ZERO:-}" = 1 ]; then
  exit 0
fi
exit "$worst"
