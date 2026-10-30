#!/usr/bin/env bash
# The constant-time checks of plan section 10, one mode at a time. Run it
# inside the builder image (scripts/lanbox-ct.sh does that) or in CI
# (.github/workflows/ct.yml), never on a developer PC.
#
#   ct/run.sh analyze         ct_analyzer on every ct/harness/*.rs: x86_64 and
#                             arm64, O0 O2 O3 Os, with --warnings
#   ct/run.sh triage          every finding must be in ct/TRIAGE.md
#   ct/run.sh wasm-scan       div/rem/sqrt/br_table/indexed loads in the WASM
#                             build, against ct/wasm-allow.toml
#   ct/run.sh dudect-native   dudect on the native build (|t| < 4.5)
#   ct/run.sh dudect-wasm     dudect on the WASM build, timed in Node
#   ct/run.sh all             all of the above
#
# Environment:
#   CT_ANALYZER   path of analyzer.py (default /opt/ct-analyzer/ct_analyzer/analyzer.py)
#   FERRET_CT_N   measurements per dudect bench (default 1000000)
#   CT_RESULTS    where results go (default ct/results)
#   CT_SMOKE      1 for the short run on a hosted runner: a threshold failure is a warning
#   CT_PIN_CPU    CPU number for the dudect runs (taskset), "auto" for the least busy,
#                 empty for no pinning
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
results="${CT_RESULTS:-ct/results}"
analyzer="${CT_ANALYZER:-/opt/ct-analyzer/ct_analyzer/analyzer.py}"
n="${FERRET_CT_N:-1000000}"
mkdir -p "$results"

harness_files=(base32 crockford ct_eq ct_select unpad)
archs=(x86_64 arm64)
opts=(O0 O2 O3 Os)

triple() {
  case "$1" in
    x86_64) echo x86_64-unknown-linux-gnu ;;
    arm64) echo aarch64-unknown-linux-gnu ;;
    *) echo "unknown arch $1" >&2; exit 2 ;;
  esac
}

# ---------------------------------------------------------------- analyze

analyze() {
  local out="$results/analyzer"
  rm -rf "$out"
  mkdir -p "$out"
  {
    echo "analyzer: $analyzer"
    echo "rustc: $(rustc --version)"
    sha256sum "$(dirname "$analyzer")"/*.py
  } > "$out/VERSIONS.txt"

  # ct_eq.rs needs `subtle`: build the rlib for each target with the release
  # settings (no debug assertions, as shipped) but unwinding panics and no
  # LTO, which is what the analyzer's rustc expects of a dependency.
  declare -A subtle_rlib
  for arch in "${archs[@]}"; do
    local t
    t="$(triple "$arch")"
    CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_LTO=off       cargo build --quiet --release -p subtle --target "$t" >&2
    subtle_rlib[$arch]="$(ls target/"$t"/release/deps/libsubtle-*.rlib | head -n1)"
  done

  local failed=0
  for file in "${harness_files[@]}"; do
    for arch in "${archs[@]}"; do
      for opt in "${opts[@]}"; do
        local extra=(--extra-flags=--edition=2024)
        if [ "$file" = ct_eq ]; then
          local t
          t="$(triple "$arch")"
          extra+=("--extra-flags=--extern=subtle=${subtle_rlib[$arch]}" "--extra-flags=-Ldependency=target/$t/release/deps")
        fi
        local json="$out/${file}__${arch}__${opt}.json"
        # The analyzer exits 1 when it finds errors; the triage decides.
        python3 "$analyzer" --warnings --json --arch "$arch" --opt-level "$opt" \
          "${extra[@]}" "ct/harness/$file.rs" > "$json" || true
        if ! grep -q '"violations"' "$json"; then
          echo "analyzer produced no report for $file $arch $opt:" >&2
          cat "$json" >&2
          failed=1
        fi
      done
    done
  done
  [ "$failed" = 0 ]
  echo "analyzer: wrote $(ls "$out"/*.json | wc -l) reports to $out" >&2
}

triage() {
  node ct/check-triage.mjs "$results/analyzer" ct/TRIAGE.md
}

# -------------------------------------------------------------- wasm-scan

wasm_scan() {
  # The release build of the binding with its function names kept. The code
  # is the same as in the shipped module (names do not change code
  # generation); wasm-opt is not run, as it strips the names.
  cargo build --release -p ferret-core-wasm --target wasm32-unknown-unknown >&2
  local wasm=target/wasm32-unknown-unknown/release/ferret_core_wasm.wasm
  mkdir -p "$results/wasm"
  cp "$wasm" "$results/wasm/ferret_core_wasm_ct.wasm"
  wasm-tools print "$wasm" -o "$results/wasm/ferret_core_wasm_ct.wat"
  node ct/wasm-scan.mjs "$results/wasm/ferret_core_wasm_ct.wat" ct/wasm-allow.toml | tee "$results/wasm/scan.txt"
}

# ----------------------------------------------------------------- dudect

# The CPU for the timing runs: CT_PIN_CPU if it is a number, the least busy
# CPU of the last second if it is "auto", none if it is empty.
pick_cpu() {
  case "${CT_PIN_CPU:-}" in
    "") echo "" ;;
    auto)
      awk '/^cpu[0-9]/ { print $1, $2+$3+$4+$7+$8, $5+$6 }' /proc/stat > /tmp/stat1
      sleep 1
      awk '/^cpu[0-9]/ { print $1, $2+$3+$4+$7+$8, $5+$6 }' /proc/stat > /tmp/stat2
      paste -d' ' /tmp/stat1 /tmp/stat2         | awk '{ busy = $5 - $2; idle = $6 - $3; print busy / (busy + idle + 1), $1 }'         | sort -n | head -n1 | sed 's/^[^ ]* cpu//'
      ;;
    *) echo "$CT_PIN_CPU" ;;
  esac
}

# One native bench; echoes its line. The statistic is dudect-bencher's `max t`.
bench_line() {
  FERRET_CT_N="$n" "${pin[@]}" "$1" --filter "$2" | grep -E '^bench ' | grep -v seeded || true
}

t_of() {
  printf '%s' "$1" | sed -n 's/.*max t = \([-+0-9.eE]*\),.*/\1/p'
}

over() {
  awk -v t="$1" 'BEGIN { exit !((t < 0 ? -t : t) >= 4.5) }'
}

# CT_SMOKE=1 (the short run on a GitHub-hosted runner, which is too noisy for
# the threshold): a bench over the threshold is a warning, not a failure. A
# run that is not valid (no result, a control that does not behave) always
# fails.
finish() {
  local failed="$1" invalid="$2"
  [ "$invalid" = 0 ] || return 1
  if [ "$failed" != 0 ] && [ "${CT_SMOKE:-}" = 1 ]; then
    echo "::warning::dudect smoke run: a bench is over |t| = 4.5; hosted runners are noisy, the real run is scripts/lanbox-ct.sh"
    return 0
  fi
  [ "$failed" = 0 ]
}

dudect_native() {
  cargo build --release -p ferret-ct --features bench --bin dudect >&2
  local bin=target/release/dudect
  local out="$results/dudect-native.txt"
  : > "$out"
  local cpu
  cpu="$(pick_cpu)"
  pin=()
  if [ -n "$cpu" ]; then pin=(taskset -c "$cpu"); fi
  {
    echo "dudect native: n=$n per bench, cpu=${cpu:-none}, $(date -u +%FT%TZ)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo || true)"
    echo "rustc: $(rustc --version)"
    echo "load: $(cat /proc/loadavg)"
  } | tee -a "$out"
  local names="control_null control_leaky commit_check mac_verify key_eq crockford_decode unpad_ct base32_decode kek_pw_commit_path info_unwrap_valid_vs_bad_commit info_unpad_position_zeros info_unpad_content"
  local failed=0 invalid=0 name
  for name in $names; do
    local attempt=0 bad=0 line t
    while [ "$attempt" -lt 2 ]; do
      attempt=$((attempt + 1))
      line="$(bench_line "$bin" "$name")"
      echo "[run $attempt] $line" | tee -a "$out"
      t="$(t_of "$line")"
      if [ -z "$t" ]; then echo "no t-value for $name" | tee -a "$out"; invalid=1; break; fi
      if over "$t"; then bad=$((bad + 1)); else break; fi
      # control_leaky is meant to be over the threshold: one run is enough.
      if [ "$name" = control_leaky ]; then break; fi
    done
    case "$name" in
      control_leaky)
        if [ "$bad" -ge 1 ]; then
          echo "[ok] $name: the setup sees an early-exit comparison" | tee -a "$out"
        else
          echo "[FAIL] $name: the setup does not see an early-exit comparison, the run is not valid" | tee -a "$out"
          invalid=1
        fi
        ;;
      info_*) echo "[info] $name is reported, not gated" | tee -a "$out" ;;
      *)
        if [ "$bad" -ge 2 ]; then
          echo "[FAIL] $name: |t| >= 4.5 in two runs" | tee -a "$out"
          failed=1
        elif [ "$bad" -eq 1 ]; then
          echo "[ok, rerun] $name: |t| >= 4.5 once, below in the rerun" | tee -a "$out"
        else
          echo "[ok] $name" | tee -a "$out"
        fi
        ;;
    esac
  done
  finish "$failed" "$invalid"
}

dudect_wasm() {
  cargo build --release -p ferret-ct --lib --target wasm32-unknown-unknown >&2
  local wasm=target/wasm32-unknown-unknown/release/ferret_ct.wasm
  mkdir -p "$results/wasm"
  cp "$wasm" "$results/wasm/ferret_ct.wasm"
  local cpu
  cpu="$(pick_cpu)"
  pin=()
  if [ -n "$cpu" ]; then pin=(taskset -c "$cpu"); fi
  FERRET_CT_N="$n" CT_CPU="${cpu:-none}" "${pin[@]}" node ct/dudect-wasm/run.mjs "$wasm" | tee "$results/dudect-wasm.txt"
  # `node` exits 1 for a threshold failure and 3 for a run that is not valid.
  local rc="${PIPESTATUS[0]}"
  case "$rc" in
    0) ;;
    1) finish 1 0 ;;
    *) return "$rc" ;;
  esac
}

case "$mode" in
  analyze) analyze ;;
  triage) triage ;;
  wasm-scan) wasm_scan ;;
  dudect-native) dudect_native ;;
  dudect-wasm) dudect_wasm ;;
  all)
    analyze
    triage
    wasm_scan
    dudect_native
    dudect_wasm
    ;;
  *)
    echo "usage: ct/run.sh analyze|triage|wasm-scan|dudect-native|dudect-wasm|all" >&2
    exit 2
    ;;
esac
