#!/usr/bin/env bash
# The constant-time checks of Fase 1 § 14, one mode at a time. Run it
# inside the builder image (scripts/lanbox-ct.sh does that) or in CI
# (.github/workflows/ct.yml), never on a developer PC.
#
#   ct/run.sh analyze         ct_analyzer on every ct/harness/*.rs: x86_64 and
#                             arm64, O0 O2 O3 Os, with --warnings
#   ct/run.sh triage          every finding must be in ct/TRIAGE.md, with the
#                             pinned counts
#   ct/run.sh select-asm      ct_select_bytes reads both slices (assembly check)
#   ct/run.sh select-asm-negative  the same check must flag a known-bad select
#   ct/run.sh lookup-asm      the unpacking of the lookup in login_start has no conditional jump
#   ct/run.sh wasm-scan       div/rem/sqrt/br_table/table loads in the WASM
#                             build at the shipped optimisation level
#                             (wasm-bindgen + wasm-opt -Oz, names kept), against
#                             ct/wasm-allow.toml
#   ct/run.sh wasm-allow-check  (after wasm-scan) ct/wasm-allow.toml is what a regeneration
#                             from that scan gives (no hand edit, no stale file)
#   ct/run.sh wasm-allow-baseline  against the base branch: nothing raised or new in a
#                             key-handling function without an APPROVED reason
#   ct/run.sh lock-selftest   the checksum comparison of the two locks fails on a doctored lock
#   ct/run.sh wasm-selftest   the scan must flag the fixtures in ct/wasm-fixtures
#   ct/run.sh wasm-shipped    the named build is the shipped package (same bytes
#                             once the names are stripped)
#   ct/run.sh dudect-native   dudect on the native build (|t| < 4.5)
#   ct/run.sh dudect-wasm     dudect on the WASM build (wasm-opt -Oz), in Node
#   ct/run.sh lock            the lock and profile of ct/dudect agree with the root
#   ct/run.sh all             all of the above
#
# A dudect bench with |t| >= 4.5 is measured once more with ten times the
# measurements; it fails if that is still >= 4.5.
#
# Environment:
#   CT_ANALYZER   path of analyzer.py (default /opt/ct-analyzer/ct_analyzer/analyzer.py)
#   FERRET_CT_N   measurements per dudect bench (default 1000000)
#   CT_RESULTS    where results go (default ct/results)
#   CT_SMOKE      1 for the short run on a hosted runner: a bench over 4.5 is a
#                 warning, a bench over CT_GROSS (500) in the rerun too is a failure
#   CT_PIN_CPU    CPU number for the dudect runs (taskset), "auto" for the least busy,
#                 empty for no pinning
#   CT_ONLY       only the dudect benches whose name contains this (the controls,
#                 control_*, always run too)
#   CT_QUIET_LOAD 1-minute load average above which a run is marked NOT DECISIVE (2)
#   CT_REPEAT     measure each selected bench this many times (spread of t)
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-all}"
results="${CT_RESULTS:-ct/results}"
analyzer="${CT_ANALYZER:-/opt/ct-analyzer/ct_analyzer/analyzer.py}"
n="${FERRET_CT_N:-1000000}"
gross="${CT_GROSS:-500}"
# A dudect run is decisive only on a quiet machine: the 1-minute load average
# at the start and at the end is recorded, and above this it is marked
# "NOT DECISIVE".
CT_QUIET_LOAD="${CT_QUIET_LOAD:-2}"
mkdir -p "$results"

harness_files=(base32 crockford ct_eq ct_select unpad)
needs_subtle=(ct_eq ct_select)
archs=(x86_64 arm64)
opts=(O0 O2 O3 Os)
# The timing tests are a workspace of their own (ct/dudect/Cargo.toml).
dudect=(--manifest-path ct/dudect/Cargo.toml --locked --target-dir target)
# Flags of wasm-opt as in scripts/build-wasm.sh.
wasm_opt_flags=(-Oz --enable-bulk-memory --enable-sign-ext --enable-nontrapping-float-to-int
  --enable-reference-types --enable-multivalue --enable-mutable-globals)

triple() {
  case "$1" in
    x86_64) echo x86_64-unknown-linux-gnu ;;
    arm64) echo aarch64-unknown-linux-gnu ;;
    *) echo "unknown arch $1" >&2; exit 2 ;;
  esac
}

in_list() { local x="$1"; shift; for y in "$@"; do [ "$x" = "$y" ] && return 0; done; return 1; }

declare -A subtle_rlib=()
# ct_eq.rs and ct_select.rs need `subtle`: build the rlib for each target with
# the release settings (no debug assertions, as shipped) but unwinding panics
# and no LTO, which is what the analyzer's rustc expects of a dependency.
ensure_subtle() {
  local arch t
  for arch in "${archs[@]}"; do
    [ -n "${subtle_rlib[$arch]:-}" ] && continue
    t="$(triple "$arch")"
    # The path of the rlib is the one cargo reports for this build, not a guess
    # from a directory listing (a reused target directory can hold others).
    subtle_rlib[$arch]="$(CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_LTO=off \
      cargo build --quiet --release -p subtle --target "$t" --message-format=json \
      | sed -n 's/.*"filenames":\["\([^"]*libsubtle\.rlib\)".*/\1/p' | tail -n1)"
    if [ ! -f "${subtle_rlib[$arch]}" ]; then
      echo "ct/run.sh: cargo did not report an rlib of subtle for $t" >&2
      return 1
    fi
  done
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
  ensure_subtle

  local failed=0 file arch opt
  for file in "${harness_files[@]}"; do
    for arch in "${archs[@]}"; do
      for opt in "${opts[@]}"; do
        # Overflow checks on, as in the release profile that is shipped.
        local extra=(--extra-flags=--edition=2024 --extra-flags=-Coverflow-checks=on)
        if in_list "$file" "${needs_subtle[@]}"; then
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

# The assembly of ct_select_bytes. A mask that the optimizer can see through
# turns the masked copy into "choose a source pointer, then copy", which reads
# only one slice. The barrier of `subtle` is what prevents that; this checks it
# on the compiler at hand: no instruction that tests bit 0 of the flag, and no
# more conditional moves than the two `min`s of the slice lengths.
#
# select_check <source file> <label> sets `select_flagged` (configurations that
# look like a pointer select), `select_flagged_archs` (the architectures that
# have one) and `select_empty` (configurations where the function was not found
# in the assembly, which would make the check pass on nothing).
select_check() {
  local src="$1" label="$2" arch opt t asm body cmovs bit0 lines
  select_flagged=0 select_empty=0 select_flagged_archs=""
  for arch in "${archs[@]}"; do
    t="$(triple "$arch")"
    for opt in 2 3 s; do
      asm="$results/select-$label-$arch-O$opt.s"
      rustc --edition=2024 --crate-type=lib --emit=asm -C "opt-level=$opt" --target "$t" \
        --extern "subtle=${subtle_rlib[$arch]}" -L "dependency=target/$t/release/deps" \
        -o "$asm" "$src"
      body="$(awk '/ct_select_bytes:$/{on=1} on{print} on&&/\.Lfunc_end/{exit}' "$asm")"
      lines="$(printf '%s\n' "$body" | grep -c . || true)"
      cmovs="$(printf '%s\n' "$body" | grep -cE '^\s+(cmov|csel)' || true)"
      bit0="$(printf '%s\n' "$body" | grep -cE '^\s+(test[bwlq]?\s+\$1,|tst\s+\w+, #0x1$|tbn?z\s+\w+, #0,)' || true)"
      echo "select-asm $label $arch O$opt: $lines lines, conditional moves $cmovs, tests of bit 0 of the flag $bit0"
      if [ "$lines" -lt 8 ]; then
        select_empty=$((select_empty + 1))
      elif [ "$bit0" != 0 ] || [ "$cmovs" -gt 2 ]; then
        select_flagged=$((select_flagged + 1))
        case " $select_flagged_archs " in *" $arch "*) ;; *) select_flagged_archs="$select_flagged_archs $arch" ;; esac
      fi
    done
  done
}

select_asm() {
  ensure_subtle
  select_check ct/harness/ct_select.rs real
  if [ "$select_empty" != 0 ]; then echo "FAIL: ct_select_bytes was not found in the assembly" >&2; return 1; fi
  if [ "$select_flagged" != 0 ]; then
    echo "FAIL: ct_select_bytes may choose a source pointer in $select_flagged configurations" >&2
    return 1
  fi
}

# The check must be able to fail: a known-bad select (ct/harness-negative) has
# to be flagged on both architectures.
select_asm_negative() {
  ensure_subtle
  select_check ct/harness-negative/ct_select_ptr.rs negative
  if [ "$select_empty" != 0 ]; then echo "FAIL: the known-bad select was not found in the assembly" >&2; return 1; fi
  case "$select_flagged_archs" in
    *x86_64*arm64* | *arm64*x86_64*) echo "select-asm negative control: flagged on x86_64 and arm64, as it must" ;;
    *) echo "FAIL: the known-bad select was not flagged on both architectures (flagged:$select_flagged_archs)" >&2; return 1 ;;
  esac
}

# The unpacking of the lookup in `login_start` (`stored_for` in
# crates/ferret-server-auth/src/login.rs) chooses between the account's own
# record and a stand-in. A branch there would be a branch on whether the name
# has an account. The function is compiled as a function of its own, and its
# body must have no conditional jump, on x86_64 and arm64.
lookup_asm() {
  local arch t asm body lines jumps
  for arch in "${archs[@]}"; do
    t="$(triple "$arch")"
    CARGO_PROFILE_RELEASE_PANIC=unwind CARGO_PROFILE_RELEASE_LTO=off CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
      cargo rustc --release --lib -p ferret-server-auth --features test-support --target "$t" -- --emit asm >&2
    asm="$(ls -t target/"$t"/release/deps/ferret_server_auth-*.s | head -n1)"
    body="$(awk '/^_ZN[0-9a-zA-Z_.$]*10stored_for17h[0-9a-f]+E:$/{on=1} on{print} on&&/\.Lfunc_end/{exit}' "$asm")"
    lines="$(printf '%s\n' "$body" | grep -c . || true)"
    case "$arch" in
      x86_64) jumps="$(printf '%s\n' "$body" | grep -cE '^\s+j[^m]' || true)" ;;
      arm64) jumps="$(printf '%s\n' "$body" | grep -cE '^\s+(b\.[a-z]+|cbn?z|tbn?z)\s' || true)" ;;
    esac
    echo "lookup-asm $arch: $lines lines, conditional jumps $jumps"
    if [ "$lines" -lt 5 ]; then
      echo "asm file: $asm ($(wc -l < "$asm") lines); lines that name stored_for:" >&2
      grep -n "stored_for" "$asm" | head -20 >&2 || true
      echo "FAIL: stored_for was not found in the assembly of $t" >&2
      return 1
    fi
    if [ "$jumps" != 0 ]; then
      printf '%s\n' "$body" >&2
      echo "FAIL: stored_for has a conditional jump on $t: the unpacking of the lookup branches" >&2
      return 1
    fi
  done
}

# -------------------------------------------------------------- wasm-scan

# Builds the binding as it is shipped (cargo release build, wasm-bindgen,
# wasm-opt -Oz with the flags of scripts/build-wasm.sh) but with the name
# section kept: wasm-bindgen keeps it unless asked to remove it, and wasm-opt
# keeps it with -g. $1 = output directory.
build_named_wasm() {
  local out="$1"
  mkdir -p "$out"
  cargo build --release -p ferret-core-wasm --target wasm32-unknown-unknown >&2
  wasm-bindgen --target web --out-dir "$out/bindgen" \
    target/wasm32-unknown-unknown/release/ferret_core_wasm.wasm >&2
  cp "$out/bindgen/ferret_core_wasm_bg.wasm" "$out/ferret_core_wasm_pre.wasm"
  wasm-opt "${wasm_opt_flags[@]}" -g "$out/ferret_core_wasm_pre.wasm" -o "$out/ferret_core_wasm_ct.wasm"
  wasm-tools print "$out/ferret_core_wasm_pre.wasm" -o "$out/ferret_core_wasm_pre.wat"
  wasm-tools print "$out/ferret_core_wasm_ct.wasm" -o "$out/ferret_core_wasm_ct.wat"
}

wasm_scan() {
  local out="$results/wasm"
  build_named_wasm "$out"
  echo "module before wasm-opt: $(wc -c < "$out/ferret_core_wasm_pre.wasm") bytes; shipped level (wasm-opt -Oz -g): $(wc -c < "$out/ferret_core_wasm_ct.wasm") bytes" | tee "$out/scan.txt"
  # Before wasm-opt: totals only, to name what the optimizer changed.
  node ct/wasm-scan.mjs "$out/ferret_core_wasm_pre.wat" ct/wasm-allow.toml --no-gate --json "$out/pre.json" > "$out/scan-pre.txt"
  # At the shipped level: this is the gate.
  node ct/wasm-scan.mjs "$out/ferret_core_wasm_ct.wat" ct/wasm-allow.toml --json "$out/post.json" --compare "$out/pre.json" | tee -a "$out/scan.txt"
  [ "${PIPESTATUS[0]}" = 0 ]
}

# The allow list is what a regeneration from the scan just made gives: no hand
# edit, no stale file, and nothing new in a key-handling function that nobody
# approved (ct/wasm-allow-gen.mjs refuses that). Run after wasm-scan.
wasm_allow_check() {
  local out="$results/wasm"
  node ct/wasm-allow-gen.mjs "$out/post.json" --existing ct/wasm-allow.toml > "$out/wasm-allow.regenerated.toml"
  if diff -u ct/wasm-allow.toml "$out/wasm-allow.regenerated.toml"; then
    echo "ct/wasm-allow.toml is what the generator gives for this scan"
  else
    echo "FAIL: ct/wasm-allow.toml differs from a regeneration; regenerate it (see ct/wasm-allow-gen.mjs) and review the diff" >&2
    return 1
  fi
}

# The allow list against the one on the base branch: a new entry or a higher
# `max` in a key-handling function has to carry an APPROVED reason (written by
# `ct/wasm-allow-gen.mjs --approve`). BASE_REF names the base branch (CI sets it
# for a pull request); CT_BASE_ALLOW gives a file instead.
wasm_allow_baseline() {
  mkdir -p "$results/wasm"
  local base="${CT_BASE_ALLOW:-}"
  if [ -z "$base" ]; then
    base="$results/wasm/base-allow.toml"
    if ! git show "origin/${BASE_REF:?set BASE_REF or CT_BASE_ALLOW}:ct/wasm-allow.toml" > "$base" 2>/dev/null; then
      echo "the base branch has no ct/wasm-allow.toml yet (first introduction): nothing to compare"
      return 0
    fi
  fi
  node ct/wasm-allow-baseline.mjs "$base" ct/wasm-allow.toml
}

# The checksum comparison of the two locks must fail on a doctored lock.
lock_selftest() {
  ct/check-lock-sums.sh ct/lock-fixtures/a.lock ct/lock-fixtures/b-same.lock
  if ct/check-lock-sums.sh ct/lock-fixtures/a.lock ct/lock-fixtures/b-doctored.lock 2>/dev/null; then
    echo "FAIL: a lock with another checksum was accepted" >&2
    return 1
  fi
  echo "lock checksum check: the same lock passes, a doctored one fails"
}

wasm_selftest() {
  local f
  for f in ct/wasm-fixtures/*.wat; do wasm-tools parse "$f" -o /dev/null; done
  node ct/wasm-selftest.mjs
}

# The named build is the shipped package: the same bytes once every custom
# section (the names) is removed from both.
wasm_shipped() {
  local out="$results/wasm"
  build_named_wasm "$out"
  scripts/build-wasm.sh >&2
  local shipped=bindings/wasm/pkg-web/ferret_core_wasm_bg.wasm
  wasm-tools strip --all "$shipped" -o "$out/shipped.stripped.wasm"
  wasm-tools strip --all "$out/ferret_core_wasm_ct.wasm" -o "$out/named.stripped.wasm"
  local a b
  a="$(sha256sum < "$out/shipped.stripped.wasm" | cut -d' ' -f1)"
  b="$(sha256sum < "$out/named.stripped.wasm" | cut -d' ' -f1)"
  echo "shipped pkg-web, names stripped: $a ($(wc -c < "$out/shipped.stripped.wasm") bytes)"
  echo "scanned build,  names stripped: $b ($(wc -c < "$out/named.stripped.wasm") bytes)"
  if [ "$a" = "$b" ]; then
    echo "the scanned module is the shipped module"
  else
    echo "FAIL: the scanned module is not the shipped module" >&2
    return 1
  fi
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
      paste -d' ' /tmp/stat1 /tmp/stat2 \
        | awk '{ busy = $5 - $2; idle = $6 - $3; print busy / (busy + idle + 1), $1 }' \
        | sort -n | head -n1 | sed 's/^[^ ]* cpu//'
      ;;
    *) echo "$CT_PIN_CPU" ;;
  esac
}

# One native bench with $3 measurements; echoes its line. The statistic is
# dudect-bencher's `max t`.
bench_line() {
  FERRET_CT_N="$3" "${pin[@]}" "$1" --filter "$2" | grep -E '^bench ' | grep -v seeded || true
}

t_of() {
  printf '%s' "$1" | sed -n 's/.*max t = \([-+0-9.eE]*\),.*/\1/p'
}

over() { # $1 t, $2 limit
  awk -v t="$1" -v l="${2:-4.5}" 'BEGIN { exit !((t < 0 ? -t : t) >= l) }'
}

# CT_SMOKE=1 (the short run on a hosted runner, which is too noisy for the
# threshold of 4.5): a bench over 4.5 whose rerun is over 4.5 too is a warning
# unless the rerun is over CT_GROSS (500): then it is a failure, as a leak of the
# size of the leaky control (|t| of 10^4) is not noise. A run that is not valid
# (no result, a control that does not behave) always fails.
finish() { # $1 failed, $2 invalid, $3 gross
  local failed="$1" invalid="$2" grossfail="${3:-0}"
  [ "$invalid" = 0 ] || return 1
  [ "$grossfail" = 0 ] || return 1
  if [ "$failed" != 0 ] && [ "${CT_SMOKE:-}" = 1 ]; then
    echo "::warning::dudect smoke run: a bench is over |t| = 4.5; hosted runners are noisy, the decisive run is scripts/lanbox-ct.sh"
    return 0
  fi
  [ "$failed" = 0 ]
}

dudect_native() {
  cargo build --release "${dudect[@]}" --features bench --bin dudect >&2
  local bin=target/release/dudect
  local out="$results/dudect-native.txt"
  : > "$out"
  local cpu
  cpu="$(pick_cpu)"
  pin=()
  if [ -n "$cpu" ]; then pin=(taskset -c "$cpu"); fi
  {
    echo "dudect native: n=$n per bench (rerun with $((n * 10)) when |t| >= 4.5), cpu=${cpu:-none}, $(date -u +%FT%TZ)"
    echo "host: $(uname -n), $(grep -m1 'model name' /proc/cpuinfo || true)"
    echo "rustc: $(rustc --version)"
    echo "load: $(cat /proc/loadavg)"
    if over "$(cut -d' ' -f1 /proc/loadavg)" "$CT_QUIET_LOAD"; then
      echo "NOT DECISIVE: the 1-minute load average at the start was above $CT_QUIET_LOAD; the machine was not quiet"
    fi
  } | tee -a "$out"
  local names="control_null control_leaky control_unpad_leaky commit_check mac_verify key_eq crockford_decode unpad_ct base32_decode kek_pw_commit_path info_unwrap_valid_vs_bad_commit info_unpad_position_zeros info_unpad_content info_unpad_random_pair info_unpad_same info_base32_a_vs_z info_base32_upper_vs_lower info_base32_random_pair server_login_start_known_vs_unknown server_login_start_known_vs_disabled control_server_login_start_null info_server_login_start_lookup_only info_server_login_start_real_vs_made_up server_prelogin_known_vs_unknown info_server_prelogin_resolve_credential server_state_binding server_finish_credential_vs_account info_server_finish_state_vs_missing"
  local failed=0 invalid=0 grossfail=0 name rep
  for name in $names; do
    # A selected run always has the controls with it: a result without them
    # does not show that the setup could see a leak, or stayed quiet on equal
    # classes, in that session.
    if [ -n "${CT_ONLY:-}" ] && [[ "$name" != *"$CT_ONLY"* ]] && [[ "$name" != control_* ]]; then continue; fi
    for rep in $(seq 1 "${CT_REPEAT:-1}"); do
      local line t line2 t2="" first_over=0 second_over=0
      line="$(bench_line "$bin" "$name" "$n")"
      echo "[run n=$n] $line" | tee -a "$out"
      t="$(t_of "$line")"
      if [ -z "$t" ]; then echo "no t-value for $name" | tee -a "$out"; invalid=1; continue; fi
      if over "$t"; then first_over=1; fi
      case "$name" in
        control_*leaky*)
          if [ "$first_over" = 1 ]; then
            echo "[ok] $name: the setup sees an early-exit comparison" | tee -a "$out"
          else
            echo "[FAIL] $name: the setup does not see an early-exit comparison, the run is not valid" | tee -a "$out"
            invalid=1
          fi
          continue
          ;;
        info_*) echo "[info] $name is reported, not gated" | tee -a "$out"; continue ;;
      esac
      if [ "$first_over" = 1 ] && [ "$n" -ge 10000000 ]; then
        # The rerun would be ten times as long again (hours); a bench over the
        # limit at 10^7 is a failure that is looked at, not measured again.
        echo "[FAIL] $name: |t| >= 4.5 at n=$n (no rerun above 10^7)" | tee -a "$out"
        failed=1
        continue
      fi
      if [ "$first_over" = 1 ]; then
        line2="$(bench_line "$bin" "$name" "$((n * 10))")"
        echo "[rerun n=$((n * 10))] $line2" | tee -a "$out"
        t2="$(t_of "$line2")"
        if [ -z "$t2" ]; then echo "no t-value for the rerun of $name" | tee -a "$out"; invalid=1; continue; fi
        if over "$t2"; then second_over=1; fi
        if over "$t2" "$gross"; then grossfail=1; fi
      fi
      if [ "$second_over" = 1 ]; then
        echo "[FAIL] $name: |t| >= 4.5 at n=$n and again at n=$((n * 10))" | tee -a "$out"
        failed=1
      elif [ "$first_over" = 1 ]; then
        echo "[ok, rerun] $name: |t| >= 4.5 at n=$n, below at n=$((n * 10))" | tee -a "$out"
      else
        echo "[ok] $name" | tee -a "$out"
      fi
    done
  done
  {
    echo "load at the end: $(cat /proc/loadavg)"
    if over "$(cut -d' ' -f1 /proc/loadavg)" "$CT_QUIET_LOAD"; then
      echo "NOT DECISIVE: the 1-minute load average at the end was above $CT_QUIET_LOAD"
    fi
  } | tee -a "$out"
  finish "$failed" "$invalid" "$grossfail"
}

dudect_wasm() {
  cargo build --release "${dudect[@]}" --lib --target wasm32-unknown-unknown >&2
  local raw=target/wasm32-unknown-unknown/release/ferret_ct.wasm
  mkdir -p "$results/wasm"
  # The shipped level: the same wasm-opt as the package of the binding.
  local wasm="$results/wasm/ferret_ct_opt.wasm"
  wasm-opt "${wasm_opt_flags[@]}" -g "$raw" -o "$wasm"
  local cpu
  cpu="$(pick_cpu)"
  pin=()
  if [ -n "$cpu" ]; then pin=(taskset -c "$cpu"); fi
  # `node` exits 1 for a threshold failure, 3 for a run that is not valid and
  # 4 for a gross failure; its status is read after the pipe, with set -e off.
  set +e
  FERRET_CT_N="$n" CT_GROSS="$gross" CT_CPU="${cpu:-none}" CT_HOST="$(uname -n)" "${pin[@]}" \
    node ct/dudect-wasm/run.mjs "$wasm" | tee "$results/dudect-wasm.txt"
  local rc="${PIPESTATUS[0]}"
  set -e
  case "$rc" in
    0) ;;
    1) finish 1 0 0 ;;
    4) finish 1 0 1 ;;
    *) return "$rc" ;;
  esac
}

case "$mode" in
  analyze) analyze ;;
  triage) triage ;;
  select-asm) select_asm ;;
  select-asm-negative) select_asm_negative ;;
  lookup-asm) lookup_asm ;;
  wasm-scan) wasm_scan ;;
  wasm-allow-check) wasm_allow_check ;;
  wasm-selftest) wasm_selftest ;;
  wasm-shipped) wasm_shipped ;;
  dudect-native) dudect_native ;;
  dudect-wasm) dudect_wasm ;;
  lock) ct/check-lock.sh ;;
  lock-selftest) lock_selftest ;;
  wasm-allow-baseline) wasm_allow_baseline ;;
  all)
    ct/check-lock.sh
    lock_selftest
    analyze
    triage
    select_asm
    select_asm_negative
    lookup_asm
    wasm_selftest
    wasm_scan
    wasm_allow_check
    wasm_shipped
    dudect_native
    dudect_wasm
    ;;
  *)
    echo "usage: ct/run.sh analyze|triage|select-asm|select-asm-negative|lookup-asm|wasm-scan|wasm-allow-check|wasm-allow-baseline|wasm-selftest|wasm-shipped|dudect-native|dudect-wasm|lock|lock-selftest|all" >&2
    exit 2
    ;;
esac
